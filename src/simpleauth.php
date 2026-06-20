<?php
declare(strict_types=1);

namespace vielhuber\simpleauth;

use vielhuber\dbhelper\dbhelper;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use vielhuber\mailhelper\mailhelper;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

class simpleauth
{
    private object $config;
    private dbhelper $db;

    public function __construct(
        ?string $config = null,
        string $table = 'users',
        string $login = 'email',
        int $ttl = 1,
        bool $uuid = false,
        false|array $throttle = [
            'attempts' => 5,
            'minutes' => 15,
            'table' => 'users_login_attempts'
        ],
        false|array $passkeys = [
            'table' => 'users_passkeys',
            'table_challenge' => 'users_passkeys_challenges'
        ],
        false|array $captcha = false,
        bool|string|array $cors = '*',
        ?callable $passwordResetMail = null
    ) {
        $dotenv = \Dotenv\Dotenv::createImmutable(str_replace(['/.env', '.env'], '', $config ?? ''));
        $dotenv->load();

        $this->config = (object) [
            'DB_CONNECTION' => @$_SERVER['DB_CONNECTION'],
            'DB_HOST' => @$_SERVER['DB_HOST'],
            'DB_PORT' => @$_SERVER['DB_PORT'],
            'DB_DATABASE' => @$_SERVER['DB_DATABASE'],
            'DB_USERNAME' => @$_SERVER['DB_USERNAME'],
            'DB_PASSWORD' => @$_SERVER['DB_PASSWORD'],
            'JWT_SECRET' => @$_SERVER['JWT_SECRET']
        ];
        $this->db = new dbhelper();
        $this->db->connect_with_create(
            'pdo',
            $this->config->DB_CONNECTION,
            $this->config->DB_HOST,
            $this->config->DB_USERNAME,
            $this->config->DB_PASSWORD,
            $this->config->DB_DATABASE,
            $this->config->DB_PORT
        );

        $this->config->TABLE = $table;
        $this->config->LOGIN = $login;
        $this->config->TTL = $ttl;
        $this->config->UUID = $uuid;
        $this->config->THROTTLE = $throttle !== false;
        $this->config->THROTTLE_ATTEMPTS = $throttle === false ? 5 : (int) ($throttle['attempts'] ?? 5);
        $this->config->THROTTLE_MINUTES = $throttle === false ? 15 : (int) ($throttle['minutes'] ?? 15);
        $this->config->THROTTLE_TABLE =
            $throttle === false ? 'users_login_attempts' : (string) ($throttle['table'] ?? 'users_login_attempts');
        $this->config->PASSKEY = $passkeys !== false;
        $passkeys_table = $passkeys === false ? 'users_passkeys' : (string) ($passkeys['table'] ?? 'users_passkeys');
        $this->config->PASSKEY_TABLE = $passkeys_table;
        $this->config->PASSKEY_CHALLENGE_TABLE =
            $passkeys === false
                ? 'users_passkeys_challenges'
                : (string) ($passkeys['table_challenge'] ?? $passkeys_table . '_challenges');
        $this->config->CAPTCHA = $captcha !== false;
        $this->config->CAPTCHA_PROVIDER = $captcha === false ? null : (string) ($captcha['provider'] ?? 'hcaptcha');
        $this->config->CAPTCHA_SITEKEY = $captcha === false ? null : (string) ($captcha['sitekey'] ?? '');
        $this->config->CAPTCHA_SECRET = $captcha === false ? null : (string) ($captcha['secret'] ?? '');
        $this->config->SMTP = (string) ($_SERVER['SMTP_HOST'] ?? '') !== '';
        $this->config->SMTP_HOST = (string) ($_SERVER['SMTP_HOST'] ?? '');
        $this->config->SMTP_PORT = (int) ($_SERVER['SMTP_PORT'] ?? 587);
        $this->config->SMTP_USERNAME = (string) ($_SERVER['SMTP_USERNAME'] ?? '');
        $this->config->SMTP_PASSWORD = (string) ($_SERVER['SMTP_PASSWORD'] ?? '');
        $this->config->SMTP_ENCRYPTION = (string) ($_SERVER['SMTP_ENCRYPTION'] ?? 'tls');
        $this->config->SMTP_FROM_EMAIL = (string) ($_SERVER['SMTP_FROM_EMAIL'] ?? '');
        $this->config->SMTP_FROM_NAME = (string) ($_SERVER['SMTP_FROM_NAME'] ?? '');
        $this->config->SMTP_TENANT_ID = (string) ($_SERVER['SMTP_TENANT_ID'] ?? '');
        $this->config->SMTP_CLIENT_ID = (string) ($_SERVER['SMTP_CLIENT_ID'] ?? '');
        $this->config->SMTP_CLIENT_SECRET = (string) ($_SERVER['SMTP_CLIENT_SECRET'] ?? '');
        $this->config->PASSWORD_RESET_URL = (string) ($_SERVER['PASSWORD_RESET_URL'] ?? '');
        $this->config->PASSWORD_RESET_MAIL = $passwordResetMail;
        $this->createTable();
        $this->handleCors($cors);
    }

    public function init(): void
    {
        global $argv;
        if (php_sapi_name() !== 'cli') {
            $this->api();
        } elseif (!empty($argv) && isset($argv[1]) && $argv[1] === 'migrate') {
            $this->migrate();
        } elseif (
            !empty($argv) &&
            isset($argv[1]) &&
            $argv[1] === 'create' &&
            isset($argv[2]) &&
            $argv[2] !== '' &&
            isset($argv[1]) &&
            $argv[3] !== ''
        ) {
            $this->create($argv[2], $argv[3]);
        }
    }

    private function api()
    {
        if ($this->apiRequestMethod() === 'POST' && $this->apiRequestPath() === 'login') {
            return $this->apiLogin();
        }
        if ($this->apiRequestMethod() === 'POST' && $this->apiRequestPath() === 'refresh') {
            return $this->apiRefresh();
        }
        if ($this->apiRequestMethod() === 'POST' && $this->apiRequestPath() === 'logout') {
            return $this->apiLogout();
        }
        if ($this->apiRequestMethod() === 'POST' && $this->apiRequestPath() === 'check') {
            return $this->apiCheck();
        }
        if ($this->apiRequestMethod() === 'POST' && $this->apiRequestPath() === 'password-reset-request') {
            return $this->apiPasswordResetRequest();
        }
        if ($this->apiRequestMethod() === 'POST' && $this->apiRequestPath() === 'password-reset') {
            return $this->apiPasswordReset();
        }
        if (
            $this->passkeyEnabled() &&
            $this->apiRequestMethod() === 'POST' &&
            $this->apiRequestPath() === 'passkey-register-options'
        ) {
            return $this->apiPasskeyRegisterOptions();
        }
        if (
            $this->passkeyEnabled() &&
            $this->apiRequestMethod() === 'POST' &&
            $this->apiRequestPath() === 'passkey-register'
        ) {
            return $this->apiPasskeyRegister();
        }
        if (
            $this->passkeyEnabled() &&
            $this->apiRequestMethod() === 'POST' &&
            $this->apiRequestPath() === 'passkey-login-options'
        ) {
            return $this->apiPasskeyLoginOptions();
        }
        if (
            $this->passkeyEnabled() &&
            $this->apiRequestMethod() === 'POST' &&
            $this->apiRequestPath() === 'passkey-login'
        ) {
            return $this->apiPasskeyLogin();
        }
        if (
            $this->passkeyEnabled() &&
            $this->apiRequestMethod() === 'POST' &&
            $this->apiRequestPath() === 'passkey-delete'
        ) {
            return $this->apiPasskeyDelete();
        }
        return $this->apiResponse(
            [
                'success' => false,
                'message' => 'unknown route',
                'public_message' => 'Unknown route!'
            ],
            404
        );
    }

    public function migrate(): void
    {
        $this->deleteTable();
        $this->createTable();
    }

    private function create(string $username, string $password): void
    {
        try {
            $this->deleteUser($username);
        } catch (\Exception $e) {
        }
        $this->createUser($username, $password);
    }

    private function apiRequestPath()
    {
        $path = @$_SERVER['REQUEST_URI'];
        $path = trim($path, '/');
        if (strrpos($path, '/') !== false) {
            $path = substr($path, strrpos($path, '/') + 1);
        }
        return $path;
    }

    private function apiRequestMethod()
    {
        return @$_SERVER['REQUEST_METHOD'];
    }

    private function handleCors(bool|string|array $cors): void
    {
        if (
            headers_sent() ||
            ob_get_length() > 0 ||
            (PHP_SAPI == 'cli' && strpos($_SERVER['argv'][0], 'phpunit') !== false)
        ) {
            return;
        }

        if ($cors === true || $cors === '*') {
            header('Access-Control-Allow-Origin: *');
            header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization');
        }

        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        if ($cors !== true && $cors !== '*' && $origin !== '' && $this->corsAllowed($origin, $cors)) {
            header('Access-Control-Allow-Origin: ' . $origin);
            header('Vary: Origin');
            header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization');
        }

        if (($_SERVER['REQUEST_METHOD'] ?? '') == 'OPTIONS') {
            die();
        }
    }

    private function corsAllowed(string $origin, bool|string|array $cors): bool
    {
        if ($cors === false) {
            return false;
        }
        if ($cors === true || $cors === '*') {
            return true;
        }
        $origins = is_array($cors) ? $cors : [$cors];
        return in_array($origin, $origins, true);
    }

    private function apiInput(string $key): mixed
    {
        $p1 = $_POST;
        $p2 = json_decode(file_get_contents('php://input'), true);
        parse_str(file_get_contents('php://input'), $p3);
        if (isset($p1) && !empty($p1) && array_key_exists($key, $p1)) {
            return $p1[$key];
        }
        if (isset($p2) && !empty($p2) && array_key_exists($key, $p2)) {
            return $p2[$key];
        }
        if (isset($p3) && !empty($p3)) {
            foreach ($p3 as $p3__key => $p3__value) {
                unset($p3[$p3__key]);
                $p3[str_replace('amp;', '', $p3__key)] = $p3__value;
            }
            if (array_key_exists($key, $p3)) {
                return $p3[$key];
            }
        }
        return null;
    }

    private function apiLogin()
    {
        try {
            $login = (string) $this->apiInput($this->config->LOGIN);
            $password = (string) $this->apiInput('password');
            if ($login == '' || $password == '') {
                throw new \Exception('login or password missing');
            }
            if (!$this->captchaValid()) {
                return $this->apiResponse(
                    [
                        'success' => false,
                        'message' => 'captcha not successful',
                        'public_message' => 'Captcha not successful'
                    ],
                    401
                );
            }
            if ($this->throttleReached($login)) {
                return $this->apiResponse(
                    [
                        'success' => false,
                        'message' => 'too many login attempts',
                        'public_message' => 'Too many login attempts. Please try again later.'
                    ],
                    429
                );
            }
            $user = $this->db->fetch_row(
                'SELECT * FROM ' . $this->config->TABLE . ' WHERE ' . $this->config->LOGIN . ' = ?',
                $login
            );
            if (empty($user) || !password_verify($password, $user['password'])) {
                $this->throttleRecord($login);
                throw new \Exception('login or password wrong');
            }
            $this->throttleClear($login);
            $data = $this->createAccessToken($user['id'], $user[$this->config->LOGIN]);
            return $this->apiResponse(
                [
                    'success' => true,
                    'message' => 'auth successful',
                    'public_message' => 'Successfully logged in',
                    'data' => $data
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'auth not successful',
                    'public_message' => 'Not successful'
                ],
                401
            );
        }
    }

    private function apiRefresh()
    {
        try {
            $user_id = $this->getUserIdFromAccessToken($_SERVER['HTTP_AUTHORIZATION'] ?? '');
            $user_login = (string) $this->getUserLoginFromAccessToken($_SERVER['HTTP_AUTHORIZATION'] ?? '');
            $data = $this->createAccessToken($user_id, $user_login);
            return $this->apiResponse(
                [
                    'success' => true,
                    'message' => 'auth successful',
                    'public_message' => 'Successfully logged in',
                    'data' => $data
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'invalid token',
                    'public_message' => 'Invalid token'
                ],
                401
            );
        }
    }

    private function apiLogout()
    {
        try {
            $this->getUserIdFromAccessToken($_SERVER['HTTP_AUTHORIZATION'] ?? '');
            return $this->apiResponse(
                [
                    'success' => true,
                    'message' => 'logout successful',
                    'public_message' => 'Successfully logged out'
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'logout not successful',
                    'public_message' => 'Logout not successful'
                ],
                401
            );
        }
    }

    private function apiCheck()
    {
        try {
            $access_token = (string) $this->apiInput('access_token');
            $user_id = $this->getUserIdFromAccessToken($access_token);
            return $this->apiResponse(
                [
                    'success' => true,
                    'message' => 'valid token',
                    'public_message' => 'Valid token',
                    'data' => [
                        'access_token' => $access_token,
                        'expires_in' => $this->config->TTL,
                        'user_id' => $user_id
                    ]
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'invalid token',
                    'public_message' => 'Invalid token'
                ],
                401
            );
        }
    }

    private function apiPasskeyRegisterOptions()
    {
        try {
            $user_id = $this->getUserIdFromAccessToken($_SERVER['HTTP_AUTHORIZATION'] ?? '');
            $user_login = (string) $this->getUserLoginFromAccessToken($_SERVER['HTTP_AUTHORIZATION'] ?? '');
            $exclude_credentials = [];
            foreach ($this->passkeyCredentialsForUser((string) $user_id) as $passkey_credential) {
                $exclude_credentials[] = $passkey_credential->getPublicKeyCredentialDescriptor();
            }
            $options = PublicKeyCredentialCreationOptions::create(
                PublicKeyCredentialRpEntity::create($this->passkeyRpName(), $this->passkeyRpId()),
                PublicKeyCredentialUserEntity::create($user_login, (string) $user_id, $user_login),
                random_bytes(32),
                [PublicKeyCredentialParameters::createPk(-7), PublicKeyCredentialParameters::createPk(-257)],
                AuthenticatorSelectionCriteria::create(
                    null,
                    AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
                    AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED
                ),
                PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
                $exclude_credentials,
                60000
            );
            $public_key = $this->passkeyNormalize($options);
            $this->passkeyStoreChallenge(
                type: 'register',
                challenge: $public_key['challenge'],
                options: $public_key,
                user_id: (string) $user_id,
                login_identifier: $user_login
            );
            return $this->apiResponse(
                [
                    'success' => true,
                    'message' => 'passkey registration options created',
                    'public_message' => 'Passkey registration prepared',
                    'data' => [
                        'publicKey' => $public_key
                    ]
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'passkey registration options not created',
                    'public_message' => 'Passkey registration not prepared'
                ],
                401
            );
        }
    }

    private function apiPasswordResetRequest()
    {
        try {
            $login = (string) ($this->apiInput($this->config->LOGIN) ?? $this->apiInput('email') ?? '');
            if ($login !== '') {
                $this->requestPasswordReset($login);
            }
            return $this->apiResponse(
                [
                    'success' => true,
                    'message' => 'password reset requested',
                    'public_message' => 'If the account exists, a password reset email has been sent'
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'password reset not requested',
                    'public_message' => 'Password reset not requested'
                ],
                500
            );
        }
    }

    private function apiPasswordReset()
    {
        try {
            $token = (string) ($this->apiInput('token') ?? '');
            $password = (string) ($this->apiInput('password') ?? '');
            if ($token === '' || $password === '') {
                throw new \Exception('token or password missing');
            }
            $this->resetPassword($token, $password);
            return $this->apiResponse(
                [
                    'success' => true,
                    'message' => 'password reset successful',
                    'public_message' => 'Password reset successful'
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'password reset not successful',
                    'public_message' => 'Password reset not successful'
                ],
                401
            );
        }
    }

    private function apiPasskeyRegister()
    {
        try {
            $user_id = $this->getUserIdFromAccessToken($_SERVER['HTTP_AUTHORIZATION'] ?? '');
            $user_login = (string) $this->getUserLoginFromAccessToken($_SERVER['HTTP_AUTHORIZATION'] ?? '');
            $credential_data = $this->apiInput('credential');
            if (!is_array($credential_data)) {
                throw new \Exception('credential missing');
            }
            $challenge = $this->passkeyChallengeFromCredential($credential_data);
            $challenge_row = $this->passkeyChallengeRow('register', $challenge, (string) $user_id);
            $serializer = $this->passkeySerializer();
            $options = $serializer->denormalize(
                json_decode($challenge_row['options'], true),
                PublicKeyCredentialCreationOptions::class
            );
            $credential = $serializer->denormalize($credential_data, PublicKeyCredential::class);
            if (!($credential->response instanceof AuthenticatorAttestationResponse)) {
                throw new \Exception('invalid credential response');
            }
            $validator = AuthenticatorAttestationResponseValidator::create(
                $this->passkeyCeremonyFactory()->creationCeremony()
            );
            $credential_record = $validator->check($credential->response, $options, $this->passkeyRpId());
            $this->passkeyStoreCredential((string) $user_id, $user_login, $credential_record);
            $this->passkeyDeleteChallenge((int) $challenge_row['id']);
            return $this->apiResponse(
                [
                    'success' => true,
                    'message' => 'passkey registered',
                    'public_message' => 'Passkey registered'
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'passkey not registered',
                    'public_message' => 'Passkey not registered'
                ],
                401
            );
        }
    }

    private function apiPasskeyLoginOptions()
    {
        try {
            $login = (string) ($this->apiInput($this->config->LOGIN) ?? '');
            $user = null;
            $allow_credentials = [];
            if ($login !== '') {
                $user = $this->db->fetch_row(
                    'SELECT * FROM ' . $this->config->TABLE . ' WHERE ' . $this->config->LOGIN . ' = ?',
                    $login
                );
                if (empty($user)) {
                    throw new \Exception('user not found');
                }
                foreach ($this->passkeyCredentialsForUser((string) $user['id']) as $passkey_credential) {
                    $allow_credentials[] = $passkey_credential->getPublicKeyCredentialDescriptor();
                }
                if (count($allow_credentials) === 0) {
                    throw new \Exception('passkey not found');
                }
            }
            $options = PublicKeyCredentialRequestOptions::create(
                random_bytes(32),
                $this->passkeyRpId(),
                $allow_credentials,
                PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
                60000
            );
            $public_key = $this->passkeyNormalize($options);
            $this->passkeyStoreChallenge(
                type: 'login',
                challenge: $public_key['challenge'],
                options: $public_key,
                user_id: empty($user) ? null : (string) $user['id'],
                login_identifier: $login === '' ? null : $login
            );
            return $this->apiResponse(
                [
                    'success' => true,
                    'message' => 'passkey login options created',
                    'public_message' => 'Passkey login prepared',
                    'data' => [
                        'publicKey' => $public_key
                    ]
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'passkey login options not created',
                    'public_message' => 'Passkey login not prepared'
                ],
                401
            );
        }
    }

    private function apiPasskeyLogin()
    {
        try {
            $credential_data = $this->apiInput('credential');
            if (!is_array($credential_data)) {
                throw new \Exception('credential missing');
            }
            $credential_id = $this->passkeyCredentialIdFromCredential($credential_data);
            $passkey = $this->db->fetch_row(
                'SELECT * FROM ' . $this->config->PASSKEY_TABLE . ' WHERE credential_id = ?',
                $credential_id
            );
            if (empty($passkey)) {
                throw new \Exception('passkey not found');
            }
            $challenge = $this->passkeyChallengeFromCredential($credential_data);
            $challenge_row = $this->passkeyChallengeRow('login', $challenge, $passkey['user_id']);
            $serializer = $this->passkeySerializer();
            $options = $serializer->denormalize(
                json_decode($challenge_row['options'], true),
                PublicKeyCredentialRequestOptions::class
            );
            $credential = $serializer->denormalize($credential_data, PublicKeyCredential::class);
            if (!($credential->response instanceof AuthenticatorAssertionResponse)) {
                throw new \Exception('invalid credential response');
            }
            $credential_record = $serializer->denormalize(
                json_decode($passkey['credential_record'], true),
                CredentialRecord::class
            );
            $validator = AuthenticatorAssertionResponseValidator::create(
                $this->passkeyCeremonyFactory()->requestCeremony()
            );
            $credential_record = $validator->check(
                $credential_record,
                $credential->response,
                $options,
                $this->passkeyRpId(),
                $credential->response->userHandle
            );
            $this->passkeyUpdateCredential((int) $passkey['id'], $credential_record);
            $this->passkeyDeleteChallenge((int) $challenge_row['id']);
            $user = $this->db->fetch_row(
                'SELECT * FROM ' . $this->config->TABLE . ' WHERE id = ?',
                $passkey['user_id']
            );
            if (empty($user)) {
                throw new \Exception('user not found');
            }
            $data = $this->createAccessToken($user['id'], $user[$this->config->LOGIN]);
            return $this->apiResponse(
                [
                    'success' => true,
                    'message' => 'auth successful',
                    'public_message' => 'Successfully logged in',
                    'data' => $data
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'passkey auth not successful',
                    'public_message' => 'Passkey not successful'
                ],
                401
            );
        }
    }

    private function apiPasskeyDelete()
    {
        try {
            $user_login = (string) $this->getUserLoginFromAccessToken($_SERVER['HTTP_AUTHORIZATION'] ?? '');
            $passkey_id = $this->apiInput('id') ?? $this->apiInput('passkey_id');
            if ($passkey_id === null || $passkey_id === '') {
                throw new \Exception('passkey id missing');
            }
            $this->deletePasskey(login: $user_login, passkey_id: $passkey_id);
            return $this->apiResponse(
                [
                    'success' => true,
                    'message' => 'passkey deleted',
                    'public_message' => 'Passkey deleted'
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'passkey not deleted',
                    'public_message' => 'Passkey not deleted'
                ],
                401
            );
        }
    }

    private function apiResponse(array $data, int $code = 200): void
    {
        http_response_code($code);
        header('Content-Type: application/json');
        echo json_encode($data);
        die();
    }

    private function dbIsSqlite(): bool
    {
        return strtolower((string) $this->config->DB_CONNECTION) === 'sqlite';
    }

    private function createTable(): bool
    {
        $this->db->query(
            '
            CREATE TABLE IF NOT EXISTS ' .
                $this->config->TABLE .
                '
            (
                id ' .
                ($this->config->UUID === true ? 'VARCHAR(36)' : ($this->dbIsSqlite() ? 'INTEGER' : 'SERIAL')) .
                ' PRIMARY KEY,
                ' .
                $this->config->LOGIN .
                ' varchar(100) NOT NULL,
                password char(255) NOT NULL
            )
        '
        );
        $this->db->query(
            '
            CREATE TABLE IF NOT EXISTS ' .
                $this->config->THROTTLE_TABLE .
                '
            (
                id ' .
                ($this->dbIsSqlite() ? 'INTEGER' : 'SERIAL') .
                ' PRIMARY KEY,
                login_identifier varchar(255) NOT NULL,
                ip_address varchar(45) NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        '
        );
        $this->db->query(
            '
            CREATE TABLE IF NOT EXISTS ' .
                $this->config->PASSKEY_TABLE .
                '
            (
                id ' .
                ($this->dbIsSqlite() ? 'INTEGER' : 'SERIAL') .
                ' PRIMARY KEY,
                user_id varchar(64) NOT NULL,
                login_identifier varchar(255) NOT NULL,
                credential_id varchar(512) NOT NULL,
                credential_record LONGTEXT NOT NULL,
                counter int NOT NULL DEFAULT 0,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP NULL DEFAULT NULL
            )
        '
        );
        $this->db->query(
            '
            CREATE TABLE IF NOT EXISTS ' .
                $this->config->PASSKEY_CHALLENGE_TABLE .
                '
            (
                id ' .
                ($this->dbIsSqlite() ? 'INTEGER' : 'SERIAL') .
                ' PRIMARY KEY,
                type varchar(20) NOT NULL,
                user_id varchar(64) NULL,
                login_identifier varchar(255) NULL,
                challenge varchar(255) NOT NULL,
                options LONGTEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        '
        );
        $this->createIndexIfMissing(
            $this->config->THROTTLE_TABLE,
            'login_attempts_lookup',
            ['login_identifier', 'ip_address', 'created_at']
        );
        $this->createIndexIfMissing($this->config->PASSKEY_TABLE, 'passkey_credential_id', ['credential_id'], true);
        $this->createIndexIfMissing($this->config->PASSKEY_TABLE, 'passkey_user_id', ['user_id']);
        $this->createIndexIfMissing(
            $this->config->PASSKEY_CHALLENGE_TABLE,
            'passkey_challenge_lookup',
            ['type', 'challenge', 'user_id']
        );
        return true;
    }

    private function createIndexIfMissing(string $table, string $index, array $columns, bool $unique = false): void
    {
        if ($this->db->has_index($table, $index)) {
            return;
        }
        $this->db->create_index($table, $index, $columns, $unique);
    }

    private function deleteTable(): bool
    {
        $this->db->query('DROP TABLE IF EXISTS ' . $this->config->TABLE);
        $this->db->query('DROP TABLE IF EXISTS ' . $this->config->THROTTLE_TABLE);
        $this->db->query('DROP TABLE IF EXISTS ' . $this->config->PASSKEY_TABLE);
        $this->db->query('DROP TABLE IF EXISTS ' . $this->config->PASSKEY_CHALLENGE_TABLE);
        return true;
    }

    private function passkeySerializer(): SerializerInterface
    {
        static $serializer = null;
        if ($serializer !== null) {
            return $serializer;
        }
        $attestation_statement_support_manager = AttestationStatementSupportManager::create([
            NoneAttestationStatementSupport::create()
        ]);
        $serializer = (new WebauthnSerializerFactory($attestation_statement_support_manager))->create();
        return $serializer;
    }

    private function passkeyEnabled(): bool
    {
        return $this->config->PASSKEY === true;
    }

    private function passkeyCeremonyFactory(): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins($this->passkeyOrigins());
        return $factory;
    }

    private function passkeyNormalize(object $value): array
    {
        return $this->passkeySerializer()->normalize($value);
    }

    private function passkeyStoreChallenge(
        string $type,
        string $challenge,
        array $options,
        ?string $user_id,
        ?string $login_identifier
    ): void {
        $this->passkeyDeleteExpiredChallenges();
        $this->db->query(
            'INSERT INTO ' .
                $this->config->PASSKEY_CHALLENGE_TABLE .
                '(type, user_id, login_identifier, challenge, options, created_at) VALUES(?,?,?,?,?,?)',
            $type,
            $user_id,
            $login_identifier,
            $challenge,
            json_encode($options),
            date('Y-m-d H:i:s')
        );
    }

    private function passkeyChallengeRow(string $type, string $challenge, ?string $user_id): array
    {
        $query =
            'SELECT * FROM ' .
            $this->config->PASSKEY_CHALLENGE_TABLE .
            ' WHERE type = ? AND challenge = ? AND created_at >= ?';
        $params = [$type, $challenge, date('Y-m-d H:i:s', time() - 300)];
        if ($user_id !== null && $user_id !== '') {
            $query .= ' AND (user_id = ? OR user_id IS NULL)';
            $params[] = $user_id;
        }
        $query .= ' ORDER BY id DESC';
        $challenge_row = $this->db->fetch_row($query, ...$params);
        if (empty($challenge_row)) {
            throw new \Exception('passkey challenge not found');
        }
        return $challenge_row;
    }

    private function passkeyDeleteChallenge(int $id): void
    {
        $this->db->query('DELETE FROM ' . $this->config->PASSKEY_CHALLENGE_TABLE . ' WHERE id = ?', $id);
    }

    private function passkeyDeleteExpiredChallenges(): void
    {
        $this->db->query(
            'DELETE FROM ' . $this->config->PASSKEY_CHALLENGE_TABLE . ' WHERE created_at < ?',
            date('Y-m-d H:i:s', time() - 300)
        );
    }

    private function passkeyCredentialsForUser(string $user_id): array
    {
        $credentials = [];
        foreach (
            $this->db->fetch_all(
                'SELECT credential_record FROM ' . $this->config->PASSKEY_TABLE . ' WHERE user_id = ?',
                $user_id
            )
            as $passkey
        ) {
            $credentials[] = $this->passkeySerializer()->denormalize(
                json_decode($passkey['credential_record'], true),
                CredentialRecord::class
            );
        }
        return $credentials;
    }

    private function passkeyStoreCredential(
        string $user_id,
        string $login_identifier,
        CredentialRecord $credential_record
    ): void {
        $credential_id = Base64UrlSafe::encodeUnpadded($credential_record->publicKeyCredentialId);
        if (
            $this->db->fetch_var(
                'SELECT COUNT(id) FROM ' . $this->config->PASSKEY_TABLE . ' WHERE credential_id = ?',
                $credential_id
            ) > 0
        ) {
            throw new \Exception('passkey already exists');
        }
        $this->db->query(
            'INSERT INTO ' .
                $this->config->PASSKEY_TABLE .
                '(user_id, login_identifier, credential_id, credential_record, counter, created_at) VALUES(?,?,?,?,?,?)',
            $user_id,
            $login_identifier,
            $credential_id,
            json_encode($this->passkeyNormalize($credential_record)),
            $credential_record->counter,
            date('Y-m-d H:i:s')
        );
    }

    private function passkeyUpdateCredential(int $id, CredentialRecord $credential_record): void
    {
        $this->db->query(
            'UPDATE ' .
                $this->config->PASSKEY_TABLE .
                ' SET credential_record = ?, counter = ?, last_used_at = ? WHERE id = ?',
            json_encode($this->passkeyNormalize($credential_record)),
            $credential_record->counter,
            date('Y-m-d H:i:s'),
            $id
        );
    }

    private function passkeyChallengeFromCredential(array $credential_data): string
    {
        if (!isset($credential_data['response']['clientDataJSON'])) {
            throw new \Exception('client data missing');
        }
        $client_data = json_decode(
            Base64UrlSafe::decodeNoPadding($credential_data['response']['clientDataJSON']),
            true
        );
        if (!is_array($client_data) || !isset($client_data['challenge'])) {
            throw new \Exception('challenge missing');
        }
        return $client_data['challenge'];
    }

    private function passkeyCredentialIdFromCredential(array $credential_data): string
    {
        if (!isset($credential_data['id'])) {
            throw new \Exception('credential id missing');
        }
        return $credential_data['id'];
    }

    private function passkeyRpId(): string
    {
        return explode(':', $this->passkeyHost())[0];
    }

    private function passkeyRpName(): string
    {
        return $this->passkeyRpId();
    }

    private function passkeyOrigins(): array
    {
        $host = $this->passkeyHost();
        $scheme = $this->passkeyScheme();
        $origins = [$scheme . '://' . $host];
        if ($scheme === 'http' && !in_array(explode(':', $host)[0], ['localhost', '127.0.0.1'], true)) {
            $origins[] = 'https://' . $host;
        }
        return array_values(array_unique($origins));
    }

    private function passkeyHost(): string
    {
        $host = $_SERVER['HTTP_X_FORWARDED_HOST'] ?? $_SERVER['HTTP_HOST'] ?? 'localhost';
        return trim(explode(',', $host)[0]);
    }

    private function passkeyScheme(): string
    {
        $forwarded_proto = strtolower(trim(explode(',', (string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''))[0]));
        if (in_array($forwarded_proto, ['http', 'https'], true)) {
            return $forwarded_proto;
        }
        $cf_visitor = json_decode((string) ($_SERVER['HTTP_CF_VISITOR'] ?? ''), true);
        if (is_array($cf_visitor) && in_array(($cf_visitor['scheme'] ?? ''), ['http', 'https'], true)) {
            return $cf_visitor['scheme'];
        }
        if (in_array(strtolower((string) ($_SERVER['HTTP_X_FORWARDED_SSL'] ?? '')), ['on', '1'], true)) {
            return 'https';
        }
        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
            return 'https';
        }
        if ((string) ($_SERVER['SERVER_PORT'] ?? '') === '443') {
            return 'https';
        }
        return 'http';
    }

    private function captchaEnabled(): bool
    {
        return $this->config->CAPTCHA === true;
    }

    private function captchaValid(): bool
    {
        if (!$this->captchaEnabled()) {
            return true;
        }
        if ($this->config->CAPTCHA_SECRET === '') {
            return false;
        }
        $endpoints = [
            'hcaptcha' => 'https://api.hcaptcha.com/siteverify',
            'turnstile' => 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
        ];
        $fields = [
            'hcaptcha' => 'h-captcha-response',
            'turnstile' => 'cf-turnstile-response'
        ];
        $provider = (string) $this->config->CAPTCHA_PROVIDER;
        if (!isset($endpoints[$provider])) {
            return false;
        }
        $token = (string) ($this->apiInput($fields[$provider]) ?? '');
        if ($token === '') {
            return false;
        }
        return $this->captchaVerify($endpoints[$provider], $token, $provider);
    }

    private function captchaVerify(string $endpoint, string $token, string $provider): bool
    {
        $form_params = [
            'secret' => $this->config->CAPTCHA_SECRET,
            'response' => $token,
            'remoteip' => $this->throttleIpAddress()
        ];
        if ($provider === 'hcaptcha' && $this->config->CAPTCHA_SITEKEY !== '') {
            $form_params['sitekey'] = $this->config->CAPTCHA_SITEKEY;
        }
        try {
            $response = (new Client())->request('POST', $endpoint, [
                'form_params' => $form_params,
                'timeout' => 5
            ]);
            $data = json_decode((string) $response->getBody(), true);
            return is_array($data) && ($data['success'] ?? false) === true;
        } catch (GuzzleException $e) {
            return false;
        }
    }

    private function throttleEnabled(): bool
    {
        return $this->config->THROTTLE === true &&
            $this->config->THROTTLE_ATTEMPTS > 0 &&
            $this->config->THROTTLE_MINUTES > 0;
    }

    private function throttleReached(string $login): bool
    {
        if (!$this->throttleEnabled()) {
            return false;
        }
        return $this->db->fetch_var(
            'SELECT COUNT(id) FROM ' .
                $this->config->THROTTLE_TABLE .
                ' WHERE login_identifier = ? AND ip_address = ? AND created_at >= ?',
            $login,
            $this->throttleIpAddress(),
            $this->throttleDateThreshold()
        ) >= $this->config->THROTTLE_ATTEMPTS;
    }

    private function throttleRecord(string $login): void
    {
        if (!$this->throttleEnabled()) {
            return;
        }
        $this->throttleDeleteExpiredAttempts();
        $this->db->query(
            'INSERT INTO ' .
                $this->config->THROTTLE_TABLE .
                '(login_identifier, ip_address, created_at) VALUES(?,?,?)',
            $login,
            $this->throttleIpAddress(),
            date('Y-m-d H:i:s')
        );
    }

    private function throttleClear(string $login): void
    {
        if (!$this->throttleEnabled()) {
            return;
        }
        $this->db->query(
            'DELETE FROM ' . $this->config->THROTTLE_TABLE . ' WHERE login_identifier = ? AND ip_address = ?',
            $login,
            $this->throttleIpAddress()
        );
    }

    private function throttleDeleteExpiredAttempts(): void
    {
        $this->db->query(
            'DELETE FROM ' . $this->config->THROTTLE_TABLE . ' WHERE created_at < ?',
            $this->throttleDateThreshold()
        );
    }

    private function throttleDateThreshold(): string
    {
        return date('Y-m-d H:i:s', time() - 60 * $this->config->THROTTLE_MINUTES);
    }

    private function throttleIpAddress(): string
    {
        return $_SERVER['REMOTE_ADDR'] ?? '';
    }

    public function getUsers(): array
    {
        return array_map(
            fn(array $user): array => $this->formatUser($user),
            $this->db->fetch_all(
                'SELECT id, ' .
                    $this->config->LOGIN .
                    ' FROM ' .
                    $this->config->TABLE .
                    ' ORDER BY ' .
                    $this->config->LOGIN .
                    ' ASC'
            )
        );
    }

    public function getUser(string $login): array
    {
        return $this->formatUser($this->getUserRowByLogin($login));
    }

    public function getPasskeys(string $login): array
    {
        $user_id = $this->getUserIdByLogin($login);
        return array_map(
            function (array $passkey): array {
                return [
                    'id' => $passkey['id'],
                    'login_identifier' => $passkey['login_identifier'],
                    'counter' => (int) $passkey['counter'],
                    'created_at' => $passkey['created_at'],
                    'last_used_at' => $passkey['last_used_at']
                ];
            },
            $this->db->fetch_all(
                'SELECT id, login_identifier, counter, created_at, last_used_at FROM ' .
                    $this->config->PASSKEY_TABLE .
                    ' WHERE user_id = ? ORDER BY created_at DESC, id DESC',
                $user_id
            )
        );
    }

    public function requestPasswordReset(string $login): bool
    {
        if (!$this->userExists($login)) {
            return false;
        }
        $this->sendPasswordResetMail($login, $this->createPasswordResetToken($login));
        return true;
    }

    public function createPasswordResetToken(string $login): string
    {
        $user = $this->getUserRowByLogin($login);
        return JWT::encode(
            [
                'iss' => $_SERVER['HTTP_HOST'] ?? null,
                'exp' => time() + 60 * 30,
                'sub' => $user['id'],
                'login' => $user[$this->config->LOGIN],
                'password_fingerprint' => $this->passwordResetFingerprint((string) $user['password']),
                'purpose' => 'password_reset'
            ],
            $this->config->JWT_SECRET,
            'HS256'
        );
    }

    public function resetPassword(string $token, string $password): bool
    {
        $data = JWT::decode($token, new Key($this->config->JWT_SECRET, 'HS256'));
        if (($data->purpose ?? null) !== 'password_reset') {
            throw new \Exception('invalid password reset token');
        }
        $user = $this->db->fetch_row(
            'SELECT id, ' .
                $this->config->LOGIN .
                ', password' .
                ' FROM ' .
                $this->config->TABLE .
                ' WHERE id = ? AND ' .
                $this->config->LOGIN .
                ' = ?',
            $data->sub,
            $data->login
        );
        if (empty($user)) {
            throw new \Exception('user does not exists');
        }
        if (($data->password_fingerprint ?? '') !== $this->passwordResetFingerprint((string) $user['password'])) {
            throw new \Exception('password reset token expired');
        }
        return $this->setPassword((string) $user[$this->config->LOGIN], $password);
    }

    public function deletePasskey(string $login, string|int $passkey_id): bool
    {
        $user_id = $this->getUserIdByLogin($login);
        if (
            $this->db->fetch_var(
                'SELECT COUNT(id) FROM ' . $this->config->PASSKEY_TABLE . ' WHERE id = ? AND user_id = ?',
                $passkey_id,
                $user_id
            ) == 0
        ) {
            throw new \Exception('passkey does not exist');
        }
        $this->db->query(
            'DELETE FROM ' . $this->config->PASSKEY_TABLE . ' WHERE id = ? AND user_id = ?',
            $passkey_id,
            $user_id
        );
        return true;
    }

    public function createUser(string $login, string $password): bool
    {
        if ($login === '' || $password === '') {
            throw new \Exception('login or password missing');
        }
        if (
            $this->db->fetch_var(
                'SELECT COUNT(id) FROM ' . $this->config->TABLE . ' WHERE ' . $this->config->LOGIN . ' = ?',
                $login
            ) > 0
        ) {
            throw new \Exception('user already exists');
        }
        if ($this->config->UUID === false) {
            $this->db->query(
                'INSERT INTO ' . $this->config->TABLE . '(' . $this->config->LOGIN . ',password) VALUES(?,?)',
                $login,
                password_hash($password, PASSWORD_DEFAULT)
            );
        } else {
            $this->db->query(
                'INSERT INTO ' .
                    $this->config->TABLE .
                    '(id, ' .
                    $this->config->LOGIN .
                    ',password) VALUES(?,?,?)',
                $this->uuid(),
                $login,
                password_hash($password, PASSWORD_DEFAULT)
            );
        }
        return true;
    }

    public function updateUser(string $login, ?string $login_new = null, ?string $password_new = null): bool
    {
        $user = $this->getUserRowByLogin($login);
        if ($login_new !== null && $login_new !== '' && $login_new !== $login) {
            if ($this->userExists($login_new)) {
                throw new \Exception('user already exists');
            }
            $this->db->query(
                'UPDATE ' . $this->config->TABLE . ' SET ' . $this->config->LOGIN . ' = ? WHERE id = ?',
                $login_new,
                $user['id']
            );
        }
        if ($password_new !== null && $password_new !== '') {
            $this->setPassword($login_new !== null && $login_new !== '' ? $login_new : $login, $password_new);
        }
        return true;
    }

    public function setPassword(string $login, string $password): bool
    {
        if ($password === '') {
            throw new \Exception('password missing');
        }
        $user = $this->getUserRowByLogin($login);
        $this->db->query(
            'UPDATE ' . $this->config->TABLE . ' SET password = ? WHERE id = ?',
            password_hash($password, PASSWORD_DEFAULT),
            $user['id']
        );
        return true;
    }

    public function deleteUser(string $login): bool
    {
        $user = $this->getUserRowByLogin($login);
        $this->db->query('DELETE FROM ' . $this->config->PASSKEY_TABLE . ' WHERE user_id = ?', (string) $user['id']);
        $this->db->query(
            'DELETE FROM ' . $this->config->PASSKEY_CHALLENGE_TABLE . ' WHERE user_id = ?',
            (string) $user['id']
        );
        $this->db->query(
            'DELETE FROM ' . $this->config->TABLE . ' WHERE ' . $this->config->LOGIN . ' = ?',
            $login
        );
        return true;
    }

    private function formatUser(array $user): array
    {
        return [
            'id' => $user['id'],
            'login' => $user[$this->config->LOGIN],
            $this->config->LOGIN => $user[$this->config->LOGIN]
        ];
    }

    private function userExists(string $login): bool
    {
        return $this->db->fetch_var(
            'SELECT COUNT(id) FROM ' . $this->config->TABLE . ' WHERE ' . $this->config->LOGIN . ' = ?',
            $login
        ) > 0;
    }

    private function getUserRowByLogin(string $login): array
    {
        $user = $this->db->fetch_row(
            'SELECT id, ' .
                $this->config->LOGIN .
                ', password' .
                ' FROM ' .
                $this->config->TABLE .
                ' WHERE ' .
                $this->config->LOGIN .
                ' = ?',
            $login
        );
        if (empty($user)) {
            throw new \Exception('user does not exists');
        }
        return $user;
    }

    private function getUserIdByLogin(string $login): string
    {
        $user = $this->getUserRowByLogin($login);
        return (string) $user['id'];
    }

    private function passwordResetFingerprint(string $password_hash): string
    {
        return hash_hmac('sha256', $password_hash, $this->config->JWT_SECRET);
    }

    private function sendPasswordResetMail(string $login, string $token): void
    {
        $link = $this->passwordResetLink($token);
        $subject = 'Password reset';
        $linkHtml = htmlspecialchars($link, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $content =
            '<!doctype html><html><body style="font-family:Arial,sans-serif;line-height:1.5;color:#111827;">' .
            '<p>Hello,</p>' .
            '<p>you requested a password reset.</p>' .
            '<p><a href="' .
            $linkHtml .
            '" style="display:inline-block;padding:10px 14px;background:#111827;color:#ffffff;text-decoration:none;">Set new password</a></p>' .
            '<p>If the button does not work, open this link:<br><a href="' .
            $linkHtml .
            '">' .
            $linkHtml .
            '</a></p>' .
            '<p>If you did not request this, you can ignore this email.</p>' .
            '</body></html>';
        if (is_callable($this->config->PASSWORD_RESET_MAIL)) {
            $mail = ($this->config->PASSWORD_RESET_MAIL)($login, $link);
            if (is_array($mail)) {
                $mail = (object) $mail;
            }
            if (is_object($mail)) {
                $subject = (string) ($mail->subject ?? $subject);
                $content = (string) ($mail->content ?? $content);
            }
        }
        $this->sendMail($login, $subject, $content);
    }

    private function passwordResetLink(string $token): string
    {
        $url = $this->config->PASSWORD_RESET_URL;
        if ($url === '') {
            throw new \Exception('password reset url missing');
        }
        if (!preg_match('/^https?:\/\//i', $url)) {
            $url = $this->passkeyScheme() . '://' . $this->passkeyHost() . '/' . ltrim($url, '/');
        }
        if (str_contains($url, '{token}')) {
            return str_replace('{token}', rawurlencode($token), $url);
        }
        return $url . (str_contains($url, '?') ? '&' : '?') . 'token=' . rawurlencode($token);
    }

    protected function sendMail(string $to, string $subject, string $content): void
    {
        if ($this->config->SMTP !== true || $this->config->SMTP_HOST === '') {
            throw new \Exception('mail is not configured');
        }
        $mailbox = $this->config->SMTP_FROM_EMAIL !== ''
            ? $this->config->SMTP_FROM_EMAIL
            : $this->config->SMTP_USERNAME;
        if ($mailbox === '') {
            throw new \Exception('mail sender missing');
        }
        $config = [
            $mailbox => [
                'smtp' => [
                    'host' => $this->config->SMTP_HOST,
                    'port' => $this->config->SMTP_PORT,
                    'encryption' => $this->config->SMTP_ENCRYPTION
                ]
            ]
        ];
        if ($this->config->SMTP_TENANT_ID !== '') {
            $config[$mailbox]['smtp']['tenant_id'] = $this->config->SMTP_TENANT_ID;
            $config[$mailbox]['smtp']['client_id'] = $this->config->SMTP_CLIENT_ID;
            $config[$mailbox]['smtp']['client_secret'] = $this->config->SMTP_CLIENT_SECRET;
        }
        if ($this->config->SMTP_TENANT_ID === '') {
            $config[$mailbox]['smtp']['username'] = $this->config->SMTP_USERNAME;
            $config[$mailbox]['smtp']['password'] = $this->config->SMTP_PASSWORD;
        }
        (new mailhelper($config))->sendMail(
            mailbox: $mailbox,
            subject: $subject,
            content: $content,
            to: $to,
            from_name: $this->config->SMTP_FROM_NAME
        );
    }

    private function createAccessToken(string|int $user_id, string $user_login): array
    {
        $expires_in = 60 * 60 * 24 * $this->config->TTL;
        $access_token = JWT::encode(
            [
                'iss' => @$_SERVER['HTTP_HOST'], // issuer
                'exp' => time() + $expires_in, // ttl
                'sub' => $user_id,
                'login' => $user_login
            ],
            $this->config->JWT_SECRET,
            'HS256'
        );

        return [
            'access_token' => $access_token,
            'expires_in' => $expires_in,
            'user_id' => $user_id
        ];
    }

    private function getUserIdFromAccessToken(?string $access_token): mixed
    {
        try {
            $data = JWT::decode(
                str_replace('Bearer ', '', $access_token ?? ''),
                new Key($this->config->JWT_SECRET, 'HS256')
            );
            return $data->sub;
        } catch (\Exception $e) {
            throw new \Exception('wrong access token');
        }
    }

    private function getUserLoginFromAccessToken(?string $access_token): mixed
    {
        try {
            $data = JWT::decode(
                str_replace('Bearer ', '', $access_token ?? ''),
                new Key($this->config->JWT_SECRET, 'HS256')
            );
            return $data->login;
        } catch (\Exception $e) {
            throw new \Exception('wrong access token');
        }
    }

    public function isLoggedIn(): bool
    {
        return $this->getCurrentUserId() !== null;
    }

    public function getCurrentUserId(): mixed
    {
        // this function can be called from within the api (via a rest call) or directly via php
        $token = null;
        if (isset($_SERVER['HTTP_AUTHORIZATION']) && $_SERVER['HTTP_AUTHORIZATION'] != '') {
            $token = $_SERVER['HTTP_AUTHORIZATION'];
        } elseif (isset($_COOKIE['access_token']) && $_COOKIE['access_token'] != '') {
            $token = $_COOKIE['access_token'];
        }
        try {
            return $this->getUserIdFromAccessToken($token);
        } catch (\Exception $e) {
            return null;
        }
    }

    private function uuid()
    {
        static $last_unix_ms = null;
        static $sequence = 0;
        $unix_ms = (int) (microtime(true) * 1000);
        if ($unix_ms === $last_unix_ms) {
            $sequence++;
            $sequence &= 0x3fff;
            if ($sequence === 0) {
                $unix_ms++;
            }
        } else {
            $sequence = random_int(0, 0x3fff);
            $last_unix_ms = $unix_ms;
        }
        $time_high = ($unix_ms >> 16) & 0xffffffff;
        $time_low = $unix_ms & 0xffff;
        $time_hi_and_version = ($time_low & 0x0fff) | (0x7 << 12);
        $clock_seq_hi_and_reserved = ($sequence & 0x3fff) | 0x8000;
        $rand_bytes = random_bytes(6);
        $rand_hex = bin2hex($rand_bytes);
        $uuid = sprintf(
            '%08x-%04x-%04x-%04x-%012s',
            $time_high,
            $time_low,
            $time_hi_and_version,
            $clock_seq_hi_and_reserved,
            $rand_hex
        );
        return $uuid;
    }
}
