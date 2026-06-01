<?php
declare(strict_types=1);

namespace vielhuber\simpleauth;

use vielhuber\dbhelper\dbhelper;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use ParagonIE\ConstantTime\Base64UrlSafe;
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

// cors
if (
    !(headers_sent() || ob_get_length() > 0) &&
    (PHP_SAPI != 'cli' || strpos($_SERVER['argv'][0], 'phpunit') === false)
) {
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
    if (@$_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
        die();
    }
}

class simpleauth
{
    private object $config;
    private dbhelper $db;

    public function __construct(
        ?string $config = null,
        string $table = 'users',
        string $login = 'email',
        int $ttl = 30,
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
        false|array $captcha = false
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

        $this->config->JWT_TABLE = $table;
        $this->config->JWT_LOGIN = $login;
        $this->config->JWT_TTL = $ttl;
        $this->config->JWT_UUID = $uuid;
        $this->config->JWT_THROTTLE = $throttle !== false;
        $this->config->JWT_THROTTLE_ATTEMPTS = $throttle === false ? 5 : (int) ($throttle['attempts'] ?? 5);
        $this->config->JWT_THROTTLE_MINUTES = $throttle === false ? 15 : (int) ($throttle['minutes'] ?? 15);
        $this->config->JWT_THROTTLE_TABLE =
            $throttle === false ? 'users_login_attempts' : (string) ($throttle['table'] ?? 'users_login_attempts');
        $this->config->JWT_PASSKEY = $passkeys !== false;
        $passkeys_table = $passkeys === false ? 'users_passkeys' : (string) ($passkeys['table'] ?? 'users_passkeys');
        $this->config->JWT_PASSKEY_TABLE = $passkeys_table;
        $this->config->JWT_PASSKEY_CHALLENGE_TABLE =
            $passkeys === false
                ? 'users_passkeys_challenges'
                : (string) ($passkeys['table_challenge'] ?? $passkeys_table . '_challenges');
        $this->config->JWT_CAPTCHA = $captcha !== false;
        $this->config->JWT_CAPTCHA_PROVIDER = $captcha === false ? null : (string) ($captcha['provider'] ?? 'hcaptcha');
        $this->config->JWT_CAPTCHA_SITEKEY = $captcha === false ? null : (string) ($captcha['sitekey'] ?? '');
        $this->config->JWT_CAPTCHA_SECRET = $captcha === false ? null : (string) ($captcha['secret'] ?? '');
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
        return $this->apiResponse(
            [
                'success' => false,
                'message' => 'unknown route',
                'public_message' => 'Unbekannte Route!'
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
            $login = (string) $this->apiInput($this->config->JWT_LOGIN);
            $password = (string) $this->apiInput('password');
            if ($login == '' || $password == '') {
                throw new \Exception('login or password missing');
            }
            if (!$this->captchaValid()) {
                return $this->apiResponse(
                    [
                        'success' => false,
                        'message' => 'captcha not successful',
                        'public_message' => 'Captcha nicht erfolgreich'
                    ],
                    401
                );
            }
            if ($this->throttleReached($login)) {
                return $this->apiResponse(
                    [
                        'success' => false,
                        'message' => 'too many login attempts',
                        'public_message' => 'Zu viele Loginversuche. Bitte später erneut versuchen.'
                    ],
                    429
                );
            }
            $user = $this->db->fetch_row(
                'SELECT * FROM ' . $this->config->JWT_TABLE . ' WHERE ' . $this->config->JWT_LOGIN . ' = ?',
                $login
            );
            if (empty($user) || !password_verify($password, $user['password'])) {
                $this->throttleRecord($login);
                throw new \Exception('login or password wrong');
            }
            $this->throttleClear($login);
            $data = $this->createAccessToken($user['id'], $user[$this->config->JWT_LOGIN]);
            return $this->apiResponse(
                [
                    'success' => true,
                    'message' => 'auth successful',
                    'public_message' => 'Erfolgreich eingeloggt',
                    'data' => $data
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'auth not successful',
                    'public_message' => 'Nicht erfolgreich'
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
                    'public_message' => 'Erfolgreich eingeloggt',
                    'data' => $data
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'invalid token',
                    'public_message' => 'Falsches Token'
                ],
                401
            );
        }
    }

    private function apiLogout()
    {
        try {
            // nothing happens :-)
            return $this->apiResponse(
                [
                    'success' => true,
                    'message' => 'logout successful',
                    'public_message' => 'Erfolgreich ausgeloggt'
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'logout not successful',
                    'public_message' => 'Nicht erfolgreich ausgeloggt'
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
                    'public_message' => 'Korrektes Token',
                    'data' => [
                        'access_token' => $access_token,
                        'expires_in' => $this->config->JWT_TTL,
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
                    'public_message' => 'Falsches Token'
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
                    'public_message' => 'Passkey-Registrierung vorbereitet',
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
                    'public_message' => 'Passkey-Registrierung nicht vorbereitet'
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
                    'public_message' => 'Passkey registriert'
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'passkey not registered',
                    'public_message' => 'Passkey nicht registriert'
                ],
                401
            );
        }
    }

    private function apiPasskeyLoginOptions()
    {
        try {
            $login = (string) ($this->apiInput($this->config->JWT_LOGIN) ?? '');
            $user = null;
            $allow_credentials = [];
            if ($login !== '') {
                $user = $this->db->fetch_row(
                    'SELECT * FROM ' . $this->config->JWT_TABLE . ' WHERE ' . $this->config->JWT_LOGIN . ' = ?',
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
                    'public_message' => 'Passkey-Login vorbereitet',
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
                    'public_message' => 'Passkey-Login nicht vorbereitet'
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
                'SELECT * FROM ' . $this->config->JWT_PASSKEY_TABLE . ' WHERE credential_id = ?',
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
                'SELECT * FROM ' . $this->config->JWT_TABLE . ' WHERE id = ?',
                $passkey['user_id']
            );
            if (empty($user)) {
                throw new \Exception('user not found');
            }
            $data = $this->createAccessToken($user['id'], $user[$this->config->JWT_LOGIN]);
            return $this->apiResponse(
                [
                    'success' => true,
                    'message' => 'auth successful',
                    'public_message' => 'Erfolgreich eingeloggt',
                    'data' => $data
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'passkey auth not successful',
                    'public_message' => 'Passkey nicht erfolgreich'
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
                $this->config->JWT_TABLE .
                '
            (
                id ' .
                ($this->config->JWT_UUID === true ? 'VARCHAR(36)' : ($this->dbIsSqlite() ? 'INTEGER' : 'SERIAL')) .
                ' PRIMARY KEY,
                ' .
                $this->config->JWT_LOGIN .
                ' varchar(100) NOT NULL,
                password char(255) NOT NULL
            )
        '
        );
        $this->db->query(
            '
            CREATE TABLE IF NOT EXISTS ' .
                $this->config->JWT_THROTTLE_TABLE .
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
                $this->config->JWT_PASSKEY_TABLE .
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
                $this->config->JWT_PASSKEY_CHALLENGE_TABLE .
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
        $this->db->create_index(
            $this->config->JWT_THROTTLE_TABLE,
            'login_attempts_lookup',
            ['login_identifier', 'ip_address', 'created_at']
        );
        $this->db->create_index($this->config->JWT_PASSKEY_TABLE, 'passkey_credential_id', ['credential_id'], true);
        $this->db->create_index($this->config->JWT_PASSKEY_TABLE, 'passkey_user_id', ['user_id']);
        $this->db->create_index(
            $this->config->JWT_PASSKEY_CHALLENGE_TABLE,
            'passkey_challenge_lookup',
            ['type', 'challenge', 'user_id']
        );
        return true;
    }

    private function deleteTable(): bool
    {
        $this->db->query('DROP TABLE IF EXISTS ' . $this->config->JWT_TABLE);
        $this->db->query('DROP TABLE IF EXISTS ' . $this->config->JWT_THROTTLE_TABLE);
        $this->db->query('DROP TABLE IF EXISTS ' . $this->config->JWT_PASSKEY_TABLE);
        $this->db->query('DROP TABLE IF EXISTS ' . $this->config->JWT_PASSKEY_CHALLENGE_TABLE);
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
        return $this->config->JWT_PASSKEY === true;
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
                $this->config->JWT_PASSKEY_CHALLENGE_TABLE .
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
            $this->config->JWT_PASSKEY_CHALLENGE_TABLE .
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
        $this->db->query('DELETE FROM ' . $this->config->JWT_PASSKEY_CHALLENGE_TABLE . ' WHERE id = ?', $id);
    }

    private function passkeyDeleteExpiredChallenges(): void
    {
        $this->db->query(
            'DELETE FROM ' . $this->config->JWT_PASSKEY_CHALLENGE_TABLE . ' WHERE created_at < ?',
            date('Y-m-d H:i:s', time() - 300)
        );
    }

    private function passkeyCredentialsForUser(string $user_id): array
    {
        $credentials = [];
        foreach (
            $this->db->fetch_all(
                'SELECT credential_record FROM ' . $this->config->JWT_PASSKEY_TABLE . ' WHERE user_id = ?',
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
                'SELECT COUNT(id) FROM ' . $this->config->JWT_PASSKEY_TABLE . ' WHERE credential_id = ?',
                $credential_id
            ) > 0
        ) {
            throw new \Exception('passkey already exists');
        }
        $this->db->query(
            'INSERT INTO ' .
                $this->config->JWT_PASSKEY_TABLE .
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
                $this->config->JWT_PASSKEY_TABLE .
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
        return $this->config->JWT_CAPTCHA === true;
    }

    private function captchaValid(): bool
    {
        if (!$this->captchaEnabled()) {
            return true;
        }
        if ($this->config->JWT_CAPTCHA_PROVIDER !== 'hcaptcha' || $this->config->JWT_CAPTCHA_SECRET === '') {
            return false;
        }
        $token = (string) ($this->apiInput('h-captcha-response') ?? '');
        if ($token === '') {
            return false;
        }
        return $this->captchaVerifyHcaptcha($token);
    }

    private function captchaVerifyHcaptcha(string $token): bool
    {
        $form_params = [
            'secret' => $this->config->JWT_CAPTCHA_SECRET,
            'response' => $token,
            'remoteip' => $this->throttleIpAddress()
        ];
        if ($this->config->JWT_CAPTCHA_SITEKEY !== '') {
            $form_params['sitekey'] = $this->config->JWT_CAPTCHA_SITEKEY;
        }
        try {
            $response = (new Client())->request('POST', 'https://api.hcaptcha.com/siteverify', [
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
        return $this->config->JWT_THROTTLE === true &&
            $this->config->JWT_THROTTLE_ATTEMPTS > 0 &&
            $this->config->JWT_THROTTLE_MINUTES > 0;
    }

    private function throttleReached(string $login): bool
    {
        if (!$this->throttleEnabled()) {
            return false;
        }
        return $this->db->fetch_var(
            'SELECT COUNT(id) FROM ' .
                $this->config->JWT_THROTTLE_TABLE .
                ' WHERE login_identifier = ? AND ip_address = ? AND created_at >= ?',
            $login,
            $this->throttleIpAddress(),
            $this->throttleDateThreshold()
        ) >= $this->config->JWT_THROTTLE_ATTEMPTS;
    }

    private function throttleRecord(string $login): void
    {
        if (!$this->throttleEnabled()) {
            return;
        }
        $this->throttleDeleteExpiredAttempts();
        $this->db->query(
            'INSERT INTO ' .
                $this->config->JWT_THROTTLE_TABLE .
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
            'DELETE FROM ' . $this->config->JWT_THROTTLE_TABLE . ' WHERE login_identifier = ? AND ip_address = ?',
            $login,
            $this->throttleIpAddress()
        );
    }

    private function throttleDeleteExpiredAttempts(): void
    {
        $this->db->query(
            'DELETE FROM ' . $this->config->JWT_THROTTLE_TABLE . ' WHERE created_at < ?',
            $this->throttleDateThreshold()
        );
    }

    private function throttleDateThreshold(): string
    {
        return date('Y-m-d H:i:s', time() - 60 * $this->config->JWT_THROTTLE_MINUTES);
    }

    private function throttleIpAddress(): string
    {
        return $_SERVER['REMOTE_ADDR'] ?? '';
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
                    $this->config->JWT_PASSKEY_TABLE .
                    ' WHERE user_id = ? ORDER BY created_at DESC, id DESC',
                $user_id
            )
        );
    }

    public function deletePasskey(string $login, string|int $passkey_id): bool
    {
        $user_id = $this->getUserIdByLogin($login);
        if (
            $this->db->fetch_var(
                'SELECT COUNT(id) FROM ' . $this->config->JWT_PASSKEY_TABLE . ' WHERE id = ? AND user_id = ?',
                $passkey_id,
                $user_id
            ) == 0
        ) {
            throw new \Exception('passkey does not exist');
        }
        $this->db->query(
            'DELETE FROM ' . $this->config->JWT_PASSKEY_TABLE . ' WHERE id = ? AND user_id = ?',
            $passkey_id,
            $user_id
        );
        return true;
    }

    public function deletePasskeys(string $login): bool
    {
        $user_id = $this->getUserIdByLogin($login);
        $this->db->query(
            'DELETE FROM ' . $this->config->JWT_PASSKEY_TABLE . ' WHERE user_id = ?',
            $user_id
        );
        $this->db->query(
            'DELETE FROM ' . $this->config->JWT_PASSKEY_CHALLENGE_TABLE . ' WHERE user_id = ?',
            $user_id
        );
        return true;
    }

    public function createUser(string $login, string $password): bool
    {
        if (
            $this->db->fetch_var(
                'SELECT COUNT(id) FROM ' . $this->config->JWT_TABLE . ' WHERE ' . $this->config->JWT_LOGIN . ' = ?',
                $login
            ) > 0
        ) {
            throw new \Exception('user already exists');
        }
        if ($this->config->JWT_UUID === false) {
            $this->db->query(
                'INSERT INTO ' . $this->config->JWT_TABLE . '(' . $this->config->JWT_LOGIN . ',password) VALUES(?,?)',
                $login,
                password_hash($password, PASSWORD_DEFAULT)
            );
        } else {
            $this->db->query(
                'INSERT INTO ' .
                    $this->config->JWT_TABLE .
                    '(id, ' .
                    $this->config->JWT_LOGIN .
                    ',password) VALUES(?,?,?)',
                $this->uuid(),
                $login,
                password_hash($password, PASSWORD_DEFAULT)
            );
        }
        return true;
    }

    public function deleteUser(string $login): bool
    {
        $user = $this->db->fetch_row(
            'SELECT id FROM ' . $this->config->JWT_TABLE . ' WHERE ' . $this->config->JWT_LOGIN . ' = ?',
            $login
        );
        if (empty($user)) {
            throw new \Exception('user does not exists');
        }
        $this->deletePasskeys($login);
        $this->db->query(
            'DELETE FROM ' . $this->config->JWT_TABLE . ' WHERE ' . $this->config->JWT_LOGIN . ' = ?',
            $login
        );
        return true;
    }

    private function getUserIdByLogin(string $login): string
    {
        $user = $this->db->fetch_row(
            'SELECT id FROM ' . $this->config->JWT_TABLE . ' WHERE ' . $this->config->JWT_LOGIN . ' = ?',
            $login
        );
        if (empty($user)) {
            throw new \Exception('user does not exists');
        }
        return (string) $user['id'];
    }

    private function createAccessToken(string|int $user_id, string $user_login): array
    {
        $access_token = JWT::encode(
            [
                'iss' => @$_SERVER['HTTP_HOST'], // issuer
                'exp' => time() + 60 * 60 * 24 * $this->config->JWT_TTL, // ttl
                'sub' => $user_id,
                'login' => $user_login
            ],
            $this->config->JWT_SECRET,
            'HS256'
        );

        return [
            'access_token' => $access_token,
            'expires_in' => $this->config->JWT_TTL,
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
