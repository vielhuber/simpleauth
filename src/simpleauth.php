<?php
declare(strict_types=1);

namespace vielhuber\simpleauth;

use vielhuber\dbhelper\dbhelper;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// cors
if (!(headers_sent() || ob_get_length() > 0) && (PHP_SAPI != 'cli' || strpos($_SERVER['argv'][0], 'phpunit') === false)) {
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
        bool $throttle = true,
        int $throttleAttempts = 5,
        int $throttleMinutes = 15,
        string $throttleTable = 'users_login_attempts'
    )
    {
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
        $this->config->JWT_THROTTLE = $throttle;
        $this->config->JWT_THROTTLE_ATTEMPTS = $throttleAttempts;
        $this->config->JWT_THROTTLE_MINUTES = $throttleMinutes;
        $this->config->JWT_THROTTLE_TABLE = $throttleTable;
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
        return $this->apiResponse(
            [
                'success' => false,
                'message' => 'unknown route',
                'public_message' => 'Unbekannte Route!'
            ],
            404
        );
    }

    private function migrate(): void
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
            $user_id = $this->getUserIdFromAccessToken(@$_SERVER['HTTP_AUTHORIZATION']);
            $user_login = (string) $this->getUserLoginFromAccessToken(@$_SERVER['HTTP_AUTHORIZATION']);
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

    private function apiResponse(array $data, int $code = 200): void
    {
        http_response_code($code);
        header('Content-Type: application/json');
        echo json_encode($data);
        die();
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
                ($this->config->JWT_UUID === true ? 'VARCHAR(36)' : 'SERIAL') .
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
                id SERIAL PRIMARY KEY,
                login_identifier varchar(255) NOT NULL,
                ip_address varchar(45) NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX login_attempts_lookup (login_identifier, ip_address, created_at)
            )
        '
        );
        return true;
    }

    private function deleteTable(): bool
    {
        $this->db->query('DROP TABLE IF EXISTS ' . $this->config->JWT_TABLE);
        $this->db->query('DROP TABLE IF EXISTS ' . $this->config->JWT_THROTTLE_TABLE);
        return true;
    }

    private function throttleEnabled(): bool
    {
        return
            $this->config->JWT_THROTTLE === true &&
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
        if (
            $this->db->fetch_var(
                'SELECT COUNT(id) FROM ' . $this->config->JWT_TABLE . ' WHERE ' . $this->config->JWT_LOGIN . ' = ?',
                $login
            ) == 0
        ) {
            throw new \Exception('user does not exists');
        }
        $this->db->query(
            'DELETE FROM ' . $this->config->JWT_TABLE . ' WHERE ' . $this->config->JWT_LOGIN . ' = ?',
            $login
        );
        return true;
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
