<?php
namespace vielhuber\simpleauth;

use vielhuber\dbhelper\dbhelper;
use Firebase\JWT\JWT;
use Dotenv\Dotenv;

// cors
if (PHP_SAPI != 'cli' || strpos($_SERVER['argv'][0], 'phpunit') === false) {
    header('Access-Control-Allow-Origin: *');
    header(
        'Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS'
    );
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
    if (@$_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
        die();
    }
}

class simpleauth
{
    private $config = null;
    private $db = null;

    function __construct($config)
    {
        $dotenv = new Dotenv(str_replace(['/.env','.env'],'',$config));
        $dotenv->load();
        $this->config = (object) $_ENV;
        $this->db = new dbhelper();
        $this->db->connect(
            'pdo',
            $this->config->DB_ENGINE,
            $this->config->DB_HOST,
            $this->config->DB_USERNAME,
            $this->config->DB_PASSWORD,
            $this->config->DB_DATABASE,
            $this->config->DB_PORT
        );
    }

    function createTable()
    {
        $this->db->query(
            '
            CREATE TABLE IF NOT EXISTS ' .
                $this->config->DB_TABLE .
                '
            (
                id SERIAL PRIMARY KEY,
                email varchar(100) NOT NULL,
                password char(255) NOT NULL
            )
        '
        );
        return true;
    }

    function createUser($email, $password)
    {
        if (
            $this->db->fetch_var(
                'SELECT COUNT(id) FROM ' .
                    $this->config->DB_TABLE .
                    ' WHERE email = ?',
                $email
            ) > 0
        ) {
            throw new \Exception('user already exists');
        }
        $this->db->query(
            'INSERT INTO ' .
                $this->config->DB_TABLE .
                '(email,password) VALUES(?,?)',
            $email,
            password_hash($password, PASSWORD_DEFAULT)
        );
        return true;
    }

    function deleteUser($email)
    {
        if (
            $this->db->fetch_var(
                'SELECT COUNT(id) FROM ' .
                    $this->config->DB_TABLE .
                    ' WHERE email = ?',
                $email
            ) == 0
        ) {
            throw new \Exception('user does not exists');
        }
        $this->db->query(
            'DELETE FROM ' . $this->config->DB_TABLE . ' WHERE email = ?',
            $email
        );
        return true;
    }

    function login($email, $password)
    {
        if ($email == '' || $password == '') {
            throw new \Exception('email or password missing');
        }

        $user = $this->db->fetch_row(
            'SELECT * FROM ' . $this->config->DB_TABLE . ' WHERE email = ?',
            $email
        );

        if (empty($user) || !password_verify($password, $user['password'])) {
            throw new \Exception('email or password wrong');
        }

        return $this->getTokenAndSetCookie($user['id']);
    }

    function refresh($access_token)
    {
        try {
            $user_id = $this->getUserIdFromAccessToken($access_token);
            return $this->getTokenAndSetCookie($user_id);
        } catch (\Exception $e) {
            throw new \Exception('wrong access token');
        }
    }

    function check($access_token)
    {
        try {
            $user_id = $this->getUserIdFromAccessToken($access_token);
            return [
                'access_token' => $access_token,
                'expires_in' => $this->config->JWT_TTL,
                'user_id' => $user_id
            ];
        } catch (\Exception $e) {
            throw new \Exception('wrong access token');
        }
    }

    private function getTokenAndSetCookie($user_id)
    {
        $access_token = JWT::encode(
            [
                'iss' => $_SERVER['HTTP_HOST'], // issuer
                'exp' => time() + 60 * 60 * 24 * $this->config->JWT_TTL, // ttl
                'sub' => $user_id
            ],
            $this->config->JWT_SECRET
        );

        if (
            PHP_SAPI != 'cli' ||
            strpos($_SERVER['argv'][0], 'phpunit') === false
        ) {
            setcookie(
                'access_token',
                $access_token,
                time() + 60 * 60 * 24 * $this->config->JWT_TTL,
                '/'
            );
        }

        $_COOKIE['access_token'] = $access_token;

        return [
            'access_token' => $access_token,
            'expires_in' => $this->config->JWT_TTL,
            'user_id' => $user_id
        ];
    }

    function getUserIdFromAccessToken($access_token)
    {
        try {
            $data = JWT::decode(
                str_replace('Bearer ', '', $access_token),
                $this->config->JWT_SECRET,
                ['HS256']
            );
            return $data->sub;
        } catch (\Exception $e) {
            throw new \Exception('wrong access token');
        }
    }

    function isLoggedIn()
    {
        return $this->getCurrentUserId() !== null;
    }

    function getCurrentUserId()
    {
        try {
            return JWT::decode(@$_COOKIE['access_token'], $this->config->JWT_SECRET, [
                'HS256'
            ])->sub;
        } catch (\Exception $e) {
            return null;
        }
    }

    function logout()
    {
        if (
            !isset($_COOKIE['access_token']) ||
            $_COOKIE['access_token'] == ''
        ) {
            return true;
        }
        unset($_COOKIE['access_token']);
        if (
            PHP_SAPI != 'cli' ||
            strpos($_SERVER['argv'][0], 'phpunit') === false
        ) {
            setcookie('access_token', '', time() - 3600, '/');
        }
        return true;
    }

    function deleteTable()
    {
        $this->db->query('DROP TABLE IF EXISTS ' . $this->config->DB_TABLE);
        return true;
    }

    function api()
    {
        if (
            $this->apiRequestMethod() === 'POST' &&
            $this->apiRequestPath() === 'login'
        ) {
            return $this->apiLogin();
        }
        if (
            $this->apiRequestMethod() === 'POST' &&
            $this->apiRequestPath() === 'refresh'
        ) {
            return $this->apiRefresh();
        }
        if (
            $this->apiRequestMethod() === 'POST' &&
            $this->apiRequestPath() === 'logout'
        ) {
            return $this->apiLogout();
        }
        if (
            $this->apiRequestMethod() === 'POST' &&
            $this->apiRequestPath() === 'check'
        ) {
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

    private function apiRequestPath()
    {
        $path = $_SERVER['REQUEST_URI'];
        $path = trim($path, '/');
        $path = substr($path, strrpos($path, '/') + 1);
        return $path;
    }

    private function apiRequestMethod()
    {
        return $_SERVER['REQUEST_METHOD'];
    }

    private function apiInput($key)
    {
        $p1 = $_POST;
        $p2 = json_decode(file_get_contents('php://input'), true);
        if (isset($p1) && !empty($p1) && array_key_exists($key, $p1)) {
            return $p1[$key];
        }
        if (isset($p2) && !empty($p2) && array_key_exists($key, $p2)) {
            return $p2[$key];
        }
        return null;
    }

    private function apiLogin()
    {
        try {
            $data = $this->login(
                $this->apiInput('email'),
                $this->apiInput('password')
            );
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
            $data = $this->refresh(@$_SERVER['HTTP_AUTHORIZATION']);
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
            $this->logout();
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
            $data = $this->check($this->apiInput('access_token'));
            return $this->apiResponse(
                [
                    'success' => true,
                    'message' => 'valid token',
                    'public_message' => 'Korrektes Token',
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

    private function apiResponse($data, $code = 200)
    {
        http_response_code($code);
        echo json_encode($data);
        die();
    }

    public function migrate()
    {
        $this->deleteTable();
        $this->createTable();
    }

    public function seed()
    {
        try {
            $this->deleteUser('david@vielhuber.de');
        } catch (\Exception $e) {

        }
        $this->createUser('david@vielhuber.de', 'secret');
    }
}
