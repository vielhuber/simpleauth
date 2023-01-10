<?php
namespace vielhuber\simpleauth;

use vielhuber\dbhelper\dbhelper;
use Firebase\JWT\JWT;

// cors
if (PHP_SAPI != 'cli' || strpos($_SERVER['argv'][0], 'phpunit') === false) {
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
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
        $dotenv = \Dotenv\Dotenv::createImmutable(str_replace(['/.env', '.env'], '', $config));
        $dotenv->load();
        $this->config = (object) [
            'DB_CONNECTION' => @$_SERVER['DB_CONNECTION'],
            'DB_HOST' => @$_SERVER['DB_HOST'],
            'DB_PORT' => @$_SERVER['DB_PORT'],
            'DB_DATABASE' => @$_SERVER['DB_DATABASE'],
            'DB_USERNAME' => @$_SERVER['DB_USERNAME'],
            'DB_PASSWORD' => @$_SERVER['DB_PASSWORD'],
            'JWT_TABLE' => @$_SERVER['JWT_TABLE'],
            'JWT_LOGIN' => @$_SERVER['JWT_LOGIN'],
            'JWT_TTL' => @$_SERVER['JWT_TTL'],
            'JWT_SECRET' => @$_SERVER['JWT_SECRET'],
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
    }

    function api()
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
                'public_message' => 'Unbekannte Route!',
            ],
            404
        );
    }

    function migrate()
    {
        $this->deleteTable();
        $this->createTable();
    }

    function seed()
    {
        try {
            $this->deleteUser('david@vielhuber.de');
        } catch (\Exception $e) {
        }
        $this->createUser('david@vielhuber.de', 'secret');
    }

    private function apiRequestPath()
    {
        $path = @$_SERVER['REQUEST_URI'];
        $path = trim($path, '/');
        $path = substr($path, strrpos($path, '/') + 1);
        return $path;
    }

    private function apiRequestMethod()
    {
        return @$_SERVER['REQUEST_METHOD'];
    }

    private function apiInput($key)
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
            $login = $this->apiInput($this->config->JWT_LOGIN);
            $password = $this->apiInput('password');
            if ($login == '' || $password == '') {
                throw new \Exception('login or password missing');
            }
            $user = $this->db->fetch_row(
                'SELECT * FROM ' . $this->config->JWT_TABLE . ' WHERE ' . $this->config->JWT_LOGIN . ' = ?',
                $login
            );
            if (empty($user) || !password_verify($password, $user['password'])) {
                throw new \Exception('login or password wrong');
            }
            $data = $this->createAccessToken($user['id'], $user[$this->config->JWT_LOGIN]);
            return $this->apiResponse(
                [
                    'success' => true,
                    'message' => 'auth successful',
                    'public_message' => 'Erfolgreich eingeloggt',
                    'data' => $data,
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'auth not successful',
                    'public_message' => 'Nicht erfolgreich',
                ],
                401
            );
        }
    }

    private function apiRefresh()
    {
        try {
            $user_id = $this->getUserIdFromAccessToken(@$_SERVER['HTTP_AUTHORIZATION']);
            $user_login = $this->getUserLoginFromAccessToken(@$_SERVER['HTTP_AUTHORIZATION']);
            $data = $this->createAccessToken($user_id, $user_login);
            return $this->apiResponse(
                [
                    'success' => true,
                    'message' => 'auth successful',
                    'public_message' => 'Erfolgreich eingeloggt',
                    'data' => $data,
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'invalid token',
                    'public_message' => 'Falsches Token',
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
                    'public_message' => 'Erfolgreich ausgeloggt',
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'logout not successful',
                    'public_message' => 'Nicht erfolgreich ausgeloggt',
                ],
                401
            );
        }
    }

    private function apiCheck()
    {
        try {
            $access_token = $this->apiInput('access_token');
            $user_id = $this->getUserIdFromAccessToken($access_token);
            return $this->apiResponse(
                [
                    'success' => true,
                    'message' => 'valid token',
                    'public_message' => 'Korrektes Token',
                    'data' => [
                        'access_token' => $access_token,
                        'expires_in' => $this->config->JWT_TTL,
                        'user_id' => $user_id,
                    ],
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->apiResponse(
                [
                    'success' => false,
                    'message' => 'invalid token',
                    'public_message' => 'Falsches Token',
                ],
                401
            );
        }
    }

    private function apiResponse($data, $code = 200)
    {
        http_response_code($code);
        header('Content-Type: application/json');
        echo json_encode($data);
        die();
    }

    function createTable()
    {
        $this->db->query(
            '
            CREATE TABLE IF NOT EXISTS ' .
                $this->config->JWT_TABLE .
                '
            (
                id SERIAL PRIMARY KEY,
                ' .
                $this->config->JWT_LOGIN .
                ' varchar(100) NOT NULL,
                password char(255) NOT NULL
            )
        '
        );
        return true;
    }

    function deleteTable()
    {
        $this->db->query('DROP TABLE IF EXISTS ' . $this->config->JWT_TABLE);
        return true;
    }

    function createUser($login, $password)
    {
        if (
            $this->db->fetch_var(
                'SELECT COUNT(id) FROM ' . $this->config->JWT_TABLE . ' WHERE ' . $this->config->JWT_LOGIN . ' = ?',
                $login
            ) > 0
        ) {
            throw new \Exception('user already exists');
        }
        $this->db->query(
            'INSERT INTO ' . $this->config->JWT_TABLE . '(' . $this->config->JWT_LOGIN . ',password) VALUES(?,?)',
            $login,
            password_hash($password, PASSWORD_DEFAULT)
        );
        return true;
    }

    function deleteUser($login)
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

    private function createAccessToken($user_id, $user_login)
    {
        $access_token = JWT::encode(
            [
                'iss' => @$_SERVER['HTTP_HOST'], // issuer
                'exp' => time() + 60 * 60 * 24 * $this->config->JWT_TTL, // ttl
                'sub' => $user_id,
                'login' => $user_login,
            ],
            $this->config->JWT_SECRET
        );

        return [
            'access_token' => $access_token,
            'expires_in' => $this->config->JWT_TTL,
            'user_id' => $user_id,
        ];
    }

    function getUserIdFromAccessToken($access_token)
    {
        try {
            $data = JWT::decode(str_replace('Bearer ', '', $access_token ?? ''), $this->config->JWT_SECRET, ['HS256']);
            return $data->sub;
        } catch (\Exception $e) {
            throw new \Exception('wrong access token');
        }
    }

    function getUserLoginFromAccessToken($access_token)
    {
        try {
            $data = JWT::decode(str_replace('Bearer ', '', $access_token ?? ''), $this->config->JWT_SECRET, ['HS256']);
            return $data->login;
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
}
