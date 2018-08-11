<?php
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
} elseif (file_exists(__DIR__ . '/../vendor/autoload.php')) {
    require_once __DIR__ . '/../vendor/autoload.php';
}
require_once __DIR__ . '/config.php';

use vielhuber\simpleauth\simpleauth;
use vielhuber\dbhelper\dbhelper;

class Api
{
    private $auth = null;

    public function __construct()
    {
        $this->setupAuth();
    }

    private function setupAuth()
    {
        global $config;
        $this->auth = new simpleauth($config);
    }

    public function getRequest()
    {
        if (
            $this->getRequestMethod() === 'POST' &&
            $this->getRequestPath() === 'login'
        ) {
            return $this->login();
        }
        if (
            $this->getRequestMethod() === 'POST' &&
            $this->getRequestPath() === 'refresh'
        ) {
            return $this->refresh();
        }
        if (
            $this->getRequestMethod() === 'POST' &&
            $this->getRequestPath() === 'logout'
        ) {
            return $this->logout();
        }
        if (
            $this->getRequestMethod() === 'POST' &&
            $this->getRequestPath() === 'check'
        ) {
            return $this->check();
        }
        return $this->response(
            [
                'success' => false,
                'message' => 'unknown route',
                'public_message' => 'Unbekannte Route!'
            ],
            404
        );
    }

    private function getRequestPath()
    {
        $path = $_SERVER['REQUEST_URI'];
        $path = trim($path, '/');
        $path = substr($path, strrpos($path, '/') + 1);
        return $path;
    }

    private function getRequestMethod()
    {
        return $_SERVER['REQUEST_METHOD'];
    }

    private function input($key)
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

    private function login()
    {
        try {
            $data = $this->auth->login(
                $this->input('email'),
                $this->input('password')
            );
            return $this->response(
                [
                    'success' => true,
                    'message' => 'auth successful',
                    'public_message' => 'Erfolgreich eingeloggt',
                    'data' => $data
                ],
                200
            );
        } catch (\Exception $e) {
            return $this->response(
                [
                    'success' => false,
                    'message' => 'auth not successful',
                    'public_message' => 'Nicht erfolgreich'
                ],
                401
            );
        }
    }

    private function refresh()
    {
        return $this->response([
            'success' => true,
            'data' => 'todo'
        ]);
    }

    private function logout()
    {
        return $this->response([
            'success' => true,
            'data' => 'todo'
        ]);
    }

    private function check($id)
    {
        return $this->response([
            'success' => true,
            'data' => 'todo'
        ]);
    }

    private function response($data, $code = 200)
    {
        http_response_code($code);
        echo json_encode($data);
        die();
    }

    public function migrate()
    {
        $this->auth->createTable();
    }

    public function seed()
    {
        $this->auth->createUser('david@vielhuber.de', 'secret');
    }
}

$api = new Api();

if (php_sapi_name() !== 'cli') {
    $api->getRequest();
}
