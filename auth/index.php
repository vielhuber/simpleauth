<?php
require_once __DIR__ . '/../../vendor/autoload.php';

use vielhuber\simpleauth\simpleauth;
use vielhuber\dbhelper\dbhelper;

class Api
{
    public function __construct()
    {
        $this->getRequest();
    }

    private function getRequest()
    {
        if (
            $this->getRequestMethod() === 'GET' &&
            $this->getRequestPathFirst() === 'tickets' &&
            $this->getRequestPathSecond() === null
        ) {
            return $this->index();
        }
        if (
            $this->getRequestMethod() === 'GET' &&
            $this->getRequestPathFirst() === 'tickets' &&
            is_numeric($this->getRequestPathSecond())
        ) {
            return $this->show($this->getRequestPathSecond());
        }
        if (
            $this->getRequestMethod() === 'POST' &&
            $this->getRequestPathFirst() === 'tickets' &&
            $this->getRequestPathSecond() === null
        ) {
            return $this->create();
        }
        if (
            $this->getRequestMethod() === 'PUT' &&
            $this->getRequestPathFirst() === 'tickets' &&
            is_numeric($this->getRequestPathSecond())
        ) {
            return $this->update($this->getRequestPathSecond());
        }
        if (
            $this->getRequestMethod() === 'DELETE' &&
            $this->getRequestPathFirst() === 'tickets' &&
            is_numeric($this->getRequestPathSecond())
        ) {
            return $this->delete($this->getRequestPathSecond());
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
        $path = str_replace('_api', '', $path);
        $path = trim($path, '/');
        return $path;
    }

    private function getRequestPathFirst()
    {
        $part = explode('/', $this->getRequestPath());
        if (!isset($part[0])) {
            return null;
        }
        return $part[0];
    }

    private function getRequestPathSecond()
    {
        $part = explode('/', $this->getRequestPath());
        if (!isset($part[1])) {
            return null;
        }
        return $part[1];
    }

    private function getRequestMethod()
    {
        return $_SERVER['REQUEST_METHOD'];
    }

    private function index()
    {
        return $this->response([
            'success' => true,
            'data' => 'todo'
        ]);
    }

    private function show($id)
    {
        return $this->response([
            'success' => true,
            'data' => 'todo'
        ]);
    }

    private function create()
    {
        return $this->response([
            'success' => true,
            'data' => 'todo'
        ]);
    }

    private function update($id)
    {
        return $this->response([
            'success' => true,
            'data' => 'todo'
        ]);
    }

    private function delete($id)
    {
        return $this->response([
            'success' => true
        ]);
    }

    private function response($data, $code = 200)
    {
        http_response_code($code);
        echo json_encode($data);
        die();
    }
}

$api = new Api();
