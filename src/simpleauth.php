<?php
namespace vielhuber\simpleauth;

use vielhuber\dbhelper\dbhelper;
use Firebase\JWT\JWT;

class simpleauth
{
    private $config = null;
    private $db = null;
    private $secret = 'jgto038AO4mtWzYcIOM0B2Yq8IKtsd3AXOYN88Pz7HJY60my6T6WIeOjgHCkHhE';

    function __construct($config)
    {
        $this->config = (object) $config;
        $this->db = new dbhelper();
        $this->db->connect(
            'pdo',
            $this->config->dbms,
            $this->config->host,
            $this->config->username,
            $this->config->password,
            $this->config->database,
            $this->config->port
        );
    }

    function createTable()
    {
        $this->db->query(
            '
            CREATE TABLE IF NOT EXISTS ' .
                $this->config->table .
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
                    $this->config->table .
                    ' WHERE email = ?',
                $email
            ) > 0
        ) {
            throw new \Exception('user already exists');
        }
        $this->db->query(
            'INSERT INTO ' .
                $this->config->table .
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
                    $this->config->table .
                    ' WHERE email = ?',
                $email
            ) == 0
        ) {
            throw new \Exception('user does not exists');
        }
        $this->db->query(
            'DELETE FROM ' . $this->config->table . ' WHERE email = ?',
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
            'SELECT * FROM ' . $this->config->table . ' WHERE email = ?',
            $email
        );

        if (empty($user) || !password_verify($password, $user['password'])) {
            throw new \Exception('email or password wrong');
        }

        $access_token = JWT::encode(
            [
                'iss' => $_SERVER['HTTP_HOST'], // issuer
                'exp' => time() + 60 * 60 * 24 * $this->config->ttl, // ttl
                'sub' => $user['id'] // user id
            ],
            $this->secret
        );

        if (
            PHP_SAPI != 'cli' ||
            strpos($_SERVER['argv'][0], 'phpunit') === false
        ) {
            setcookie(
                'access_token',
                $access_token,
                time() + 60 * 60 * 24 * $this->config->ttl,
                '/'
            );
        }

        $_COOKIE['access_token'] = $access_token;

        return $access_token;
    }

    function isLoggedIn()
    {
        return $this->getCurrentUserId() !== null;
    }

    function getCurrentUserId()
    {
        try {
            return JWT::decode(@$_COOKIE['access_token'], $this->secret, [
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
        $this->db->query('DROP TABLE IF EXISTS ' . $this->config->table);
        return true;
    }
}
