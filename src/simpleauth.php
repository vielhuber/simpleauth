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
        $this->config = $config;
        $this->db = new dbhelper();
        $this->db->connect(
            'pdo',
            $config['dbms'],
            $config['host'],
            $config['username'],
            $config['password'],
            $config['database'],
            $config['port']
        );
    }

    function migrate()
    {
        $this->db->query(
            '
            CREATE TABLE ' .
                $this->config->table .
                '
            (
                id SERIAL PRIMARY KEY,
                email varchar(100) NOT NULL,
                password char(255) NOT NULL
            )
        '
        );
    }

    function createUser($email, $password)
    {
        if (
            $this->db->fetch_var(
                'SELECT COUNT(id) FROM users WHERE email = ?',
                $email
            ) > 0
        ) {
            throw new \Exception('user already exists');
        }
        db_query(
            'INSERT INTO users(email,password) VALUES(?,?)',
            $email,
            password_hash($password, PASSWORD_DEFAULT)
        );
    }

    function login($username, $password)
    {
    }

    function isLoggedIn()
    {
        return $this->getCurrentUserId() !== null;
    }

    function getCurrentUserId()
    {
        try {
            return JWT::decode(
                $_COOKIE['access_token'],
                $this->config['secret'],
                ['HS256']
            )->sub;
        } catch (Exception $e) {
            return null;
        }
    }

    function logout()
    {
    }
}
