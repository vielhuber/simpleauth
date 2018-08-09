<?php
require __DIR__ . '/../vendor/autoload.php';
use vielhuber\simpleauth\simpleauth;

$auth = new simpleauth([
    'dbms' => 'mysql',
    'host' => '127.0.0.1',
    'username' => 'root',
    'password' => 'root',
    'database' => 'simpleauth',
    'table' => 'users',
    'port' => 3306,
    'ttl' => 30
]);

try {
    $auth->createTable();
    $auth->createUser('david@vielhuber.de', 'secret');
} catch (\Exception $e) {

}
