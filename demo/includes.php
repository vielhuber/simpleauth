<?php
require __DIR__ . '/../vendor/autoload.php';
use vielhuber\simpleauth\simpleauth;

$auth = new simpleauth(__DIR__.'/../.env');

try {
    $auth->createTable();
    $auth->createUser('david@vielhuber.de', 'secret');
} catch (\Exception $e) {

}
