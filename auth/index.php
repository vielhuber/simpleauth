<?php
require_once __DIR__ . '/../vendor/autoload.php';
use vielhuber\simpleauth\simpleauth;
$auth = new simpleauth(__DIR__ . '/../.env', 'users', 'email', 30, false);
$auth->init();
