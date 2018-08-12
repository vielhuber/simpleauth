<?php
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
} elseif (file_exists(__DIR__ . '/../vendor/autoload.php')) {
    require_once __DIR__ . '/../vendor/autoload.php';
}
require_once __DIR__ . '/config.php';

use vielhuber\simpleauth\simpleauth;

$auth = new simpleauth($config);

if (php_sapi_name() !== 'cli') {
    $auth->api();
}
