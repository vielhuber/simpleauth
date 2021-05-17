<?php
require_once __DIR__ . '/../vendor/autoload.php';
use vielhuber\simpleauth\simpleauth;
$auth = new simpleauth(__DIR__ . '/../.env');
if (php_sapi_name() !== 'cli') {
    $auth->api();
} elseif (@$argv[1] === 'migrate') {
    $auth->migrate();
} elseif (@$argv[1] === 'seed') {
    $auth->seed();
}
