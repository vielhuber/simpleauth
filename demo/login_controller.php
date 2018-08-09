<?php
require_once 'includes.php';
$input = json_decode(file_get_contents('php://input'), true);
try {
    $auth->login($input['email'], $input['password']);
    http_response_code(200);
    echo json_encode('ok');
    die();
} catch (\Exception $e) {
    http_response_code(401);
    echo json_encode('error');
    die();
}
