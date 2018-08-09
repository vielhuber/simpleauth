<?php
require_once 'includes.php';
if (!$auth->isLoggedIn()) {
    header('Location: ' . 'login_view.php');
    die();
}
echo 'I am logged in now and have the user id ' .
    $auth->getCurrentUserId() .
    '<br/>' .
    '<a href="logout_controller.php">Logout</a>';
