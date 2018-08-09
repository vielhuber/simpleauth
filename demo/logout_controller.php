<?php
require_once 'includes.php';
$auth->logout();
header('Location: index.php');
