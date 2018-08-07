<?php
require_once('functions.php');

if( !auth_is_user_logged_in() ) { header("Location: " . "login_form.php"); die(); }
echo 'I am logged in now and have the user id '.auth_get_current_user_id().'<br/>'.'<a href="logout_controller.php">Logout</a>';