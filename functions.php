<?php
/* connect to db (via dbhelper) */
require_once('https://raw.githubusercontent.com/vielhuber/dbhelper/master/index.php?rand=3876');
$sql = db_connect('pdo', 'mysql', '127.0.0.1', 'root', 'root', 'simpleauth');

/* helper functions */

/* create user */
function auth_create_user($username, $password, $email)
{
    if (db_fetch_var("SELECT COUNT(id) FROM users WHERE username = ?", $username) > 0)
    {
        die('error');
    }
    $salt     = md5(uniqid(mt_rand(), true));
    $password = sha1($password . $salt);
    db_query("INSERT INTO users(`username`,`password`,`salt`,`email`) VALUES(?,?,?,?)", $username, $password, $salt, $email);
}

/* login controller */
function auth_login_controller($username, $password)
{
    
    // check if everything is present
    if (!isset($username) || $username == "" || !isset($password) || $password == "")
    {
        die('error');
    }
    
    // check if that user exists
    if (db_fetch_var("SELECT COUNT(id) as count FROM users WHERE username = '" . strip_tags($_POST['username']) . "' AND SHA1(CONCAT('" . strip_tags($password) . "', salt)) = password;") == 0)
    {
        die('error');
    }
    
    // get user id
    $user_id = db_fetch_var("SELECT id FROM users WHERE username = '" . strip_tags($_POST['username']) . "' AND SHA1(CONCAT('" . strip_tags($password) . "', salt)) = password;");
    
    // generate new random token
    $token = md5(uniqid(mt_rand(), true));
    
    // save token in database	
    db_query("
		INSERT INTO auth
			(`token`, `valid_until`, `user_id`)
		VALUES
			(
				'" . $token . "',
				'" . date('Y-m-d H:i:s', strtotime("now + 70 days")) . "',
				'" . $user_id . "'
			)
	");
    
    // save token as cookie
    setcookie('user_authentication_token', $token, time() + 60 * 60 * 24 * 70, '/');
    
    die('ok');
    
}

/* logout controller */
function auth_logout_controller()
{
    
    // check data
    if (!isset($_COOKIE['user_authentication_token']) || $_COOKIE['user_authentication_token'] == "")
    {
        header("Location: " . "login_form.php");
        die();
    }
    
    // remote token from database
    db_query("DELETE FROM auth WHERE token = '" . strip_tags($_COOKIE['user_authentication_token']) . "';");
    
    // unset Cookie
    unset($_COOKIE['user_authentication_token']);
    setcookie('user_authentication_token', '', time() - 3600, '/');
    
    // prg
    header("Location: " . "login_form.php");
    die();
    
}

/* check if user is logged in */
function auth_is_user_logged_in()
{
    if (isset($_COOKIE["user_authentication_token"]))
    {
        if (db_fetch_var("SELECT COUNT(id) as count FROM auth WHERE token = '" . strip_tags($_COOKIE["user_authentication_token"]) . "' AND valid_until >= NOW();") > 0)
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    return false;
}

/* get current user id */
function auth_get_current_user_id()
{
    if (!auth_is_user_logged_in())
    {
        return false;
    }
    return db_fetch_var("SELECT user_id FROM auth WHERE token = '" . strip_tags($_COOKIE["user_authentication_token"]) . "' AND valid_until >= NOW();");
}
