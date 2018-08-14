# 🔒 simpleauth 🔒

simpleauth is a simple php based authentication library.

it leverages:

-   json web tokens
-   bcrypted passwords
-   full api

## installation

install once with composer:

```
composer require vielhuber/simpleauth
```

simply copy out the auth folder in your public directory:

```
cp -r vendor/vielhuber/simpleauth/auth auth/
```

now

-   run `cp auth/.env.example auth/.env` and edit in `.env` your database credentials and your secret key
-   run `php auth/migrate`
-   run `php auth/seed`

and you should be done. you can now fully authenticate with the routes below.

## routes

the following routes are provided automatically:

| route         | method | arguments      | header                      | response                                                                                                                                                                |
| ------------- | ------ | -------------- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| /auth/login   | POST   | email password | --                          | `([ 'success' => true, 'message' => 'auth successful', 'public_message' => '...', 'data' => [ 'access_token' => '...', 'expires_in' => 3600, 'user_id' => 42 ] ], 200)` |
| /auth/refresh | POST   | --             | Authorization: Bearer token | `([ 'success' => true, 'message' => 'auth successful', 'public_message' => '...', 'data' => [ 'access_token' => '...', 'expires_in' => 3600, 'user_id' => 42 ] ], 200)` |
| /auth/logout  | POST   | --             | Authorization: Bearer token | `([ 'success' => true, 'message' => 'logout successful', 'public_message' => '...' ], 200)`                                                                             |
| /auth/check   | POST   | access_token   | --                          | `([ 'success' => true, 'message' => 'valid token', 'public_message' => '...', 'data' => [ 'expires_in' => 3600, 'user_id' => 42, 'client_id' => 7000000 ] ], 200)`      |

## further usage

you can use the following functions in your own application:

```php
require __DIR__.'/vendor/autoload.php';
use vielhuber\simpleauth\simpleauth;

$auth = new simpleauth(__DIR__.'/.env');

// these two common routes are commonly used inside your application (they do not need any database lookups)
$auth->isLoggedIn();
$auth->getCurrentUserId();

/* use the following functions instead of the public auth routes, if you need more fine grained control  */

// table migrations included
$auth->createTable();
$auth->deleteTable();

// easy user management
$auth->createUser($email, $password);
$auth->deleteUser($email);

// do this before any output (cookies are set)
$auth->login($email, $password);
$auth->refresh();
$auth->logout();
$auth->check($access_token);
```

## frontend

if you need a neat frontend library that works together with simpleauth seemlessly, try out [jtwbutler](https://github.com/vielhuber/jwtbutler).
