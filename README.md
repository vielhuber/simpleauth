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

-   edit your database credentials inside `auth/config.php`
-   run `php auth/migrate`
-   run `php auth/seed`

and you should be done.

## routes

the following routes are then provided automatically:

| route         | method | arguments      | header                      | response                                                                                                                                                                |
| ------------- | ------ | -------------- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| /auth/login   | POST   | email password | --                          | `([ 'success' => true, 'message' => 'auth successful', 'public_message' => '...', 'data' => [ 'access_token' => '...', 'expires_in' => 3600, 'user_id' => 42 ] ], 200)` |
| /auth/refresh | POST   | --             | Authorization: Bearer token | `([ 'success' => true, 'message' => 'auth successful', 'public_message' => '...', 'data' => [ 'access_token' => '...', 'expires_in' => 3600, 'user_id' => 42 ] ], 200)` |
| /auth/logout  | POST   | --             | Authorization: Bearer token | `([ 'success' => true, 'message' => 'logout successful', 'public_message' => '...' ], 200)`                                                                             |
| /auth/check   | POST   | access_token   | --                          | `([ 'success' => true, 'message' => 'valid token', 'public_message' => '...', 'data' => [ 'expires_in' => 3600, 'user_id' => 42, 'client_id' => 7000000 ] ], 200)`      |

## further usage

if you instead want to have more control, you can use the following public functions in your own application:

```php
require __DIR__.'/vendor/autoload.php';
use vielhuber\simpleauth\simpleauth;

// config
$auth = new simpleauth([
    'dbms' => 'mysql',
    'host' => '127.0.0.1',
    'username' => 'foo',
    'password' => 'bar',
    'database' => 'baz',
    'table' => 'users',
    'port' => 3306,
    'ttl' => 30
]);

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

// this does not need any database lookups
$auth->isLoggedIn();
$auth->getCurrentUserId();
```

## frontend

if you need a neat frontend library that works together with simpleauth seemlessly, try out [jtwbutler](https://github.com/vielhuber/jwtbutler).
