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

then add this to your files:

```php
require __DIR__.'/vendor/autoload.php';
use vielhuber\simpleauth\simpleauth;

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
```

## usage

```php
// table migrations included
$auth->createTable();
$auth->deleteTable();

// easy user management
$auth->createUser($email, $password);
$auth->deleteUser($email);

// do this before any output (cookies are set)
$auth->login($email, $password);
$auth->logout();

// this does not need any database lookups
$auth->isLoggedIn();
$auth->getCurrentUserId();
```

## api

if you instead/also want to use a fully prepared api, simply copy out the auth folder in your public directory:

```
cp -r vendor/vielhuber/simpleauth/auth auth/
```

The following routes are then provided automatically:

-   /login (email, password)
-   /logout
-   /refresh
-   /check (access_token)

## frontend

if you need a neat frontend library that works together with simpleauth seemlessly, try out [jtwbutler](https://github.com/vielhuber/jwtbutler).
