# 🔒 simpleauth 🔒

simpleauth is a simple php based authentication library.

it leverages:

-   json web tokens
-   bcrypted passwords

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
