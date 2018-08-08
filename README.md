# ⚿ simpleauth ⚿

simpleauth is a simple php based authentication library.

it leverages

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
$auth->createTable();

$auth->createUser($email, $password);

$auth->login($email, $password);

$auth->isLoggedIn();

$auth->getCurrentUserId();

$auth->logout();

$auth->deleteTable();
```
