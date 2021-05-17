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

now simply create the following files in a new folder called `auth` in your public directory:

#### /auth/index.php

```php
<?php
require_once __DIR__ . '/../vendor/autoload.php';
use vielhuber\simpleauth\simpleauth;
$auth = new simpleauth(__DIR__ . '/../.env');
if (php_sapi_name() !== 'cli') {
    $auth->api();
} elseif (@$argv[1] === 'migrate') {
    $auth->migrate();
} elseif (@$argv[1] === 'seed') {
    $auth->seed();
}
```

#### /auth/.htaccess

```.htaccess
RewriteEngine on
RewriteCond %{HTTP:Authorization} ^(.*)
RewriteRule .* - [e=HTTP_AUTHORIZATION:%1]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^.*$ /auth/index.php [L,QSA]
```

#### /.env

```.env
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=simpleauth
DB_USERNAME=root
DB_PASSWORD=root
JWT_TABLE=users
JWT_LOGIN=email
JWT_TTL=30
JWT_SECRET=I2hkRtw6t8Yg9Wvlg99Nij23Bvdm0n0L4UPkVC33a7rMo5EQGlnIv79LAOIMIxE
BASE_URL=http://simpleauth.local.vielhuber.de
```

if you want to migrate and seed data, simply run

```sh
php auth/index.php migrate
php auth/index.php seed
```

and you should be done (a test user `david@vielhuber.de` with the password `secret` is created).\
you can now fully authenticate with the routes below.\
if you want to authenticate via username instead of email, simply change JWT_LOGIN to `username`.

## routes

the following routes are provided automatically:

| route         | method | arguments      | header                      | response                                                                                                                                                                |
| ------------- | ------ | -------------- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| /auth/login   | POST   | email password | --                          | `([ 'success' => true, 'message' => 'auth successful', 'public_message' => '...', 'data' => [ 'access_token' => '...', 'expires_in' => 3600, 'user_id' => 42 ] ], 200)` |
| /auth/refresh | POST   | --             | Authorization: Bearer token | `([ 'success' => true, 'message' => 'auth successful', 'public_message' => '...', 'data' => [ 'access_token' => '...', 'expires_in' => 3600, 'user_id' => 42 ] ], 200)` |
| /auth/logout  | POST   | --             | Authorization: Bearer token | `([ 'success' => true, 'message' => 'logout successful', 'public_message' => '...' ], 200)`                                                                             |
| /auth/check   | POST   | access_token   | --                          | `([ 'success' => true, 'message' => 'valid token', 'public_message' => '...', 'data' => [ 'expires_in' => 3600, 'user_id' => 42, 'client_id' => 7000000 ] ], 200)`      |

## further usage

you can use the following functions inside your own application (they do not need any database lookups):

```php
require __DIR__ . '/vendor/autoload.php';
use vielhuber\simpleauth\simpleauth;
$auth = new simpleauth(__DIR__ . '/.env');

$auth->isLoggedIn();
$auth->getCurrentUserId();
```

## frontend

if you need a neat frontend library that works together with simpleauth seemlessly, try out [jwtbutler](https://github.com/vielhuber/jwtbutler).
