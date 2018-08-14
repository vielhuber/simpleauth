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
require_once __DIR__.'/../vendor/autoload.php';
use vielhuber\simpleauth\simpleauth;
$auth = new simpleauth(__DIR__.'/../.env');
if (php_sapi_name() !== 'cli') { $auth->api(); }
elseif(@$argv[1] === 'migrate') { $auth->migrate(); }
elseif(@$argv[1] === 'seed') { $auth->seed(); }
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
DB_ENGINE=mysql
DB_HOST=127.0.0.1
DB_USERNAME=root
DB_PASSWORD=root
DB_DATABASE=simpleauth
DB_PORT=3306
JWT_TABLE=users
JWT_TTL=30
JWT_SECRET=I2hkRtw6t8Yg9Wvlg99Nij23Bvdm0n0L4UPkVC33a7rMo5EQGlnIv79LAOIMIxE
```

if you want to migrate and seed data, simply run

```sh
php auth/index.php migrate
php auth/index.php seed
```

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
