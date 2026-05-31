[![build status](https://github.com/vielhuber/simpleauth/actions/workflows/ci.yml/badge.svg)](https://github.com/vielhuber/simpleauth/actions)
[![GitHub Tag](https://img.shields.io/github/v/tag/vielhuber/simpleauth)](https://github.com/vielhuber/simpleauth/tags)
[![Code Style](https://img.shields.io/badge/code_style-psr--12-ff69b4.svg)](https://www.php-fig.org/psr/psr-12/)
[![License](https://img.shields.io/github/license/vielhuber/simpleauth)](https://github.com/vielhuber/simpleauth/blob/main/LICENSE.md)
[![Last Commit](https://img.shields.io/github/last-commit/vielhuber/simpleauth)](https://github.com/vielhuber/simpleauth/commits)
[![PHP Version Support](https://img.shields.io/packagist/php-v/vielhuber/simpleauth)](https://packagist.org/packages/vielhuber/simpleauth)
[![Packagist Downloads](https://img.shields.io/packagist/dt/vielhuber/simpleauth)](https://packagist.org/packages/vielhuber/simpleauth)

# 🔒 simpleauth 🔒

simpleauth is a simple php based authentication library.

it leverages:

- json web tokens
- bcrypted passwords
- full api

## installation

install once with composer:

```
composer require vielhuber/simpleauth
```

now simply create the following files inside a new folder called `auth` inside your public directory:

#### /auth/index.php

```php
<?php
require_once __DIR__ . '/../vendor/autoload.php';
use vielhuber\simpleauth\simpleauth;
$auth = new simpleauth(config: __DIR__ . '/../.env', table: 'users', login: 'email', ttl: 30, uuid: false);
$auth->init();
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

create a jwt secret (`openssl rand -base64 64 | tr -d '\n' | xclip -selection clipboard`)\
and populate an `.env` file:

```.env
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=simpleauth
DB_USERNAME=root
DB_PASSWORD=root
JWT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

if you want to migrate and seed data, simply run

```sh
php auth/index.php migrate
php auth/index.php create "david@vielhuber.de" "secret"
```

and you should be done (a test user `'david@vielhuber.de'` with the password `'secret'` is created).\
you can now fully authenticate with the routes below.\
if you want to authenticate via username instead of email, simply change `login` to `'username'`.\
if you need uuids instead of integers as your user ids, change `uuid` to `true`.

login throttling is enabled by default: after 5 failed login attempts per login and IP within 15 minutes, `/auth/login` responds with status `429`. You can disable it with `throttle: false` or adjust the limits with `throttle`:

```php
$auth = new simpleauth(
    /* ... */
    throttle: [
        'attempts' => 5,
        'minutes' => 15,
        'table' => 'users_login_attempts'
    ]
);
```

captcha validation is disabled by default. \
you can enable [hCaptcha](https://www.hcaptcha.com):

```php
$auth = new simpleauth(
    /* ... */
    captcha: [
        'provider' => 'hcaptcha',
        'sitekey' => 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'secret' => 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
    ]
);
```

passkeys are supported via WebAuthn and are available after running `migrate`. Browsers require a secure context for passkeys, except on localhost. You can disable passkeys with `passkeys: false` or adjust the table names with `passkeys`:

```php
$auth = new simpleauth(
    /* ... */
    passkeys: [
        'table' => 'users_passkeys',
        'table_challenge' => 'users_passkeys_challenges'
    ]
);
```

## routes

the following routes are provided automatically:

| route                            | method | arguments                         | header                      | response                                                                                                                                                                |
| -------------------------------- | ------ | --------------------------------- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/auth/login`                    | POST   | email password h-captcha-response | --                          | `([ 'success' => true, 'message' => 'auth successful', 'public_message' => '...', 'data' => [ 'access_token' => '...', 'expires_in' => 3600, 'user_id' => 42 ] ], 200)` |
| `/auth/refresh`                  | POST   | --                                | Authorization: Bearer token | `([ 'success' => true, 'message' => 'auth successful', 'public_message' => '...', 'data' => [ 'access_token' => '...', 'expires_in' => 3600, 'user_id' => 42 ] ], 200)` |
| `/auth/logout`                   | POST   | --                                | Authorization: Bearer token | `([ 'success' => true, 'message' => 'logout successful', 'public_message' => '...' ], 200)`                                                                             |
| `/auth/check`                    | POST   | access_token                      | --                          | `([ 'success' => true, 'message' => 'valid token', 'public_message' => '...', 'data' => [ 'expires_in' => 3600, 'user_id' => 42, 'client_id' => 7000000 ] ], 200)`      |
| `/auth/passkey-register-options` | POST   | --                                | Authorization: Bearer token | `([ 'success' => true, 'message' => 'passkey registration options created', 'public_message' => '...', 'data' => [ 'publicKey' => [] ] ], 200)`                         |
| `/auth/passkey-register`         | POST   | credential                        | Authorization: Bearer token | `([ 'success' => true, 'message' => 'passkey registered', 'public_message' => '...' ], 200)`                                                                            |
| `/auth/passkey-login-options`    | POST   | email optional                    | --                          | `([ 'success' => true, 'message' => 'passkey login options created', 'public_message' => '...', 'data' => [ 'publicKey' => [] ] ], 200)`                                |
| `/auth/passkey-login`            | POST   | credential                        | --                          | `([ 'success' => true, 'message' => 'auth successful', 'public_message' => '...', 'data' => [ 'access_token' => '...', 'expires_in' => 3600, 'user_id' => 42 ] ], 200)` |

## tests

```sh
php -S localhost:8007 -t auth
./vendor/bin/phpunit
```

## further usage

you can use the following functions inside your own application (they do not need any database lookups):

```php
require __DIR__ . '/vendor/autoload.php';
use vielhuber\simpleauth\simpleauth;
$auth = new simpleauth(config: __DIR__ . '/../.env', table: 'users', login: 'email', ttl: 30, uuid: false);
$auth->isLoggedIn();
$auth->getCurrentUserId();
$auth->migrate();
$auth->createUser('david@vielhuber.de', 'secret2');
$auth->deleteUser('david@vielhuber.de');
```

## frontend

if you need a neat frontend library that works together with\
`simpleauth` seemlessly, try out [jwtbutler](https://github.com/vielhuber/jwtbutler). The library exposes `passkeyRegister()` for logged-in users and `passkeyLogin()` for passwordless login.
