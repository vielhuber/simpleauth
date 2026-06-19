<?php
use vielhuber\comparehelper\comparehelper;
use GuzzleHttp\Client;

class UnitTest extends \PHPUnit\Framework\TestCase
{
    protected function setUp(): void
    {
        $dotenv = \Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
        $dotenv->load();
        shell_exec(escapeshellarg(PHP_BINARY) . ' ./auth/index.php migrate');
        shell_exec(escapeshellarg(PHP_BINARY) . ' ./auth/index.php create david@vielhuber.de secret');
    }

    function testLogin()
    {
        $response = $this->request('POST', '/auth/login', [
            'email' => 'david@vielhuber.de',
            'password' => 'secret'
        ]);
        comparehelper::assertEquals(
            [
                'response' => [
                    'success' => true,
                    'message' => 'auth successful',
                    'public_message' => '#STR#',
                    'data' => '*'
                ],
                'code' => 200
            ],
            $response
        );
        $this->assertSame(60 * 60 * 24 * 30, $response['response']['data']['expires_in']);
    }

    function testLoginFailure()
    {
        comparehelper::assertEquals(
            [
                'response' => [
                    'success' => false,
                    'message' => 'auth not successful',
                    'public_message' => '#STR#'
                ],
                'code' => 401
            ],
            $this->request('POST', '/auth/login', [
                'foo' => 'bar'
            ])
        );
    }

    function testLoginThrottling()
    {
        for ($i = 0; $i < 5; $i++) {
            comparehelper::assertEquals(
                [
                    'response' => [
                        'success' => false,
                        'message' => 'auth not successful',
                        'public_message' => '#STR#'
                    ],
                    'code' => 401
                ],
                $this->request('POST', '/auth/login', [
                    'email' => 'david@vielhuber.de',
                    'password' => 'wrong'
                ])
            );
        }

        comparehelper::assertEquals(
            [
                'response' => [
                    'success' => false,
                    'message' => 'too many login attempts',
                    'public_message' => '#STR#'
                ],
                'code' => 429
            ],
            $this->request('POST', '/auth/login', [
                'email' => 'david@vielhuber.de',
                'password' => 'secret'
            ])
        );
    }

    function testRefresh()
    {
        $access_token = $this->request('POST', '/auth/login', [
            'email' => 'david@vielhuber.de',
            'password' => 'secret'
        ])['response']['data']['access_token'];
        comparehelper::assertEquals(
            [
                'response' => [
                    'success' => true,
                    'message' => 'auth successful',
                    'public_message' => '#STR#',
                    'data' => '*'
                ],
                'code' => 200
            ],
            $this->request('POST', '/auth/refresh', null, [
                'Authorization' => 'Bearer ' . $access_token
            ])
        );
    }

    function testRefreshFailure()
    {
        comparehelper::assertEquals(
            [
                'response' => [
                    'success' => false,
                    'message' => 'invalid token',
                    'public_message' => '#STR#'
                ],
                'code' => 401
            ],
            $this->request('POST', '/auth/refresh', null, [
                'Authorization' => 'Bearer foo'
            ])
        );
    }

    function testLogout()
    {
        $access_token = $this->request('POST', '/auth/login', [
            'email' => 'david@vielhuber.de',
            'password' => 'secret'
        ])['response']['data']['access_token'];
        comparehelper::assertEquals(
            [
                'response' => [
                    'success' => true,
                    'message' => 'logout successful',
                    'public_message' => '#STR#'
                ],
                'code' => 200
            ],
            $this->request('POST', '/auth/logout', null, [
                'Authorization' => 'Bearer ' . $access_token
            ])
        );
    }

    function testLogoutFailure()
    {
        comparehelper::assertEquals(
            [
                'response' => [
                    'success' => false,
                    'message' => 'logout not successful',
                    'public_message' => '#STR#'
                ],
                'code' => 401
            ],
            $this->request('POST', '/auth/logout', null, [
                'Authorization' => 'Bearer foo'
            ])
        );
    }

    function testCheck()
    {
        $access_token = $this->request('POST', '/auth/login', [
            'email' => 'david@vielhuber.de',
            'password' => 'secret'
        ])['response']['data']['access_token'];
        comparehelper::assertEquals(
            [
                'response' => [
                    'success' => true,
                    'message' => 'valid token',
                    'public_message' => '#STR#',
                    'data' => '*'
                ],
                'code' => 200
            ],
            $this->request('POST', '/auth/check', [
                'access_token' => $access_token
            ])
        );
    }

    function testCheckFailure()
    {
        comparehelper::assertEquals(
            [
                'response' => [
                    'success' => false,
                    'message' => 'invalid token',
                    'public_message' => '#STR#'
                ],
                'code' => 401
            ],
            $this->request('POST', '/auth/check', null, [
                'Authorization' => 'Bearer foo'
            ])
        );
    }

    function testPasskeyRegister()
    {
        $access_token = $this->request('POST', '/auth/login', [
            'email' => 'david@vielhuber.de',
            'password' => 'secret'
        ])['response']['data']['access_token'];
        comparehelper::assertEquals(
            [
                'response' => [
                    'success' => true,
                    'message' => 'passkey registration options created',
                    'public_message' => '#STR#',
                    'data' => [
                        'publicKey' => [
                            'challenge' => '#STR#',
                            'rp' => '*',
                            'user' => '*',
                            'pubKeyCredParams' => '*',
                            'authenticatorSelection' => '*',
                            'attestation' => 'none',
                            'excludeCredentials' => '*',
                            'timeout' => 60000
                        ]
                    ]
                ],
                'code' => 200
            ],
            $this->request('POST', '/auth/passkey-register-options', null, [
                'Authorization' => 'Bearer ' . $access_token
            ])
        );
    }

    function testPasskeyLogin()
    {
        comparehelper::assertEquals(
            [
                'response' => [
                    'success' => true,
                    'message' => 'passkey login options created',
                    'public_message' => '#STR#',
                    'data' => [
                        'publicKey' => [
                            'challenge' => '#STR#',
                            'rpId' => '#STR#',
                            'allowCredentials' => [],
                            'userVerification' => 'preferred',
                            'timeout' => 60000
                        ]
                    ]
                ],
                'code' => 200
            ],
            $this->request('POST', '/auth/passkey-login-options')
        );
    }

    function testPasskeyDelete()
    {
        $access_token = $this->request('POST', '/auth/login', [
            'email' => 'david@vielhuber.de',
            'password' => 'secret'
        ])['response']['data']['access_token'];
        comparehelper::assertEquals(
            [
                'response' => [
                    'success' => false,
                    'message' => 'passkey not deleted',
                    'public_message' => '#STR#'
                ],
                'code' => 401
            ],
            $this->request('POST', '/auth/passkey-delete', ['id' => 1], [
                'Authorization' => 'Bearer ' . $access_token
            ])
        );
    }

    function testPasskeyManagement()
    {
        $auth = new \vielhuber\simpleauth\simpleauth(__DIR__ . '/../.env', 'users', 'email', 30, false);
        comparehelper::assertEquals([], $auth->getPasskeys(login: 'david@vielhuber.de'));
        $this->expectException(\Exception::class);
        $auth->deletePasskey(login: 'david@vielhuber.de', passkey_id: 1);
    }

    function testUserManagement()
    {
        $auth = new \vielhuber\simpleauth\simpleauth(__DIR__ . '/../.env', 'users', 'email', 30, false);
        comparehelper::assertEquals(
            [
                [
                    'id' => '*',
                    'login' => 'david@vielhuber.de',
                    'email' => 'david@vielhuber.de'
                ]
            ],
            $auth->getUsers()
        );
        comparehelper::assertEquals(
            [
                'id' => '*',
                'login' => 'david@vielhuber.de',
                'email' => 'david@vielhuber.de'
            ],
            $auth->getUser(login: 'david@vielhuber.de')
        );
        $this->assertTrue($auth->createUser(login: 'jane@vielhuber.de', password: 'secret'));
        $this->assertTrue(
            $auth->updateUser(login: 'jane@vielhuber.de', login_new: 'david2@vielhuber.de', password_new: 'secret2')
        );
        comparehelper::assertEquals(
            [
                'response' => [
                    'success' => true,
                    'message' => 'auth successful',
                    'public_message' => '#STR#',
                    'data' => '*'
                ],
                'code' => 200
            ],
            $this->request('POST', '/auth/login', [
                'email' => 'david2@vielhuber.de',
                'password' => 'secret2'
            ])
        );
        $this->assertTrue($auth->deleteUser(login: 'david2@vielhuber.de'));
    }

    function testPasswordReset()
    {
        $auth = new \vielhuber\simpleauth\simpleauth(__DIR__ . '/../.env', 'users', 'email', 30, false);
        $this->assertFalse($auth->requestPasswordReset(login: 'missing@vielhuber.de'));
        $token = $auth->createPasswordResetToken(login: 'david@vielhuber.de');
        comparehelper::assertEquals(
            [
                'response' => [
                    'success' => true,
                    'message' => 'password reset successful',
                    'public_message' => '#STR#'
                ],
                'code' => 200
            ],
            $this->request('POST', '/auth/password-reset', [
                'token' => $token,
                'password' => 'reset-secret'
            ])
        );
        comparehelper::assertEquals(
            [
                'response' => [
                    'success' => true,
                    'message' => 'auth successful',
                    'public_message' => '#STR#',
                    'data' => '*'
                ],
                'code' => 200
            ],
            $this->request('POST', '/auth/login', [
                'email' => 'david@vielhuber.de',
                'password' => 'reset-secret'
            ])
        );
        comparehelper::assertEquals(
            [
                'response' => [
                    'success' => false,
                    'message' => 'password reset not successful',
                    'public_message' => '#STR#'
                ],
                'code' => 401
            ],
            $this->request('POST', '/auth/password-reset', [
                'token' => $token,
                'password' => 'reset-secret-2'
            ])
        );
    }

    private function request($method = 'GET', $route = '/', $data = [], $headers = [])
    {
        $client = new Client([
            'base_uri' => 'http://localhost:8007'
        ]);
        try {
            $response = $client->request($method, $route, [
                'form_params' => $data,
                'headers' => $headers,
                'http_errors' => false
            ]);
            return [
                'code' => $response->getStatusCode(),
                'response' => json_decode(json_encode(json_decode((string) $response->getBody())), true)
            ];
        } catch (\Exception $e) {
            return [
                'response' => $e->getMessage()
            ];
        }
    }
}
