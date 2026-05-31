<?php
use vielhuber\comparehelper\comparehelper;
use GuzzleHttp\Client;

class UnitTest extends \PHPUnit\Framework\TestCase
{
    protected function setUp(): void
    {
        $dotenv = \Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
        $dotenv->load();
        shell_exec('php ./auth/index.php migrate');
        shell_exec('php ./auth/index.php create david@vielhuber.de secret');
    }

    function testLogin()
    {
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
                'password' => 'secret'
            ])
        );
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
