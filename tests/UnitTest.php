<?php
use vielhuber\comparehelper\comparehelper;
use GuzzleHttp\Client;

class ApiTest extends \PHPUnit\Framework\TestCase
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
        CompareHelper::assertEquals(
            $this->request('POST', '/auth/login', [
                'email' => 'david@vielhuber.de',
                'password' => 'secret'
            ]),
            [
                'response' => [
                    'success' => true,
                    'message' => 'auth successful',
                    'public_message' => '#STR#',
                    'data' => '*'
                ],
                'code' => 200
            ]
        );
    }

    function testLoginFailure()
    {
        CompareHelper::assertEquals(
            $this->request('POST', '/auth/login', [
                'foo' => 'bar'
            ]),
            [
                'response' => [
                    'success' => false,
                    'message' => 'auth not successful',
                    'public_message' => '#STR#'
                ],
                'code' => 401
            ]
        );
    }

    function testRefresh()
    {
        $access_token = $this->request('POST', '/auth/login', [
            'email' => 'david@vielhuber.de',
            'password' => 'secret'
        ])['response']['data']['access_token'];
        CompareHelper::assertEquals(
            $this->request('POST', '/auth/refresh', null, [
                'Authorization' => 'Bearer ' . $access_token
            ]),
            [
                'response' => [
                    'success' => true,
                    'message' => 'auth successful',
                    'public_message' => '#STR#',
                    'data' => '*'
                ],
                'code' => 200
            ]
        );
    }

    function testRefreshFailure()
    {
        CompareHelper::assertEquals(
            $this->request('POST', '/auth/refresh', null, [
                'Authorization' => 'Bearer foo'
            ]),
            [
                'response' => [
                    'success' => false,
                    'message' => 'invalid token',
                    'public_message' => '#STR#'
                ],
                'code' => 401
            ]
        );
    }

    function testLogout()
    {
        $access_token = $this->request('POST', '/auth/login', [
            'email' => 'david@vielhuber.de',
            'password' => 'secret'
        ])['response']['data']['access_token'];
        CompareHelper::assertEquals(
            $this->request('POST', '/auth/logout', null, [
                'Authorization' => 'Bearer ' . $access_token
            ]),
            [
                'response' => [
                    'success' => true,
                    'message' => 'logout successful',
                    'public_message' => '#STR#'
                ],
                'code' => 200
            ]
        );
    }

    function testCheck()
    {
        $access_token = $this->request('POST', '/auth/login', [
            'email' => 'david@vielhuber.de',
            'password' => 'secret'
        ])['response']['data']['access_token'];
        CompareHelper::assertEquals(
            $this->request('POST', '/auth/check', [
                'access_token' => $access_token
            ]),
            [
                'response' => [
                    'success' => true,
                    'message' => 'valid token',
                    'public_message' => '#STR#',
                    'data' => '*'
                ],
                'code' => 200
            ]
        );
    }

    function testCheckFailure()
    {
        CompareHelper::assertEquals(
            $this->request('POST', '/auth/check', null, [
                'Authorization' => 'Bearer foo'
            ]),
            [
                'response' => [
                    'success' => false,
                    'message' => 'invalid token',
                    'public_message' => '#STR#'
                ],
                'code' => 401
            ]
        );
    }

    private function request($method = 'GET', $route = '/', $data = [], $headers = [])
    {
        $client = new Client([
            'base_uri' => 'http://localhost:8000'
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
