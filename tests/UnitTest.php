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
        shell_exec('php ./auth/index.php seed');
    }

    function testLogin()
    {
        $this->assertTrue(
            CompareHelper::compare(
                $this->request('POST', '/auth/login', [
                    @$_SERVER['JWT_LOGIN'] => 'david@vielhuber.de',
                    'password' => 'secret',
                ]),
                [
                    'response' => [
                        'success' => true,
                        'message' => 'auth successful',
                        'public_message' => '#STR#',
                        'data' => '*',
                    ],
                    'code' => 200,
                ]
            )
        );
    }

    function testLoginFailure()
    {
        $this->assertTrue(
            CompareHelper::compare(
                $this->request('POST', '/auth/login', [
                    'foo' => 'bar',
                ]),
                [
                    'response' => [
                        'success' => false,
                        'message' => 'auth not successful',
                        'public_message' => '#STR#',
                    ],
                    'code' => 401,
                ]
            )
        );
    }

    function testRefresh()
    {
        $access_token = $this->request('POST', '/auth/login', [
            @$_SERVER['JWT_LOGIN'] => 'david@vielhuber.de',
            'password' => 'secret',
        ])['response']['data']['access_token'];
        $this->assertTrue(
            CompareHelper::compare(
                $this->request('POST', '/auth/refresh', null, [
                    'Authorization' => 'Bearer ' . $access_token,
                ]),
                [
                    'response' => [
                        'success' => true,
                        'message' => 'auth successful',
                        'public_message' => '#STR#',
                        'data' => '*',
                    ],
                    'code' => 200,
                ]
            )
        );
    }

    function testRefreshFailure()
    {
        $this->assertTrue(
            CompareHelper::compare(
                $this->request('POST', '/auth/refresh', null, [
                    'Authorization' => 'Bearer foo',
                ]),
                [
                    'response' => [
                        'success' => false,
                        'message' => 'invalid token',
                        'public_message' => '#STR#',
                    ],
                    'code' => 401,
                ]
            )
        );
    }

    function testLogout()
    {
        $access_token = $this->request('POST', '/auth/login', [
            @$_SERVER['JWT_LOGIN'] => 'david@vielhuber.de',
            'password' => 'secret',
        ])['response']['data']['access_token'];
        $this->assertTrue(
            CompareHelper::compare(
                $this->request('POST', '/auth/logout', null, [
                    'Authorization' => 'Bearer ' . $access_token,
                ]),
                [
                    'response' => [
                        'success' => true,
                        'message' => 'logout successful',
                        'public_message' => '#STR#',
                    ],
                    'code' => 200,
                ]
            )
        );
    }

    function testCheck()
    {
        $access_token = $this->request('POST', '/auth/login', [
            @$_SERVER['JWT_LOGIN'] => 'david@vielhuber.de',
            'password' => 'secret',
        ])['response']['data']['access_token'];
        $this->assertTrue(
            CompareHelper::compare(
                $this->request('POST', '/auth/check', [
                    'access_token' => $access_token,
                ]),
                [
                    'response' => [
                        'success' => true,
                        'message' => 'valid token',
                        'public_message' => '#STR#',
                        'data' => '*',
                    ],
                    'code' => 200,
                ]
            )
        );
    }

    function testCheckFailure()
    {
        $this->assertTrue(
            CompareHelper::compare(
                $this->request('POST', '/auth/check', null, [
                    'Authorization' => 'Bearer foo',
                ]),
                [
                    'response' => [
                        'success' => false,
                        'message' => 'invalid token',
                        'public_message' => '#STR#',
                    ],
                    'code' => 401,
                ]
            )
        );
    }

    private function request($method = 'GET', $route = '/', $data = [], $headers = [])
    {
        $client = new Client([
            'base_uri' => @$_SERVER['BASE_URL'],
        ]);
        try {
            $response = $client->request($method, $route, [
                'form_params' => $data,
                'headers' => $headers,
                'http_errors' => false,
            ]);
            return [
                'code' => $response->getStatusCode(),
                'response' => json_decode(json_encode(json_decode((string) $response->getBody())), true),
            ];
        } catch (\Exception $e) {
            return [
                'response' => $e->getMessage(),
            ];
        }
    }
}
