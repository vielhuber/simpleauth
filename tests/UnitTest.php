<?php
use vielhuber\simpleauth\simpleauth;

class UnitTest extends \PHPUnit\Framework\TestCase
{
    protected $auth = null;

    protected function setUp()
    {
        $this->auth = new simpleauth(__DIR__.'/../auth/.env');
        $this->auth->deleteTable();
        $this->auth->createTable();
    }

    protected function tearDown()
    {
        $this->auth->deleteTable();
    }

    function testAll()
    {
        $this->assertSame(
            $this->auth->createUser('david@vielhuber.de', 'secret'),
            true
        );

        $this->assertSame(
            strlen(
                $this->auth->login('david@vielhuber.de', 'secret')[
                    'access_token'
                ]
            ) > 10,
            true
        );

        $this->assertSame(
            strlen(
                $this->auth->refresh($_COOKIE['access_token'])['access_token']
            ) > 10,
            true
        );

        $this->assertSame(
            $this->auth->check($_COOKIE['access_token'])['user_id'],
            1
        );

        $this->assertSame($this->auth->isLoggedIn(), true);

        $this->assertSame($this->auth->getCurrentUserId(), 1);

        $this->assertSame($this->auth->logout(), true);

        $this->assertSame($this->auth->isLoggedIn(), false);

        $this->assertSame($this->auth->getCurrentUserId(), null);

        $this->assertSame($this->auth->deleteUser('david@vielhuber.de'), true);

        try {
            $this->auth->login('david@vielhuber.de', 'secret');
            $this->assertSame(true, false);
        } catch (\Exception $e) {
            $this->assertSame(true, true);
        }
    }
}
