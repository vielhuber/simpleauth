<?php
use vielhuber\simpleauth\simpleauth;

class BasicTest extends \PHPUnit\Framework\TestCase
{
    protected $auth = null;

    protected function setUp()
    {
        $this->auth = new simpleauth([
            'dbms' => 'mysql',
            'host' => '127.0.0.1',
            'username' => 'root',
            'password' => 'root',
            'database' => 'simpleauth',
            'table' => 'users',
            'port' => 3306,
            'ttl' => 30
        ]);
        $this->auth->deleteTable();
        $this->auth->createTable();
    }

    protected function tearDown()
    {
        $this->auth->deleteTable();
    }

    function test__all()
    {
        $this->assertSame(
            $this->auth->createUser('david@vielhuber.de', 'secret'),
            true
        );

        $this->assertSame(
            strlen($this->auth->login('david@vielhuber.de', 'secret')) > 10,
            true
        );

        $this->assertSame($this->auth->isLoggedIn(), true);

        $this->assertSame($this->auth->getCurrentUserId(), 1);

        $this->assertSame($this->auth->logout(), true);

        $this->assertSame($this->auth->isLoggedIn(), false);

        $this->assertSame($this->auth->getCurrentUserId(), null);
    }
}
