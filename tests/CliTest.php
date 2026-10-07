<?php
declare(strict_types=1);

final class CliTest extends \PHPUnit\Framework\TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/simpleauth-cli-' . bin2hex(random_bytes(8));
        mkdir($this->directory, 0700);
        file_put_contents(
            $this->directory . '/.env',
            implode(PHP_EOL, [
                'DB_CONNECTION=sqlite',
                'DB_HOST=' . $this->directory . '/database.sqlite',
                'DB_PORT=',
                'DB_DATABASE=',
                'DB_USERNAME=',
                'DB_PASSWORD=',
                'JWT_SECRET=' . bin2hex(random_bytes(32)),
                ''
            ])
        );
        file_put_contents(
            $this->directory . '/auth.php',
            '<?php declare(strict_types=1); require ' .
                var_export(dirname(__DIR__) . '/vendor/autoload.php', true) .
                '; (new \vielhuber\simpleauth\simpleauth(config: __DIR__ . "/.env", passkeys: false, cors: false))->init();'
        );
    }

    protected function tearDown(): void
    {
        foreach (glob($this->directory . '/*') as $file) {
            unlink($file);
        }
        unlink($this->directory . '/.env');
        rmdir($this->directory);
    }

    public function testCreateRejectsDuplicatesWithoutChangingUser(): void
    {
        $first = $this->runCommand(['create', 'cli@example.test', 'first-test-password']);
        $this->assertSame(0, $first['exit']);
        $this->assertSame('User created.' . PHP_EOL, $first['stdout']);
        $this->assertSame('', $first['stderr']);
        $database = new \PDO('sqlite:' . $this->directory . '/database.sqlite');
        $firstUser = $database->query('SELECT id, password FROM users')->fetch(\PDO::FETCH_ASSOC);
        $this->assertTrue(password_verify('first-test-password', $firstUser['password']));
        $database->exec(
            "INSERT INTO users_passkeys (user_id, login_identifier, credential_id, credential_record) VALUES ('" .
                $firstUser['id'] .
                "', 'cli@example.test', 'test-credential', '{}')"
        );
        $passkeys = $database->query('SELECT * FROM users_passkeys')->fetchAll(\PDO::FETCH_ASSOC);
        $other = $this->runCommand(['create', 'other@example.test', 'other-test-password']);
        $this->assertSame(0, $other['exit']);

        $second = $this->runCommand(['create', 'cli@example.test', 'second-test-password']);
        $this->assertSame(1, $second['exit']);
        $this->assertSame('', $second['stdout']);
        $this->assertSame('Error: user already exists' . PHP_EOL, $second['stderr']);
        $users = $database
            ->query("SELECT id, password FROM users WHERE email = 'cli@example.test'")
            ->fetchAll(\PDO::FETCH_ASSOC);
        $this->assertCount(1, $users);
        $this->assertSame('2', (string) $database->query('SELECT COUNT(*) FROM users')->fetchColumn());
        $this->assertSame($firstUser, $users[0]);
        $this->assertSame($passkeys, $database->query('SELECT * FROM users_passkeys')->fetchAll(\PDO::FETCH_ASSOC));
        $this->assertTrue(password_verify('first-test-password', $users[0]['password']));
        $this->assertFalse(password_verify('second-test-password', $users[0]['password']));
        $this->assertStringNotContainsString('second-test-password', $second['stdout'] . $second['stderr']);
    }

    public function testInvalidArgumentsReportUsageAndFailure(): void
    {
        foreach (
            [
                [],
                ['unknown'],
                ['create'],
                ['create', 'cli@example.test'],
                ['create', '', 'test-password'],
                ['create', 'cli@example.test', '']
            ]
            as $arguments
        ) {
            $result = $this->runCommand($arguments);
            $this->assertSame(1, $result['exit']);
            $this->assertSame('', $result['stdout']);
            $this->assertStringContainsString('Usage:', $result['stderr']);
            $this->assertStringNotContainsString('Undefined array key', $result['stderr']);
            $this->assertStringNotContainsString('test-password', $result['stderr']);
        }
    }

    public function testMigrationReportsSuccess(): void
    {
        $result = $this->runCommand(['migrate']);
        $this->assertSame(0, $result['exit']);
        $this->assertSame('Tables migrated.' . PHP_EOL, $result['stdout']);
        $this->assertSame('', $result['stderr']);
        $database = new \PDO('sqlite:' . $this->directory . '/database.sqlite');
        $this->assertSame('0', (string) $database->query('SELECT COUNT(*) FROM users')->fetchColumn());
    }

    private function runCommand(array $arguments): array
    {
        $process = proc_open(
            [PHP_BINARY, $this->directory . '/auth.php', ...$arguments],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        return ['stdout' => $stdout, 'stderr' => $stderr, 'exit' => proc_close($process)];
    }
}
