<?php
use vielhuber\comparehelper\comparehelper;

class BasicTest extends \PHPUnit\Framework\TestCase
{

    function test__compare()
    {

        $this->assertSame(CompareHelper::compare('foo','foo'), true);

        $this->assertSame(CompareHelper::compare(42,42), true);

        $this->assertSame(CompareHelper::compare(42,'42'), false);

        $this->assertSame(CompareHelper::compare(
            [
                'foo' => 'bar'
            ],
            [
                'foo' => 'bar',
                'foo2' => 'bar'
            ]
        ), false);

        $this->assertSame(CompareHelper::compare(
            [
                'foo' => 'bar',
                'bar' => [
                    'baz',
                    42
                ]
            ],
            [
                '#INT#' => 'bar',
                'bar' => [
                    '#STR#',
                    '#INT#'
                ]
            ]
        ), false);

        $this->assertSame(CompareHelper::compare(
            [
                'foo' => 'bar',
                'bar' => [
                    'baz',
                    42
                ]
            ],
            [
                'foo' => '*',
                'bar' => [
                    '#INT#',
                    '#STR#'
                ]
            ]           
        ), false);

        $this->assertSame(CompareHelper::compare(
            [
                'foo' => 'bar',
                'bar' => [
                    'baz',
                    42
                ]
            ],
            [
                '*' => '*',
                'bar' => [
                    '#STR#',
                    '#INT#'
                ]
            ]
        ), true);

        $this->assertSame(CompareHelper::compare(
            [
                'foo' => 'bar',
                'bar' => [
                    'baz',
                    42
                ]
            ],
            [
                '*' => '*',
                'bar' => [
                    42,
                    'baz'
                ]
            ]
        ), true);

        $this->assertSame(CompareHelper::compare(['foo','bar'],['bar','foo']), true);

        $this->assertSame(CompareHelper::compare(['#INT#' => true, '#STR#' => true],[42 => true, 'foo' => true]), true);

        $this->assertSame(CompareHelper::compare(['#STR#' => true, '#INT#' => true],[42 => true, 'foo' => true]), false);

        $this->assertSame(CompareHelper::compare(['#INT#', '#STR#'], [42, 'foo']), true);

        $this->assertSame(CompareHelper::compare(['#STR#', '#INT#'], [42, 'foo']), false);

        $this->assertSame(CompareHelper::compare(['foo' => 7,'bar' => 42],['bar' => 42,'foo' => 7,]), true);

        $this->assertSame(CompareHelper::compare(['#INT#' => 7,'#STR#' => 42],[7 => 7,'foo' => 42]), true);

        $this->assertSame(CompareHelper::compare(['#INT#' => 7,'#STR#' => 42],['foo' => 42,7 => 7]), false);

        $this->assertTrue(CompareHelper::compare(
            json_decode('{"pages":"*"}'),
            json_decode('{"pages":{"1":"foo"}}')
        ));       

    }

}