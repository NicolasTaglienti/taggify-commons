<?php

namespace Taggify\Common\Tests\Security;

use Taggify\Common\Security\McryptEncryptor;

class McryptEncryptorTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->encryptor = McryptEncryptor::create();
    }

    public function testEncrypt()
    {
        $expected = 'uD4cAhRPG5s.';
        $acutal = $this->encryptor->encrypt('test');

        $this->assertEquals($expected, $acutal);
    }

    public function testEncrypt2()
    {
        $expected = 'ICPiJoUFELk.';
        $acutal = $this->encryptor->encrypt('12|0.2');

        $this->assertEquals($expected, $acutal);
    }

    public function testDecrypt()
    {
        $expected = 'test';
        $acutal = $this->encryptor->decrypt('uD4cAhRPG5s.');

        $this->assertEquals($expected, $acutal);
    }

    public function testDecrypt2()
    {
        $expected = '12|0.2';
        $acutal = $this->encryptor->decrypt('ICPiJoUFELk.');

        $this->assertEquals($expected, $acutal);
    }

    public function testSecureTimestamp()
    {
        $ts = $this->encryptor->generateSecureTimestamp();

        $this->assertEquals(['ts', 'tc'], array_keys($ts));
    }
}