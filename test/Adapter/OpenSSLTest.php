<?php
/**
 * sFire Framework (https://sfire.io)
 *
 * @link      https://github.com/sfire-framework/ for the canonical source repository
 * @copyright Copyright (c) 2014-2020 sFire Framework.
 * @license   http://sfire.io/license BSD 3-CLAUSE LICENSE
 */
 
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use sFire\DataControl\Encryption\Adapter\OpenSSL;

final class OpenSSLTest extends TestCase {


    /**
     * Contains instance of OpenSSL
     * @var OpenSSL
     */
    private OpenSSL $openssl;


    /**
     * Contains the key that is used for encryption
     * @var string
     */
    private string $key = 'key';
    

    /**
     * Setup. Created new OpenSSL instance
     * @return void
     */
    protected function setUp(): void {
        $this -> openssl = new OpenSSL();
    }


    /**
     * Test if data can be encrypted and decrypted
     * @return void
     */
    public function testIfDataCanBeEncryptedAndDecrypted(): void {

        $encrypted = $this -> openssl -> encrypt('data', $this -> key);

        $this -> assertIsString($encrypted);
        $this -> assertTrue(64 === strlen($encrypted));
        $this -> assertEquals('data', $this -> openssl -> decrypt($encrypted, $this -> key));
    }


    /**
     * Test setting non existing/not supported encoding
     * @return void
     */
    public function testSettingNonExistingEncoding(): void {
        
        $this -> expectException(ErrorException :: class);
        $this -> openssl -> setEncoding('non-existing');
    }


    /**
     * Test if data can be encrypted and decrypted
     * @return void
     */
    public function testSettingExistingEncoding(): void {

        $this -> openssl -> setEncoding('7bit');

        $encrypted = $this -> openssl -> encrypt('data', $this -> key);

        $this -> assertIsString($encrypted);
        $this -> assertTrue(64 === strlen($encrypted));
        $this -> assertEquals('data', $this -> openssl -> decrypt($encrypted, $this -> key));
    }
}