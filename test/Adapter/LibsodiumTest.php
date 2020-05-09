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
use sFire\DataControl\Encryption\Adapter\Libsodium;

final class LibsodiumTest extends TestCase {


    /**
     * Contains instance of Libsodium
     * @var Libsodium
     */
    private Libsodium $libsodium;


    /**
     * Contains the key that is used for encryption
     * @var string
     */
    private string $key = '1234567891234526789123456789123456789';
    

    /**
     * Setup. Created new Libsodium instance
     * @return void
     */
    protected function setUp(): void {
        $this -> libsodium = new Libsodium();
    }


    /**
     * Test if data can be encrypted and decrypted
     * @return void
     */
    public function testIfDatacanbeEncryptedAndDecrypted(): void {

        $encrypted = $this -> libsodium -> encrypt('data', $this -> key);
        
        $this -> assertIsString($encrypted);
        $this -> assertEquals('data', $this -> libsodium -> decrypt($encrypted, $this -> key));
    }


    /**
     * Test setting non existing/not supported encoding
     * @return void
     */
    public function testSettingNonExistingEncoding(): void {
        
        $this -> expectException(ErrorException :: class);
        $this -> libsodium -> setEncoding('non-existing');
    }


    /**
     * Test setting a invalid key
     * @return void
     */
    public function testSettingAInvalidKey(): void {
        
        $this -> expectException(sFire\DataControl\Exception\InvalidArgumentException :: class);
        $this -> libsodium -> encrypt('data', 'key-to-short');
    }


    /**
     * Test if data can be encrypted and decrypted
     * @return void
     */
    public function testSettingExistingEncoding(): void {

        $this -> libsodium -> setEncoding('7bit');

        $encrypted = $this -> libsodium -> encrypt('data', $this -> key);

        $this -> assertIsString($encrypted);
        $this -> assertEquals('data', $this -> libsodium -> decrypt($encrypted, $this -> key));
    }
}