<?php
/**
 * sFire Framework (https://sfire.io)
 *
 * @link      https://github.com/sfire-framework/ for the canonical source repository
 * @copyright Copyright (c) 2014-2020 sFire Framework.
 * @license   http://sfire.io/license BSD 3-CLAUSE LICENSE
 */

declare(strict_types=1);

namespace sFire\Encryption\Adapter;

use sFire\Encryption\EncryptionAbstract;
use sFire\Encryption\Exception\BadFunctionCallException;
use sFire\Encryption\Exception\InvalidArgumentException;


/**
 * Class Libsodium
 * @package sFire\DataControl
 */
class Libsodium extends EncryptionAbstract {


    /**
     * Constructor
     * @throws BadFunctionCallException
     */
	public function __construct() {
		
		if(false === extension_loaded('sodium')) {
			throw new BadFunctionCallException('PHP extension sodium is not installed or enabled');
		}
	}


    /**
     * Encrypting data
     * @param string $data The data that needs to be encrypted
     * @param string $key A secret key
     * @return string
     * @throws InvalidArgumentException
     */
	public function encrypt(string $data, string $key): string {

		if(strlen($key) < SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
			throw new InvalidArgumentException(sprintf('Argument 2 passed to %s should be at least %s characters long', __METHOD__, SODIUM_CRYPTO_SECRETBOX_KEYBYTES));
		}

		$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
		$key   = substr($key, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

		return $nonce . sodium_crypto_secretbox($data, $nonce, $key);
	}


    /**
     * Decrypting data
     * @param string $data The data that needs to be encrypted
     * @param string $key A secret key
     * @return string
     * @throws InvalidArgumentException
     */
	public function decrypt(string $data, string $key): ?string {

		if(strlen($key) < SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
			throw new InvalidArgumentException(sprintf('Argument 2 passed to %s should be at least %s characters long', __METHOD__, SODIUM_CRYPTO_SECRETBOX_KEYBYTES));
		}

		$nonce      = mb_substr($data, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, $this -> encoding);
		$cipherText = mb_substr($data, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, null, $this -> encoding);
		$key        = substr($key, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

		return sodium_crypto_secretbox_open($cipherText, $nonce, $key);
	}
}