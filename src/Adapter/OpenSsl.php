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

use Exception;
use sFire\Encryption\EncryptionAbstract;
use sFire\Encryption\Exception\BadFunctionCallException;


/**
 * Class OpenSsl
 * @package sFire\DataControl
 */
class OpenSsl extends EncryptionAbstract {


    /**
     * Contains the encryption cipher
     * @var string
     */
    private string $cipher = 'AES-256-CBC';


    /**
     * Contains the algorithm
     * @var string
     */
    private string $algorithm = 'SHA256';


	/**
	 * Constructor
     * @throws BadFunctionCallException
	 */
	public function __construct() {
		
        if(false === extension_loaded('openssl')) {
			throw new BadFunctionCallException('PHP extension openssl is not installed or enabled');
		}
	}


    /**
     * Encrypting data
     * @param string $data The data that needs to be encrypted
     * @param string $key A secret key
     * @return string
     * @throws Exception
     */
	public function encrypt($data, $key): string {

        $iv 		= random_bytes(16);
        $cipherText = openssl_encrypt($data, $this -> cipher, mb_substr($key, 0, 32, $this -> encoding), OPENSSL_RAW_DATA, $iv);
        $hmac 		= hash_hmac($this -> algorithm, $iv . $cipherText, mb_substr($key, 32, null, $this -> encoding), true);

        return $hmac . $iv . $cipherText;
    }


	/**
	 * Decrypting data
	 * @param string $data The data that needs to be encrypted
	 * @param string $key A secret key
	 * @return string
	 */
	public function decrypt($data, $key): ?string {

        $hmac       = mb_substr($data, 0, 32, $this -> encoding);
        $iv         = mb_substr($data, 32, 16, $this -> encoding);
        $cipherText = mb_substr($data, 48, null, $this -> encoding);
        $hmacNew 	= hash_hmac($this -> algorithm, $iv . $cipherText, mb_substr($key, 32, null, $this -> encoding), true);

        if(true === hash_equals($hmac, $hmacNew)) {
            return openssl_decrypt($cipherText, $this -> cipher, mb_substr($key, 0, 32, $this -> encoding), OPENSSL_RAW_DATA, $iv);
        }

        return null;
    }
}