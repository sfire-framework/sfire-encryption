<?php
/**
 * sFire Framework (https://sfire.io)
 *
 * @link      https://github.com/sfire-framework/ for the canonical source repository
 * @copyright Copyright (c) 2014-2020 sFire Framework.
 * @license   http://sfire.io/license BSD 3-CLAUSE LICENSE
 */

declare(strict_types=1);

namespace sFire\Encryption;

use sFire\Encryption\Exception\InvalidArgumentException;


/**
 * Class EncryptionAbstract
 * @package sFire\DataControl
 */
abstract class EncryptionAbstract {


	/**
	 * Contains the encoding type
	 * @var string
	 */
	protected string $encoding = '8bit';


	/**
	 * Encrypting data
	 * @param string $data The data that needs to be encrypted
	 * @param string $key A secret key
	 * @return string
	 */
	abstract public function encrypt(string $data, string $key): string;


	/**
	 * Decrypting data
	 * @param string $data The data that needs to be encrypted
	 * @param string $key A secret key
	 * @return string
	 */
	abstract public function decrypt(string $data, string $key): ?string;


    /**
     * Set the encoding type
     * @param string $encoding The type of encoding
     * @return void
     * @throws InvalidArgumentException
     */
	public function setEncoding(string $encoding): void {

		if(false === in_array($encoding, mb_list_encodings())) {
			throw new InvalidArgumentException(sprintf('Encoding "%s" given to "%s" is not supported', $encoding, __METHOD__));
		}

		$this -> encoding = $encoding;
	}
}