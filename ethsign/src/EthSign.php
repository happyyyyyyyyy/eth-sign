<?php

namespace huigan;

use InvalidArgumentException;
use Elliptic\EC;
use Elliptic\EC\KeyPair;
use Elliptic\EC\Signature;
use kornrunner\Keccak;

class EthSign
{

    /**
     * SHA3_NULL_HASH
     *
     * @const string
     */
    const SHA3_NULL_HASH = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';

    /**
     * secp256k1
     *
     * @var \Elliptic\EC
     */
    protected $secp256k1;

    /**
     * construct
     *
     * @return void
     */
    public function __construct()
    {
        $this->secp256k1 = new EC('secp256k1');
    }

    /**
     * recoverPublicKey
     *
     * @param string $msg
     * @param string $sign
     * @param string $address
     * @return bool
     */
    public function verifySign(string $msg, string $sign, string $address): bool
    {
        if (strlen($sign) !== 132) {
            throw new InvalidArgumentException('Invalid signature length.');
        }
        $r = substr($sign, 2, 64);
        $s = substr($sign, 66, 64);

        if (strlen($r) !== 64 || strlen($s) !== 64) {
            throw new InvalidArgumentException('Invalid signature length.');
        }
        $hash = $this->hashPersonalMessage($msg);
//        $hash = Keccak::hash(sprintf("\x19Ethereum Signed Message:\n%s%s", strlen($msg), $msg), 256);
        $q = substr($sign, 130, 2);
        $w = hex2bin($q);
        $recid = ord($w) - 27;

        $publicKey = $this->secp256k1->recoverPubKey($hash, [
            'r' => $r,
            's' => $s
        ], $recid);
        $publicKey = $publicKey->encode('hex');
        $publicAddress = $this->publicKeyToAddress($publicKey);
        $address = strtolower($address);
        $publicAddress = strtolower($publicAddress);
        return $publicAddress == $address;
    }

    /**
     * recoverPublicKey
     *
     * @param string $hash
     * @param string $r
     * @param string $s
     * @param int $v
     * @return string
     */
    public function recoverPublicKey(string $hash, string $r, string $s, int $v)
    {
        if ($this->isHex($hash) === false) {
            throw new InvalidArgumentException('Invalid hash format.');
        }
        $hash = $this->stripZero($hash);

        if ($this->isHex($r) === false || $this->isHex($s) === false) {
            throw new InvalidArgumentException('Invalid signature format.');
        }
        $r = $this->stripZero($r);
        $s = $this->stripZero($s);

        if (strlen($r) !== 64 || strlen($s) !== 64) {
            throw new InvalidArgumentException('Invalid signature length.');
        }
        $publicKey = $this->secp256k1->recoverPubKey($hash, [
            'r' => $r,
            's' => $s
        ], $v);
        $publicKey = $publicKey->encode('hex');

        return '0x' . $publicKey;
    }

    /**
     * sha3
     * keccak256
     *
     * @param string $value
     * @return string
     */
    public function sha3(string $value)
    {
        $hash = Keccak::hash($value, 256);

        if ($hash === $this::SHA3_NULL_HASH) {
            return null;
        }
        return $hash;
    }

    /**
     * isZeroPrefixed
     *
     * @param string $value
     * @return bool
     */
    public function isZeroPrefixed(string $value)
    {
        return (strpos($value, '0x') === 0);
    }

    /**
     * stripZero
     *
     * @param string $value
     * @return string
     */
    public function stripZero(string $value)
    {
        if ($this->isZeroPrefixed($value)) {
            $count = 1;
            return str_replace('0x', '', $value, $count);
        }
        return $value;
    }

    /**
     * isHex
     *
     * @param string $value
     * @return bool
     */
    public function isHex(string $value)
    {
        return (is_string($value) && preg_match('/^(0x)?[a-fA-F0-9]+$/', $value) === 1);
    }

    /**
     * publicKeyToAddress
     *
     * @param string $publicKey
     * @return string
     */
    public function publicKeyToAddress(string $publicKey)
    {
        if ($this->isHex($publicKey) === false) {
            throw new InvalidArgumentException('Invalid public key format.');
        }
        $publicKey = $this->stripZero($publicKey);

        if (strlen($publicKey) !== 130) {
            throw new InvalidArgumentException('Invalid public key length.');
        }
        return '0x' . substr($this->sha3(substr(hex2bin($publicKey), 1)), 24);
    }

    /**
     * privateKeyToPublicKey
     *
     * @param string $privateKey
     * @return string
     */
    public function privateKeyToPublicKey(string $privateKey)
    {
        if ($this->isHex($privateKey) === false) {
            throw new InvalidArgumentException('Invalid private key format.');
        }
        $privateKey = $this->stripZero($privateKey);

        if (strlen($privateKey) !== 64) {
            throw new InvalidArgumentException('Invalid private key length.');
        }
        $privateKey = $this->secp256k1->keyFromPrivate($privateKey, 'hex');
        $publicKey = $privateKey->getPublic(false, 'hex');

        return '0x' . $publicKey;
    }

    /**
     * hasPersonalMessage
     *
     * @param string $message
     * @return string
     */
    public function hashPersonalMessage(string $message)
    {
        $prefix = sprintf("\x19Ethereum Signed Message:\n%d", strlen($message));
        return $this->sha3($prefix . $message);
    }

}
