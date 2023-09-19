<?php

namespace IODigital\ABlockPHP\Functions;

use FurqanSiddiqui\BIP39\BIP39;
use IODigital\ABlockPHP\DTO\TransactionDTO;

class KeyHelpers
{
    /**
     * Returns array with seed phrase, nonce, save
     */
    public static function initialiseFromPassphrase(string $passPhraseHash): array
    {
        $generatedSeed = self::generateSeed();
        $newMasterKey = self::generateMasterKey($generatedSeed, $passPhraseHash);

        $masterKeyEncryptedAndNonce = self::encryptMasterKey($newMasterKey, $passPhraseHash);
        $masterKeyEncryptedBase64 = $masterKeyEncryptedAndNonce['master_key_encrypted'];
        $nonceHex = $masterKeyEncryptedAndNonce['nonce'];

        return [
            'seedPhrase'         => $generatedSeed,
            'masterKeyEncrypted' => $masterKeyEncryptedBase64,
            'nonce'              => $nonceHex,
        ];
    }

    private static function generateMasterKey(string $seed, string $passPhraseHash): string
    {
        $hash = hash_pbkdf2('sha512', $seed, $passPhraseHash, 2048, 64);

        return substr(hash_hmac('sha512', $hash, 'Bitcoin seed'), 0, 64);
    }

    private static function getNonce(): string
    {
        return random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    }

    private static function encryptMasterKey(string $masterKey, string $passPhraseHash): array
    {
        $nonce = self::getNonce();

        $ciphertext = sodium_crypto_secretbox(
            $masterKey,
            $nonce,
            $passPhraseHash
        );

        return [
            'master_key_encrypted' => sodium_bin2base64($ciphertext, SODIUM_BASE64_VARIANT_ORIGINAL),
            'nonce'                => sodium_bin2hex($nonce),
        ];
    }

    public static function getNewKeypair(string $masterPrivateKey, string $passPhrase)
    {
        $keypairRaw = sodium_crypto_sign_seed_keypair($masterPrivateKey);
        $publicKey = sodium_crypto_sign_publickey($keypairRaw);
        $privateKey = sodium_crypto_sign_secretkey($keypairRaw);
        $nonce = self::getNonce();

        $save = sodium_crypto_secretbox($publicKey.$privateKey, $nonce, $passPhrase);

        return [
            'address' => self::constructAddress($publicKey),
            'nonce'   => sodium_bin2hex($nonce),
            'save'    => sodium_bin2base64($save, SODIUM_BASE64_VARIANT_ORIGINAL),
        ];
    }

    public static function decryptKeypair(
        string $encryptedKey,
        string $nonce,
        string $passPhrase
    ): array {
        $encryptedKeyPair = sodium_base642bin($encryptedKey, SODIUM_BASE64_VARIANT_ORIGINAL);
        $nonce = sodium_hex2bin($nonce);

        $decrypted = sodium_crypto_secretbox_open($encryptedKeyPair, $nonce, $passPhrase);

        return [
            'publicKey' => substr($decrypted, 0, SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES),
            'secretKey' => substr($decrypted, SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, SODIUM_CRYPTO_SIGN_SECRETKEYBYTES),
        ];
    }

    public static function encryptTransaction(TransactionDTO $transaction, string $passPhrase): array
    {
        $nonce = self::getNonce();
        $encryptedStr = sodium_crypto_secretbox(json_encode($transaction->formatForAPI()), $nonce, $passPhrase);

        return [
            'druid' => $transaction->getDruid(),
            'nonce' => sodium_bin2hex($nonce),
            'save'  => sodium_bin2base64($encryptedStr, SODIUM_BASE64_VARIANT_ORIGINAL),
        ];
    }

    public static function getPassPhraseHash(string $passPhrase): string
    {
        return substr(hash('sha3-256', $passPhrase), 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    }

    private static function generateSeed(int $length = 12): string
    {
        return implode(' ', BIP39::Generate($length)->words);
    }

    public static function createSignature(string $message, string $secretKey): string
    {
        return sodium_bin2hex(sodium_crypto_sign_detached($message, $secretKey));
    }

    public static function generateDRUID(): string
    {
        return 'DRUID0x'.self::getPassPhraseHash(sodium_bin2hex(random_bytes(32)));
    }

    // if there are issues, this is a place to check
    public static function constructTransactionInputAddress(array $inputs): string
    {
        $signableTxIns = implode('-', array_map(function ($input) {
            $scriptSignature = $input['script_signature']['Pay2PkH'];
            $previousOutPoint = $input['previous_out'];

            $scriptStack = self::getPayToPublicKeyHashScript(
                checkData: $scriptSignature['signable_data'],
                signatureData: $scriptSignature['signature'],
                publicKeyData: $scriptSignature['public_key'],
                addressVersion: $scriptSignature['address_version']
            );

            $formattedScriptString = implode('-', array_map(fn ($item) => "{$item['type']}:{$item['value']}", $scriptStack));
            $previousOutpointStr = $previousOutPoint ? self::getFormattedOutPointString($previousOutPoint) : 'null';

            return "$previousOutpointStr-$formattedScriptString";
        }, $inputs));

        return self::constructAddress($signableTxIns);
    }

    private static function constructAddress(string $address): string
    {
        return hash('sha3-256', $address);
    }

    public static function getFormattedOutPointString(array $outpoint): string
    {
        return "{$outpoint['n']}-{$outpoint['t_hash']}";
    }

    private static function getPayToPublicKeyHashScript(
        string $checkData,
        string $signatureData,
        string $publicKeyData,
        int $addressVersion = null
    ): array {
        return  [
            [
                'type'  => 'Bytes',
                'value' => $checkData,
            ],
            [
                'type'  => 'Signature',
                'value' => $signatureData,
            ],
            [
                'type'  => 'PubKey',
                'value' => $publicKeyData,
            ],
            [
                'type'  => 'Op',
                'value' => 'OP_DUP',
            ],
            [
                'type'  => 'Op',
                'value' => 'OP_HASH256',
            ],
            [
                'type'  => 'PubKeyHash',
                'value' => self::constructAddress($publicKeyData),
            ],
            [
                'type'  => 'Op',
                'value' => 'OP_EQUALVERIFY',
            ],
            [
                'type'  => 'Op',
                'value' => 'OP_CHECKSIG',
            ],
        ];
    }
}
