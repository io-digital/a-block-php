<?php

namespace IODigital\ABlockPHP\Functions;

class IntercomUtils
{
    /**
     * value -> senderExpectation -> to === $addressField
     * value -> receiverExpectation -> to === $addressKey
     * value -> receiverExpectation -> from === 64-char hash
     */

    public static function generateIntercomSetBody(
        string $addressKey, // payment address (Bob)
        string $addressField, // sending address (Alice)
        array $keyPairForField, // this is the decrypted sending address keypair (Alice)
        $value
    ): array {
        return [
            'key'       => $addressKey,
            'field'     => $addressField,
            'signature' => KeyHelpers::createSignature(
                message: sodium_hex2bin($addressField),
                secretKey: $keyPairForField['secretKey']
            ),
            'publicKey' => sodium_bin2hex($keyPairForField['publicKey']),
            'value'     => $value,
        ];
    }

    public static function generateIntercomGetBody(
        string $addressKey,
        array $keyPairForField
    ): array {
        return [
            'key'       => $addressKey,
            'publicKey' => sodium_bin2hex($keyPairForField['publicKey']),
            'signature' => KeyHelpers::createSignature(
                message: sodium_hex2bin($addressKey),
                secretKey: $keyPairForField['secretKey']
            ),
        ];
    }

    public static function isValidIntercomData(array $item): bool
    {
        return !array_diff_key(array_flip(['druid', 'senderExpectation', 'receiverExpectation', 'status', 'computeHost']), $item);
    }
}
