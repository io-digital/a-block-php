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
            'signature' => KeyHelpers::createSignature(sodium_hex2bin($addressField), $keyPairForField['secretKey']),
            'publicKey' => sodium_bin2hex($keyPairForField['publicKey']),
            'value'     => $value,
        ];
    }
}
