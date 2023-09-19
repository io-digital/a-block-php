<?php

namespace IODigital\ABlockPHP\DTO;

class EncryptedWalletDTO
{
    public function __construct(
        private string $masterKeyEncrypted,
        private string $nonce,
        private ?string $seedPhrase = null
    ) {
    }

    public function formatForAPI(): array
    {
        return [
            'masterKeyEncrypted' => $this->masterKeyEncrypted,
            'nonce'              => $this->nonce,
        ];
    }

    public function getSeedPhrase(): string|null
    {
        return $this->seedPhrase;
    }

    public function getMasterKeyEncrypted(): string
    {
        return $this->masterKeyEncrypted;
    }

    public function getNonce(): string
    {
        return $this->nonce;
    }
}
