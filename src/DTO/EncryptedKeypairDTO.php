<?php

namespace IODigital\ABlockPHP\DTO;

class EncryptedKeypairDTO
{
    public function __construct(
        private string $address,
        private string $nonce,
        private string $content
    ) {}

    public function formatForAPI(): array
    {
        return [
            // 'masterKeyEncrypted' => $this->masterKeyEncrypted,
            // 'nonce'              => $this->nonce,
        ];
    }

    public function getAddress(): string
    {
        return $this->address;
    }

    public function getContent(): string
    {
        return $this->content;
    }

    public function getNonce(): string
    {
        return $this->nonce;
    }
}
