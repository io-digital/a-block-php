<?php

namespace IODigital\ABlockPHP\DTO;

class DecryptedWalletDTO
{
    public function __construct(
        private string $masterPrivateKey,
        private string $chainCode,
    ) {
    }

    public function formatForAPI(): array
    {
        return [
            'masterPrivateKey' => $this->masterPrivateKey,
            'chainCode'        => $this->chainCode,
        ];
    }

    public function getMasterPrivateKey(): string
    {
        return $this->masterPrivateKey;
    }

    public function getChainCode(): string
    {
        return $this->chainCode;
    }
}
