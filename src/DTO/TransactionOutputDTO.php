<?php

namespace IODigital\ABlockPHP\DTO;

class TransactionOutputDTO
{
    public function __construct(
        private string $scriptPublicKey,
        private PaymentAssetDTO $paymentAsset,
        private ?string $drsBlockHash = null,
        private ?int $locktime = 0,
    ) {
    }

    public function formatForAPI(): array
    {
        return [
            'drs_block_hash' => $this->drsBlockHash,
            'locktime' => $this->locktime,
            'script_public_key' => $this->scriptPublicKey,
            'value' => $this->paymentAsset->formatForAPI(),
        ];
    }
}
