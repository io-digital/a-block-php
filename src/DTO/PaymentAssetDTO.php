<?php

namespace IODigital\ABlockPHP\DTO;

class PaymentAssetDTO
{
    public const ASSET_TYPE_TOKEN = 'Token';

    public const ASSET_TYPE_RECEIPT = 'Receipt';

    public function __construct(
        private string $assetType,
        private int $amount,
        private ?string $drsTxHash = null,
        private ?array $metaData = null
    ) {
    }

    public function formatForAPI(): array
    {
        switch ($this->assetType) {
            case self::ASSET_TYPE_TOKEN:
                return [
                    $this->assetType => $this->amount,
                ];
            case self::ASSET_TYPE_RECEIPT:
                return [
                    $this->assetType => [
                        'amount' => $this->amount,
                        'drs_tx_hash' => $this->drsTxHash,
                        'metadata' => $this->metaData ? json_encode($this->metaData) : null,
                    ],
                ];
            default:
                return [];
        }
    }

    public function getAmount(): int
    {
        return $this->amount;
    }

    public function addToAmount(int $amount): void
    {
        $this->amount += $amount;
    }

    public function setAmount(int $amount): void
    {
        $this->amount = $amount;
    }

    public function getAssetType(): string
    {
        return $this->assetType;
    }

    public function getDrsTxHash(): string
    {
        return $this->drsTxHash;
    }
}
