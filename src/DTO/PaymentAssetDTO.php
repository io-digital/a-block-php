<?php

namespace IODigital\ABlockPHP\DTO;

class PaymentAssetDTO
{
    public const ASSET_TYPE_TOKEN = 'Token';

    public const ASSET_TYPE_ITEM = 'Item';

    public function __construct(
        private int $amount,
        private ?string $drsTxHash = null,
        private ?array $metaData = null
    ) {}

    public function formatForAPI(): array
    {
        return !!$this->drsTxHash ? [
            self::ASSET_TYPE_ITEM => [
                'amount' => $this->amount,
                'drs_tx_hash' => $this->drsTxHash,
                'metadata' => $this->metaData ? json_encode($this->metaData) : null,
            ],
        ] : [
            self::ASSET_TYPE_TOKEN => $this->amount
        ];
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
        return !!$this->drsTxHash ? self::ASSET_TYPE_ITEM : self::ASSET_TYPE_TOKEN;
    }

    public function getDrsTxHash(): string
    {
        return $this->drsTxHash;
    }
}
