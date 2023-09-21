<?php

namespace IODigital\ABlockPHP\DTO;

class PaymentExpectationDTO
{
    public function __construct(
        private string $to,
        private PaymentAssetDTO $asset,
        private ?string $from = '',
    ) {}

    public function formatForAPI(): array
    {
        return [
            'from' => $this->from,
            'to' => $this->to,
            'asset' => $this->asset->formatForAPI(),
        ];
    }

    public function setFrom(string $address): void
    {
        $this->from = $address;
    }

    public function getAsset(): PaymentAssetDTO
    {
        return $this->asset;
    }

    public function getToAddress(): string
    {
        return $this->to;
    }
}
