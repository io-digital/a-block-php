<?php

namespace IODigital\ABlockPHP\DTO;

class PaymentExpectationDTO
{
    public function __construct(
        private string $to,
        private PaymentAssetDTO $asset,
        private ?string $from = '',
    ) {
    }

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
}
