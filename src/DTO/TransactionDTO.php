<?php

namespace IODigital\ABlockPHP\DTO;

class TransactionDTO
{
    public function __construct(
        private array $inputs,
        private array $outputs,
        private ?DruidInfoDTO $druidInfo,
        private ?int $version = 2
    ) {
    }

    public function formatForAPI(): array
    {
        return [
            'version' => $this->version,
            'inputs' => $this->inputs,
            'outputs' => $this->outputs,
            'druid_info' => $this->druidInfo ? $this->druidInfo->formatForAPI() : null,
        ];
    }

    public function getDruid(): ?string
    {
        return $this->druidInfo ? $this->druidInfo->getDruid() : null;
    }

    public function getInputs(): array
    {
        return $this->inputs;
    }
}
