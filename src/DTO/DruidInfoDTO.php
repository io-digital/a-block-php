<?php

namespace IODigital\ABlockPHP\DTO;

use IODigital\ABlockPHP\Functions\KeyHelpers;

class DruidInfoDTO
{
    public function __construct(
        private array $expectations,
        private ?string $druid = null,
        private ?int $participants = 2,
    ) {
        $this->druid = $druid ?? KeyHelpers::generateDRUID();
    }

    public function formatForAPI(): array
    {
        return [
            'participants' => $this->participants,
            'druid' => $this->druid,
            'expectations' => $this->expectations,
            'drs_tx_hash' => $this->expectations[0]['asset']['Item']['drs_tx_hash']
        ];
    }

    public function getDruid(): string
    {
        return $this->druid;
    }
}
