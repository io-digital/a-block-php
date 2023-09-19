<?php

namespace IODigital\ABlockPHP\DTO;

use IODigital\ABlockPHP\Functions\KeyHelpers;

class DruidInfoDTO
{
    private string $druid;

    public function __construct(
        private array $expectations,
        private ?int $participants = 2
    ) {
        $this->druid = KeyHelpers::generateDRUID();
    }

    public function formatForAPI(): array
    {
        return [
            'participants' => $this->participants,
            'druid' => $this->druid,
            'expectations' => $this->expectations,
        ];
    }

    public function getDruid(): string
    {
        return $this->druid;
    }
}
