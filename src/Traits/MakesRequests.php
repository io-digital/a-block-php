<?php

declare(strict_types=1);

namespace IODigital\ABlockPHP\Traits;

use Exception;
use Illuminate\Http\Response;

trait MakesRequests
{
    final public const POST = 'post';

    final public const GET = 'get';

    final public const SUCCESS = 'Success';

    final public const ERROR = 'Error';

    final public const ENDPOINT_FETCH_BALANCE = 'fetch_balance';

    final public const ENDPOINT_CREATE_RECEIPT_ASSET = 'create_receipt_asset';

    final public const ENDPOINT_CREATE_TRANSACTIONS = 'create_transactions';

    final public const ENDPOINT_SET_DATA = 'set_data';

    final public const ENDPOINT_GET_DATA = 'get_data';

    final public const ENDPOINT_DELETE_DATA = 'del_data';

    final public const COMPUTE_ENDPOINTS = [
        self::ENDPOINT_FETCH_BALANCE => [
            'difficulty'    => 0,
            'requestMethod' => self::POST,
        ],
        self::ENDPOINT_CREATE_RECEIPT_ASSET => [
            'difficulty'    => 0,
            'requestMethod' => self::POST,
        ],
        self::ENDPOINT_CREATE_TRANSACTIONS => [
            'difficulty'    => 4,
            'requestMethod' => self::POST,
        ],
    ];

    final public const INTERCOM_ENDPOINTS = [
        self::ENDPOINT_SET_DATA => [
            'requestMethod' => self::POST,
        ],
        self::ENDPOINT_GET_DATA => [
            'requestMethod' => self::POST,
        ],
        self::ENDPOINT_DELETE_DATA => [
            'requestMethod' => self::POST,
        ]
    ];

    public function makeRequest(
        string $apiRoute,
        array $payload,
        ?string $host = null
    ): array {
        if (array_key_exists($apiRoute, self::COMPUTE_ENDPOINTS)) {
            return $this->makeComputeRequest(
                apiRoute: $apiRoute,
                requestMethod: self::COMPUTE_ENDPOINTS[$apiRoute]['requestMethod'],
                difficulty: self::COMPUTE_ENDPOINTS[$apiRoute]['difficulty'],
                payload: $payload,
                host: $host
            );
        } elseif (array_key_exists($apiRoute, self::INTERCOM_ENDPOINTS)) {
            return $this->makeIntercomRequest(
                apiRoute: $apiRoute,
                requestMethod: self::INTERCOM_ENDPOINTS[$apiRoute]['requestMethod'],
                payload: $payload
            );
        }
    }

    private function makeComputeRequest(
        string $apiRoute,
        string $requestMethod,
        array $payload,
        int $difficulty = 4,
        ?string $host = null
    ): array {
        $requestId = substr(sodium_bin2hex(random_bytes(32)), 0, 32);
        $nonce = $this->getNonce($requestId, $difficulty);

        $finalHost = $host ?? $this->computeHost;

        try {
            $response = $this->http->request(
                $requestMethod,
                $finalHost . '/' . $apiRoute,
                [
                    'headers' => [
                        'x-request-id' => $requestId,
                        'x-nonce'      => $nonce,
                    ],
                    'json' => $payload
                ]
            );

            if($response->getStatusCode() === Response::HTTP_OK) {
                $jsonResponse = json_decode($response->getBody()->getContents(), true);

                if ($jsonResponse['status'] === self::ERROR) {
                    throw new Exception($result['reason']);
                }

                return $jsonResponse['content'];
            }

            throw new Exception('An unexpected API error has occurred');
        } catch (Exception $e) {
            throw $e;
        }
    }

    public function makeIntercomRequest(
        string $apiRoute,
        string $requestMethod,
        array $payload,
    ): array {
        try {
            $response = $this->http->request(
                $requestMethod,
                $this->intercomHost . '/' . $apiRoute,
                [
                    'json' => $payload
                ]
            );

            if ($response->getStatusCode() === Response::HTTP_OK) {
                $text = $response->getBody()->getContents();
                $contents = json_decode($text, true);
                return $contents ?? [$text];
            }

            throw new Exception('An error has occurred');
        } catch (Exception $e) {
            throw new Exception($e->getMessage());
        }
    }

    // TEMP for dev
    public function makeProxyRequest(string $command, array $payload = []): array
    {
        try {
            $response = $this->http->request(
                self::POST,
                config('a-block.proxy_url') . "/$command",
                ['json' => $payload]
            );

            return json_decode($response->getBody()->getContents(), true);
        } catch (ConnectionException $e) {
            dd($e->getMessage());
        }
    }

    private function getNonce(string $id, int $target): int
    {
        $nonce = 0;
        $hash = hash('sha3-256', "$nonce-$id");
        $testStr = str_repeat('0', $target);

        while (substr($hash, 0, $target) !== $testStr) {
            $nonce++;
            $hash = hash('sha3-256', "$nonce-$id");
        }

        return $nonce;
    }
}
