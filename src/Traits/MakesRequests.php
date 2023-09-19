<?php

declare(strict_types=1);

namespace IODigital\ABlockPHP\Traits;

use Exception;
//use Illuminate\Support\Facades\Http;
use GuzzleHttp\Client;

trait MakesRequests
{
    private Client $http;

    final public const POST = 'post';

    final public const GET = 'get';

    final public const SUCCESS = 'Success';

    final public const ERROR = 'Error';

    final public const ENDPOINT_FETCH_BALANCE = 'fetch_balance';

    final public const ENDPOINT_CREATE_RECEIPT_ASSET = 'create_receipt_asset';

    final public const ENDPOINT_CREATE_TRANSACTIONS = 'create_transactions';

    final public const ENDPOINT_SET_DATA = 'set_data';

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
    ];

    public function __construct()
    {
        $this->http = new Client();
    }

    public function makeRequest(
        string $apiRoute,
        array $payload
    ): array {
        if (array_key_exists($apiRoute, self::COMPUTE_ENDPOINTS)) {
            return $this->makeComputeRequest(
                apiRoute: $apiRoute,
                requestMethod: self::COMPUTE_ENDPOINTS[$apiRoute]['requestMethod'],
                difficulty: self::COMPUTE_ENDPOINTS[$apiRoute]['difficulty'],
                payload: $payload
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
    ): array {
        $requestId = substr(sodium_bin2hex(random_bytes(32)), 0, 32);
        $nonce = $this->getNonce($requestId, $difficulty);

        try {
            $result = Http::withoutVerifying()
                ->acceptJson()
                ->withHeaders([
                    'x-request-id' => $requestId,
                    'x-nonce'      => $nonce,
                ])
                ->$requestMethod(
                    $this->computeHost.'/'.$apiRoute,
                    $payload
                )->json();

            if ($result['status'] === self::ERROR) {
                throw new Exception($result['reason']);
            }

            return $result['content'];
        } catch (Exception $e) {
            $errorStr = "Error for API route $apiRoute: ".$e->getMessage();
            \Log::error($errorStr);
            throw new Exception($errorStr);
        }
    }

    public function makeIntercomRequest(
        string $apiRoute,
        string $requestMethod,
        array $payload,
    ): string {
        try {
            $result = Http::withoutVerifying()
                ->acceptJson()
                ->$requestMethod(
                    $this->getHostFromEndpoint($apiRoute).'/'.$apiRoute,
                    $payload
                );

            dd($result->body());

            if (is_array($result)) {
                if ($result['status'] === self::ERROR) {
                    throw new Exception($result['reason']);
                }

                return $result['content'];
            }

            return $result;
        } catch (Exception $e) {
            $errorStr = "Error for API route $apiRoute: ".$e->getMessage();
            \Log::error($errorStr);
            throw new Exception($errorStr);
        }
    }

    public function makeProxyRequest(string $command, array $payload = []): array
    {
        try {
            return Http::acceptJson()
                ->post(
                    config('zenotta.proxy_url')."/$command",
                    $payload
                )->json();
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

    private function getHostFromEndpoint(string $endpoint): string
    {
        switch ($endpoint) {
            case self::ENDPOINT_SET_DATA:
                return 'http://zen-intercom.zenotta.com:3002';//$this->intercomHost;
            case self::ENDPOINT_FETCH_BALANCE:
            case self::ENDPOINT_CREATE_RECEIPT_ASSET:
            case self::ENDPOINT_CREATE_TRANSACTIONS:
            default:
                return $this->computeHost;
        }
    }
}
