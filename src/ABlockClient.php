<?php

namespace IODigital\ABlockPHP;

use IODigital\ABlockPHP\DTO\DecryptedWalletDTO;
use IODigital\ABlockPHP\DTO\EncryptedWalletDTO;
use IODigital\ABlockPHP\DTO\PaymentAssetDTO;
use IODigital\ABlockPHP\DTO\TransactionDTO;
use IODigital\ABlockPHP\DTO\TransactionOutputDTO;
use IODigital\ABlockPHP\Functions\KeyHelpers;
use IODigital\ABlockPHP\Traits\MakesRequests;
use IODigital\ABlockPHP\Exceptions\PassPhraseNotSetException;
use IODigital\ABlockPHP\Exceptions\ActiveWalletNotSetException;
use GuzzleHttp\Client as HttpClient;

class ABlockClient
{
    use MakesRequests;

    private ?string $passPhraseHash = null;

    private ?string $seedPhrase = null;

    //private ?EncryptedWalletDTO $wallet = null;

    private ?DecryptedWalletDTO $walletDecrypted = null;

    private HttpClient $http;

    public function __construct(
        private string $computeHost,
        private string $intercomHost,
    ) {
        $this->http = new HttpClient();
    }

    public function getComputeHost(): string
    {
        return $this->computeHost;
    }

    public function getIntercomHost(): string
    {
        return $this->intercomHost;
    }

    // public function __destruct()
    // {
    //     sodium_memzero($this->passPhraseHash);
    //     sodium_memzero($this->seedPhrase);
    //     sodium_memzero($this->masterKeyEncrypted);
    // }

    public function setPassPhrase(string $passPhrase): void
    {
        $this->passPhraseHash = KeyHelpers::getPassPhraseHash($passPhrase);
    }

    public function getPassPhrase(): string
    {
        if(!$this->passPhraseHash) {
            throw new PassPhraseNotSetException();
        }

        return $this->passPhraseHash;
    }

    public function createWallet(): EncryptedWalletDTO
    {
        $walletArr = KeyHelpers::initialiseFromPassphrase($this->getPassPhrase());

        $walletDTO = new EncryptedWalletDTO(
            masterKeyEncrypted: $walletArr['masterKeyEncrypted'],
            nonce: $walletArr['nonce'],
            seedPhrase: $walletArr['seedPhrase']
        );

        return $walletDTO;
    }

    public function openWallet(EncryptedWalletDTO $wallet): bool
    {
        try {
            $masterKeyDecrypted = $this->decryptKeypair(
                encryptedKey: $wallet->getMasterKeyEncrypted(),
                nonce: $wallet->getNonce()
            );

            $this->walletDecrypted = new DecryptedWalletDTO(
                masterPrivateKey: $masterKeyDecrypted['publicKey'],
                chainCode: $masterKeyDecrypted['secretKey']
            );

            //$this->wallet = $wallet;

            return true;
        } catch (\Exception $e) {
            throw $e;
        }
    }

    // public function setWallet(EncryptedWalletDTO $wallet): void
    // {
    //     $this->wallet = $wallet;
    //     $this->openWallet($this->wallet);
    // }

    public function fetchBalance(array $addressList = [])
    {
        return $this->makeRequest(
            apiRoute: self::ENDPOINT_FETCH_BALANCE,
            payload: [
                'address_list' => $addressList,
            ]
        );
    }

    public function createReceiptAsset(
        string $name,
        string $encryptedKey,
        string $nonce,
        int $amount,
        bool $defaultDrsTxHash,
        ?array $metaData = [],
    ): array {
        try {
            $decryptedKeypair = $this->decryptKeypair(
                encryptedKey: $encryptedKey,
                nonce: $nonce
            );

            $address = hash('sha3-256', $decryptedKeypair['publicKey']);

            $signableAssetHash = $this->getSignableAssetHash([
                'amount' => $amount,
            ]);

            $signature = $this->constructSignature(
                $signableAssetHash,
                $decryptedKeypair['secretKey']
            );

            $metaDataStr = json_encode([
                ...$metaData,
                'name' => $name,
            ]);

            $payload = [
                'receipt_amount'    => $amount,
                'script_public_key' => $address,
                'public_key'        => sodium_bin2hex($decryptedKeypair['publicKey']),
                'signature'         => $signature,
                'drs_tx_hash_spec'  => $defaultDrsTxHash ? 'Default' : 'Create',
                'metadata'          => $metaDataStr,
                'version'           => null,
            ];

            return $this->makeRequest(
                apiRoute: self::ENDPOINT_CREATE_RECEIPT_ASSET,
                payload: $payload
            );
        } catch (\Exception $e) {
            throw $e;
        }
    }

    public function createReceiptPayment(
        array $senderKeypairs,
        string $paymentAddress,
        int $amount,
        string $drsTxHash,
        array $metaData = null,
        string $excessAddress = null
    ): array {
        $paymentAsset = new PaymentAssetDTO(
            amount: $amount,
            drsTxHash: $drsTxHash,
            metaData: $metaData,
            assetType: PaymentAssetDTO::ASSET_TYPE_RECEIPT
        );

        $payload = $this->makePaymentPayload(
            senderKeypairs: $senderKeypairs,
            paymentAsset: $paymentAsset,
            paymentAddress: $paymentAddress,
            excessAddress: $excessAddress
        );

        return $this->doTransaction($payload);
    }

    private function makePaymentPayload(
        array $senderKeypairs,
        PaymentAssetDTO $paymentAsset,
        string $paymentAddress,
        string $excessAddress = null,
        DruidInfoDTO $druidInfo = null,
    ): array {
        $balance = $this->fetchBalance(array_keys($senderKeypairs));

        $amountAvailable = $paymentAsset->getAssetType() === PaymentAssetDTO::ASSET_TYPE_TOKEN ?
            $balance['total']['tokens'] : $balance['total']['receipts'][$paymentAsset->getDrsTxHash()] ?? 0;

        if ($amountAvailable < $paymentAsset->getAmount()) {
            throw new Exception('Insufficient funds');
        }

        $excessAddress = $excessAddress ?? array_keys($balance['address_list'])[0];

        $inputs = $this->getInputsForTransaction(
            keyPairs: $senderKeypairs,
            balance: $balance,
            paymentAsset: $paymentAsset,
        );

        $totalAmountGathered = $inputs['totalAmountGathered'];

        $outputs = [
            (new TransactionOutputDTO(
                scriptPublicKey: $paymentAddress,
                paymentAsset: $paymentAsset
            ))->formatForAPI(),
        ];

        $hasExcess = $totalAmountGathered > $paymentAsset->getAmount();

        if ($hasExcess) {
            $excessAsset = clone $paymentAsset;
            $excessAsset->setAmount($totalAmountGathered - $paymentAsset->getAmount());

            array_push($outputs, (new TransactionOutputDTO(
                scriptPublicKey: $excessAddress,
                paymentAsset: $excessAsset
            ))->formatForAPI());
        }

        $payload = [
            'createTx' => (new TransactionDTO(
                inputs: $inputs['inputs'],
                outputs: $outputs,
                druidInfo: $druidInfo
            )),
            'excessAddressUsed' => $hasExcess,
            'usedAddresses'     => $inputs['usedAddresses'],
        ];

        return $payload;
    }

    private function getInputsForTransaction(
        array $keyPairs,
        array $balance,
        PaymentAssetDTO $paymentAsset
    ): array {
        $totalAmountGathered = 0;
        $usedAddresses = [];
        $depletedAddresses = [];
        $addressVersion = null;
        $inputs = [];

        foreach ($balance['address_list'] as $address => $outPoints) {
            $usedOutpointsCount = 0;
            $keypair = $keyPairs[$address];
            $keypairDecrypted = [
                'address' => $address,
                'version' => null,
                ...$this->decryptKeypair(
                    encryptedKey: $keypair['encryptedKey'],
                    nonce: $keypair['nonce']
                ),
            ];

            foreach ($outPoints as $outPointArr) {
                if ($totalAmountGathered < $paymentAsset->getAmount()
                    && isset($outPointArr['value'][$paymentAsset->getAssetType()])) {
                    $signableData = $this->getSignableAssetHash($outPointArr['out_point']);

                    $signature = $this->constructSignature(
                        $signableData,
                        $keypairDecrypted['secretKey']
                    );

                    array_push($inputs, [
                        'script_signature' => ['Pay2PkH' => [
                            'signable_data'   => $signableData ?? '',
                            'signature'       => $signature,
                            'public_key'      => sodium_bin2hex($keypairDecrypted['publicKey']),
                            'address_version' => $addressVersion,
                        ]],
                        'previous_out' => $outPointArr['out_point'],
                    ]);

                    $totalAmountGathered += $outPointArr['value'][$paymentAsset->getAssetType()]['amount'];

                    if (! in_array($address, $usedAddresses)) {
                        array_push($usedAddresses, $address);
                    }

                    $usedOutpointsCount++;

                    if (count($outPoints) == $usedOutpointsCount) {
                        array_push($depletedAddresses, $address);
                    }
                }
            }
        }

        return [
            'depletedAddresses'   => $depletedAddresses,
            'inputs'              => $inputs,
            'totalAmountGathered' => $totalAmountGathered,
            'usedAddresses'       => $usedAddresses,
        ];
    }

    private function doTransaction(
        array $payload
    ): array {
        $result = $this->makeRequest(
            apiRoute: self::ENDPOINT_CREATE_TRANSACTIONS,
            payload: [($payload['createTx'])->formatForAPI()],
        );

        return [
            'usedAddresses' => $payload['usedAddresses'],
            'result'        => $result,
        ];
    }

    public function createTokenPayment(
        string $paymentAddress,
        int $amount,
        string $excessAddress = null
    ): array {
        try {
            $paymentAsset = new PaymentAssetDTO(
                amount: $amount,
                assetType: PaymentAssetDTO::ASSET_TYPE_TOKEN
            );

            dd($paymentAsset);

            // $payload = $this->makePaymentPayload(
            //     paymentAsset: $paymentAsset,
            //     paymentAddress: $paymentAddress,
            //     excessAddress: $excessAddress
            // );

            // return $this->doTransaction(
            //     payload: $payload
            // );
        } catch (Exception $e) {
            \Log::error($e->getMessage());
            throw $e;
        }
    }

    public function createKeypair(): array
    {
        if(!$this->walletDecrypted) {
            throw new ActiveWalletNotSetException();
        }

        return KeyHelpers::getNewKeypair(
            masterPrivateKey: $this->walletDecrypted->getMasterPrivateKey(),
            passPhrase: $this->getPassPhrase()
        );
    }

    private function decryptKeypair(string $encryptedKey, string $nonce): array
    {
        return KeyHelpers::decryptKeypair(
            encryptedKey: $encryptedKey,
            nonce: $nonce,
            passPhrase: $this->getPassPhrase()
        );
    }

    public function encryptTransaction(TransactionDTO $transaction): array
    {
        return KeyHelpers::encryptTransaction(
            transaction: $transaction,
            passPhrase: $this->getPassPhrase()
        );
    }

    public function getSignableAssetHash(array $asset): string
    {
        if (isset($asset['n']) && isset($asset['t_hash'])) {
            return hash('sha3-256', KeyHelpers::getFormattedOutPointString($asset));
        }

        if (isset($asset['token'])) {
            return hash('sha3-256', ("Token:{$asset['amount']}"));
        }

        if (isset($asset['amount'])) {
            return hash('sha3-256', ("Receipt:{$asset['amount']}"));
        }

        return '';
    }

    public function constructSignature(string $message, string $secretKey): string
    {
        return KeyHelpers::createSignature($message, $secretKey);
    }

    public function constructTransactionInputAddress(array $inputs): string
    {
        return KeyHelpers::constructTransactionInputAddress($inputs);
    }
}
