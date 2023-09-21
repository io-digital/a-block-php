<?php

namespace IODigital\ABlockPHP;

use IODigital\ABlockPHP\DTO\DecryptedWalletDTO;
use IODigital\ABlockPHP\DTO\EncryptedWalletDTO;
use IODigital\ABlockPHP\DTO\PaymentAssetDTO;
use IODigital\ABlockPHP\DTO\TransactionDTO;
use IODigital\ABlockPHP\DTO\TransactionOutputDTO;
use IODigital\ABlockPHP\DTO\DruidInfoDTO;
use IODigital\ABlockPHP\DTO\PaymentExpectationDTO;
use IODigital\ABlockPHP\Functions\KeyHelpers;
use IODigital\ABlockPHP\Functions\IntercomUtils;
use IODigital\ABlockPHP\Traits\MakesRequests;
use IODigital\ABlockPHP\Exceptions\PassPhraseNotSetException;
use IODigital\ABlockPHP\Exceptions\ActiveWalletNotSetException;
use GuzzleHttp\Client as HttpClient;

class ABlockClient
{
    use MakesRequests;

    final public const TRANSACTION_STATUS_PENDING = 'pending';
    final public const TRANSACTION_STATUS_ACCEPTED = 'accepted';

    private ?string $passPhraseHash = null;

    private ?DecryptedWalletDTO $walletDecrypted = null;

    private HttpClient $http;

    public function __construct(
        private string $computeHost,
        private string $intercomHost,
    ) {
        $this->http = new HttpClient();
    }

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
        string $excessAddress = null,
        string $druid
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

    public function createReceiptBasedPayment(
        // address to send $sendingAsset to
        string $paymentAddress,
        PaymentAssetDTO $sendingAsset,

        // address to get some $receivingAsset back into
        string $receiveAddress,
        PaymentAssetDTO $receivingAsset,

        // where to collect the sending asset from
        array $senderKeypairs,
    ): array {
        try {
            $senderExpectation = new PaymentExpectationDTO(
                to: $receiveAddress,
                asset: $receivingAsset
            );

            $receiverExpectation = new PaymentExpectationDTO(
                to: $paymentAddress,
                asset: $sendingAsset
            );

            $druidInfo = new DruidInfoDTO(
                expectations: [
                    $senderExpectation->formatForAPI(),
                ]
            );

            $payload = $this->makePaymentPayload(
                senderKeypairs: $senderKeypairs,
                paymentAsset: $sendingAsset,
                paymentAddress: $paymentAddress,
                excessAddress: $receiveAddress,
                druidInfo: $druidInfo
            );

            $encryptedTransaction = $this->encryptTransaction($payload['createTx']);

            $receiverExpectation->setFrom(KeyHelpers::constructTransactionInputAddress($payload['createTx']->getInputs()));

            $valuePayload = [
                'druid'               => $druidInfo->getDruid(),
                'senderExpectation'   => $senderExpectation->formatForAPI(),
                'receiverExpectation' => $receiverExpectation->formatForAPI(),
                'status'              => 'pending', // Status of the DDE transaction
                'computeHost'         => $this->computeHost,
            ];

            $keyPairForField = $this->decryptKeypair(
                encryptedKey: $senderKeypairs[$receiveAddress]['encryptedKey'],
                nonce: $senderKeypairs[$receiveAddress]['nonce']
            );

            $sendBody = IntercomUtils::generateIntercomSetBody(
                addressKey: $paymentAddress,
                addressField: $receiveAddress,
                keyPairForField: $keyPairForField,
                value: $valuePayload
            );

            $this->makeRequest(
                apiRoute: self::ENDPOINT_SET_DATA,
                payload: [$sendBody],
            );

            return $encryptedTransaction;

        } catch (\Exception $e) {
            throw $e;
        }
    }

    public function getPendingTransactions(
        array $keypairs,
    ): array {
        try {
            $payload = [];

            foreach($keypairs as $address => $keypair) {
                $keypairDecrypted = [
                    'address' => $address,
                    'version' => null,
                    ...$this->decryptKeypair(
                        encryptedKey: $keypair['encryptedKey'],
                        nonce: $keypair['nonce']
                    ),
                ];

                array_push($payload, IntercomUtils::generateIntercomGetBody(
                    addressKey: $address,
                    keyPairForField: $keypairDecrypted
                ));
            }

            $result = $this->makeRequest(
                apiRoute: self::ENDPOINT_GET_DATA,
                payload: $payload,
            );

            return $result;

            // $return = [];

            // foreach($result as $address => $pendingTransaction) {
            //     if($pendingTransaction['value']['status'] !== self::TRANSACTION_STATUS_PENDING) {
            //         continue;
            //     }

            //     $return[$address] = $pendingTransaction;
            // }

            // return $return;
        } catch (\Exception $e) {
            throw $e;
        }
    }

    public function acceptPendingTransaction(
        string $druid,
        array $keypairs,
        array $pendingTransactions
    ): array {

        // we are now the original receiver, so the context switches around. So here we are Bob, the sender
        $pendingTransaction = reset($pendingTransactions)['value'];

        if($pendingTransaction['druid'] !== $druid) {
            throw new Exception('Provided DRUID mismatch');
        }

        $pendingTransaction['status'] = self::TRANSACTION_STATUS_ACCEPTED;

        $senderAssetType = array_keys($pendingTransaction['receiverExpectation']['asset'])[0];

        $senderExpectation = new PaymentExpectationDTO(
            to: $pendingTransaction['receiverExpectation']['to'],
            from: $pendingTransaction['receiverExpectation']['from'],
            asset: new PaymentAssetDTO(
                assetType: $senderAssetType,
                amount: $pendingTransaction['receiverExpectation']['asset'][$senderAssetType]['amount'],
                drsTxHash: $senderAssetType === PaymentAssetDTO::ASSET_TYPE_RECEIPT ? $pendingTransaction['receiverExpectation']['asset'][$senderAssetType]['drs_tx_hash'] : null
            )
        );

        $receiverAssetType = array_keys($pendingTransaction['senderExpectation']['asset'])[0];

        $receiverExpectation = new PaymentExpectationDTO(
            to: $pendingTransaction['senderExpectation']['to'],
            asset: new PaymentAssetDTO(
                assetType: $receiverAssetType,
                amount: $pendingTransaction['senderExpectation']['asset'][$receiverAssetType]['amount'],
                drsTxHash: $receiverAssetType === PaymentAssetDTO::ASSET_TYPE_RECEIPT ? $pendingTransaction['senderExpectation']['asset'][$senderAssetType]['drs_tx_hash'] : null
            )
        );

        $druidInfo = new DruidInfoDTO(
            druid: $druid,
            expectations: [
                $receiverExpectation->formatForAPI(), // is this right way round?
            ]
        );

        $payload = $this->makePaymentPayload(
            senderKeypairs: $keypairs,
            paymentAsset: $receiverExpectation->getAsset(),
            paymentAddress: $receiverExpectation->getToAddress(),
            excessAddress: $senderExpectation->getToAddress(),
            druidInfo: $druidInfo
        );

        $rs = $this->doTransaction(payload: $payload, host: $pendingTransaction['computeHost']);

        $receiverExpectation->setFrom(KeyHelpers::constructTransactionInputAddress($payload['createTx']->getInputs()));

        $keyPairForField = $this->decryptKeypair(
            encryptedKey: $keypairs[$senderExpectation->getToAddress()]['encryptedKey'],
            nonce: $keypairs[$senderExpectation->getToAddress()]['nonce']
        );

        $sendBody = IntercomUtils::generateIntercomSetBody(
            addressKey: $receiverExpectation->getToAddress(),
            addressField: $senderExpectation->getToAddress(),
            keyPairForField: $keyPairForField,
            value: [
                ...$pendingTransaction,
                "senderExpectation" => $senderExpectation->formatForAPI(),
                "receiverExpectation" => $receiverExpectation->formatForAPI()
            ]
        );

        return$this->makeRequest(
            apiRoute: self::ENDPOINT_SET_DATA,
            payload: [$sendBody],
        );
    }

    private function makePaymentPayload(
        array $senderKeypairs,
        PaymentAssetDTO $paymentAsset,
        string $paymentAddress,
        string $excessAddress = null,
        DruidInfoDTO $druidInfo = null
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
        array $payload,
        ?string $host = null
    ): array {
        $result = $this->makeRequest(
            apiRoute: self::ENDPOINT_CREATE_TRANSACTIONS,
            payload: [($payload['createTx'])->formatForAPI()],
            host: $host
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

    private function getDecryptedKeypair($address, $keypair): array
    {
        return [
            'address' => $address,
            'version' => null,
            ...$this->decryptKeypair(
                encryptedKey: $keypair['encryptedKey'],
                nonce: $keypair['nonce']
            ),
        ];
    }

    private function decryptKeypair(string $encryptedKey, string $nonce): array
    {
        return KeyHelpers::decryptKeypair(
            encryptedKey: $encryptedKey,
            nonce: $nonce,
            passPhrase: $this->getPassPhrase()
        );
    }

    private function encryptTransaction(TransactionDTO $transaction): array
    {
        return KeyHelpers::encryptTransaction(
            transaction: $transaction,
            passPhrase: $this->getPassPhrase()
        );
    }

    private function getSignableAssetHash(array $asset): string
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
}
