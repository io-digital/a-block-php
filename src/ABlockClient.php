<?php

namespace IODigital\ABlockPHP;

use IODigital\ABlockPHP\DTO\DecryptedWalletDTO;
use IODigital\ABlockPHP\DTO\EncryptedWalletDTO;
use IODigital\ABlockPHP\DTO\EncryptedKeypairDTO;
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
use Exception;

class ABlockClient
{
    use MakesRequests;

    final public const TRANSACTION_STATUS_PENDING = 'pending';
    final public const TRANSACTION_STATUS_ACCEPTED = 'accepted';
    final public const TRANSACTION_STATUS_REJECTED = 'rejected';

    private ?string $passPhraseHash = null;

    private ?DecryptedWalletDTO $walletDecrypted = null;

    private HttpClient $http;

    public function __construct(
        private string $computeHost,
        private string $intercomHost,
    ) {
        $this->http = new HttpClient();
    }

    /**
     * Set the pass phrase for the wallet to be created or opened.
     *
     * @param string $passPhrase
     * @return void
     */
    public function setPassPhrase(string $passPhrase): void
    {
        $this->passPhraseHash = KeyHelpers::getPassPhraseHash($passPhrase);
    }

    /**
     * Return the hashed passphrase set earlier.
     *
     * @return string
     */
    private function getPassPhrase(): string
    {
        if(!$this->passPhraseHash) {
            throw new PassPhraseNotSetException();
        }

        return $this->passPhraseHash;
    }

    /**
     * Creates and returns an encrypted A-Block wallet. The return value includes the 12-word mnemonic
     * Seed Phrase, which is to be stored securely by the owner of this wallet
     *
     * @return EncryptedWalletDTO
     */
    public function createWallet(?string $seedPhrase = null): EncryptedWalletDTO
    {
        $walletArr = KeyHelpers::initialiseFromPassphrase($this->getPassPhrase(), $seedPhrase);

        $walletDTO = new EncryptedWalletDTO(
            masterKeyEncrypted: $walletArr['masterKeyEncrypted'],
            nonce: $walletArr['nonce'],
            seedPhrase: $walletArr['seedPhrase']
        );

        return $walletDTO;
    }

    /**
     * Opens (decrypts) an existing wallet and returns true or false depending on if it was
     * successful.
     *
     * @param EncryptedWalletDTO $wallet
     * @return boolean
     */
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

            return true;
        } catch (\Exception $e) {
            throw $e;
        }
    }

    /**
     * Creates and returns an encrypted keypair and associated address,
     * using the decrypted wallet and supplied pass phrase
     *
     * @return array
     */
    public function createKeypair(array $existingAddresses = []): EncryptedKeypairDTO
    {
        if(!$this->walletDecrypted) {
            throw new ActiveWalletNotSetException();
        }

        $keypairArr = KeyHelpers::getNewKeypair(
            masterPrivateKey: $this->walletDecrypted->getMasterPrivateKey(),
            passPhrase: $this->getPassPhrase(),
            existingAddresses: $existingAddresses
        );

        return new EncryptedKeypairDTO(
            address: $keypairArr['address'],
            nonce: $keypairArr['nonce'],
            content: $keypairArr['save']
        );
    }


    /**
     * Fetches the balance for the opened wallet, using the addresses to keypairs supplied in $addressList.
     *
     * @param array $addressList
     * @return void
     */
    public function fetchBalance(array $addressList = [])
    {
        return $this->makeRequest(
            apiRoute: self::ENDPOINT_FETCH_BALANCE,
            payload: [
                'address_list' => $addressList,
            ]
        );
    }

    /**
     * Creates a receipt asset at the address associated with the encrypted keypair. Returns the receipt.
     *
     * @param string $name - this is the name that will be merged in with supplied meta data (if any)
     * @param string $encryptedKey - the encrypted keypair
     * @param string $nonce - the nonce as returned by the keypair creation
     * @param integer $amount - how many of these are we making
     * @param boolean $defaultHash - if false, a generic receipt is created. If not, a hash that identifies this receipt will be generated
     * @param array|null $metaData - an optional key-value array of extra info
     * @return array
     */
    public function createAsset(
        string $name,
        string $encryptedKey,
        string $nonce,
        int $amount,
        bool $defaultHash,
        ?array $metaData = [],
    ): PaymentAssetDTO {
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
                'drs_tx_hash_spec'  => $defaultHash ? 'Default' : 'Create',
                'metadata'          => $metaDataStr,
                'version'           => null,
            ];

            $result = $this->makeRequest(
                apiRoute: self::ENDPOINT_CREATE_RECEIPT_ASSET,
                payload: $payload
            );

            return new PaymentAssetDTO(
                assetType: PaymentAssetDTO::ASSET_TYPE_RECEIPT,
                amount: $amount,
                drsTxHash: $result['asset']['asset'][PaymentAssetDTO::ASSET_TYPE_RECEIPT]['drs_tx_hash'],
                metaData: json_decode($result['asset']['asset'][PaymentAssetDTO::ASSET_TYPE_RECEIPT]['metadata'], true)
            );
        } catch (\Exception $e) {
            throw $e;
        }
    }

    public function sendAssetToAddress(
        array $senderKeypairs,
        string $address,
        PaymentAssetDTO $asset,
        string $excessAddress = null,
    ): array {
        $payload = $this->makePaymentPayload(
            myKeypairs: $senderKeypairs,
            myAsset: $asset,
            otherPartyAddress: $address,
            excessAddress: $excessAddress
        );

        return $this->doTransaction([($payload['createTx'])->formatForAPI()]);
    }

    public function createTradeRequest(
        // the other party's address to send $myAsset to
        string $otherPartyAddress,
        PaymentAssetDTO $myAsset,

        // my address to get some $otherPartyAsset back into
        string $myAddress,
        PaymentAssetDTO $otherPartyAsset,

        // where to collect $myAsset from
        array $myKeypairs,
    ): array {
        $myExpectation = new PaymentExpectationDTO(
            to: $myAddress,
            asset: $otherPartyAsset
        );

        $otherPartyExpectation = new PaymentExpectationDTO(
            to: $otherPartyAddress,
            asset: $myAsset
        );

        $druidInfo = new DruidInfoDTO(
            expectations: [
                $myExpectation->formatForAPI(),
            ]
        );

        $payload = $this->makePaymentPayload(
            myKeypairs: $myKeypairs,
            myAsset: $myAsset,
            otherPartyAddress: $otherPartyAddress,
            excessAddress: $myAddress,
            druidInfo: $druidInfo
        );

        $encryptedTransaction = $this->encryptTransaction($payload['createTx']);

        $otherPartyExpectation->setFrom(KeyHelpers::constructTransactionInputAddress($payload['createTx']->getInputs()));

        $sendBody = IntercomUtils::generateIntercomSetBody(
            addressKey: $otherPartyAddress,
            addressField: $myAddress,
            keyPairForField: $this->decryptKeypair(
                encryptedKey: $myKeypairs[$myAddress]['encryptedKey'],
                nonce: $myKeypairs[$myAddress]['nonce']
            ),
            value: [
                'druid'               => $druidInfo->getDruid(),
                'senderExpectation'   => $myExpectation->formatForAPI(),
                'receiverExpectation' => $otherPartyExpectation->formatForAPI(),
                'status'              => self::TRANSACTION_STATUS_PENDING,
                'computeHost'         => $this->computeHost,
            ]
        );

        $this->makeRequest(
            apiRoute: self::ENDPOINT_SET_DATA,
            payload: [$sendBody],
        );

        return $encryptedTransaction;
    }

    private function makePaymentPayload(
        array $myKeypairs,
        PaymentAssetDTO $myAsset,
        string $otherPartyAddress,
        string $excessAddress = null,
        DruidInfoDTO $druidInfo = null
    ): array {
        $balance = $this->fetchBalance(array_keys($myKeypairs));

        $amountAvailable = $myAsset->getAssetType() === PaymentAssetDTO::ASSET_TYPE_TOKEN ?
            $balance['total']['tokens'] : $balance['total']['receipts'][$myAsset->getDrsTxHash()] ?? 0;

        if ($amountAvailable < $myAsset->getAmount()) {
            throw new Exception('Insufficient funds');
        }

        $excessAddress = $excessAddress ?? array_keys($myKeypairs)[0];

        $inputs = $this->getInputsForTransaction(
            myKeypairs: $myKeypairs,
            myBalance: $balance,
            myAsset: $myAsset,
        );

        $totalAmountGathered = $inputs['totalAmountGathered'];

        $outputs = [
            (new TransactionOutputDTO(
                scriptPublicKey: $otherPartyAddress,
                paymentAsset: $myAsset
            ))->formatForAPI(),
        ];

        $hasExcess = $totalAmountGathered > $myAsset->getAmount();

        if ($hasExcess) {
            $excessAsset = clone $myAsset;
            $excessAsset->setAmount($totalAmountGathered - $myAsset->getAmount());

            array_push($outputs, (new TransactionOutputDTO(
                scriptPublicKey: $excessAddress,
                paymentAsset: $excessAsset
            ))->formatForAPI());
        }

        return [
            'createTx' => (new TransactionDTO(
                inputs: $inputs['inputs'],
                outputs: $outputs,
                druidInfo: $druidInfo
            )),
            'excessAddressUsed' => $hasExcess,
            'usedAddresses'     => $inputs['usedAddresses'],
        ];
    }

    //Not sure I agree with this - accepted transactions are processed in this function, as per the JS lib
    public function getPendingTransactions(
        array $keypairs,
        ?array $encryptedTransactionMap = []
    ): array {
        try {
            $payload = [];

            foreach($keypairs as $address => $keypair) {
                array_push($payload, IntercomUtils::generateIntercomGetBody(
                    addressKey: $address,
                    keyPairForField: $this->getDecryptedKeypair($address, $keypair)
                ));
            }

            $transactions = $this->makeRequest(
                apiRoute: self::ENDPOINT_GET_DATA,
                payload: $payload,
            );

            $validTransactions = array_filter($transactions, fn ($item) => IntercomUtils::isValidIntercomData($item['value']));

            $transactionsByStatus = array_reduce($validTransactions, function (array $carry, array $item) {
                if(isset($carry[$item['value']['status']])) {
                    array_push($carry[$item['value']['status']], $item['value']);
                }

                return $carry;
            }, [
                self::TRANSACTION_STATUS_ACCEPTED => [],
                self::TRANSACTION_STATUS_REJECTED => [],
                self::TRANSACTION_STATUS_PENDING => []
            ]);

            if((bool) count($transactionsByStatus[self::TRANSACTION_STATUS_ACCEPTED])) {
                $transactionsToSend = [];

                foreach($transactionsByStatus[self::TRANSACTION_STATUS_ACCEPTED] as $acceptedTransaction) {
                    $encryptedTransaction = $encryptedTransactionMap[$acceptedTransaction['druid']];

                    $decryptedTransaction = KeyHelpers::decryptTransaction(
                        encryptedTransaction: $encryptedTransaction,
                        passPhrase: $this->getPassPhrase()
                    );

                    if(!isset($decryptedTransaction['druid_info'])) {
                        continue;
                    }

                    $decryptedTransaction['druid_info']['expectations'] = [
                        $acceptedTransaction['senderExpectation']
                    ];

                    array_push($transactionsToSend, $decryptedTransaction);
                }

                if(count($transactionsToSend)) {
                    $result = $this->doTransaction(payload: $transactionsToSend);
                }
            }

            return $transactionsByStatus[self::TRANSACTION_STATUS_PENDING];
        } catch (\Exception $e) {
            throw $e;
        }

        return $validTransactions;
    }

    public function acceptPendingTransaction(
        string $druid,
        array $keypairs,
    ): array {
        try {
            $pendingTransactions = $this->getPendingTransactions($keypairs);
            $pendingTransaction = reset($pendingTransactions);

            if($pendingTransaction['druid'] !== $druid) {
                throw new Exception('Provided DRUID mismatch');
            }

            $pendingTransaction['status'] = self::TRANSACTION_STATUS_ACCEPTED;

            $otherPartyAssetType = $this->getAssetType($pendingTransaction['receiverExpectation']);

            $myExpectation = new PaymentExpectationDTO(
                to: $pendingTransaction['receiverExpectation']['to'],
                from: $pendingTransaction['receiverExpectation']['from'],
                asset: new PaymentAssetDTO(
                    assetType: $otherPartyAssetType,
                    amount: $pendingTransaction['receiverExpectation']['asset'][$otherPartyAssetType]['amount'],
                    drsTxHash: $otherPartyAssetType === PaymentAssetDTO::ASSET_TYPE_RECEIPT ? $pendingTransaction['receiverExpectation']['asset'][$otherPartyAssetType]['drs_tx_hash'] : null
                )
            );

            $myAssetType = $this->getAssetType($pendingTransaction['senderExpectation']);

            $otherPartyExpectation = new PaymentExpectationDTO(
                to: $pendingTransaction['senderExpectation']['to'],
                asset: new PaymentAssetDTO(
                    assetType: $myAssetType,
                    amount: $pendingTransaction['senderExpectation']['asset'][$myAssetType]['amount'],
                    drsTxHash: $myAssetType === PaymentAssetDTO::ASSET_TYPE_RECEIPT ? $pendingTransaction['senderExpectation']['asset'][$myAssetType]['drs_tx_hash'] : null
                )
            );

            $druidInfo = new DruidInfoDTO(
                druid: $druid,
                expectations: [
                    $myExpectation->formatForAPI()
                ]
            );

            $payload = $this->makePaymentPayload(
                myKeypairs: $keypairs,
                myAsset: $otherPartyExpectation->getAsset(),
                otherPartyAddress: $otherPartyExpectation->getToAddress(),
                excessAddress: $myExpectation->getToAddress(),
                druidInfo: $druidInfo
            );

            $this->doTransaction(payload: [($payload['createTx'])->formatForAPI()], host: $pendingTransaction['computeHost']);

            $otherPartyExpectation->setFrom(KeyHelpers::constructTransactionInputAddress($payload['createTx']->getInputs()));

            $sendBody = IntercomUtils::generateIntercomSetBody(
                addressKey: $otherPartyExpectation->getToAddress(),
                addressField: $myExpectation->getToAddress(),
                keyPairForField: $this->decryptKeypair(
                    encryptedKey: $keypairs[$myExpectation->getToAddress()]['encryptedKey'],
                    nonce: $keypairs[$myExpectation->getToAddress()]['nonce']
                ),
                value: [
                    ...$pendingTransaction,
                    "senderExpectation" => $myExpectation->formatForAPI(),
                    "receiverExpectation" => $otherPartyExpectation->formatForAPI()
                ]
            );

            return $this->makeRequest(
                apiRoute: self::ENDPOINT_SET_DATA,
                payload: [$sendBody],
            );
        } catch (Exception $e) {
            throw $e;
        }
    }

    private function getInputsForTransaction(
        array $myKeypairs,
        array $myBalance,
        PaymentAssetDTO $myAsset
    ): array {
        $totalAmountGathered = 0;
        $usedAddresses = [];
        $depletedAddresses = [];
        $addressVersion = null;
        $inputs = [];

        foreach ($myBalance['address_list'] as $address => $outPoints) {
            $usedOutpointsCount = 0;
            $keypair = $myKeypairs[$address];
            $keypairDecrypted = $this->getDecryptedKeypair(address: $address, keypair: $keypair);

            foreach ($outPoints as $outPointArr) {
                if ($totalAmountGathered < $myAsset->getAmount()
                    && isset($outPointArr['value'][$myAsset->getAssetType()])) {
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

                    $thisAmount = isset($outPointArr['value'][$myAsset->getAssetType()]['amount']) ?
                        $outPointArr['value'][$myAsset->getAssetType()]['amount'] : $outPointArr['value'][$myAsset->getAssetType()];

                    $totalAmountGathered += $thisAmount;

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
            payload: $payload,
            host: $host
        );

        return $result;
    }

    private function getAssetType(array $expectation): string
    {
        return array_keys($expectation['asset'])[0];
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

    private function constructSignature(string $message, string $secretKey): string
    {
        return KeyHelpers::createSignature($message, $secretKey);
    }
}
