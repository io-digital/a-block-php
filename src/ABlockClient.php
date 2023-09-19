<?php

namespace IODigital\ABlockPHP;

use Illuminate\Database\Eloquent\Collection;
use IODigital\ABlockPHP\DTO\DecryptedWalletDTO;
use IODigital\ABlockPHP\DTO\EncryptedWalletDTO;
use IODigital\ABlockPHP\DTO\TransactionDTO;
use IODigital\ABlockPHP\Functions\KeyHelpers;
use IODigital\ABlockPHP\Traits\MakesRequests;

class ABlockClient
{
    use MakesRequests;

    private ?string $passPhraseHash = null;

    private ?string $seedPhrase = null;

    //private ?string $masterKeyEncrypted = null;

    // private ?string $masterPrivateKey = null;

    // private ?string $chainCode = null;

    private ?EncryptedWalletDTO $wallet = null;

    private ?DecryptedWalletDTO $walletDecrypted = null;

    public function __construct(
        private string $computeHost,
        private string $intercomHost,
    ) {
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

    public function setWallet(EncryptedWalletDTO $wallet): void
    {
        $this->wallet = $wallet;
        $this->openWallet($this->wallet);
    }

    public function getPassPhrase(): string
    {
        return $this->passPhraseHash;
    }

    public function getKeypairs(): Collection
    {
        return $this->wallet->keypairs()->get();
    }

    public function getDecryptedKeypairByAddress(string $address): array
    {
        $keypair = $this->getKeypairs()->where('address', $address)->first();

        return [
            'address' => $address,
            'version' => null,
            ...$this->decryptKeypair($keypair),
        ];
    }

    public function getAddresses(): array
    {
        return $this->wallet->keypairs()->get()->map(fn ($keypair) => $keypair->address)->toArray();
    }

    public function createWallet(bool $open = true): EncryptedWalletDTO
    {
        $walletArr = KeyHelpers::initialiseFromPassphrase($this->getPassPhrase());

        $walletDTO = new EncryptedWalletDTO(
            masterKeyEncrypted: $walletArr['masterKeyEncrypted'],
            nonce: $walletArr['nonce'],
            seedPhrase: $walletArr['seedPhrase']
        );

        if ($open === true) {
            $this->openWallet($walletDTO);
        }

        return $walletDTO;
    }

    public function openWallet(EncryptedWalletDTO $wallet): bool
    {
        try {
            $masterKeyDecrypted = KeyHelpers::decryptKeypair(
                encryptedKey: $wallet->getMasterKeyEncrypted(),
                nonce: $wallet->getNonce(),
                passPhrase: $this->getPassPhrase()
            );

            if (!$masterKeyDecrypted) {
                throw new \Exception('Cannot open wallet');
            }

            // $this->masterPrivateKey = $masterKeyDecrypted['publicKey'];
            // $this->chainCode = $masterKeyDecrypted['secretKey'];

            $this->walletDecrypted = new DecryptedWalletDTO(
                masterPrivateKey: $masterKeyDecrypted['publicKey'],
                chainCode: $masterKeyDecrypted['secretKey']
            );

            $this->wallet = $wallet;

            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    public function createNewKeypair(): array
    {
        return KeyHelpers::getNewKeypair(
            masterPrivateKey: $this->walletDecrypted->getMasterPrivateKey(),
            passPhrase: $this->getPassPhrase()
        );
    }

    public function saveTransaction()
    {
    }

    public function decryptKeypair($encryptedKey)
    {
        return KeyHelpers::decryptKeypair(
            encryptedKey: $encryptedKey->save,
            nonce: $encryptedKey->nonce,
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
