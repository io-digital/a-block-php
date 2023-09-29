# a-block-php

Composer package for direct communication with A-Block's API

## Requirements

- PHP >= 8.2
- composer

## Features

- Create wallets
- Create addresses/keypairs for wallets
- Create receipt assets (A-Block's equivalent to NFTs) related to keypairs
- Transfer assets (Receipts or Tokens) to another address
- Initiate and complete Dual Double Entry (DDE) using a DRUID to trade assets between addresses

## Installation

- Simply run `composer require io-digital/a-block-php`
- Include `IODigital\ABlockPHP\ABlockClient` in your PHP code and you're ready to go
- Instantiate the above client with `

## A note on Data Transfer Objects (DTOs)

This package makes use of PHP's typing of function definitions to increase robustness. Many of the client's functions require a Data Transfer Object (DTO) to be passed as input and some return a DTO. Some usage examples below will illustrate this.

It may seem cumbersome at first but it helps ensure that the data we send to the A-Block API is formatted correctly.

## Usage Examples

These are listed in an order that you could follow to do most of the things this package allows you, as one may in the real world.

### Instantiating the client

```
$client = new ABlockClient(
    computeHost: 'http://your-compute-host',
    intercomHost: 'http://your-intercom-host'
);

$client->setPassPhrase('my very intricate passphrase');
```

A pass phrase (text string) is used to encrypt and decrypt data in any typical cryptography implementation and this setup is no different.

Please ensure that you run `$client->setPassPhrase('my very intricate passphrase');` before attempting any interaction with the client.

### Creating a new wallet

Creates and returns a new wallet. It is up to the developer to store this.

```
$encryptedWalletDTO = $client->createWallet();
```

### Opening an encrypted wallet

```
$walletIsOpen = $client->openWallet(
    wallet: $encryptedWalletDTO
);
```

### Create a new Address/Keypair for the opened wallet

```
$encryptedKeypairDTO = $client->createKeypair();

```

### Fetch opened wallet balance

```
$balance = $client->fetchBalance(
    addressList: [$encryptedKeypairDTO->getAddress()]
);
```

### Create a Receipt Asset at a specified address

```
$receiptAssetArr = $client->createAsset(
    name: 'Some friendly identifier',
    encryptedKey: $encryptedKeypairDTO->getAddress(),
    nonce: $encryptedKeypairDTO->getNonce(),
    amount: 100,
    defaultDrsTxHash: false, // make true to create generic receipts
    metaData: [
        'foo' => 'bar'
    ]
);
```

Please note that this newly created asset will only reflect in a `fetchBalance` enquiry once it has been verified by A-Block's compute node.
