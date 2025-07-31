# secure-wallet-native

A React Native module for secure wallet functionality using iOS Secure Enclave and secp256k1 cryptography.

## Features

- 🔐 iOS Secure Enclave integration
- 🗝️ secp256k1 cryptographic operations
- 📱 BIP39 mnemonic generation
- 🔒 Secure key storage in Keychain
- ✍️ Transaction signing
- 🏠 Ethereum address derivation

## Installation

```bash
npm install secure-wallet-native
```

## Usage

```javascript
import SecureWallet from 'secure-wallet-native';

// Check if Secure Enclave is available
const isAvailable = await SecureWallet.isSecureEnclaveAvailable();

// Generate a new wallet
const wallet = await SecureWallet.generateSecureWallet({});

// Sign a transaction
const signature = await SecureWallet.signTransactionHash('0x...');

// Get mnemonic phrase
const mnemonic = await SecureWallet.getMnemonic();
```

## API Reference

### `isSecureEnclaveAvailable()`
Returns `Promise<boolean>` - Whether the device supports Secure Enclave.

### `generateSecureWallet(config)`
Generates a new secure wallet using Secure Enclave.
Returns `Promise<WalletGenerationResult>`

### `signTransactionHash(hash)`
Signs a transaction hash using the stored private key.
Returns `Promise<SignatureResult>`

### `getMnemonic()`
Retrieves the stored mnemonic phrase.
Returns `Promise<string>`

### `deleteWallet()`
Deletes all wallet data from the device.
Returns `Promise<boolean>`

## Requirements

- iOS 15.1+
- React Native 0.60+
- Device with Secure Enclave support

## License

MIT 