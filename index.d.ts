export interface ExistingWalletResult {
  exists: boolean;
  wallet?: {
    publicKey: string;
    address: string;
  };
}

export interface SecureWalletConfig {
  // Optional: return mnemonic with wallet generation (one-time only)
  returnMnemonic?: boolean;
  // Optional: store mnemonic in keychain (explicit opt-in, not recommended)
  storeMnemonic?: boolean;
}

export interface WalletGenerationResult {
  publicKey: string;
  address: string;
  success: boolean;
  // Optional: mnemonic is only included if returnMnemonic was true
  mnemonic?: string;
}

export interface SignatureResult {
  r: string;
  s: string;
  v: number;
  recid: number; // Recovery ID for EIP-155 compatibility
  publicKey: string;
  success: boolean;
}

declare const SecureWallet: {
  checkForExistingWallet(): Promise<ExistingWalletResult>;
  generateSecureWallet(config: SecureWalletConfig): Promise<WalletGenerationResult>;
  storePrivateKeyHex(privateKeyHex: string): Promise<WalletGenerationResult>;
  signTransactionHash(transactionHash: string): Promise<SignatureResult>;
  isSecureEnclaveAvailable(): Promise<boolean>;
  hasMnemonicBackup(): Promise<boolean>; // Check if encrypted backup exists
  revealMnemonic(): Promise<string>; // Biometry-gated, only if stored as encrypted backup
  deleteWallet(): Promise<boolean>;
};

export default SecureWallet; 