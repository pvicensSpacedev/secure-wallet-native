export interface ExistingWalletResult {
  exists: boolean;
  wallet?: {
    publicKey: string;
    address: string;
  };
}

export interface SecureWalletConfig {
  // Add any configuration options here
}

export interface WalletGenerationResult {
  publicKey: string;
  address: string;
  success: boolean;
}

export interface SignatureResult {
  r: string;
  s: string;
  v: number;
  publicKey: string;
  success: boolean;
}

declare const SecureWallet: {
  checkForExistingWallet(): Promise<ExistingWalletResult>;
  generateSecureWallet(config: SecureWalletConfig): Promise<WalletGenerationResult>;
  signTransactionHash(transactionHash: string): Promise<SignatureResult>;
  isSecureEnclaveAvailable(): Promise<boolean>;
  getMnemonic(): Promise<string>;
  deleteWallet(): Promise<boolean>;
  getPrivateKey(): Promise<string>;
};

export default SecureWallet; 