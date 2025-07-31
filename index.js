import { NativeModules } from 'react-native';

const { SecureWallet } = NativeModules;

if (!SecureWallet) {
  throw new Error('SecureWallet native module is not available. Make sure it is properly linked.');
}

export default SecureWallet;

// Export individual functions for better TypeScript support
export const {
  checkForExistingWallet,
  generateSecureWallet,
  signTransactionHash,
  isSecureEnclaveAvailable,
  getMnemonic,
  deleteWallet,
  getPrivateKey
} = SecureWallet; 