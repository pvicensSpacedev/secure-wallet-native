#import "SecureWallet.h"
#import <React/RCTLog.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#include <string.h>  // for memset_s
// Trust Wallet Core (bundled headers)
#import "TWHDWallet.h"
#import "TWDerivationPath.h"
#import "TWPrivateKey.h"
#import "TWPublicKey.h"
#import "TWData.h"
#import "TWString.h"
#import "TWCoinType.h"
#import "TWCurve.h"
#import "TWAsnParser.h"   

// TODO(multikey):
// - Make Keychain accounts per wallet by suffixing with keyId, e.g. "encrypted_private_key.<keyId>"
// - Either add `keyId` to the config dict for generateSecureWallet/revealMnemonic/storePrivateKeyHex
//   OR overload the bridge to accept a keyId param.
// - Consider also suffixing the Enclave master key application tag (or keep one device-wide key).


// --- TWC helpers: NSData <-> TWData ---
static inline TWData *_Nonnull TWDataCreateWithNSData(NSData *_Nonnull d) {
  return TWDataCreateWithBytes((const uint8_t *)d.bytes, d.length);
}
static inline NSData *_Nonnull NSDataFromTWData(TWData *_Nonnull d) {
  return [NSData dataWithBytes:TWDataBytes(d) length:TWDataSize(d)];
}

#ifndef ENCLAVE_ALLOW_PASSCODE_FALLBACK
#define ENCLAVE_ALLOW_PASSCODE_FALLBACK 0
#endif

@implementation SecureWallet {
    // Private instance variables if needed
}

+ (void)initialize {
    if (self == [SecureWallet class]) {
        // TrustWalletCore handles secp256k1 context internally
        // No manual randomization needed as TWC manages this
    }
}

#pragma mark - Private Methods

- (void)authenticateUser:(void (^)(BOOL success, NSError *error))completion {
    self.cachedAuthContext = [[LAContext alloc] init];
    self.cachedAuthContext.touchIDAuthenticationAllowableReuseDuration = 30;
    
    [self.cachedAuthContext evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                          localizedReason:@"Authenticate to use wallet"
                                    reply:completion];
}

RCT_EXPORT_METHOD(authenticateForWalletAccess:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    [self authenticateUser:^(BOOL success, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (success) {
                resolve(@YES);
            } else {
                reject(@"auth_failed", error.localizedDescription ?: @"Failed to authenticate", error);
            }
        });
    }];
}

- (void)invalidateAuthContext {
    [self.cachedAuthContext invalidate];
    self.cachedAuthContext = nil;
}

- (NSString *)formatPublicKey:(NSData *)publicKey {
    NSMutableString *hexString = [NSMutableString string];
    const unsigned char *bytes = (const unsigned char *)publicKey.bytes;
    for (NSUInteger i = 0; i < publicKey.length; i++) {
        [hexString appendFormat:@"%02x", bytes[i]];
    }
    return hexString;
}

#pragma mark - Public Methods

RCT_EXPORT_MODULE()

// Constants for key management
static NSString *const kKeyTag = @"com.walletpoc.securekey";
static NSString *const kKeychainLabel = @"WalletPOC Secure Key";
static NSString *const kAcctEncryptedPriv = @"encrypted_private_key";
static NSString *const kAcctEncryptedMnemonic = @"encrypted_mnemonic";
static NSString *const kService = @"com.walletpoc.secure";

#pragma mark - Verification Methods

- (BOOL)verifyKeyPairInSecureEnclave:(SecKeyRef)privateKey publicKey:(SecKeyRef)publicKey {
    RCTLogInfo(@"🔐 Starting key pair verification in Secure Enclave");
    
    // 1. Verify keys exist
    if (!privateKey || !publicKey) {
        RCTLogError(@"❌ Key pair verification failed: One or both keys are nil");
        return NO;
    }
    
    RCTLogInfo(@"✅ Both private and public keys are present");
    
    // 2. Verify key attributes
    RCTLogInfo(@"🔍 Retrieving key attributes...");
    CFDictionaryRef privateAttrs = SecKeyCopyAttributes(privateKey);
    CFDictionaryRef publicAttrs = SecKeyCopyAttributes(publicKey);
    
    if (!privateAttrs || !publicAttrs) {
        RCTLogError(@"❌ Failed to get key attributes");
        if (privateAttrs) CFRelease(privateAttrs);
        if (publicAttrs) CFRelease(publicAttrs);
        return NO;
    }
    
    RCTLogInfo(@"✅ Successfully retrieved key attributes");
    
    // Convert public key to hex for logging
    CFDataRef logPubKeyData = SecKeyCopyExternalRepresentation(publicKey, NULL);
    if (logPubKeyData) CFRelease(logPubKeyData); // avoid logging full pubkey; not needed

    // Check if private key is in Secure Enclave
    CFStringRef tokenID = (CFStringRef)CFDictionaryGetValue(privateAttrs, kSecAttrTokenID);
    BOOL isInSecureEnclave = tokenID && CFEqual(tokenID, kSecAttrTokenIDSecureEnclave);
    RCTLogInfo(@"🏰 Private key is in Secure Enclave: %@", isInSecureEnclave ? @"YES" : @"NO");
    
    if (!isInSecureEnclave) {
        RCTLogWarn(@"⚠️ Private key is NOT in Secure Enclave - this may indicate a security issue");
    }
    
    // Check key type and size
    CFStringRef keyType = (CFStringRef)CFDictionaryGetValue(privateAttrs, kSecAttrKeyType);
    CFNumberRef keySizeNum = (CFNumberRef)CFDictionaryGetValue(privateAttrs, kSecAttrKeySizeInBits);
    
    BOOL isCorrectType = keyType && CFEqual(keyType, kSecAttrKeyTypeECSECPrimeRandom);
    int keySize = 0;
    if (keySizeNum) {
        CFNumberGetValue(keySizeNum, kCFNumberIntType, &keySize);
    }
    
    RCTLogInfo(@"🔑 Key type is EC: %@", isCorrectType ? @"YES" : @"NO");
    RCTLogInfo(@"📏 Key size: %d bits", keySize);
    
    if (!isCorrectType) {
        RCTLogError(@"❌ Invalid key type - expected EC key");
        CFRelease(privateAttrs);
        CFRelease(publicAttrs);
        return NO;
    }
    
    if (keySize != 256) {
        RCTLogWarn(@"⚠️ Unexpected key size: %d bits (expected 256)", keySize);
    }
    
    // 3. Test signing operation
    RCTLogInfo(@"🧪 Testing signing operation with test data...");
    NSData *testData = [@"test" dataUsingEncoding:NSUTF8StringEncoding];
    CFErrorRef error = NULL;
    
    CFDataRef signature = SecKeyCreateSignature(privateKey,
                                              kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                                              (__bridge CFDataRef)testData,
                                              &error);
    
    if (!signature) {
        NSError *err = (__bridge_transfer NSError *)error;
        RCTLogError(@"❌ Signing test failed: %@", err);
        CFRelease(privateAttrs);
        CFRelease(publicAttrs);
        return NO;
    }
    
    RCTLogInfo(@"✅ Signing test successful");
    
    // 4. Verify signature
    RCTLogInfo(@"🔍 Verifying signature...");
    
    BOOL verified = SecKeyVerifySignature(publicKey,
                                        kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                                        (__bridge CFDataRef)testData,
                                        signature,
                                        &error);
    
    CFRelease(signature);
    CFRelease(privateAttrs);
    CFRelease(publicAttrs);
    
    if (!verified) {
        NSError *err = (__bridge_transfer NSError *)error;
        RCTLogError(@"❌ Signature verification failed: %@", err);
        return NO;
    }
    
    RCTLogInfo(@"✅ Key pair successfully verified with test signature");
    return YES;
}

#pragma mark - Entropy Generation

- (NSData *)generateSecureEntropy:(NSUInteger)bytes {
    RCTLogInfo(@"🎲 Generating %lu bytes of secure entropy...", (unsigned long)bytes);
    
    NSMutableData *entropy = [NSMutableData dataWithLength:bytes];
    int result = SecRandomCopyBytes(kSecRandomDefault, (size_t)bytes, entropy.mutableBytes);
    
    if (result == errSecSuccess) {
        RCTLogInfo(@"✅ Successfully generated %lu bytes of entropy", (unsigned long)bytes);
        return entropy;
    }
    RCTLogError(@"❌ Failed to generate secure entropy, error: %d", result);
    return nil;
}

#pragma mark - Secure Enclave Methods

- (SecAccessControlRef)createAccessControl {
    RCTLogInfo(@"🔐 Creating access control with biometry...");
    
    // Create access control with biometry
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlBiometryAny | kSecAccessControlPrivateKeyUsage,
        NULL
    );
    
    if (access) {
        RCTLogInfo(@"✅ Access control created successfully");
    } else {
        RCTLogError(@"❌ Failed to create access control");
    }
    
    return access;
}

- (BOOL)isSecureEnclavePresent {
    RCTLogInfo(@"🏰 Checking Secure Enclave availability...");
    
    // First check if device has Secure Enclave by attempting to create a test key
    NSDictionary *testKeyParams = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrKeySizeInBits: @256,
        (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
    };
    
    RCTLogInfo(@"🔑 Attempting to create test key in Secure Enclave...");
    
    CFErrorRef error = NULL;
    SecKeyRef testKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)testKeyParams, &error);
    
    if (testKey) {
        // Clean up test key
        CFRelease(testKey);
        RCTLogInfo(@"✅ Secure Enclave is present and working");
        
        // In production, we'll be more lenient about biometric availability
        // Just check if biometric is available, but don't require it
        RCTLogInfo(@"🔍 Checking biometric authentication availability...");
        LAContext *context = [[LAContext alloc] init];
        NSError *biometricError = nil;
        
        if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&biometricError]) {
            RCTLogInfo(@"✅ Biometric authentication is available, type: %ld", (long)context.biometryType);
            return YES;
        }
        
        if (biometricError) {
            RCTLogInfo(@"⚠️ Biometric not available, but Secure Enclave is working: %@", biometricError);
            // Still return YES if Secure Enclave works, even without biometric
            return YES;
        }
        
        RCTLogInfo(@"✅ Secure Enclave is working (no biometric required)");
        return YES;
        
    } else {
        NSError *keyError = (__bridge_transfer NSError *)error;
        RCTLogError(@"❌ Failed to create test key in Secure Enclave: %@", keyError);
    }
    
    RCTLogError(@"❌ Secure Enclave is not available");
    return NO;
}

RCT_EXPORT_METHOD(isSecureEnclaveAvailable:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    resolve(@([self isSecureEnclavePresent]));
}

// Presence check without unwrapping (no Face ID/passcode)
RCT_EXPORT_METHOD(hasWallet:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    @try {
        BOOL present = [self hasExistingWallet];
        resolve(@(present));
    } @catch (NSException *exception) {
        reject(@"presence_error", exception.reason, nil);
    }
}

#pragma mark - Enclave ECIES helpers (wrap/unwrap) and zeroization

// Create or fetch an Enclave P-256 key that gates unwrap operations
- (SecKeyRef)createOrGetEnclaveKey {
    RCTLogInfo(@"🔑 Creating or retrieving Enclave master key...");
    
    CFErrorRef err = NULL;
    // Require biometric authentication when using the key
    // This ensures biometric prompt at signing/unwrap time for hardware wallet operations.
    CFOptionFlags flags = kSecAccessControlBiometryAny | kSecAccessControlPrivateKeyUsage;
    SecAccessControlRef ac = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        flags,
        &err);
    if (!ac) { 
        if (err) {
            NSError *error = (__bridge_transfer NSError *)err;
            RCTLogError(@"❌ Failed to create access control: %@", error);
        }
        return NULL; 
    }
    
    RCTLogInfo(@"✅ Access control created successfully");

    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrApplicationTag: @"com.walletpoc.enclave.masterkey",
        (__bridge id)kSecReturnRef: @YES
    };
    
    RCTLogInfo(@"🔍 Checking for existing Enclave master key...");
    CFTypeRef existing = NULL;
    OSStatus s = SecItemCopyMatching((__bridge CFDictionaryRef)query, &existing);
    if (s == errSecSuccess && existing) {
        RCTLogInfo(@"✅ Found existing Enclave master key");
        if (ac) CFRelease(ac);
        return (SecKeyRef)existing; // caller CFRelease
    }
    
    if (s != errSecSuccess && s != errSecItemNotFound) {
        RCTLogWarn(@"⚠️ Unexpected error checking for existing key: %d", (int)s);
    }
    
    RCTLogInfo(@"🔨 Creating new Enclave master key...");

    NSDictionary *attrs = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrKeySizeInBits: @256,
        (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
        (__bridge id)kSecPrivateKeyAttrs: @{
            (__bridge id)kSecAttrIsPermanent: @YES,
            (__bridge id)kSecAttrApplicationTag: @"com.walletpoc.enclave.masterkey",
            (__bridge id)kSecAttrAccessControl: (__bridge id)ac
        }
    };
    
    CFErrorRef createErr = NULL;
    SecKeyRef priv = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &createErr);
    if (ac) CFRelease(ac);
    
    if (!priv) {
        if (createErr) {
            NSError *error = (__bridge_transfer NSError *)createErr;
            RCTLogError(@"❌ Failed to create Enclave master key: %@", error);
        } else {
            RCTLogError(@"❌ Failed to create Enclave master key: Unknown error");
        }
        return NULL;
    }
    
    RCTLogInfo(@"✅ Successfully created new Enclave master key");
    return priv; // caller CFRelease
}

// Get public key for ECIES encryption
- (SecKeyRef)copyEnclavePublicKey:(SecKeyRef)privKey {
    if (!privKey) {
        RCTLogError(@"❌ Cannot get public key: private key is nil");
        return NULL;
    }
    
    RCTLogInfo(@"🔑 Extracting public key from Enclave private key...");
    SecKeyRef pubKey = SecKeyCopyPublicKey(privKey);
    if (pubKey) {
        RCTLogInfo(@"✅ Successfully extracted public key");
    } else {
        RCTLogError(@"❌ Failed to extract public key");
    }
    return pubKey; // caller CFRelease
}

// ECIES-AESGCM wrap (encrypt) data with Enclave public key
- (NSData *)wrapWithEnclave:(NSData *)plaintext publicKey:(SecKeyRef)pub error:(NSError **)outErr {
    if (!pub) { 
        RCTLogError(@"❌ Cannot wrap data: no enclave public key");
        if (outErr) *outErr = [NSError errorWithDomain:@"SecureWallet" code:-1 userInfo:@{NSLocalizedDescriptionKey:@"No enclave public key"}]; 
        return nil; 
    }
    
    RCTLogInfo(@"🔒 Wrapping %lu bytes with ECIES-AESGCM...", (unsigned long)plaintext.length);
    
    CFErrorRef cfErr = NULL;
    CFDataRef ct = SecKeyCreateEncryptedData(pub,
        kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM,
        (__bridge CFDataRef)plaintext, &cfErr);
    
    if (!ct) {
        if (cfErr) {
            NSError *error = (__bridge_transfer NSError *)cfErr;
            RCTLogError(@"❌ ECIES encryption failed: %@", error);
            if (outErr) *outErr = error;
        } else {
            RCTLogError(@"❌ ECIES encryption failed: Unknown error");
            if (outErr) *outErr = [NSError errorWithDomain:@"SecureWallet" code:-2 userInfo:@{NSLocalizedDescriptionKey:@"ECIES encryption failed"}];
        }
        return nil;
    }
    
    NSData *result = (__bridge_transfer NSData *)ct;
    RCTLogInfo(@"✅ Successfully wrapped data (%lu bytes -> %lu bytes)", (unsigned long)plaintext.length, (unsigned long)result.length);
    return result;
}

// ECIES-AESGCM unwrap (decrypt) with Enclave private key (prompts biometry)
- (NSData *)unwrapWithEnclave:(NSData *)ciphertext error:(NSError **)outErr {
    RCTLogInfo(@"🔓 Unwrapping %lu bytes with ECIES-AESGCM...", (unsigned long)ciphertext.length);
    
    // Use cached authentication context for biometric authentication
    NSMutableDictionary *q = [@{
        (__bridge id)kSecClass: (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrApplicationTag: @"com.walletpoc.enclave.masterkey",
        (__bridge id)kSecReturnRef: @YES
    } mutableCopy];
    
    // Use cached context if available, otherwise iOS will prompt automatically
    if (self.cachedAuthContext) {
        q[(__bridge id)kSecUseAuthenticationContext] = self.cachedAuthContext;
    }
    
    RCTLogInfo(@"🔍 Retrieving Enclave private key for decryption...");
    CFTypeRef privRef = NULL;
    OSStatus s = SecItemCopyMatching((__bridge CFDictionaryRef)q, &privRef);
    if (s != errSecSuccess || !privRef) {
        RCTLogError(@"❌ Failed to retrieve Enclave key: %d", (int)s);
        if (outErr) *outErr = [NSError errorWithDomain:@"SecureWallet" code:s userInfo:@{NSLocalizedDescriptionKey:@"Enclave key not found"}];
        return nil;
    }
    
    RCTLogInfo(@"✅ Retrieved Enclave private key, attempting decryption...");
    SecKeyRef priv = (SecKeyRef)privRef;
    CFErrorRef cfErr = NULL;
    CFDataRef pt = SecKeyCreateDecryptedData(priv,
        kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM,
        (__bridge CFDataRef)ciphertext, &cfErr);
    CFRelease(priv);
    
    if (!pt) {
        if (cfErr) {
            NSError *error = (__bridge_transfer NSError *)cfErr;
            RCTLogError(@"❌ ECIES decryption failed: %@", error);
            if (outErr) *outErr = error;
        } else {
            RCTLogError(@"❌ ECIES decryption failed: Unknown error");
            if (outErr) *outErr = [NSError errorWithDomain:@"SecureWallet" code:-3 userInfo:@{NSLocalizedDescriptionKey:@"ECIES decryption failed"}];
        }
        return nil;
    }
    
    NSData *result = (__bridge_transfer NSData *)pt;
    RCTLogInfo(@"✅ Successfully unwrapped data (%lu bytes -> %lu bytes)", (unsigned long)ciphertext.length, (unsigned long)result.length);
    return result;
}

static inline void zeroize_mutable(NSMutableData *data) {
    if (!data) return;
    void *buf = (void *)data.bytes;
    if (buf && data.length > 0) {
        memset(buf, 0, data.length);
        // Create a memory barrier to prevent optimization
        __asm__ __volatile__("" ::: "memory");
        // Force a read to ensure memset isn't elided
        volatile unsigned char *p = (volatile unsigned char *)buf;
        (void)*p;
    }
}


#pragma mark - Mnemonic backup (Enclave-wrapped, device-only)

// Delete any existing encrypted mnemonic
- (BOOL)deleteEncryptedMnemonic {
    NSDictionary *q = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: kAcctEncryptedMnemonic,
        (__bridge id)kSecAttrService: kService
    };
    OSStatus s = SecItemDelete((__bridge CFDictionaryRef)q);
    return (s == errSecSuccess || s == errSecItemNotFound);
}

// Store mnemonic as ECIES (Enclave) ciphertext
- (BOOL)storeEncryptedMnemonic:(NSString *)mnemonic error:(NSError **)outErr {
    if (!mnemonic) { return NO; }
    // Wrap with Enclave public key
    SecKeyRef encPriv = [self createOrGetEnclaveKey];
    if (!encPriv) {
        if (outErr) *outErr = [NSError errorWithDomain:@"SecureWallet" code:-1 userInfo:@{NSLocalizedDescriptionKey:@"Failed to create/retrieve enclave key"}];
        return NO;
    }
    SecKeyRef encPub = [self copyEnclavePublicKey:encPriv];
    CFRelease(encPriv);
    if (!encPub) {
        if (outErr) *outErr = [NSError errorWithDomain:@"SecureWallet" code:-1 userInfo:@{NSLocalizedDescriptionKey:@"Failed to get enclave public key"}];
        return NO;
    }
    NSMutableData *mnData = [[mnemonic dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    NSError *wrapErr = nil;
    NSData *wrapped = [self wrapWithEnclave:mnData publicKey:encPub error:&wrapErr];
    CFRelease(encPub);
    zeroize_mutable(mnData);
    if (!wrapped) {
        if (outErr) *outErr = wrapErr ?: [NSError errorWithDomain:@"SecureWallet" code:-2 userInfo:@{NSLocalizedDescriptionKey:@"Failed to wrap mnemonic"}];
        return NO;
    }
    // Use SecItemUpdate to avoid race condition between delete and add
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: kAcctEncryptedMnemonic,
        (__bridge id)kSecAttrService: kService
    };
    
    NSDictionary *updateAttributes = @{
        (__bridge id)kSecValueData: wrapped,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    };
    
    OSStatus updateStatus = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)updateAttributes);
    
    if (updateStatus == errSecItemNotFound) {
        // Item doesn't exist, add it
        NSDictionary *addQ = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrAccount: kAcctEncryptedMnemonic,
            (__bridge id)kSecAttrService: kService,
            (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            (__bridge id)kSecValueData: wrapped
        };
        updateStatus = SecItemAdd((__bridge CFDictionaryRef)addQ, NULL);
    }
    
    return (updateStatus == errSecSuccess);
}

// Unwrap (biometry) and return mnemonic string
- (NSString *)revealEncryptedMnemonicWithError:(NSError **)outErr {
    NSDictionary *q = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: kAcctEncryptedMnemonic,
        (__bridge id)kSecAttrService: kService,
        (__bridge id)kSecReturnData: @YES
    };
    CFTypeRef res = NULL;
    OSStatus s = SecItemCopyMatching((__bridge CFDictionaryRef)q, &res);
    if (s != errSecSuccess) {
        if (outErr) *outErr = [NSError errorWithDomain:@"SecureWallet" code:s userInfo:@{NSLocalizedDescriptionKey:@"No encrypted mnemonic stored"}];
        return nil;
    }
    NSData *wrapped = (__bridge_transfer NSData *)res;
    NSError *unwrapErr = nil;
    NSData *pt = [self unwrapWithEnclave:wrapped error:&unwrapErr]; // prompts biometry
    if (!pt) {
        if (outErr) *outErr = unwrapErr ?: [NSError errorWithDomain:@"SecureWallet" code:-3 userInfo:@{NSLocalizedDescriptionKey:@"Failed to unwrap mnemonic"}];
        return nil;
    }
    NSMutableData *mnData = [pt mutableCopy];
    // wipe the original CFData buffer ASAP
    zeroize_mutable((NSData *)pt);
    NSString *mn = [[NSString alloc] initWithData:mnData encoding:NSUTF8StringEncoding];
    // wipe our mutable copy too
    zeroize_mutable(mnData);
    return mn;
}

#pragma mark - Wallet Methods

- (BOOL)hasExistingWallet {
    // Check for encrypted private key in Keychain
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: kAcctEncryptedPriv,
        (__bridge id)kSecAttrService: kService,
        (__bridge id)kSecReturnData: @YES
    };
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    BOOL hasEncryptedKey = (status == errSecSuccess);
    
    if (result) CFRelease(result);
    
    // Check for enclave key by application tag (new scheme)
    NSDictionary *keyQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrApplicationTag: @"com.walletpoc.enclave.masterkey",
        (__bridge id)kSecReturnRef: @YES
    };
    
    CFTypeRef keyResult = NULL;
    OSStatus keyStatus = SecItemCopyMatching((__bridge CFDictionaryRef)keyQuery, &keyResult);
    BOOL hasMasterKey = (keyStatus == errSecSuccess);
    
    if (keyResult) CFRelease(keyResult);
    
#if DEBUG
    RCTLogInfo(@"Wallet check - Has encrypted key: %@, Has master key: %@", 
               hasEncryptedKey ? @"YES" : @"NO",
               hasMasterKey ? @"YES" : @"NO");
#endif
               
    return hasEncryptedKey && hasMasterKey;
}

- (NSDictionary *)getExistingWallet {
    // Get the encrypted private key blob from Keychain (ECIES ciphertext)
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: kAcctEncryptedPriv,
        (__bridge id)kSecAttrService: kService,
        (__bridge id)kSecReturnData: @YES
    };
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    
    if (status != errSecSuccess) {
        RCTLogError(@"Failed to retrieve encrypted private key, status: %d", (int)status);
        return nil;
    }
    
    NSData *encryptedPrivateKeyData = (__bridge_transfer NSData *)result;
static inline void zeroize_mutable(NSMutableData *data) {
    // Unwrap (decrypt) with Enclave (will prompt user)
    NSError *unwrapErr = nil;
    NSData *pt = [self unwrapWithEnclave:encryptedPrivateKeyData error:&unwrapErr];
    if (!pt) {
        RCTLogError(@"Failed to unwrap private key: %@", unwrapErr.localizedDescription);
        return nil;
    }
    if (pt.length != 32) {
        zeroize_mutable((NSData *)pt);
        RCTLogError(@"Invalid private key length after unwrap");
        return nil;
    }
    NSMutableData *privateKeyData = [pt mutableCopy];
    zeroize_mutable((NSData *)pt);
    
    // Derive public key from private key
    NSString *publicKeyHex = [self derivePublicKeyFromPrivateKey:privateKeyData];
    
    if (!publicKeyHex) {
        zeroize_mutable(privateKeyData);
        RCTLogError(@"Failed to derive public key from private key");
        return nil;
    }
    
    NSDictionary *walletResult = @{
        @"publicKey": publicKeyHex,
        @"address": @"0x0000000000000000000000000000000000000000" // Placeholder - will be derived in JS
    };
    
    // wipe privkey from memory
    zeroize_mutable(privateKeyData);
    return walletResult;
}

RCT_EXPORT_METHOD(checkForExistingWallet:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    if ([self hasExistingWallet]) {
#if DEBUG
        RCTLogInfo(@"Found existing wallet, retrieving it");
#endif
        NSDictionary *existingWallet = [self getExistingWallet];
        if (existingWallet) {
            resolve(existingWallet);
            return;
        }
        RCTLogError(@"Found wallet but failed to retrieve it");
    }
    resolve(nil);
}

RCT_EXPORT_METHOD(generateSecureWallet:(NSDictionary *)config
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    RCTLogInfo(@"🚀 Starting secure wallet generation...");
    RCTLogInfo(@"📋 Config: returnMnemonic=%@, storeMnemonic=%@", 
               [[config objectForKey:@"returnMnemonic"] boolValue] ? @"YES" : @"NO",
               [[config objectForKey:@"storeMnemonic"] boolValue] ? @"YES" : @"NO");
    
    BOOL returnMnemonic = [[config objectForKey:@"returnMnemonic"] boolValue];
    BOOL storeMnemonic  = [[config objectForKey:@"storeMnemonic"] boolValue]; // explicit opt-in, Enclave-wrapped

    // First check if wallet already exists
    RCTLogInfo(@"🔍 Checking for existing wallet...");
    if ([self hasExistingWallet]) {
        RCTLogInfo(@"✅ Wallet already exists, retrieving existing one");
        NSDictionary *existingWallet = [self getExistingWallet];
        if (existingWallet) {
            RCTLogInfo(@"✅ Successfully retrieved existing wallet");
            // For existing wallets, mnemonic can only be retrieved via revealMnemonic() if stored as backup
            resolve(existingWallet);
            return;
        }
        // If we couldn't get the existing wallet, continue to create a new one
        RCTLogWarn(@"⚠️ Failed to retrieve existing wallet, creating new one");
    } else {
        RCTLogInfo(@"ℹ️ No existing wallet found, creating new one");
    }
    
    RCTLogInfo(@"🏰 Checking Secure Enclave availability...");
    if (![self isSecureEnclavePresent]) {
        RCTLogError(@"❌ Secure Enclave not available");
        reject(@"secure_enclave_error", @"Secure Enclave not available", nil);
        return;
    }
    
    RCTLogInfo(@"✅ Secure Enclave is available");

    // ---- Create 24-word mnemonic via Trust Wallet Core ----
    RCTLogInfo(@"🎲 Creating 24-word mnemonic with TrustWalletCore...");
    // Strength 256 => 24 words. Passphrase empty by default; add one if you support it.
    TWString *twPass = TWStringCreateWithUTF8Bytes("");
    TWHDWallet *twWallet = TWHDWalletCreate(256, twPass); // strength, passphrase
    TWString *twMn = TWHDWalletMnemonic(twWallet);
    const char *mnCStr = TWStringUTF8Bytes(twMn);
    NSString *mnemonic = [NSString stringWithUTF8String:mnCStr];
    
    RCTLogInfo(@"✅ Successfully generated mnemonic (%lu words)", (unsigned long)[[mnemonic componentsSeparatedByString:@" "] count]);


    // ---- Derive m/44'/60'/0'/0/0 private key ----
    RCTLogInfo(@"🔑 Deriving private key from mnemonic (path: m/44'/60'/0'/0/0)...");
    // Use getKeyForCoin which uses the standard Ethereum path m/44'/60'/0'/0/0
    // This method is recommended for Ethereum because it handles the path internally
    TWPrivateKey *twPriv = TWHDWalletGetKeyForCoin(twWallet, TWCoinTypeEthereum);
    TWData *twPkData = TWPrivateKeyData(twPriv); // 32 bytes
    NSMutableData *privateKeyData = [NSMutableData dataWithBytes:TWDataBytes(twPkData)
                                                          length:TWDataSize(twPkData)];
    
    RCTLogInfo(@"✅ Derived private key (%lu bytes)", (unsigned long)privateKeyData.length);
    
    if (privateKeyData.length != 32) {
        RCTLogError(@"❌ Unexpected private key length: %lu (expected 32)", (unsigned long)privateKeyData.length);
        // cleanup TWC objects
        TWDataDelete(twPkData); TWPrivateKeyDelete(twPriv);
        TWStringDelete(twMn); TWHDWalletDelete(twWallet); TWStringDelete(twPass);
        reject(@"key_derivation_error", @"Unexpected private key length", nil);
        return;
    }

    // ---- Validate private key with TrustWalletCore ----
    RCTLogInfo(@"🔍 Validating private key with TrustWalletCore...");
    TWData *pkInput = TWDataCreateWithNSData(privateKeyData);
    BOOL isValid = TWPrivateKeyIsValid(pkInput, TWCurveSECP256k1);
    TWDataDelete(pkInput);
    if (!isValid) {
        RCTLogError(@"❌ Invalid secp256k1 private key");
        // cleanup TWC objects
        TWDataDelete(twPkData); TWPrivateKeyDelete(twPriv);
        TWStringDelete(twMn); TWHDWalletDelete(twWallet); TWStringDelete(twPass);
        reject(@"key_derivation_error", @"Invalid secp256k1 private key", nil);
        return;
    }
    
    RCTLogInfo(@"✅ Private key validation passed");

    // ---- Wrap with Enclave ECIES and store in Keychain ----
    RCTLogInfo(@"🔐 Creating/retrieving Enclave key for encryption...");
    SecKeyRef enclavePriv = [self createOrGetEnclaveKey];
    if (!enclavePriv) {
        RCTLogError(@"❌ Failed to create/retrieve enclave key");
        // cleanup TWC objects
        TWDataDelete(twPkData); TWPrivateKeyDelete(twPriv);
        TWStringDelete(twMn); TWHDWalletDelete(twWallet); TWStringDelete(twPass);
        reject(@"key_generation_error", @"Failed to create/retrieve enclave key", nil);
        return;
    }
    
    RCTLogInfo(@"🔑 Getting Enclave public key for encryption...");
    SecKeyRef enclavePub = [self copyEnclavePublicKey:enclavePriv];
    if (!enclavePub) {
        RCTLogError(@"❌ Failed to get enclave public key");
        CFRelease(enclavePriv);
        // cleanup TWC objects
        TWDataDelete(twPkData); TWPrivateKeyDelete(twPriv);
        TWStringDelete(twMn); TWHDWalletDelete(twWallet); TWStringDelete(twPass);
        reject(@"key_generation_error", @"Failed to get enclave public key", nil);
        return;
    }
    
    RCTLogInfo(@"🔒 Wrapping private key with ECIES encryption...");
    NSError *wrapErr = nil;
    NSData *wrappedPrivKey = [self wrapWithEnclave:privateKeyData publicKey:enclavePub error:&wrapErr];
    CFRelease(enclavePub);
    CFRelease(enclavePriv);
    if (!wrappedPrivKey) {
        RCTLogError(@"❌ Failed to wrap private key: %@", wrapErr.localizedDescription);
        // cleanup TWC objects
        TWDataDelete(twPkData); TWPrivateKeyDelete(twPriv);
        TWStringDelete(twMn); TWHDWalletDelete(twWallet); TWStringDelete(twPass);
        reject(@"encryption_error", wrapErr.localizedDescription ?: @"Failed to wrap private key", nil);
        return;
    }
    
    RCTLogInfo(@"✅ Successfully wrapped private key (%lu bytes)", (unsigned long)wrappedPrivKey.length);

    // Replace any existing ciphertext to avoid errSecDuplicateItem
    RCTLogInfo(@"🗑️ Removing any existing encrypted private key from Keychain...");
    NSDictionary *delQ = @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrAccount: kAcctEncryptedPriv,
                            (__bridge id)kSecAttrService: kService };
    OSStatus deleteStatus = SecItemDelete((__bridge CFDictionaryRef)delQ);
    if (deleteStatus == errSecSuccess) {
        RCTLogInfo(@"✅ Removed existing encrypted private key");
    } else if (deleteStatus == errSecItemNotFound) {
        RCTLogInfo(@"ℹ️ No existing encrypted private key found");
    } else {
        RCTLogWarn(@"⚠️ Unexpected error removing existing key: %d", (int)deleteStatus);
    }

    RCTLogInfo(@"💾 Storing encrypted private key in Keychain...");
    NSDictionary *addQ = @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrAccount: kAcctEncryptedPriv,
                            (__bridge id)kSecAttrService: kService,
                            (__bridge id)kSecValueData: wrappedPrivKey,
                            (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly };
    OSStatus storeStatus = SecItemAdd((__bridge CFDictionaryRef)addQ, NULL);
    if (storeStatus != errSecSuccess) {
        RCTLogError(@"❌ Failed to store encrypted private key in Keychain: %d", (int)storeStatus);
        // cleanup TWC objects
        TWDataDelete(twPkData); TWPrivateKeyDelete(twPriv);
        TWStringDelete(twMn); TWHDWalletDelete(twWallet); TWStringDelete(twPass);
        reject(@"keychain_error", @"Failed to store encrypted private key", nil);
        return;
    }
    
    RCTLogInfo(@"✅ Successfully stored encrypted private key in Keychain");

    // ---- Derive uncompressed public key for display ----
    RCTLogInfo(@"🔑 Deriving public key for display...");
    TWPublicKey *twPub = TWPrivateKeyGetPublicKeySecp256k1(twPriv, false /* uncompressed */);
    TWData *twPubData = TWPublicKeyData(twPub);
    NSData *pubNSData = [NSData dataWithBytes:TWDataBytes(twPubData) length:TWDataSize(twPubData)];
    NSString *publicKeyHex = [self formatPublicKey:pubNSData];
    
    RCTLogInfo(@"✅ Derived public key: %@", publicKeyHex);

    // Optional: Enclave-wrapped mnemonic backup (device-only). Not synced.
    if (storeMnemonic && !returnMnemonic) {
        RCTLogInfo(@"💾 Storing encrypted mnemonic backup...");
        NSError *mnErr = nil;
        if (![self storeEncryptedMnemonic:mnemonic error:&mnErr]) {
            RCTLogError(@"❌ Failed to store encrypted mnemonic: %@", mnErr.localizedDescription);
            // cleanup TWC objects
            TWDataDelete(twPubData); TWPublicKeyDelete(twPub);
            TWDataDelete(twPkData); TWPrivateKeyDelete(twPriv);
            TWStringDelete(twMn); TWHDWalletDelete(twWallet); TWStringDelete(twPass);
            reject(@"keychain_error", mnErr.localizedDescription ?: @"Failed to store encrypted mnemonic", nil);
            return;
        }
        RCTLogInfo(@"✅ Successfully stored encrypted mnemonic backup");
    } else if (!returnMnemonic) {
        RCTLogInfo(@"ℹ️ Not storing mnemonic (not requested)");
        // Do not keep a reference around if not returning/storing
        mnemonic = nil;
    }

    // ---- Cleanup TWC objects; zeroize 32-byte key buffer ----
    RCTLogInfo(@"🧹 Cleaning up TrustWalletCore objects and zeroizing sensitive data...");
    // (NSData is immutable; we held a copy. Zeroize that copy now.)
    zeroize_mutable(privateKeyData);
    TWDataDelete(twPubData); TWPublicKeyDelete(twPub);
    TWDataDelete(twPkData);  TWPrivateKeyDelete(twPriv);
    TWStringDelete(twMn); TWHDWalletDelete(twWallet); TWStringDelete(twPass);

    // ---- Resolve ----
    RCTLogInfo(@"✅ Wallet generation completed successfully");
    NSMutableDictionary *walletResult = [@{
        @"publicKey": publicKeyHex,
        @"address": @"0x0000000000000000000000000000000000000000" // let JS compute checksummed addr
    } mutableCopy];
    if (returnMnemonic) {
        RCTLogInfo(@"📝 Including mnemonic in response");
        walletResult[@"mnemonic"] = mnemonic;
    }
    
    RCTLogInfo(@"🎉 Secure wallet generation completed successfully");
    resolve(walletResult);
}

RCT_EXPORT_METHOD(storePrivateKeyHex:(NSString *)privateKeyHex
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    // Convert hex string to data (mutable buffer for reliable zeroization)
    NSData *tmp = [self hexStringToData:privateKeyHex];
    NSMutableData *privateKeyData = tmp ? [tmp mutableCopy] : nil;
    if (!privateKeyData || privateKeyData.length != 32) {
        reject(@"invalid_key", @"Private key must be 32 bytes (64 hex chars)", nil);
        return;
    }
    
    // Validate private key with TrustWalletCore
    TWData *pkInput = TWDataCreateWithNSData(privateKeyData);
    BOOL isValid = TWPrivateKeyIsValid(pkInput, TWCurveSECP256k1);
    TWDataDelete(pkInput);
    if (!isValid) {
        zeroize_mutable(privateKeyData);
        RCTLogError(@"Private key is not valid for secp256k1");
        reject(@"validation_error", @"Invalid private key for secp256k1", nil);
        return;
    }
    
    // Wrap the 32-byte private key with Enclave ECIES
    SecKeyRef enclavePriv = [self createOrGetEnclaveKey];
    if (!enclavePriv) {
        zeroize_mutable(privateKeyData);
        reject(@"key_generation_error", @"Failed to create/retrieve enclave key", nil);
        return;
    }
    SecKeyRef enclavePub = [self copyEnclavePublicKey:enclavePriv];
    if (!enclavePub) {
        CFRelease(enclavePriv);
        zeroize_mutable(privateKeyData);
        reject(@"key_generation_error", @"Failed to get enclave public key", nil);
        return;
    }
    NSError *wrapErr = nil;
    NSData *wrappedPrivKey = [self wrapWithEnclave:privateKeyData publicKey:enclavePub error:&wrapErr];
    CFRelease(enclavePub);
    CFRelease(enclavePriv);
    if (!wrappedPrivKey) {
        zeroize_mutable(privateKeyData);
        reject(@"encryption_error", wrapErr.localizedDescription ?: @"Failed to wrap private key", nil);
        return;
    }
    
    // Replace any existing ciphertext to avoid errSecDuplicateItem
    NSDictionary *delQ = @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrAccount: kAcctEncryptedPriv,
                            (__bridge id)kSecAttrService: kService };
    SecItemDelete((__bridge CFDictionaryRef)delQ);

    // Store encrypted private key in Keychain
    NSDictionary *encryptedKeyQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: kAcctEncryptedPriv,
        (__bridge id)kSecValueData: wrappedPrivKey,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        (__bridge id)kSecAttrService: kService
    };
    
    OSStatus storeStatus = SecItemAdd((__bridge CFDictionaryRef)encryptedKeyQuery, NULL);
    if (storeStatus != errSecSuccess) {
        zeroize_mutable(privateKeyData);
        reject(@"keychain_error", @"Failed to store encrypted private key", nil);
        return;
    }
    
    // Derive public key for response
    NSString *publicKeyHex = [self derivePublicKeyFromPrivateKey:privateKeyData];
    zeroize_mutable(privateKeyData);
    
    resolve(@{
        @"publicKey": publicKeyHex,
        @"address": @"0x0000000000000000000000000000000000000000" // JavaScript will derive the correct address
    });
}

RCT_EXPORT_METHOD(signTransactionHash:(NSString *)transactionHash
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    // Get the encrypted private key blob from Keychain
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: kAcctEncryptedPriv,
        (__bridge id)kSecAttrService: kService,
        (__bridge id)kSecReturnData: @YES
    };
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    
    if (status != errSecSuccess) {
        RCTLogError(@"❌ Failed to retrieve encrypted private key from Keychain: %d", (int)status);
        reject(@"key_error", @"Failed to retrieve encrypted private key", nil);
        return;
    }
    
    NSData *encryptedPrivateKeyData = (__bridge_transfer NSData *)result;

    // Unwrap with Enclave (biometry)
    NSError *unwrapErr = nil;
    NSData *pt = [self unwrapWithEnclave:encryptedPrivateKeyData error:&unwrapErr];
    if (!pt) {
        RCTLogError(@"❌ Failed to unwrap private key: %@", unwrapErr.localizedDescription);
        reject(@"decrypt_error", unwrapErr.localizedDescription ?: @"Failed to unwrap private key", nil);
        return;
    }
    
    if (pt.length != 32) {
        RCTLogError(@"❌ Invalid private key length after unwrap: %lu (expected 32)", (unsigned long)pt.length);
        zeroize_mutable((NSData *)pt);
        reject(@"decrypt_error", @"Invalid private key length after unwrap", nil);
        return;
    }
    
    NSMutableData *privateKeyData = [pt mutableCopy];
    zeroize_mutable((NSData *)pt);
    
    // Convert transaction hash to data
    NSData *hashData = [self hexStringToData:transactionHash];
    if (!hashData) {
        RCTLogError(@"❌ Invalid transaction hash format");
        zeroize_mutable(privateKeyData);
        reject(@"invalid_hash", @"Invalid transaction hash format", nil);
        return;
    }
    
    if (hashData.length != 32) {
        RCTLogError(@"❌ Transaction hash must be 32 bytes, got %lu", (unsigned long)hashData.length);
        zeroize_mutable(privateKeyData);
        reject(@"invalid_hash", @"Transaction hash must be 32 bytes", nil);
        return;
    }
    
    // Use TrustWalletCore for signing
    TWData *pkBytes = TWDataCreateWithNSData(privateKeyData);
    TWPrivateKey *pk = TWPrivateKeyCreateWithData(pkBytes);
    TWDataDelete(pkBytes);
    if (!pk) {
        RCTLogError(@"❌ Failed to create TrustWalletCore private key object");
        zeroize_mutable(privateKeyData);
        reject(@"signing_error", @"Failed to create private key", nil);
        return;
    }
    
    TWData *twDigest = TWDataCreateWithNSData(hashData);
    TWData *der = TWPrivateKeySign(pk, twDigest, TWCurveSECP256k1);
    TWDataDelete(twDigest);
    if (!der) {
        RCTLogError(@"❌ TrustWalletCore signing failed");
        TWPrivateKeyDelete(pk);
        zeroize_mutable(privateKeyData);
        reject(@"signing_error", @"Failed to sign transaction", nil);
        return;
    }
    
    // Convert TWData to NSData for easier manipulation
    NSData *signatureData = [NSData dataWithBytes:TWDataBytes(der) length:TWDataSize(der)];

    NSMutableData *r = nil, *s = nil;

    // Debug: Log signature format
    RCTLogInfo(@"🔍 Signature length: %lu bytes", (unsigned long)signatureData.length);
    if (signatureData.length > 0) {
        RCTLogInfo(@"🔍 First byte: 0x%02x", ((const unsigned char*)signatureData.bytes)[0]);
    }

    // Decide format and parse
    NSString *sigFormat = @"";
    if (signatureData.length == 64) {
        // Raw signature: first 32 bytes are r, last 32 bytes are s
        r = [NSMutableData dataWithBytes:signatureData.bytes length:32];
        s = [NSMutableData dataWithBytes:(const char*)signatureData.bytes + 32 length:32];
        sigFormat = @"raw64";
        RCTLogInfo(@"✅ Parsed as raw signature (64 bytes)");
    } else if (*((const unsigned char*)signatureData.bytes) == 0x30) {
        // DER sequence
        if (![self parseDERSigSafe:signatureData r:&r s:&s]) {
            RCTLogError(@"❌ Failed to parse DER signature");
            TWDataDelete(der);
            TWPrivateKeyDelete(pk);
            zeroize_mutable(privateKeyData);
            reject(@"signing_error", @"Failed to parse DER signature", nil);
            return;
        }
        sigFormat = @"der";
        RCTLogInfo(@"✅ Parsed as DER signature");
    } else if (signatureData.length == 65) {
        // Common format: r(32) || s(32) || v(1)
        const unsigned char *bytes = (const unsigned char*)signatureData.bytes;
        r = [NSMutableData dataWithBytes:bytes length:32];
        s = [NSMutableData dataWithBytes:bytes + 32 length:32];
        unsigned char vByte = bytes[64];
        sigFormat = @"rsv65";
        RCTLogInfo(@"✅ Parsed as 65-byte signature (r||s||v), v=0x%02x", vByte);
    } else {
        RCTLogError(@"❌ Unsupported signature format (len=%lu, first=0x%02x)", (unsigned long)signatureData.length, signatureData.length ? ((const unsigned char*)signatureData.bytes)[0] : 0);
        TWDataDelete(der);
        TWPrivateKeyDelete(pk);
        zeroize_mutable(privateKeyData);
        reject(@"signing_error", @"Unsupported signature format", nil);
        return;
    }
    
    // Canonicalize s value (must be ≤ n/2 for ECDSA)
    NSMutableData *canonicalS = [s mutableCopy];
    [self canonicalizeS:canonicalS];
    
    NSString *rHex = [self formatPublicKey:r];
    NSString *sHex = [self formatPublicKey:canonicalS];
    
    // Get public key for verification
    TWPublicKey *pub = TWPrivateKeyGetPublicKeySecp256k1(pk, false);
    TWData *pubData = TWPublicKeyData(pub);
    NSData *pubNS = [NSData dataWithBytes:TWDataBytes(pubData) length:TWDataSize(pubData)];
    NSString *pubHex = [self formatPublicKey:pubNS];
    
    // Cleanup
    TWDataDelete(pubData);
    TWPublicKeyDelete(pub);
    TWDataDelete(der);
    TWPrivateKeyDelete(pk);
    zeroize_mutable(privateKeyData);
    
    // Include signature diagnostics
    NSString *sigHex = [self formatPublicKey:signatureData];
    resolve(@{
        @"r": rHex,
        @"s": sHex,
        @"v": @27,            // placeholder; JS overwrites it
        @"publicKey": pubHex,
        @"sigFormat": sigFormat,
        @"sigHex": sigHex
    });
}

// Removed: SHA-256 placeholder derivation. Now using Trust Wallet Core for proper BIP39/32/44.

// Safe DER parsing with comprehensive bounds checking
- (BOOL)parseDERSigSafe:(NSData *)der r:(NSMutableData **)rOut s:(NSMutableData **)sOut {
    const unsigned char *p = (const unsigned char *)der.bytes;
    size_t len = der.length;
    
    // Basic validation
    if (len < 8) {
        RCTLogError(@"❌ DER too short: %lu bytes", (unsigned long)len);
        return NO;
    }
    
    if (p[0] != 0x30) {
        RCTLogError(@"❌ Invalid DER header: 0x%02x", p[0]);
        return NO;
    }
    
    // Parse length
    size_t idx = 2;
    if (p[1] & 0x80) {
        size_t lengthBytes = p[1] & 0x7F;
        if (lengthBytes == 0 || lengthBytes > 4) {
            RCTLogError(@"❌ Invalid length encoding: %lu bytes", (unsigned long)lengthBytes);
            return NO;
        }
        idx = 2 + lengthBytes;
        if (idx > len) {
            RCTLogError(@"❌ Length encoding out of bounds");
            return NO;
        }
    }
    
    // Parse r component
    if (idx >= len || p[idx] != 0x02) {
        RCTLogError(@"❌ Missing r component marker");
        return NO;
    }
    idx++;
    
    if (idx >= len) {
        RCTLogError(@"❌ Incomplete r length");
        return NO;
    }
    
    size_t rlen = p[idx++];
    if (rlen & 0x80) {
        size_t lengthBytes = rlen & 0x7F;
        if (lengthBytes == 0 || lengthBytes > 4) {
            RCTLogError(@"❌ Invalid r length encoding");
            return NO;
        }
        rlen = 0;
        for (size_t i = 0; i < lengthBytes; i++) {
            if (idx >= len) {
                RCTLogError(@"❌ r length encoding out of bounds");
                return NO;
            }
            rlen = (rlen << 8) | p[idx++];
        }
    }
    
    if (idx + rlen > len) {
        RCTLogError(@"❌ r component out of bounds");
        return NO;
    }
    
    NSData *rRaw = [NSData dataWithBytes:p + idx length:rlen];
    idx += rlen;
    
    // Parse s component
    if (idx >= len || p[idx] != 0x02) {
        RCTLogError(@"❌ Missing s component marker");
        return NO;
    }
    idx++;
    
    if (idx >= len) {
        RCTLogError(@"❌ Incomplete s length");
        return NO;
    }
    
    size_t slen = p[idx++];
    if (slen & 0x80) {
        size_t lengthBytes = slen & 0x7F;
        if (lengthBytes == 0 || lengthBytes > 4) {
            RCTLogError(@"❌ Invalid s length encoding");
            return NO;
        }
        slen = 0;
        for (size_t i = 0; i < lengthBytes; i++) {
            if (idx >= len) {
                RCTLogError(@"❌ s length encoding out of bounds");
                return NO;
            }
            slen = (slen << 8) | p[idx++];
        }
    }
    
    if (idx + slen > len) {
        RCTLogError(@"❌ s component out of bounds");
        return NO;
    }
    
    NSData *sRaw = [NSData dataWithBytes:p + idx length:slen];
    
    // Create padded 32-byte components
    NSMutableData *r = [NSMutableData dataWithLength:32];
    NSMutableData *s = [NSMutableData dataWithLength:32];
    
    // Copy r component with proper padding
    if (rRaw.length <= 32) {
        size_t offset = 32 - rRaw.length;
        memcpy((char*)r.mutableBytes + offset, rRaw.bytes, rRaw.length);
    } else {
        RCTLogError(@"❌ r component too long: %lu bytes", (unsigned long)rRaw.length);
        return NO;
    }
    
    // Copy s component with proper padding
    if (sRaw.length <= 32) {
        size_t offset = 32 - sRaw.length;
        memcpy((char*)s.mutableBytes + offset, sRaw.bytes, sRaw.length);
    } else {
        RCTLogError(@"❌ s component too long: %lu bytes", (unsigned long)sRaw.length);
        return NO;
    }
    
    if (rOut) *rOut = r;
    if (sOut) *sOut = s;
    
    return YES;
}

// Canonicalize s value for ECDSA (must be ≤ n/2)
- (void)canonicalizeS:(NSMutableData *)s {
    // secp256k1 curve order n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    // n/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    
    const unsigned char *bytes = (const unsigned char*)s.bytes;
    
    // Check if s > n/2
    unsigned char nHalf[32] = {
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
        0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0
    };
    
    bool needsFlip = false;
    for (int i = 0; i < 32; i++) {
        if (bytes[i] > nHalf[i]) {
            needsFlip = true;
            break;
        } else if (bytes[i] < nHalf[i]) {
            break;
        }
    }
    
    if (needsFlip) {
        // s = n - s
        unsigned char n[32] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
        };
        
        unsigned char result[32];
        int borrow = 0;
        for (int i = 31; i >= 0; i--) {
            int diff = n[i] - bytes[i] - borrow;
            if (diff < 0) {
                diff += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            result[i] = diff;
        }
        
        [s replaceBytesInRange:NSMakeRange(0, 32) withBytes:result];
    }
}

// Derive public key from private key using secp256k1
- (NSString *)derivePublicKeyFromPrivateKey:(NSData *)privateKeyData {
    TWData *pkBytes = TWDataCreateWithNSData(privateKeyData);
    TWPrivateKey *pk = TWPrivateKeyCreateWithData(pkBytes);
    TWDataDelete(pkBytes);
    if (!pk) return nil;
    
    TWPublicKey *pub = TWPrivateKeyGetPublicKeySecp256k1(pk, false /* uncompressed */);
    if (!pub) {
        TWPrivateKeyDelete(pk);
        return nil;
    }
    
    TWData *d = TWPublicKeyData(pub);
    NSData *data = [NSData dataWithBytes:TWDataBytes(d) length:TWDataSize(d)];
    NSString *hex = [self formatPublicKey:data];
    
    TWDataDelete(d);
    TWPublicKeyDelete(pub);
    TWPrivateKeyDelete(pk);
    
    return hex;
}

// Sign with secp256k1 using libsecp256k1 - EVM compatible format
- (NSData *)signWithSecp256k1:(NSData *)privateKeyData hashData:(NSData *)hashData {
    // Deprecated by recoverable path; kept for compatibility if needed.
    return nil;
}

// Get recovery ID for EVM transactions
- (int)getRecoveryId:(NSData *)signatureData hashData:(NSData *)hashData publicKey:(NSData *)publicKeyData {
    // Deprecated; recoverable signing used directly in signTransactionHash:
    return 0;
}

// Helper method to get public key as NSData
- (NSData *)derivePublicKeyDataFromPrivateKey:(NSData *)privateKeyData {
    TWData *pkBytes = TWDataCreateWithNSData(privateKeyData);
    TWPrivateKey *pk = TWPrivateKeyCreateWithData(pkBytes);
    TWDataDelete(pkBytes);
    if (!pk) return nil;
    
    TWPublicKey *pub = TWPrivateKeyGetPublicKeySecp256k1(pk, false /* uncompressed */);
    if (!pub) {
        TWPrivateKeyDelete(pk);
        return nil;
    }
    
    TWData *d = TWPublicKeyData(pub);
    NSData *data = [NSData dataWithBytes:TWDataBytes(d) length:TWDataSize(d)];
    
    TWDataDelete(d);
    TWPublicKeyDelete(pub);
    TWPrivateKeyDelete(pk);
    
    return data;
}

// Helper method to convert hex string to NSData
- (NSData *)hexStringToData:(NSString *)hexString {
    // Remove '0x' prefix if present
    NSString *cleanHex = [hexString hasPrefix:@"0x"] ? [hexString substringFromIndex:2] : hexString;
    
    // Add length validation
    if (cleanHex.length > 128) { // 64 bytes max
        return nil;
    }
    
    if (cleanHex.length % 2 != 0) {
        return nil;
    }
    
    NSMutableData *data = [NSMutableData dataWithLength:cleanHex.length / 2];
    unsigned char *bytes = (unsigned char *)data.mutableBytes;
    
    for (NSUInteger i = 0; i < cleanHex.length; i += 2) {
        NSString *byteString = [cleanHex substringWithRange:NSMakeRange(i, 2)];
        unsigned int byte;
        if (![[NSScanner scannerWithString:byteString] scanHexInt:&byte]) {
            return nil;
        }
        bytes[i / 2] = byte;
    }
    
    return data;
}

// Check if encrypted mnemonic backup exists (for UI state)
RCT_EXPORT_METHOD(hasMnemonicBackup:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSDictionary *q = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: kAcctEncryptedMnemonic,
        (__bridge id)kSecAttrService: kService,
        (__bridge id)kSecReturnData: @NO
    };
    OSStatus s = SecItemCopyMatching((__bridge CFDictionaryRef)q, NULL);
    resolve(@(s == errSecSuccess));
}

// Biometry-gated mnemonic reveal (only works if stored as Enclave-wrapped backup)
RCT_EXPORT_METHOD(revealMnemonic:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    // This method will trigger biometric authentication when accessing the Enclave key
    NSError *err = nil;
    NSString *mn = [self revealEncryptedMnemonicWithError:&err];
    if (!mn) {
        reject(@"no_backup", err.localizedDescription ?: @"No encrypted mnemonic stored or authentication failed", nil);
        return;
    }
    resolve(mn);
}

RCT_EXPORT_METHOD(deleteWallet:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    // Require authentication before deletion
    LAContext *context = [[LAContext alloc] init];
    NSError *authError = nil;
    
    // Check if biometric authentication is available
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&authError]) {
        // Use biometric authentication
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                localizedReason:@"Authenticate to delete your hardware wallet"
                          reply:^(BOOL success, NSError *error) {
            if (success) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self performWalletDeletion:resolve rejecter:reject];
                });
            } else {
                dispatch_async(dispatch_get_main_queue(), ^{
                    if (error.code == LAErrorUserCancel) {
                        reject(@"auth_canceled", @"Authentication canceled by user", error);
                    } else {
                        reject(@"auth_failed", @"Authentication failed", error);
                    }
                });
            }
        }];
    } else if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&authError]) {
        // Fallback to device passcode
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
                localizedReason:@"Authenticate to delete your hardware wallet"
                          reply:^(BOOL success, NSError *error) {
            if (success) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self performWalletDeletion:resolve rejecter:reject];
                });
            } else {
                dispatch_async(dispatch_get_main_queue(), ^{
                    if (error.code == LAErrorUserCancel) {
                        reject(@"auth_canceled", @"Authentication canceled by user", error);
                    } else {
                        reject(@"auth_failed", @"Authentication failed", error);
                    }
                });
            }
        }];
    } else {
        // No authentication available
        reject(@"auth_unavailable", @"No authentication method available", authError);
    }
}

- (void)performWalletDeletion:(RCTPromiseResolveBlock)resolve
                     rejecter:(RCTPromiseRejectBlock)reject {
    // Delete encrypted mnemonic (if present)
    NSDictionary *mnemonicQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: kAcctEncryptedMnemonic,
        (__bridge id)kSecAttrService: kService
    };
    OSStatus mnemonicStatus = SecItemDelete((__bridge CFDictionaryRef)mnemonicQuery);
    
    // Delete encrypted private key from Keychain
    NSDictionary *encryptedKeyQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: kAcctEncryptedPriv,
        (__bridge id)kSecAttrService: kService
    };
    
    OSStatus encryptedKeyStatus = SecItemDelete((__bridge CFDictionaryRef)encryptedKeyQuery);
    
    // No separate AES key stored anymore
    OSStatus encryptedAesKeyStatus = errSecSuccess;
    
    // Delete Enclave key by application tag
    NSDictionary *masterKeyQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrApplicationTag: @"com.walletpoc.enclave.masterkey"
    };
    OSStatus masterKeyStatus = SecItemDelete((__bridge CFDictionaryRef)masterKeyQuery);
    
    // Log the deletion results
#if DEBUG
    RCTLogInfo(@"Delete results - Mnemonic: %d, Encrypted Key: %d, Encrypted AES Key: %d, Master Key: %d", 
               (int)mnemonicStatus, (int)encryptedKeyStatus, (int)encryptedAesKeyStatus, (int)masterKeyStatus);
#endif
    
    // Consider it successful if all items are either deleted or not found
    BOOL mnemonicDeleted = (mnemonicStatus == errSecSuccess || mnemonicStatus == errSecItemNotFound);
    BOOL encryptedKeyDeleted = (encryptedKeyStatus == errSecSuccess || encryptedKeyStatus == errSecItemNotFound);
    BOOL encryptedAesKeyDeleted = (encryptedAesKeyStatus == errSecSuccess || encryptedAesKeyStatus == errSecItemNotFound);
    BOOL masterKeyDeleted = (masterKeyStatus == errSecSuccess || masterKeyStatus == errSecItemNotFound);
    
    if (mnemonicDeleted && encryptedKeyDeleted && encryptedAesKeyDeleted && masterKeyDeleted) {
#if DEBUG
        RCTLogInfo(@"Successfully deleted all wallet data");
#endif
        resolve(@YES);
    } else {
        NSString *errorMsg = [NSString stringWithFormat:@"Failed to delete some wallet data - Mnemonic: %@, Encrypted Key: %@, Encrypted AES Key: %@, Master Key: %@",
                             mnemonicDeleted ? @"YES" : @"NO",
                             encryptedKeyDeleted ? @"YES" : @"NO",
                             encryptedAesKeyDeleted ? @"YES" : @"NO",
                             masterKeyDeleted ? @"YES" : @"NO"];
        reject(@"delete_error", errorMsg, nil);
    }
}

// Removed: deriveEncryptionKeyFromMasterKey (unsafe). We now use ECIES via Security framework.

// Derive Ethereum address from public key
- (NSString *)deriveEthereumAddressFromPublicKey:(NSData *)publicKeyData {
    // Note: This method is not used anymore since we let JavaScript handle address derivation
    // The JavaScript side uses ethers.js which has proper Keccak-256 implementation
    return @"0x0000000000000000000000000000000000000000";
}

@end