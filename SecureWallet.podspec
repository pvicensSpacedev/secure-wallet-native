require 'json'

package = JSON.parse(File.read(File.join(__dir__, './package.json')))

Pod::Spec.new do |s|
  s.name           = 'SecureWallet'
  s.version        = package['version']
  s.summary        = 'Secure wallet implementation using iOS Secure Enclave'
  s.description    = 'Native module for secure key generation and storage using iOS Secure Enclave'
  s.homepage       = package['repository']['url']
  s.license        = { :type => package['license'], :text => 'MIT License' }
  s.author         = { package['author'].split(' <')[0] => package['author'].split('<')[1].split('>')[0] }
  s.platform       = :ios, '15.1'
  s.source         = { :git => package['repository']['url'], :tag => "v#{s.version}" }
  s.source_files   = 'ios/*.{h,m}'
  s.requires_arc   = true
  
  s.dependency 'React-Core'
  s.dependency 'secp256k1', '~> 0.2.0'  # Use older version to avoid header issues
  
  # React Native auto-linking support
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'SWIFT_COMPILATION_MODE' => 'wholemodule',
    'GCC_PREPROCESSOR_DEFINITIONS' => 'SECP256K1_BUILD=1 SECP256K1_ENABLE_MODULE_ECDH=1 SECP256K1_ENABLE_MODULE_SCHNORRSIG=1',
    'HEADER_SEARCH_PATHS' => '$(PODS_ROOT)/secp256k1/include',
    'CLANG_WARN_DOCUMENTATION_COMMENTS' => 'NO'
  }
  
  # Add this to ensure secp256k1 builds correctly
  s.xcconfig = {
    'GCC_PREPROCESSOR_DEFINITIONS' => 'SECP256K1_BUILD=1 SECP256K1_ENABLE_MODULE_ECDH=1 SECP256K1_ENABLE_MODULE_SCHNORRSIG=1'
  }
  
  s.module_name = 'SecureWallet'
  
  # Ensure proper module structure for auto-linking
  s.module_map = 'ios/SecureWallet.modulemap'
end