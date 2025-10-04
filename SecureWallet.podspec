require 'json'
package = JSON.parse(File.read(File.join(__dir__, './package.json')))

Pod::Spec.new do |s|
  s.name         = 'SecureWallet'
  s.version      = package['version']
  s.summary      = 'Secure wallet implementation using iOS Secure Enclave'
  s.description  = 'Native module for secure key generation and storage using iOS Secure Enclave'
  s.homepage     = package['repository']['url']
  s.license      = { :type => package['license'], :text => 'MIT License' }
  s.author       = { package['author'].split(' <')[0] => package['author'].split('<')[1].split('>')[0] }
  s.platform     = :ios, '15.1'

  s.source       = { :git => package['repository']['url'], :tag => "v#{s.version}" }
  s.source_files = 'ios/*.{h,m,mm}'
  s.resources    = 'ios/*.txt'
  s.requires_arc = true

  # Deps
  s.dependency 'React-Core'
  s.dependency 'TrustWalletCore'

  s.frameworks = 'Security', 'LocalAuthentication'
  s.libraries  = 'c++'

  # Keep config minimal; let CocoaPods expose headers/modules.
  s.pod_target_xcconfig = {
    'CLANG_ENABLE_MODULES'   => 'YES',
    'DEFINES_MODULE'         => 'YES',
    'HEADER_SEARCH_PATHS'    => '$(inherited)'
  }

  # Only keep this if you actually have the file; otherwise remove it.
  # s.module_map = 'ios/SecureWallet.modulemap'

  s.module_name = 'SecureWallet'
end
