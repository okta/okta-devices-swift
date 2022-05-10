Pod::Spec.new do |s|
  s.name             = 'DeviceAuthenticator'
  s.version          = '0.0.1'
  s.summary          = 'Okta Authenticator SDK'
  s.description      = <<-DESC
SDK for iOS devices for communicating with Okta's device APIs
                       DESC
  s.platforms        = { :ios => "13.0" }
  s.homepage         = 'https://github.com/okta/okta-devices-swift'
  s.license          = { :type => 'APACHE2', :file => 'LICENSE' }
  s.authors          = { "Okta Developers" => "developer@okta.com" }

  # Library configuration
  s.swift_version = '5.3'
  s.source            = { :http => 'https://github.com/okta/okta-devices-swift/releases/download/0.0.1/DeviceAuthenticator.zip' } 
  s.ios.vendored_frameworks = 'DeviceAuthenticator.xcframework'

  # Dependencies
  s.dependency 'SwiftBase32','0.8.0'
  s.dependency 'GRDB.swift','~>5'
  s.dependency 'JOSESwift','~>1'
  s.dependency 'OktaStorage','~>1'
  s.dependency 'OktaJWT', '~>2'
  s.dependency 'OktaLogger/FileLogger', '~>1'
  s.user_target_xcconfig = { 'BUILD_LIBRARY_FOR_DISTRIBUTION' => 'YES' }
end
