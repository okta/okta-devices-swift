Pod::Spec.new do |s|
  s.name             = 'DeviceAuthenticator'
  s.version          = '1.0.0'
  s.summary          = 'Okta Authenticator SDK'
  s.description      = <<-DESC
SDK for iOS devices for communicating with Okta's device APIs
                       DESC
  s.platforms        = { :ios => "13.0" }
  s.homepage         = 'https://github.com/okta/okta-devices-swift'
  s.license          = { :type => 'APACHE2', :file => 'LICENSE' }
  s.authors          = { "Okta Developers" => "developer@okta.com" }
  s.source           = { :git => 'https://github.com/okta/okta-devices-swift.git', :tag => s.version.to_s }

  s.ios.deployment_target = '13.0'
  s.swift_version = '5.3'
  s.source_files = 'Sources/**/*.swift'
  s.exclude_files = 'Sources/DeviceAuthenticator/DeviceSignals/macOS/*.swift'

  # Dependencies
  s.dependency 'GRDB.swift','~>5'
  s.dependency 'OktaJWT', '~>2.3'
  s.dependency 'OktaLogger/FileLogger', '~>1'
end
