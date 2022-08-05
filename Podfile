inhibit_all_warnings!

def okta_logger(subspec = 'FileLogger')
  pod 'OktaLogger/' + subspec
end

def okta_jwt
  pod 'OktaJWT', '~> 2.3'
end

def device_authenticator_common
  okta_jwt
  okta_logger
  pod 'SwiftLint', '0.32.0'
  pod 'GRDB.swift', '~> 5'
end

target 'DeviceAuthenticator' do
  platform :ios, '13.0'
  device_authenticator_common
end

target 'DeviceAuthenticatorUnitTests' do
  platform :ios, '13.0'
  pod 'SwiftLint', '0.32.0'
  pod 'DeviceAuthenticator', :path => '.'
end

target 'DeviceAuthenticatorFunctionalTests' do
  platform :ios, '13.0'
  pod 'SwiftLint', '0.32.0'
  pod 'DeviceAuthenticator', :path => '.'
end

post_install do |project|
  project.pods_project.targets.each do |target|
      target.build_configurations.each do |config|
        config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] = '13.0'
        config.build_settings['MACOSX_DEPLOYMENT_TARGET'] = '10.14'
      end
    end
end
