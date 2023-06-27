/*
* Copyright (c) 2021, Okta, Inc. and/or its affiliates. All rights reserved.
* The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
*
* You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*
* See the License for the specific language governing permissions and limitations under the License.
*/

import Foundation

/// Class represents information about application and some application specific settings, e.g. APNS environment, application shared group id and etc.
public class ApplicationConfig {

    /// Push notification settings
    public struct PushSettings {
        public enum APSEnvironment {
            case development
            case production
        }

        /// Type of APS Environment, `production` by default.
        public var apsEnvironment: APSEnvironment = .production
        /// Approve push button title for actionable notification, for example 'Yes, It's Me'
        public var approveActionTitle: String?
        /// Deny push button title for actionable notification, for example 'No, It's Not Me'
        public var denyActionTitle: String?
        /// Button title for a push challenge that requires user verification, for example 'Review'
        public var userVerificationActionTitle: String?
    }

    /// Set of settings for push notifications
    public var pushSettings = PushSettings()

    /// Initialize config.
    /// - Parameters:
    ///   - applicationName: Host application name, can be application bundle id
    ///   - applicationVersion: Host application version
    ///   - applicationGroupId: AppGroupId entitlement identifier for sharing files and keychain items between applications and extensions
    ///   - keychainGroupId: Optional KeychainSharing entitlement identifier for sharing keychain data. If not provided by your application then sdk falls back to applicationGroupId entitlement for keychain operations
    ///   - applicationInstallationId: an id that may be used to uniquely identify the device. If not provided SDK will use `UIDevice.current.identifierForVendor` property
    public init(applicationName: String,
                applicationVersion: String,
                applicationGroupId: String,
                keychainGroupId: String? = nil,
                applicationInstallationId: String? = nil) {
        self.applicationInfo = OktaApplicationInfo(
            applicationName: applicationName,
            applicationVersion: applicationVersion,
            applicationGroupId: applicationGroupId,
            keychainGroupId: keychainGroupId,
            applicationInstallationId: applicationInstallationId)
    }

    /// Returns a config value for the specified raw key.
    /// - Parameters:
    ///   - key: Raw key for config that needs to be fetched.
    /// - Returns: Returns config value if it's exists, returns `nil` otherwise.
    func getConfigValue<T>(forKey key: String) -> T? {
        defer { lock.unlock() }
        lock.readLock()
        return configs[key] as? T
    }

    // MARK: - Private
    let applicationInfo: OktaApplicationInfo
    var configs: [String: Any] = [:]
    let lock = OktaLock()
}
