/*
* Copyright (c) 2019, Okta, Inc. and/or its affiliates. All rights reserved.
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
import OktaLogger

/// Deprecated. To be removed in further versions
class OktaSharedKeychainStorage {

    private struct Constants {
        static let storageDescription = "Keychain"
    }

    let underlyingStorageDescription: String = OktaSharedKeychainStorage.Constants.storageDescription
    var sharedAccessId: String?

    func save(data: Data, with key: String) throws {
        do {
            try secureStorage.set(data: data,
                                  forKey: key,
                                  behindBiometrics: false,
                                  accessGroup: sharedAccessId,
                                  accessibility: OktaEnvironment.Constants.keychainAccessibilityFlag)
        } catch let error as NSError {
            let resultError = convertFromSecureStorageError(error)
            logger.error(eventName: "Keychain storage error", message: "Keychain storage can't save data for key: \(key), error: \(resultError)")
            throw resultError
        }
    }

    func data(with key: String) throws -> Data {
        do {
            return try secureStorage.getData(key: key, accessGroup: sharedAccessId)
        } catch let error as NSError {
            let resultError = convertFromSecureStorageError(error)
            logger.error(eventName: "Keychain storage error", message: "Keychain storage can't retrieve data for key: \(key), error: \(resultError)")
            throw resultError
        }
    }

    /**
     Performs fetch from Keychain for stored keys filtered by a specified prefix
     - Returns:
     * In case of no keys for a given prefix, an empty array will be returned
     * In case of unauthorized Keychain access or other Keychain errors, will rethrow that error
    */
    func fetchKeys(with prefix: String) throws -> [String] {
        do {
            let keys = try secureStorage
                .getStoredKeys(accessGroup: sharedAccessId)
                .filter {
                    $0.hasPrefix(prefix)
                }
            return keys
        } catch let error as NSError {
            let resultError = convertFromSecureStorageError(error)
            logger.error(eventName: "Keychain storage error", message: "Keychain storage can't retrieve stored keys for keys with prefix: \(prefix), error: \(resultError)")
            throw resultError
        }
    }

    func delete(with key: String) throws {
        do {
            try secureStorage.delete(key: key, accessGroup: sharedAccessId)
        } catch let error as NSError {
            let resultError = convertFromSecureStorageError(error)
            logger.error(eventName: "Keychain storage error", message: "Keychain storage can't delete data for key: \(key), error: \(resultError)")
            throw resultError
        }
    }

    var logger: OktaLoggerProtocol
    let secureStorage: OktaSecureStorage

    init(with appGroupId: String?,
         secureStorage: OktaSecureStorage = OktaSecureStorage(),
         logger: OktaLoggerProtocol) throws {
        self.sharedAccessId = appGroupId
        self.secureStorage = secureStorage
        self.logger = logger
        // Check for invalid app group id error
        do {
            _ = try secureStorage.getData(key: "dummy_key", biometricPrompt: nil, accessGroup: appGroupId)
        } catch {
            let nsError = error as NSError
            if nsError.code == errSecMissingEntitlement {
                logger.error(eventName: "Keychain storage error", message: "Failed to create keychain storage error: \(error)")
                throw DeviceAuthenticatorError.storageError(StorageError.missingAppGroupEntitlement)
            }
        }
    }

    private func convertFromSecureStorageError(_ error: NSError) -> StorageError {
        var oktaStorageError: StorageError
        if error.code == errSecItemNotFound {
            oktaStorageError = StorageError.itemNotFound
        } else {
            oktaStorageError = StorageError.generalStorageError(SecCopyErrorMessageString(OSStatus(error.code), nil) as String? ?? "")
        }

        return oktaStorageError
    }
}
