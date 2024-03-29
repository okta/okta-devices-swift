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
import LocalAuthentication
import CryptoKit
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif

protocol OktaSQLiteColumnEncryptionManagerProtocol {
    /// Returns Data, which represents an encrypted Data UTF8 encoded string
    /// So the general path for encryption is: original String -> encoded UTF8 string data -> encrypted data
    /// Will generate/retreive previously encryption generated key, associated with
    /// SQLite-column level encryption
    /// String can be decrypted back via `decryptedColumnString(from: _)` method
    func encryptedColumnUTF8Data(from string: String) throws -> Data

    /// Decrypts String from an encrypted Data representation
    /// So the general path for decryption is: encrypted data -> encoded UTF8 string data -> original String output
    /// Will retreive previously encryption generated key, associated with
    /// SQLite-column level encryption
    /// Expects an input of `encryptedColumnString(from: _)` method return
    func decryptedColumnString(from encryptedStringData: Data) throws -> String?

    /// Returns Data, which represents an encrypted input Data
    /// Will generate/retreive previously encryption generated key, associated with
    /// SQLite-column level encryption
    /// Data can be decrypted back via `decryptedColumnData(from: _)` method
    func encryptedColumnData(from data: Data) throws -> Data

    /// Decrypts Data from an encrypted Data representation
    /// Will retreive previously encryption generated key, associated with
    /// SQLite-column level encryption
    /// Expects an input of `encryptedColumnData(from: _)` method return
    func decryptedColumnData(from data: Data) throws -> Data
}

class OktaSQLiteEncryptionManager: OktaSQLiteColumnEncryptionManagerProtocol {
    let cryptoManager: OktaSharedCryptoProtocol
    let keychainStorage: OktaSecureStorageProtocol
    let keychainGroupId: String?
    let applicationGroupId: String
    let accessibility: CFString?
    let logger: OktaLoggerProtocol
    var cryptoKey: SymmetricKey?

    init(cryptoManager: OktaSharedCryptoProtocol,
         keychainGroupId: String?,
         keychainStorage: OktaSecureStorageProtocol = OktaSecureStorage(applicationPassword: nil),
         applicationGroupId: String,
         logger: OktaLoggerProtocol) {
        self.cryptoManager = cryptoManager
        self.keychainGroupId = keychainGroupId
        self.keychainStorage = keychainStorage
        self.accessibility = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        self.applicationGroupId = applicationGroupId
        self.logger = logger
    }

    func encryptedColumnUTF8Data(from string: String) throws -> Data {
        guard let stringData = string.data(using: .utf8) else {
            throw DeviceAuthenticatorError.internalError("Failed to convert string into data")
        }
        let encryptedData = try encryptedColumnData(from: stringData)
        return encryptedData
    }

    func decryptedColumnString(from encryptedStringData: Data) throws -> String? {
        let stringData = try decryptedColumnData(from: encryptedStringData)
        guard let string = String(data: stringData, encoding: .utf8) else {
            throw DeviceAuthenticatorError.internalError("Failed to convert data into string")
        }
        return string
    }

    func encryptedColumnData(from data: Data) throws -> Data {
        let cryptoKey = try getCryptoKey()
        let encryptedData = try cryptoManager.encrypt(data: data, with: cryptoKey)

        return encryptedData
    }

    func decryptedColumnData(from data: Data) throws -> Data {
        let cryptoKey = try getCryptoKey()
        return try cryptoManager.decrypt(data: data, with: cryptoKey)
    }

    private func getCryptoKey() throws -> SymmetricKey {
        if let cryptoKey = self.cryptoKey {
            return cryptoKey
        }

        let keyTag = Constants.columnEncryptionKeyTag
        do {
            let storedPublicKey = try keychainStorage.getData(key: keyTag.rawValue, biometricPrompt: nil, accessGroup: keychainGroupId)
            let symmetricKey = SymmetricKey(data: storedPublicKey)
            self.cryptoKey = symmetricKey

            migrateCryptoKeyIfNeeded(symmetricKey: symmetricKey, keyTag: keyTag.rawValue)

            return symmetricKey
        } catch let error as NSError {
            if error.code == errSecItemNotFound {
                let cryptoKey = try generateCryptoKey()
                let rawKey = cryptoKey.withUnsafeBytes { rawBufferPointer in
                    return Data(rawBufferPointer)
                }
                do {
                    try keychainStorage.set(data: rawKey,
                                            forKey: keyTag.rawValue,
                                            behindBiometrics: false,
                                            accessGroup: keychainGroupId,
                                            accessibility: self.accessibility)

                    return cryptoKey
                } catch {
                    throw DeviceAuthenticatorError.securityError(.dataEncryptionDecryptionError(error))
                }
            } else {
                throw DeviceAuthenticatorError.securityError(.dataEncryptionDecryptionError(error))
            }
        } catch {
            throw DeviceAuthenticatorError.securityError(.dataEncryptionDecryptionError(error))
        }
    }

    func migrateCryptoKeyIfNeeded(symmetricKey: SymmetricKey, keyTag: String) {
        // Migrate from kSecAttrAccessibleAfterFirstUnlock to kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let userDefaults = UserDefaults(suiteName: applicationGroupId) ?? UserDefaults.standard
        if !userDefaults.bool(forKey: Constants.cryptoKeyMigratedFlag.rawValue) {
            let rawKey = symmetricKey.withUnsafeBytes { rawBufferPointer in
                return Data(rawBufferPointer)
            }
            do {
                try keychainStorage.set(data: rawKey,
                                        forKey: keyTag,
                                        behindBiometrics: false,
                                        accessGroup: keychainGroupId,
                                        accessibility: self.accessibility)
                userDefaults.setValue(true, forKey: Constants.cryptoKeyMigratedFlag.rawValue)
            } catch {
                logger.error(eventName: "SQLite column encryption", message: "Failed to migrate encryption key, error: \(error.localizedDescription)")
            }
        }
    }

    private func generateCryptoKey() throws -> SymmetricKey {
        return try cryptoManager.generateSymmetricKey()
    }

    enum Constants: String {
        case columnEncryptionKeyTag = "com.okta.SQLiteEncryptionKeyTag"
        case cryptoKeyMigratedFlag = "com.okta.SQLiteEncryptionKeyMigrated_V0"
    }
}
