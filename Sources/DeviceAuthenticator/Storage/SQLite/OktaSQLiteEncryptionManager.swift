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
import OktaLogger

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

protocol OktaSQLiteFileEncryptionManagerProtocol {
    /// Generates/retreives encryption key for SQLite full encryption (file-level encryption)
    /// Column-level encryption and file-level encryption do not interfer each other,
    /// so that they can be used together. That is, an encrypted SQLite file can hold
    /// some individual columns encrypted as well by `OktaSQLiteColumnEncryptionManagerProtocol`
    var fileEncryptionKey: Data? { get }
}

class OktaSQLiteEncryptionManager: OktaSQLiteColumnEncryptionManagerProtocol, OktaSQLiteFileEncryptionManagerProtocol {
    let cryptoManager: OktaSharedCryptoProtocol
    let useSecureEnclaveIfNeeded: Bool

    lazy var fileEncryptionKey: Data? = {
        return try? getFileEncryptionKey()
    }()

    init(cryptoManager: OktaSharedCryptoProtocol, prefersSecureEnclaveUsage: Bool) {
        self.cryptoManager = cryptoManager
        self.useSecureEnclaveIfNeeded = prefersSecureEnclaveUsage && OktaEnvironment.canUseSecureEnclave()
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
        guard let publicKey = columnPublicKey else {
            throw DeviceAuthenticatorError.securityError(SecurityError.invalidSecKey("Can't proceed with Decrypion because of No Public Key stored for existing Key Pair"))
        }

        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, Constants.encryptionAlgorithm) else {
            throw DeviceAuthenticatorError.securityError(SecurityError.secKeyTypeAndAlgorithmMismatch("Mismatch of key and \(Constants.encryptionAlgorithm) algorithm"))
        }

        var error: Unmanaged<CFError>?
        let encryptedData = SecKeyCreateEncryptedData(publicKey, Constants.encryptionAlgorithm, data as CFData, &error)
        let encryptionError: Error? = error?.takeRetainedValue()
        guard encryptionError == nil, let result = encryptedData else {
            var osStatus: OSStatus = -1
            if let encryptionError = encryptionError {
                let nsError = encryptionError as Error as NSError
                osStatus = OSStatus(nsError.code)
            }
            throw DeviceAuthenticatorError.securityError(SecurityError.generalEncryptionError(osStatus, encryptionError, "Failed to encrypt data"))
        }

        return result as Data
    }

    func decryptedColumnData(from data: Data) throws -> Data {
        guard let columnPrivateKey = columnPrivateKey else {
            throw DeviceAuthenticatorError.securityError(.invalidSecKey("Can't proceed with Decrypion because of No Private Key stored for existing Key Pair"))
        }

        guard SecKeyIsAlgorithmSupported(columnPrivateKey, .decrypt, Constants.encryptionAlgorithm) else {
            throw DeviceAuthenticatorError.securityError(SecurityError.secKeyTypeAndAlgorithmMismatch("Mismatch of key and \(Constants.encryptionAlgorithm) algorithm"))
        }

        var error: Unmanaged<CFError>?
        let decryptedData = SecKeyCreateDecryptedData(columnPrivateKey, Constants.encryptionAlgorithm, data as CFData, &error)
        let decryptionError: Error? = error?.takeRetainedValue()
        guard decryptionError == nil, let result = decryptedData else {
            var osStatus: OSStatus = -1
            if let decryptionError = decryptionError {
                let nsError = decryptionError as Error as NSError
                osStatus = OSStatus(nsError.code)
            }
            throw DeviceAuthenticatorError.securityError(SecurityError.generalEncryptionError(osStatus, decryptionError, "Failed to decrypt data"))
        }

        return result as Data
    }

    private lazy var columnPublicKey: SecKey? = {
        return try? getColumnPublicKey()
    }()

    private lazy var columnPrivateKey: SecKey? = {
        return try? getColumnPrivateKey()
    }()

    private func getColumnPublicKey() throws -> SecKey? {
        let keyTag = EncryptionTag.columnEncryptionKeyTag
        var storedPublicKey = cryptoManager.get(keyOf: .publicKey, with: keyTag.rawValue)
        if storedPublicKey == nil || !cryptoManager.isPrivateKeyAvailable(keyTag.rawValue) {
            try generateNewKeyPair(keyTag: keyTag, useSecureEnclave: useSecureEnclaveIfNeeded)
            storedPublicKey = cryptoManager.get(keyOf: .publicKey, with: keyTag.rawValue)
        }
        return storedPublicKey
    }

    private func getColumnPrivateKey() throws -> SecKey {
        let keyTag = EncryptionTag.columnEncryptionKeyTag
        guard cryptoManager.isPrivateKeyAvailable(keyTag.rawValue),
              let key = cryptoManager.get(keyOf: .privateKey, with: keyTag.rawValue) else {
            throw DeviceAuthenticatorError.securityError(.invalidSecKey("No Private Key stored for existing Key Pair for tag \(keyTag)"))
        }
        return key
    }

    private func getFileEncryptionKey() throws -> Data {
        let keyTag = EncryptionTag.fileEncryptionKeyTag
        var storedPrivateKey = cryptoManager.get(keyOf: .privateKey, with: keyTag.rawValue)
        if storedPrivateKey == nil || !cryptoManager.isPrivateKeyAvailable(keyTag.rawValue) {
            try generateNewKeyPair(keyTag: keyTag, useSecureEnclave: false)
            storedPrivateKey = cryptoManager.get(keyOf: .privateKey, with: keyTag.rawValue)
        }

        guard let key = storedPrivateKey else {
            throw DeviceAuthenticatorError.securityError(SecurityError.invalidSecKey("No Private Key stored for existing Key Pair for tag \(keyTag)"))
        }

        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
            throw DeviceAuthenticatorError.securityError(.invalidSecKey("Failed to get Data representation of stored Private Key for existing Key Pair for tag \(keyTag)"))
        }
        return keyData
    }

    private func generateNewKeyPair(keyTag: EncryptionTag, useSecureEnclave: Bool) throws {
        let _ = try cryptoManager.generate(keyPairWith: .ES256,
                                           with: keyTag.rawValue,
                                           useSecureEnclave: useSecureEnclave,
                                           useBiometrics: false,
                                           isAccessibleOnOtherDevice: !useSecureEnclave,
                                           biometricSettings: nil)
        guard cryptoManager.isPrivateKeyAvailable(keyTag.rawValue) else {
            throw DeviceAuthenticatorError.securityError(.invalidSecKey("No Private Key stored for newly generated Key Pair for \(keyTag.rawValue) tag"))
        }
    }

    enum EncryptionTag: String {
        case columnEncryptionKeyTag = "SQLiteColumnEncryptionKeyTag"
        case fileEncryptionKeyTag = "SQLiteFileEncryptionKeyTag"
    }

    struct Constants {
        static let encryptionAlgorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA512AESGCM
    }

}
