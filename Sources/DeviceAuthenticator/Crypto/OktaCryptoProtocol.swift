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
import LocalAuthentication
import CryptoKit

enum SignatureFormat: Int {
    case BER_ASN

    func toString() -> String {
        switch self {
        case .BER_ASN:
            return "BER_ASN"
        }
    }
}

enum PrivateKeyState {
    case available
    case lockedOut
    case lost
}

protocol OktaSharedCryptoProtocol: OktaCryptoProtocol {
    var accessGroupId: String { get }
}

/// Protocol for managing public and private keys
protocol OktaCryptoProtocol {

    /// Generate public private key pair
    /// - Parameters:
    ///   - keyPairWithAlgorithm: algorith used for generating keys
    ///   - tag: unique identifier used to store or retrieve keys
    ///   - useSecureEnclave: option to store the key in secure enclave
    ///   - isAccessibleOnOtherDevice: reflects to accesibility setting. If `true`, `kSecAttrAccessibleAfterFirstUnlock` is passed while if `false`  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` is passed as accesibility setting.
    ///   - useBiometrics: option to store key protected by biometrics
    /// - Returns: true if sucessful
    func generate(keyPairWith algorithm: Algorithm,
                  with tag: String,
                  useSecureEnclave: Bool,
                  useBiometrics: Bool,
                  isAccessibleOnOtherDevice: Bool,
                  biometricSettings: BiometricEnrollmentSettings?) throws -> SecKey

    /// Generate symmetric key
    /// - Returns: symmetric key
    func generateSymmetricKey() throws -> SymmetricKey

    ///  Delete both public and private key pair
    /// - Parameter tag: unique identifier that was used to create the keys
    /// - Returns: true if key exists and key deletion was successful
    func delete(keyPairWith tag: String) -> Bool

    /// Retrieve reference to public private key pair. This method does not return binary data of the key itself.
    /// - Parameters:
    ///   - type: Public or private key
    ///   - tag: unique identifier that was used to create the public key
    ///   - context: pass LAContext if biometric check is already done on the context
    /// - Returns: Reference to SecKey if it can find the key otherwise returns nil
    func get(keyOf type: KeyType, with tag: String, context: LAContext) -> SecKey?

    ///  Given a key tag, ascertain whether it is available for signing operations
    /// - Parameters:
    ///   - keyTag: Private key tag (e.g. userVerificationKeyTag)
    /// - Returns: True if the private key is available for signing operations, otherwise false
    /// - Discussion: The only way to determine availability for signin operations is to attempt to sign.
    ///               We do not want user interaction, however, so we disable that.
    ///               As a result, we assume that if the error is 'user interaction required' then the key is available.
    ///               All other errors are interpreted as an unavailable key.
    func isPrivateKeyAvailable(_ keyTag: String) -> Bool

    ///  Given a key tag, check its availability for signing operations
    /// - Parameters:
    ///   - keyTag: Private key tag (e.g. userVerificationKeyTag)
    /// - Returns: Returns a tuple. The first value is true if the private key is available for signing operations, otherwise false.
    ///            The second value is the error from attempting to sign.
    /// - Discussion: The only way to determine availability for signin operations is to attempt to sign.
    ///               We do not want user interaction, however, so we disable that.
    ///               As a result, we assume that if the error is 'user interaction required' then the key is available.
    ///               All other errors are interpreted as an unavailable key.
    func checkPrivateKeyAvailability(_ keyTag: String) -> (keyState: PrivateKeyState, error: DeviceAuthenticatorError?)

    /// Ecnrypt data with provided symmetric key
    ///  - Parameters:
    ///   - data: Sequence of bytes to be encrypted
    ///   - symmetricKey: Symmetric key
    func encrypt(data: Data, with symmetricKey: SymmetricKey) throws -> Data

    /// Decrypt data with provided symmetric key
    ///  - Parameters:
    ///   - data: Previously encrypted data
    ///   - symmetricKey: Symmetric key
    ///  - Returns: Decoded sequence of bytes
    func decrypt(data: Data, with symmetricKey: SymmetricKey) throws -> Data
}

extension OktaCryptoProtocol {
    func generate(keyPairWith algorithm: Algorithm,
                  with tag: String,
                  useSecureEnclave: Bool,
                  useBiometrics: Bool = false,
                  isAccessibleOnOtherDevice: Bool = false,
                  biometricSettings: BiometricEnrollmentSettings? = nil) throws -> SecKey {
        return try generate(keyPairWith: algorithm,
                            with: tag,
                            useSecureEnclave: useSecureEnclave,
                            useBiometrics: useBiometrics,
                            isAccessibleOnOtherDevice: isAccessibleOnOtherDevice,
                            biometricSettings: biometricSettings)
    }

    func get(keyOf type: KeyType, with tag: String, context: LAContext = LAContext()) -> SecKey? {
        return get(keyOf: type, with: tag, context: context)
    }
}
