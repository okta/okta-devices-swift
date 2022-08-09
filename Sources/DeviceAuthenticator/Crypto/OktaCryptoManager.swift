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
import OktaLogger
import CryptoKit

class OktaCryptoManager: OktaSharedCryptoProtocol {
    var accessGroupId: String
    var secKeyHelper: SecKeyHelper
    var logger: OktaLoggerProtocol

    init(accessGroupId: String,
         secKeyHelper: SecKeyHelper = SecKeyHelper(),
         logger: OktaLoggerProtocol) {
        self.accessGroupId = accessGroupId
        self.secKeyHelper = secKeyHelper
        self.logger = logger
    }

    func generate(keyPairWith algorithm: Algorithm,
                  with tag: String,
                  useSecureEnclave: Bool,
                  useBiometrics: Bool,
                  isAccessibleOnOtherDevice: Bool,
                  biometricSettings: BiometricEnrollmentSettings?) throws -> SecKey {
        if delete(keyPairWith: tag) {
            logger.info(eventName: "Existing key deleted", message: "tag: \(tag)")
        }

        var accessControlFlags: SecAccessControlCreateFlags = SecAccessControlCreateFlags()
        if useSecureEnclave {
            accessControlFlags.update(with: .privateKeyUsage)
        }
        if useBiometrics {
            let settings = biometricSettings ?? BiometricEnrollmentSettings.default
            accessControlFlags.update(with: settings.accessControlFlags)
        }
        let accesibilitySetting = isAccessibleOnOtherDevice ? kSecAttrAccessibleAfterFirstUnlock : kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        var accessControlError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
                                  kCFAllocatorDefault,
                                  accesibilitySetting,
                                  accessControlFlags,
                                  &accessControlError) else {
            var osStatus: OSStatus = -1
            if let cfError = accessControlError?.takeUnretainedValue() {
                let nsError = cfError as Error as NSError
                osStatus = OSStatus(nsError.code)
            }
            logger.error(eventName: "Set access control failed", message: "Cannot set access control")
            throw SecurityError.keyGenFailed(osStatus, "Failed to set access control")
        }

        var keyAttr = baseQuery(with: tag)
        if !accessGroupId.isEmpty {
            keyAttr[kSecAttrAccessGroup] = accessGroupId as NSObject
        }
        if useSecureEnclave {
            keyAttr[kSecAttrTokenID] =  kSecAttrTokenIDSecureEnclave as NSObject
        }

        switch algorithm {
        case .ES256:
            keyAttr[kSecAttrKeyType] = kSecAttrKeyTypeECSECPrimeRandom
            keyAttr[kSecAttrKeySizeInBits] =  256 as NSObject
            break
        }

        var privateKeyAttr: [NSObject: Any] = baseQuery(with: tag)
        privateKeyAttr[kSecAttrIsPermanent] = true
        #if !targetEnvironment(simulator)
        privateKeyAttr[kSecAttrAccessControl] = accessControl
        #endif

        keyAttr[kSecPrivateKeyAttrs] = privateKeyAttr as NSObject

        var error: Unmanaged<CFError>?
        guard let privateKey = self.secKeyHelper.generateRandomKey(keyAttr as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            var osStatus: OSStatus = -1
            if let cfError = error?.takeUnretainedValue() {
                let nsError = cfError as Error as NSError
                osStatus = OSStatus(nsError.code)
            }
            logger.error(eventName: "Key generation failed", message: "Error: private key generation failed, OSStatus:\(osStatus)")
            throw SecurityError.keyGenFailed(osStatus, "private key generation failed")
        }

        return publicKey
    }

    func delete(keyPairWith tag: String) -> Bool {
        var keyQuery = baseQuery(with: tag)
        if !accessGroupId.isEmpty {
            keyQuery[kSecAttrAccessGroup] = accessGroupId
        }
        let statusCode = self.secKeyHelper.deleteKey(keyQuery as CFDictionary)

        return (statusCode == errSecSuccess)
    }

    func get(keyOf type: KeyType, with tag: String, context: LAContext) -> SecKey? {
        var keyQuery = baseQuery(with: tag)
        keyQuery[kSecReturnRef] = true
        if !accessGroupId.isEmpty {
            keyQuery[kSecAttrAccessGroup] = accessGroupId
        }
        #if !targetEnvironment(simulator)
        keyQuery[kSecUseAuthenticationContext] = context
        #endif
        var resultKey: AnyObject?
        let statusCode = self.secKeyHelper.getKey(keyQuery as CFDictionary, &resultKey)
        if statusCode == errSecSuccess && resultKey != nil {
            let privateKey = resultKey as! SecKey // swiftlint:disable:this force_cast
            switch  type {
            case .publicKey:
                return SecKeyCopyPublicKey(privateKey)
            default:
                return privateKey
            }
        } else {
            return nil
        }
    }

    func checkPrivateKeyAvailability(_ keyTag: String) -> (keyState: PrivateKeyState, error: DeviceAuthenticatorError?) {
        let context = LAContext()
        context.interactionNotAllowed = true
        guard let key = self.get(keyOf: .privateKey,
                                 with: keyTag,
                                 context: context) else {
            logger.error(eventName: "Private Key Not Found", message: "Key with tag \(keyTag) could not be found in the keychain")
            let encryptionError = SecurityError.generalEncryptionError(-1, nil, "Private Key Not Found")
            return (.lost, DeviceAuthenticatorError.securityError(encryptionError))
        }

        var error: Unmanaged<CFError>?
        if let _ = self.secKeyHelper.createSignature(key,
                                                     .ecdsaSignatureMessageX962SHA256,
                                                     Data() as CFData, &error) {
            return (.available, nil)
        }

        guard let signingError = error else {
            return (.available, nil)
        }

        let value = signingError.takeUnretainedValue()
        let nsError: NSError = value as Error as NSError
        let notInteractiveKeyErrorCode = LAError.Code.notInteractive.rawValue // -1004
        if nsError.code == notInteractiveKeyErrorCode && nsError.domain == LAErrorDomain {
            // Biometric keys will return this error if the key is valid but requires user interaction.
            // We treat this special case as "available" in order to allow silent checks
            let encryptionError = SecurityError.create(with: error)
            return (.available, DeviceAuthenticatorError.securityError(encryptionError))
        } else {
            logger.error(eventName: "Private Key Local Authentication Error: \(nsError)",
                         message: "Key with tag \(keyTag) failed health check with Local Authentication Error: \(nsError.localizedDescription)")
            let encryptionError = SecurityError.create(with: error)
            var keyState: PrivateKeyState = .lost
            if nsError.domain == LAErrorDomain && nsError.code == LAError.Code.biometryLockout.rawValue {
                keyState = .lockedOut
            }
            return (keyState, DeviceAuthenticatorError.securityError(encryptionError))
        }
    }

    func isPrivateKeyAvailable(_ keyTag: String) -> Bool {
        return checkPrivateKeyAvailability(keyTag).keyState == .available
    }

    func baseQuery(with tag: String) -> [NSObject: Any] {
        var query: [NSObject: Any] = [kSecClass: kSecClassKey, kSecAttrApplicationTag: tag]
        #if os(macOS)
        if #available(macOS 10.15, *) {
            logger.error(eventName: "CRYPTO", message: "Adding kSecUseDataProtectionKeychain key")
            query[kSecUseDataProtectionKeychain] = kCFBooleanTrue
        }
        #endif
        return query
    }
}
