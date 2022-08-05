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
@testable import DeviceAuthenticator

class CryptoManagerMock: OktaCryptoManager {

    var privateKey: SecKey?
    var publicKey: SecKey?
    var deleteHook: deleteType?

    typealias deleteType = (String) -> Bool

    override public func generate(keyPairWith algorithm: Algorithm,
                                  with tag: String,
                                  useSecureEnclave: Bool,
                                  useBiometrics: Bool,
                                  isAccessibleOnOtherDevice: Bool = false,
                                  biometricSettings: BiometricEnrollmentSettings?) throws -> SecKey {
        let _ = delete(keyPairWith: tag)
        let accessControlFlags: SecAccessControlCreateFlags = SecAccessControlCreateFlags()

        var accessControlError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
                                  kCFAllocatorDefault,
                                  kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
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

        var privateKeyAttr = privateKeyQueryWithRefReturn(forKeyTag: tag)
        privateKeyAttr[kSecAttrAccessControl] = accessControl
        privateKeyAttr[kSecAttrIsPermanent] = false

        var publicKeyAttr = publicKeyQueryWithRefReturn(forKeyTag: tag)
        publicKeyAttr[kSecAttrIsPermanent] = false

        var keyPairAttr = [NSObject: NSObject]()
        keyPairAttr[kSecPublicKeyAttrs] = publicKeyAttr as NSObject
        keyPairAttr[kSecPrivateKeyAttrs] = privateKeyAttr as NSObject

        switch algorithm {
        case .ES256:
            keyPairAttr[kSecAttrKeyType] = kSecAttrKeyTypeECSECPrimeRandom
            keyPairAttr[kSecAttrKeySizeInBits] =  256 as NSObject
            break
        }

        if useSecureEnclave {
            keyPairAttr[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
        }

        let statusCode = self.secKeyHelper.generateKeyPair(keyPairAttr as CFDictionary, &publicKey, &privateKey)
        guard let key = publicKey, statusCode == 0 else {
            logger.error(eventName: "Key generation failed", message: "Error: public private key pair generation failed OSStatus:\(statusCode)")
            throw SecurityError.keyGenFailed(statusCode, "public private key pair generation failed")
        }

        return key
    }

    override public func get(keyOf type: KeyType, with tag: String, context: LAContext = LAContext()) -> SecKey? {
        return type == .publicKey ? publicKey : privateKey
    }

    override public func delete(keyPairWith tag: String) -> Bool {
        if let deleteHook = deleteHook {
            return deleteHook(tag)
        } else {
            return super.delete(keyPairWith: tag)
        }
    }

    private func privateKeyQueryWithRefReturn(forKeyTag tag: String) -> [NSObject: Any] {
        var privateKeyAttr: [NSObject: Any] = privateKeyBaseQuery(forKeyTag: tag)
        privateKeyAttr[kSecReturnRef] = true
        return privateKeyAttr
    }

    private func privateKeyBaseQuery(forKeyTag tag: String) -> [NSObject: Any] {
        let internalPrivateKeyTag = addPrefixPostfix(toTag: tag, type: .privateKey)
        return [
        kSecAttrLabel: internalPrivateKeyTag,
        kSecClass: kSecClassKey,
        ]
    }

    private func publicKeyQueryWithRefReturn(forKeyTag tag: String) -> [NSObject: Any] {
        var publicKeyAttr: [NSObject: Any] = publicKeyBaseQuery(forKeyTag: tag)
        publicKeyAttr[kSecReturnRef] = true
        return publicKeyAttr
    }

    private func publicKeyBaseQuery(forKeyTag tag: String) -> [NSObject: Any] {
        let internalPublicKeyTag = addPrefixPostfix(toTag: tag, type: .publicKey)
        return [
        kSecAttrLabel: internalPublicKeyTag,
        kSecClass: kSecClassKey]
    }

    private func addPrefixPostfix(toTag tag: String, type: KeyType) -> String {
        return tagPrefix() + tag + tagPostfix(type: type)
    }

    private func tagPostfix(type: KeyType) -> String {
        return ((type == .publicKey) ? ".key.public" : ".key.private")
    }

    private func tagPrefix() -> String {
        return "crypto.manager.mock."
    }
}
