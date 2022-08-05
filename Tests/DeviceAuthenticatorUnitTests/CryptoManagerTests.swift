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
// swiftlint:disable force_unwrapping
import XCTest
import LocalAuthentication
import CryptoTokenKit
@testable import DeviceAuthenticator

class CryptoManagerTests: XCTestCase {
    var mut: OktaCryptoManager?
    var secKeyHelperMock: SecKeyHelperMock!
    var expectedListPublicPrivateDeleteAttr: [CFDictionary] = []

    let privateKeyInternalTag = "com.okta.device.sdk.user1@okta.com.key.private"
    let keyData = Data([
        0x12, 0xEA, 0x41, 0x29, 0x15, 0x4E, 0x48, 0x2E, 0x01, 0x92, 0xA5, 0x28, 0x89, 0x70, 0xAD, 0x56,
        0x82, 0x19, 0xBF, 0xC8, 0x25, 0x5E, 0xF2, 0x03, 0x0E, 0x4C, 0x1D, 0xCF, 0x46, 0x8A, 0x7E, 0x25
    ])
    let dataToBeSigned = Data([
        0x12, 0xEA
    ])
    let signature = Data([
        0x12, 0xEA, 0x41, 0x29
    ])

    override func setUp() {
        super.setUp()
        secKeyHelperMock = SecKeyHelperMock()
        mut = OktaCryptoManager(accessGroupId: "", secKeyHelper: secKeyHelperMock, logger: OktaLoggerMock())
        var expectedPrivateKeyDeleteAttr = [kSecAttrLabel: privateKeyInternalTag as Any,
                                            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                                            kSecClass: kSecClassKey]
        if #available(macOS 10.15, iOS 13.0, *) {
            expectedPrivateKeyDeleteAttr[kSecUseDataProtectionKeychain] = kCFBooleanTrue
        }
        expectedListPublicPrivateDeleteAttr = [self.baseQuery(with: privateKeyInternalTag) as CFDictionary]
    }

#if os(iOS)
    func testEncryptionManager_BasicOperations() {
        let encryptionManager = OktaCryptoManager(accessGroupId: ExampleAppConstants.appGroupId, logger: OktaLoggerMock())
        do {
            let key = try encryptionManager.generate(keyPairWith: .ES256, with: "tag", useSecureEnclave: false, useBiometrics: false)
            XCTAssertNotNil(key)
        } catch {
            XCTFail("Key generation failed")
            return
        }
        guard let _ = encryptionManager.get(keyOf: .publicKey, with: "tag") else {
            XCTFail("Fail to read public key")
            return
        }
        guard let privateKey = encryptionManager.get(keyOf: .privateKey, with: "tag") else {
            XCTFail("Fail to read private key")
            return
        }
        let oktaJWTGenerator = OktaJWTGenerator(logger: OktaLoggerMock())
        do {
            _ = try oktaJWTGenerator.generate(with: "JWT", for: ["some": "data"], with: privateKey, using: Algorithm.ES256)
        } catch {
            XCTFail("Fail to sign data")
        }

        XCTAssertTrue(encryptionManager.delete(keyPairWith: "tag"))
    }
#endif

    func testEncryptionManager_EncryptionError() {
        secKeyHelperMock.keyExpectation = nil
        let cfError = CFErrorCreate(kCFAllocatorDefault, "domain" as CFString, -1, nil)
        var error: Unmanaged<CFError>? = Unmanaged<CFError>.passUnretained(cfError!)
        withUnsafeMutablePointer(to: &error) {
            secKeyHelperMock.generateKeyPairErrorSpyParameter = UnsafeMutablePointer($0)
            do {
                _ = try mut?.generate(keyPairWith: .ES256, with: "tag", useSecureEnclave: false, useBiometrics: false)
                XCTFail("generate call should fail")
            } catch {
                let encryptionError = error as? SecurityError
                XCTAssertNotNil(encryptionError)
                XCTAssertEqual(SecurityError.keyGenFailed(-1, "private key generation failed"), encryptionError)
            }
        }
    }

    func testGenerateES256NoSecureEnclaveNoBiometrics() {
        secKeyHelperMock.generateKeyPairExpectaion = 0
        secKeyHelperMock.deleteKeyExpectations = [0, 0]
        do {
            _ = try mut?.generate(keyPairWith: .ES256, with: privateKeyInternalTag, useSecureEnclave: false, useBiometrics: false)
            var accessControlError: Unmanaged<CFError>?
            var privateKeyAttr: [NSObject: Any] = self.baseQuery(with: privateKeyInternalTag)
            privateKeyAttr[kSecAttrIsPermanent] = true

            #if !targetEnvironment(simulator)
            privateKeyAttr[kSecAttrAccessControl] = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                                                                    [],
                                                                                    &accessControlError) as Any
            #endif
            if #available(macOS 10.15, iOS 13.0, *) {
                privateKeyAttr[kSecUseDataProtectionKeychain] = true
            }

            var keyPairAttr = self.baseQuery(with: privateKeyInternalTag)
            keyPairAttr[kSecPrivateKeyAttrs] = privateKeyAttr as Any
            keyPairAttr[kSecAttrKeyType] = kSecAttrKeyTypeECSECPrimeRandom
            keyPairAttr[kSecAttrKeySizeInBits] = 256 as NSObject

            XCTAssertTrue(secKeyHelperMock.verifyGenerateKeyPairExpectation(keyPairAttr as CFDictionary))
            XCTAssertTrue(secKeyHelperMock.verifyDeleteExpectation(expectedListPublicPrivateDeleteAttr))
        } catch {
            XCTFail("testGenerateES256NoSecureEnclaveNoBiometrics failed with error - \(error)")
        }
    }

    func testGenerateES256WithSecureEnclaveNoBiometrics() {
        secKeyHelperMock.generateKeyPairExpectaion = 0
        secKeyHelperMock.deleteKeyExpectations = [0, 1]
        do {
            _ = try mut?.generate(keyPairWith: .ES256, with: privateKeyInternalTag, useSecureEnclave: true, useBiometrics: false)
            var accessControlError: Unmanaged<CFError>?
            var privateKeyAttr: [NSObject: Any] = self.baseQuery(with: privateKeyInternalTag)
            privateKeyAttr[kSecAttrIsPermanent] = true

            #if !targetEnvironment(simulator)
            privateKeyAttr[kSecAttrAccessControl] = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                                                                    [.privateKeyUsage],
                                                                                    &accessControlError) as Any
            #endif
            if #available(macOS 10.15, iOS 13.0, *) {
                privateKeyAttr[kSecUseDataProtectionKeychain] = true
            }

            var keyPairAttr = self.baseQuery(with: privateKeyInternalTag)
            keyPairAttr[kSecPrivateKeyAttrs] = privateKeyAttr as Any
            keyPairAttr[kSecAttrKeyType] = kSecAttrKeyTypeECSECPrimeRandom
            keyPairAttr[kSecAttrKeySizeInBits] = 256 as NSObject
            keyPairAttr[kSecAttrTokenID] =  kSecAttrTokenIDSecureEnclave as NSObject

            XCTAssertTrue(secKeyHelperMock.verifyGenerateKeyPairExpectation(keyPairAttr as CFDictionary))
            XCTAssertTrue(secKeyHelperMock.verifyDeleteExpectation(expectedListPublicPrivateDeleteAttr))
        } catch {
            XCTFail("testGenerateES256WithSecureEnclaveNoBiometrics failed with error - \(error)")
        }
    }

    func testGenerateES256WithNoSecureEnclaveAndBiometrics() {
        secKeyHelperMock.generateKeyPairExpectaion = 0
        secKeyHelperMock.deleteKeyExpectations = [0, 1]
        do {
            _ = try mut?.generate(keyPairWith: .ES256, with: privateKeyInternalTag, useSecureEnclave: false, useBiometrics: true)
            var accessControlError: Unmanaged<CFError>?
            var privateKeyAttr: [NSObject: Any] = self.baseQuery(with: privateKeyInternalTag)
            privateKeyAttr[kSecAttrIsPermanent] = true

            #if !targetEnvironment(simulator)
            privateKeyAttr[kSecAttrAccessControl] = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                                                                    [.biometryCurrentSet],
                                                                                    &accessControlError) as Any
            #endif
            if #available(macOS 10.15, iOS 13.0, *) {
                privateKeyAttr[kSecUseDataProtectionKeychain] = true
            }

            var keyPairAttr = self.baseQuery(with: privateKeyInternalTag)
            keyPairAttr[kSecPrivateKeyAttrs] = privateKeyAttr as Any
            keyPairAttr[kSecAttrKeyType] = kSecAttrKeyTypeECSECPrimeRandom
            keyPairAttr[kSecAttrKeySizeInBits] = 256 as NSObject

            XCTAssertTrue(secKeyHelperMock.verifyGenerateKeyPairExpectation(keyPairAttr as CFDictionary))
            XCTAssertTrue(secKeyHelperMock.verifyDeleteExpectation(expectedListPublicPrivateDeleteAttr))
        } catch {
            XCTFail("testGenerateES256WithNoSecureEnclaveAndBiometrics failed with error - \(error)")
        }
    }

    func testGenerateES256WithSecureEnclaveAndBiometrics() {
        secKeyHelperMock.generateKeyPairExpectaion = 0
        secKeyHelperMock.deleteKeyExpectations = [0, 1]
        do {
            _ = try mut?.generate(keyPairWith: .ES256, with: privateKeyInternalTag, useSecureEnclave: true, useBiometrics: true)
            var accessControlError: Unmanaged<CFError>?
            var privateKeyAttr: [NSObject: Any] = self.baseQuery(with: privateKeyInternalTag)
            privateKeyAttr[kSecAttrIsPermanent] = true

            #if !targetEnvironment(simulator)
            privateKeyAttr[kSecAttrAccessControl] = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                                                                    [.privateKeyUsage, .biometryCurrentSet],
                                                                                    &accessControlError) as Any
            #endif
            if #available(macOS 10.15, iOS 13.0, *) {
                privateKeyAttr[kSecUseDataProtectionKeychain] = true
            }

            var keyPairAttr = self.baseQuery(with: privateKeyInternalTag)
            keyPairAttr[kSecPrivateKeyAttrs] = privateKeyAttr as Any
            keyPairAttr[kSecAttrKeyType] = kSecAttrKeyTypeECSECPrimeRandom
            keyPairAttr[kSecAttrKeySizeInBits] = 256 as NSObject
            keyPairAttr[kSecAttrTokenID] =  kSecAttrTokenIDSecureEnclave as NSObject

            XCTAssertTrue(secKeyHelperMock.verifyGenerateKeyPairExpectation(keyPairAttr as CFDictionary))
            XCTAssertTrue(secKeyHelperMock.verifyDeleteExpectation(expectedListPublicPrivateDeleteAttr))
        } catch {
            XCTFail("testGenerateES256WithSecureEnclaveAndBiometrics failed with error - \(error)")
        }
    }

    func testDeleteOnlyPrivateKey() {
        secKeyHelperMock.deleteKeyExpectations = [0, 1]
        XCTAssertTrue(mut?.delete(keyPairWith: privateKeyInternalTag) ?? false)
        XCTAssertTrue(secKeyHelperMock.verifyDeleteExpectation(expectedListPublicPrivateDeleteAttr))
    }

    func testDeleteNoKeys() {
        secKeyHelperMock.deleteKeyExpectations = [1, 1]
        XCTAssertFalse(mut?.delete(keyPairWith: privateKeyInternalTag) ?? true)
        XCTAssertTrue(secKeyHelperMock.verifyDeleteExpectation(expectedListPublicPrivateDeleteAttr))
    }

    func testGetPrivateKey() {
        secKeyHelperMock.getKeyExpectation = 0
        secKeyHelperMock.getKeyRefExpectation = keyData as CFTypeRef
        let context = LAContext()

        XCTAssertNotNil(mut?.get(keyOf: .privateKey, with: privateKeyInternalTag, context: context))

        var expectedKeyAttr = self.baseQuery(with: privateKeyInternalTag)
        expectedKeyAttr[kSecReturnRef] = true
        #if !targetEnvironment(simulator)
        expectedKeyAttr[kSecUseAuthenticationContext] = context
        #endif
        XCTAssertTrue(secKeyHelperMock.verifyGet(expectedKeyAttr as CFDictionary))
    }

    func testGetPrivateKeyFail() {
        secKeyHelperMock.getKeyExpectation = 1
        secKeyHelperMock.getKeyRefExpectation = nil
        let context = LAContext()

        XCTAssertNil(mut?.get(keyOf: .privateKey, with: privateKeyInternalTag, context: context))

        var expectedKeyAttr = self.baseQuery(with: privateKeyInternalTag)
        expectedKeyAttr[kSecReturnRef] = true
        #if !targetEnvironment(simulator)
        expectedKeyAttr[kSecUseAuthenticationContext] = context
        #endif
        XCTAssertTrue(secKeyHelperMock.verifyGet(expectedKeyAttr as CFDictionary))
    }

    func baseQuery(with tag: String) -> [NSObject: Any] {
        var query: [NSObject: Any] = [kSecClass: kSecClassKey, kSecAttrApplicationTag: tag]
        if #available(macOS 10.15, iOS 13.0, *) {
            query[kSecUseDataProtectionKeychain] = kCFBooleanTrue
        }
        return query
    }

    func testPrivateKeyAvailability_Success() {
        secKeyHelperMock.getKeyExpectation = 0
        secKeyHelperMock.getKeyRefExpectation = keyData as CFTypeRef
        let available = mut?.isPrivateKeyAvailable(privateKeyInternalTag)
        XCTAssertEqual(available, true)
    }

    func testPrivateKeyAvailability_NotInteractiveSuccess() {
        secKeyHelperMock.getKeyExpectation = 0
        secKeyHelperMock.getKeyRefExpectation = keyData as CFTypeRef

        secKeyHelperMock.createSignatureExpectation = nil
        let cferr = CFErrorCreate(nil, LAError.errorDomain as NSString, LAError.notInteractive.rawValue, nil)!
        secKeyHelperMock.createSignatureError = cferr
        let available = mut?.isPrivateKeyAvailable(privateKeyInternalTag)
        XCTAssertEqual(available, true)
    }

    func testPrivateKeyAvailability_KeyCorrupted() {
        secKeyHelperMock.getKeyExpectation = 0
        secKeyHelperMock.getKeyRefExpectation = keyData as CFTypeRef

        secKeyHelperMock.createSignatureExpectation = nil
        let cferr = CFErrorCreate(nil, TKError.errorDomain as NSString, TKError.corruptedData.rawValue, nil)!
        secKeyHelperMock.createSignatureError = cferr
        let available = mut?.isPrivateKeyAvailable(privateKeyInternalTag)
        XCTAssertEqual(available, false)
    }

    func testCheckPrivateKeyAvailability_InClamshellMode() {
        secKeyHelperMock.getKeyExpectation = 0
        secKeyHelperMock.getKeyRefExpectation = keyData as CFTypeRef

        secKeyHelperMock.createSignatureExpectation = nil
        let cferr = CFErrorCreate(nil, LAError.errorDomain as NSString, LAError.systemCancel.rawValue, nil)!
        secKeyHelperMock.createSignatureError = cferr

        let result = mut?.checkPrivateKeyAvailability(privateKeyInternalTag)
        XCTAssertNotNil(result)
        XCTAssertEqual(result!.keyState, .lost)
        let oktaError = result!.error
        XCTAssertNotNil(oktaError)
        switch oktaError! {
        case let .securityError(encryptionError):
            switch encryptionError {
            case let .generalEncryptionError(_, generalError, _):
                let nsError = generalError as NSError?
                XCTAssertNotNil(nsError)
                XCTAssertEqual(nsError!.domain, LAError.errorDomain)
                XCTAssertEqual(nsError!.code, LAError.systemCancel.rawValue)
            default:
                XCTFail("Wrong error type. Expect a generalEncryptionError")
            }
        default:
            XCTFail("Wrong error type. Expect an encryptionError")
        }
    }

    func testCheckPrivateKeyAvailability_BiometryLockedOut() {
        secKeyHelperMock.getKeyExpectation = 0
        secKeyHelperMock.getKeyRefExpectation = keyData as CFTypeRef

        secKeyHelperMock.createSignatureExpectation = nil
        let cferr = CFErrorCreate(nil, LAError.errorDomain as NSString, LAError.biometryLockout.rawValue, nil)!
        secKeyHelperMock.createSignatureError = cferr

        let result = mut?.checkPrivateKeyAvailability(privateKeyInternalTag)
        XCTAssertNotNil(result)
        XCTAssertEqual(result!.keyState, .lockedOut)
        let oktaError = result!.error
        XCTAssertNotNil(oktaError)
        switch oktaError! {
        case let .securityError(encryptionError):
            switch encryptionError {
            case let .generalEncryptionError(_, generalError, _):
                let nsError = generalError as NSError?
                XCTAssertNotNil(nsError)
                XCTAssertEqual(nsError!.domain, LAError.errorDomain)
                XCTAssertEqual(nsError!.code, LAError.biometryLockout.rawValue)
            default:
                XCTFail("Wrong error type. Expect a generalEncryptionError")
            }
        default:
            XCTFail("Wrong error type. Expect an encryptionError")
        }
    }
}
