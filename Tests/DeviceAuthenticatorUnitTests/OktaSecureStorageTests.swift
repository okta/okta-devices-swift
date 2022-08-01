/*
* Copyright (c) 2022, Okta, Inc. and/or its affiliates. All rights reserved.
* The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
*
* You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*
* See the License for the specific language governing permissions and limitations under the License.
*/

import XCTest
import LocalAuthentication
@testable import DeviceAuthenticator

class OktaSecureStorageTests: XCTestCase {

    var secureStorage : OktaSecureStorage!
    
    override func setUp() {
        secureStorage = OktaSecureStorage()
    }

    override func tearDown() {
        try? secureStorage.clear()
    }

    #if !SWIFT_PACKAGE
    func testSetAndGetWithStringSuccessCases() {
        do {
            try secureStorage.set("token", forKey: "account1", behindBiometrics: false)
            let result = try secureStorage.get(key: "account1")
            XCTAssertEqual("token", result)
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }

        #if !targetEnvironment(simulator)
        do {
            try secureStorage.set("token", forKey: "account2", behindBiometrics: true)
            let result = try secureStorage.get(key: "account2")
            XCTAssertEqual("token", result)
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }
        #endif

        do {
            try secureStorage.set("token", forKey: "account3", behindBiometrics: false, accessibility: kSecAttrAccessibleAfterFirstUnlock)
            let result = try secureStorage.get(key: "account3")
            XCTAssertEqual("token", result)
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }
        
        var accessGroup : String? = nil
        do {
            let seedId = try secureStorage.bundleSeedId()
            accessGroup = seedId + ".\(ExampleAppConstants.bundleId)"
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
            return
        }

        do {
            try secureStorage.set("token", forKey: "account4", behindBiometrics: false, accessGroup:accessGroup!)
            let result = try secureStorage.get(key: "account4")
            XCTAssertEqual("token", result)
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }

        do {
            try secureStorage.set("token",
                                  forKey: "account5",
                                  behindBiometrics: false,
                                  accessGroup:accessGroup,
                                  accessibility:kSecAttrAccessibleAfterFirstUnlock)
            let result = try secureStorage.get(key: "account5")
            XCTAssertEqual("token", result)
        } catch {
            XCTFail("Keychain operation failed - \(error)")
        }

        #if !targetEnvironment(simulator)
        do {
            try secureStorage.set("token",
                                  forKey: "account6",
                                  behindBiometrics: true,
                                  accessGroup:accessGroup,
                                  accessibility:kSecAttrAccessibleAfterFirstUnlock)
            let result = try secureStorage.get(key: "account6")
            XCTAssertEqual("token", result)
        } catch {
            XCTFail("Keychain operation failed - \(error)")
        }
        #endif
    }

    func testSetAndGetWithDataSuccessCases() {
        do {
            try secureStorage.set(data:"token".data(using: .utf8)!, forKey: "account7", behindBiometrics: false)
            let result = try secureStorage.getData(key: "account7")
            XCTAssertEqual("token".data(using: .utf8)!, result)
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }

        #if !targetEnvironment(simulator)
        do {
            try secureStorage.set(data:"token".data(using: .utf8)!, forKey: "account8", behindBiometrics: true)
            let result = try secureStorage.getData(key: "account8")
            XCTAssertEqual("token".data(using: .utf8)!, result)
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }
        #endif
        
        do {
            try secureStorage.set(data:"token".data(using: .utf8)!, forKey: "account9", behindBiometrics: false, accessibility: kSecAttrAccessibleAfterFirstUnlock)
            let result = try secureStorage.getData(key: "account9")
            XCTAssertEqual("token".data(using: .utf8)!, result)
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }

        var accessGroup : String? = nil
        do {
            let seedId = try secureStorage.bundleSeedId()
            accessGroup = seedId + ".\(ExampleAppConstants.bundleId)"
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
            return
        }

        do {
            try secureStorage.set(data:"token".data(using: .utf8)!, forKey: "account10", behindBiometrics: false, accessGroup:accessGroup!)
            let result = try secureStorage.getData(key: "account10")
            XCTAssertEqual("token".data(using: .utf8)!, result)
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }
        
        do {
            try secureStorage.set(data:"token".data(using: .utf8)!,
                                  forKey: "account11",
                                  behindBiometrics: false,
                                  accessGroup:accessGroup,
                                  accessibility:kSecAttrAccessibleAfterFirstUnlock)
            let result = try secureStorage.getData(key: "account11")
            XCTAssertEqual("token".data(using: .utf8)!, result)
        } catch {
            XCTFail("Keychain operation failed - \(error)")
        }

        #if !targetEnvironment(simulator)
        do {
            try secureStorage.set(data:"token".data(using: .utf8)!,
                                  forKey: "account12",
                                  behindBiometrics: true,
                                  accessGroup:accessGroup,
                                  accessibility:kSecAttrAccessibleAfterFirstUnlock)
            let result = try secureStorage.getData(key: "account12")
            XCTAssertEqual("token".data(using: .utf8)!, result)
        } catch {
            XCTFail("Keychain operation failed - \(error)")
        }
        #endif
    }
    #endif

    #if !SWIFT_PACKAGE
    func testSetWithApplicationPassword() {
        #if !targetEnvironment(simulator)
            secureStorage = OktaSecureStorage(applicationPassword: "password")
            do {
                try secureStorage.set("token", forKey: "john doe", behindBiometrics: false)
                let result = try secureStorage.getData(key: "john doe")
                XCTAssertEqual("token".data(using: .utf8)!, result)
            } catch let error {
                XCTFail("Keychain operation failed - \(error)")
            }
        #endif
    }

    func testSetWithWrongApplicationPassword() {
#if targetEnvironment(simulator)
        return
#else
        secureStorage = OktaSecureStorage(applicationPassword: "password")
        do {
            try secureStorage.set("token", forKey: "john doe", behindBiometrics: false)
            secureStorage = OktaSecureStorage(applicationPassword: "wrong_password")
            let result = try secureStorage.get(key: "john doe")
            XCTFail("Failure is expected, got data - \(result)")
        } catch let error as NSError {
            XCTAssertEqual(-25293, error.code)
        }
        
        do {
            secureStorage = OktaSecureStorage(applicationPassword: "password")
            let result = try secureStorage.get(key: "john doe")
            XCTAssertEqual("token", result)
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }
#endif
    }
    
    func testSetAndGetWithEmptyApplicationPassword() {
#if targetEnvironment(simulator)
        return
#else
        secureStorage = OktaSecureStorage(applicationPassword: "")
        do {
            try secureStorage.set("token", forKey: "john doe", behindBiometrics: false)
            XCTFail("Failure is expected")
        } catch let error as NSError {
            XCTAssertEqual(-25293, error.code)
        }
#endif
    }

    func testDeleteSuccessCase() {
        do {
            try secureStorage.set("token", forKey: "john doe", behindBiometrics: false)
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }

        do {
            try secureStorage.delete(key: "john doe")
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }

        do {
            _ = try secureStorage.get(key: "john doe")
            XCTAssert(false, "Exception expected here")
        } catch let error as NSError {
            XCTAssert(error.code == errSecItemNotFound)
        }
    }

    func testClearSuccessCase() {
        do {
            try secureStorage.set("token", forKey: "account0", behindBiometrics: false)
            try secureStorage.set("token", forKey: "account1", behindBiometrics: false)
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }
        
        do {
            try secureStorage.clear()
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }
        
        do {
            _ = try secureStorage.get(key: "account0")
            XCTFail("Exception expected here")
        } catch let error as NSError {
            XCTAssert(error.code == errSecItemNotFound)
        }

        do {
            _ = try secureStorage.get(key: "account1")
            XCTFail("Exception expected here")
        } catch let error as NSError {
            XCTAssert(error.code == errSecItemNotFound)
        }
    }
    #endif
    
    func testTouchIDSupported() {
        let laContext = LAContext()
        var touchIdSupported = false
        if #available(iOS 11.0, *) {
            let touchIdEnrolled = laContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            touchIdSupported = laContext.biometryType == .touchID && touchIdEnrolled
        } else {
            touchIdSupported = laContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        }
        XCTAssert(touchIdSupported == secureStorage.isTouchIDSupported())
    }

    @available(macOS 10.15, *)
    func testFaceIDSupported() {
        let  laContext = LAContext()
        var faceIdSupported = false
        let biometricsEnrolled = laContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        if #available(iOS 11.0, *) {
            faceIdSupported = laContext.biometryType == .faceID
        }
        let faceIDSupported = biometricsEnrolled && faceIdSupported
        XCTAssert(faceIDSupported == secureStorage.isFaceIDSupported())
    }

    #if !SWIFT_PACKAGE
    func testBundleSeedIdSuccessCase() {
        do {
            let seedId = try secureStorage.bundleSeedId()
            XCTAssertEqual(seedId, "7WXXBW6Z2Y")
        } catch let error as NSError {
            XCTFail("Keychain operation failed - \(error)")
        }
    }

    func testDataOverwriteSuccessCase() {
        do {
            try secureStorage.set("token", forKey: "john doe", behindBiometrics: false)
            var result = try secureStorage.get(key: "john doe")
            XCTAssertEqual("token", result)
            try secureStorage.set("password", forKey: "john doe", behindBiometrics: false)
            result = try secureStorage.get(key: "john doe")
            XCTAssertEqual("password", result)
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }
    }
    #endif

    #if !SWIFT_PACKAGE
    func testSetFailureCases() {
        do {
            try secureStorage.set("token", forKey: "", behindBiometrics: false, accessibility:"" as CFString)
            XCTFail("Exception expected here")
        } catch let error as NSError {
            XCTAssert(error.code == errSecParam)
        }

        do {
            try secureStorage.set("token", forKey: "", behindBiometrics: true, accessibility:"" as CFString)
            XCTFail("Exception expected here")
        } catch let error as NSError {
            XCTAssert(error.code == errSecParam)
        }
    }

    func testSetGetDeleteWithGroupId() {

        let seedId = try? secureStorage.bundleSeedId()
        let accessGroup = (seedId ?? "") + ".\(ExampleAppConstants.bundleId)"
        do {
            try secureStorage.set("data1", forKey: "key1", behindBiometrics: false, accessGroup: accessGroup)
            let result = try secureStorage.get(key: "key1")
            XCTAssertEqual("data1", result)
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }

        do {
            try secureStorage.set("data2", forKey: "key2", behindBiometrics: false, accessGroup: accessGroup)
            let result = try secureStorage.get(key: "key2", accessGroup: accessGroup)
            XCTAssertEqual("data2", result)
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }

        do {
            try secureStorage.set("data", forKey: "key", behindBiometrics: false, accessGroup: "wrong_group")
            XCTFail("Unexpected successful set")
        } catch let error as NSError {
            XCTAssertEqual(error.code, -34018)
        }

        do {
            try secureStorage.delete(key: "key1")
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }

        do {
            try secureStorage.delete(key: "key2", accessGroup: accessGroup)
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }
    }
    #endif
    
    func testGetFailureCases() {
        do {
            _ = try secureStorage.get(key: "")
            XCTFail("Exception expected here")
        } catch let error as NSError {
            XCTAssert(error.code == errSecItemNotFound)
        }
    }
    
    private func verifyMultipleSetAndGetStoredKeys(behindBiometrics: Bool) {
        XCTAssertThrowsError(try secureStorage.getStoredKeys(biometricPrompt: nil), "getStoredKeys() throws for no keys stored") { error in
            XCTAssertEqual((error as NSError).code, -25300)
        }

        do {
            try secureStorage.set(data: "someData1".data(using: .utf8)!, forKey: "account1", behindBiometrics: behindBiometrics)
            try secureStorage.set(data: "someData2".data(using: .utf8)!, forKey: "account2", behindBiometrics: behindBiometrics)
            try secureStorage.set(data: "someData3".data(using: .utf8)!, forKey: "anotherKey", behindBiometrics: behindBiometrics)
            let result = try secureStorage.getStoredKeys(biometricPrompt: nil)
            XCTAssertEqual(3, result.count)
            XCTAssertTrue(result.contains("account1"))
            XCTAssertTrue(result.contains("account2"))
            XCTAssertTrue(result.contains("anotherKey"))
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }

        do {
            try secureStorage.delete(key: "account2")
            let result = try secureStorage.getStoredKeys(biometricPrompt: nil)
            XCTAssertEqual(2, result.count)
            XCTAssertTrue(result.contains("account1"))
            XCTAssertTrue(result.contains("anotherKey"))
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }

        do {
            try secureStorage.delete(key: "account1")
            try secureStorage.delete(key: "anotherKey")
        } catch let error {
            XCTFail("Keychain operation failed - \(error)")
        }
        XCTAssertThrowsError(try secureStorage.getStoredKeys(biometricPrompt: nil), "getStoredKeys() should throw when no keys are stored") { error in
            XCTAssertEqual((error as NSError).code, -25300)
        }
    }
}
