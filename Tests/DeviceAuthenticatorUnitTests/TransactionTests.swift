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

import XCTest
import LocalAuthentication
@testable import DeviceAuthenticator

class TransactionTests: XCTestCase {

    var storageMock: StorageMock!
    var restAPIMock: RestAPIMock!
    var cryptoManager: CryptoManagerMock!
    var jwtGeneratorMock: OktaJWTGeneratorMock!
    var deviceAuthenticator: DeviceAuthenticator!

    override func setUp() {
        cryptoManager = CryptoManagerMock(accessGroupId: ExampleAppConstants.appGroupId, logger: OktaLoggerMock())
        jwtGeneratorMock = OktaJWTGeneratorMock(logger: OktaLoggerMock())
        storageMock = StorageMock()
        deviceAuthenticator = try! DeviceAuthenticatorBuilder(applicationConfig: ApplicationConfig(applicationName: "",
                                                                                                   applicationVersion: "",
                                                                                                   applicationGroupId: ExampleAppConstants.appGroupId))
                                   .create() as! DeviceAuthenticator
        deviceAuthenticator.impl.storageManager = storageMock
    }

    func testGenerateAuthenticationJWTString_Success() {
        let mut = OktaTransaction(loginHint: nil, storageManager: storageMock, cryptoManager: cryptoManager, jwtGenerator: nil, logger: OktaLoggerMock())
        let authenticator = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string:"okta.okta.com")!,
                                                                    orgId: "orgId",
                                                                    enrollmentId: "enrollment_id",
                                                                    cryptoManager: cryptoManager)
        let ex = expectation(description: "Completion expected!")
        mut.generateAuthenticationJWTString(for: authenticator, onCompletion: { authenticationToken, error in
            XCTAssertNotNil(authenticationToken)
            ex.fulfill()
        })
        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testGenerateAuthenticationJWTString_CantGetKey() {
        let mut = OktaTransaction(loginHint: nil, storageManager: storageMock, cryptoManager: OktaCryptoManager(accessGroupId: "", logger: OktaLoggerMock()), jwtGenerator: nil, logger: OktaLoggerMock())
        let authenticator = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string:"okta.okta.com")!,
                                                                    orgId: "orgId",
                                                                    enrollmentId: "enrollment_id",
                                                                    cryptoManager: cryptoManager)
        
        let ex = expectation(description: "Completion expected!")
        mut.generateAuthenticationJWTString(for: authenticator) { token, error in
            XCTAssertNil(token)
            if case let .securityError(encryptionError) = error {
                XCTAssertEqual(encryptionError, SecurityError.jwtError("Failed to read private key"))
            } else {
                XCTFail()
            }
            ex.fulfill()
        }
        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testGenerateAuthenticationJWTString_GenerationFailed() {
        jwtGeneratorMock.generateHook = { jwtType, kid, payLoad, key, algo in
            XCTAssertEqual(kid, "userVerificationKeyTag")
            throw DeviceAuthenticatorError.genericError("Some error")
        }
        let mut = OktaTransaction(loginHint: nil, storageManager: storageMock, cryptoManager: cryptoManager, jwtGenerator: jwtGeneratorMock, logger: OktaLoggerMock())
        let authenticator = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string:"okta.okta.com")!,
                                                                    orgId: "orgId",
                                                                    enrollmentId: "enrollment_id",
                                                                    cryptoManager: cryptoManager)
        let ex = expectation(description: "Completion expected!")
        mut.generateAuthenticationJWTString(for: authenticator) { token, error in
            XCTAssertNil(token)
            if case let .securityError(encryptionError) = error {
                XCTAssertEqual(encryptionError, SecurityError.jwtError("Failed to sign jwt"))
            } else {
                XCTFail()
            }
            ex.fulfill()
        }
        waitForExpectations(timeout: 1.0, handler: nil)
    }
    
    func testGenerateAuthenticationJWTString_UserCancelled() {
        jwtGeneratorMock.generateHook = { jwtType, kid, payLoad, key, algo in
            XCTAssertEqual(kid, "userVerificationKeyTag")
            throw SecurityError.localAuthenticationCancelled(LAError(.userCancel))
        }
        let mut = OktaTransaction(loginHint: nil, storageManager: storageMock, cryptoManager: cryptoManager, jwtGenerator: jwtGeneratorMock, logger: OktaLoggerMock())
        let authenticator = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string:"okta.okta.com")!,
                                                                    orgId: "orgId",
                                                                    enrollmentId: "enrollment_id",
                                                                    cryptoManager: cryptoManager)
        let ex = expectation(description: "Completion expected!")
        mut.generateAuthenticationJWTString(for: authenticator) { token, error in
            XCTAssertNil(token)
            XCTAssertEqual(error?.userVerificationCancelled(), true)
            XCTAssertEqual(error?.localizedDescription, "Encryption operation failed")
            let expectedErrorCode = DeviceAuthenticatorError.securityError(SecurityError.localAuthenticationCancelled(LAError(.userCancel))).errorCode
            XCTAssertEqual(error?.errorCode, expectedErrorCode)
            ex.fulfill()
        }
        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testGenerateAuthenticationJWTString_UseProofOfPossessionKeyIfUVIsNotEnrolled() {
        jwtGeneratorMock.generateHook = { jwtType, kid, payLoad, key, algo in
            XCTAssertEqual(kid, "proofOfPossessionKeyTag")
            throw DeviceAuthenticatorError.genericError("Some error")
        }
        let mut = OktaTransaction(loginHint: nil, storageManager: storageMock, cryptoManager: cryptoManager, jwtGenerator: jwtGeneratorMock, logger: OktaLoggerMock())
        let authenticator = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string:"okta.okta.com")!,
                                                                    orgId: "orgId",
                                                                    enrollmentId: "enrollment_id",
                                                                    cryptoManager: cryptoManager,
                                                                    userVerificationKeyTag: nil)
        let ex = expectation(description: "Completion expected!")
        mut.generateAuthenticationJWTString(for: authenticator) { token, error in
            XCTAssertNil(token)
            if case let .securityError(encryptionError) = error {
                XCTAssertEqual(encryptionError, SecurityError.jwtError("Failed to sign jwt"))
            } else {
                XCTFail()
            }
            ex.fulfill()
        }
        waitForExpectations(timeout: 1.0, handler: nil)
    }
}
