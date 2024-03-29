/*
* Copyright (c) 2019-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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

class TransactionEnrollTests: XCTestCase {

    var jwkGeneratorMock: OktaJWKGeneratorMock!
    var jwtGeneratorMock: OktaJWTGeneratorMock!
    var secKeyHelperMock: SecKeyHelperMock!
    var transaction: OktaTransactionEnroll!
    fileprivate var transactionPartialMock: OktaTransactionEnrollPartialMock!
    fileprivate var cryptoManager: OktaCryptoManagerMock!
    var mockStorageManager: StorageMock!
    var restAPIMock: RestAPIMock!
    var metaData: AuthenticatorMetaDataModel!
    let applicationConfig = ApplicationConfig(applicationName: "Test App",
                                              applicationVersion: "1.0.0",
                                              applicationGroupId: ExampleAppConstants.appGroupId)
    let authenticatorConfig = DeviceAuthenticatorConfig(orgURL: URL(string: "tenant.okta.com")!, oidcClientId: "oidcClientId")
    var enrollmentContext: EnrollmentContext!

    override func setUp() {
        secKeyHelperMock = SecKeyHelperMock()
        cryptoManager = OktaCryptoManagerMock(keychainGroupId: "", secKeyHelper: secKeyHelperMock, logger: OktaLoggerMock())

        let mockURL = URL(string: "https://example.okta.com")!
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                                                            HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                                                            HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!],
                                                            dataArray: [GoldenData.orgData(), MyAccountTestData.policyResponse(), MyAccountTestData.enrollmentResponse()])
        restAPIMock = RestAPIMock(client: mockHTTPClient, logger: OktaLoggerMock())

        mockStorageManager = StorageMock()

        let decoder = JSONDecoder()
        let metaDataArray = try! decoder.decode([AuthenticatorMetaDataModel].self, from: GoldenData.authenticatorMetaData())
        metaData = metaDataArray[0]
        jwkGeneratorMock = OktaJWKGeneratorMock(logger: OktaLoggerMock())
        jwtGeneratorMock = OktaJWTGeneratorMock(logger: OktaLoggerMock())
        enrollmentContext = createEnrollmentContext(enrollBiometricKey: true, enrollBiometricOrPinKey: true, pushToken: "push_token", supportsCIBA: true)
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: nil, jwtGenerator: OktaJWTGenerator(logger: OktaLoggerMock()))
        transaction.metaData = metaData
        transaction.orgId = ""
        transactionPartialMock = OktaTransactionEnrollPartialMock(storageManager: mockStorageManager,
                                                                  cryptoManager: cryptoManager,
                                                                  restAPI: restAPIMock,
                                                                  enrollmentContext: enrollmentContext,
                                                                  jwkGenerator: jwkGeneratorMock,
                                                                  jwtGenerator: OktaJWTGenerator(logger: OktaLoggerMock()),
                                                                  applicationConfig: applicationConfig,
                                                                  logger: OktaLoggerMock())
        transactionPartialMock.metaData = metaData
        transactionPartialMock.orgId = ""
    }

    func testEnroll_SuccessDoEnrollmentCalled() {
        let deviceEnrollment = OktaDeviceEnrollment(id: "id",
                                                    orgId: "tenant.okta.com",
                                                    clientInstanceId: "clientInstanceId",
                                                    clientInstanceKeyTag: "clientInstanceTag")
        try? mockStorageManager.storeDeviceEnrollment(deviceEnrollment, for: transactionPartialMock.orgId)
        let enrollExpectation = expectation(description: "Do enrollment expectation")
        transactionPartialMock.doEnrollmentHook = { factorsMetaData, completion in
            XCTAssertTrue(factorsMetaData.count == 1)
            XCTAssertNil(self.transactionPartialMock.deviceEnrollment)
            enrollExpectation.fulfill()
        }

        transactionPartialMock.enroll { result in
            if case Result.failure(_) = result {
                XCTFail("Unexpected result")
            }
        }

        wait(for: [enrollExpectation], timeout: 5.0)
    }

    func testEnroll_Error() {
        secKeyHelperMock.generateRandomKeyHook = { _, _ in
            return nil
        }
        transaction.enroll { result in
            switch result {
            case .success(_):
                XCTFail("Unexpected result")
            case .failure(let error):
                let expectedErrorCode = DeviceAuthenticatorError.securityError(SecurityError.jwkError("")).errorCode
                XCTAssertEqual(error.errorCode, expectedErrorCode)
            }
        }
    }

    func testEnrollFactors_Success() {
        do {
            let factors = try transaction.enrollFactors()
            XCTAssertTrue(factors.count == 1)
        } catch {
            XCTFail("Unexpected exception thrown - \(error)")
        }
    }

    func testEnrollFactors_EncyptionError() {
        secKeyHelperMock.generateRandomKeyHook = { _, _ in
            return nil
        }
        do {
            let _ = try transaction.enrollFactors()
            XCTFail("Unexpected. Exception should be thrown")
        } catch let error as DeviceAuthenticatorError {
            let expectedErrorCode = DeviceAuthenticatorError.securityError(SecurityError.jwkError("")).errorCode
            XCTAssertEqual(error.errorCode, expectedErrorCode)
        } catch {
            XCTFail("Unexpected exception thrown - \(error)")
        }
    }

    func testEnrollFactors_EmptyMetaData() {
        // provide empty metadata
        let metaData = AuthenticatorMetaDataModel(id: "",
                                                  key: "",
                                                  type: "",
                                                  status: .active,
                                                  name: nil,
                                                  settings: nil,
                                                  _links: AuthenticatorMetaDataModel.Links(enroll: AuthenticatorMetaDataModel.Links.EnrollLink(href: ""),
                                                    logos: nil),
                                                  _embedded: AuthenticatorMetaDataModel.Embedded(methods: []))
        let mut = createTransaction(enrollmentContext: enrollmentContext, enrollment: nil, jwtGenerator: OktaJWTGenerator(logger: OktaLoggerMock()))
        mut.metaData = metaData
        do {
            let _ = try mut.enrollFactors()
            XCTFail("Unexpected. Exception should be thrown")
        } catch let error as DeviceAuthenticatorError {
            XCTAssertEqual(error.errorCode, DeviceAuthenticatorError.noVerificationMethodsToEnroll.errorCode)
        } catch {
            XCTFail("Unexpected exception thrown - \(error)")
        }
    }

    func testEnrollPushFactor_Success() {
        var numberOfRegisterKeyCalls = 0
        transactionPartialMock.registerKeyHook = { algorithm, keyTag, reuseKey, useBiometrics, biometricSettings in
            numberOfRegisterKeyCalls += 1
            XCTAssertEqual(algorithm, Algorithm.ES256)
            if numberOfRegisterKeyCalls == 2 {
                XCTAssertTrue(useBiometrics)
                XCTAssertNotNil(biometricSettings)
            }
            XCTAssertFalse(reuseKey)

            return [:]
        }
        do {
            let pushMethod = try transactionPartialMock.enrollPushFactor(serverMethod: transaction.metaData._embedded.methods[0])
            XCTAssertNotNil(pushMethod)
            XCTAssertEqual(pushMethod?.methodType, .push)
            XCTAssertNotNil(pushMethod?.proofOfPossessionKeyTag)
            XCTAssertNotNil(pushMethod?.userVerificationKeyTag)
            XCTAssertNotNil(pushMethod?.userVerificationBioOrPinKeyTag)
            XCTAssertNotNil(pushMethod?.keys)
            XCTAssertNotNil(pushMethod?.pushToken)
            XCTAssertEqual(pushMethod?.pushToken, "push_token".data(using: .utf8)?.hexString())
            XCTAssertEqual(pushMethod?.methodType, AuthenticatorMethod.push)
        } catch {
            XCTFail("Unexpected exception thrown - \(error)")
        }

        XCTAssertEqual(numberOfRegisterKeyCalls, 3)
    }

    func testEnrollPushFactorWithBioOrPinKey_Success() {
        enrollmentContext = createEnrollmentContext(enrollBiometricKey: true,
                                                    enrollBiometricOrPinKey: true,
                                                    pushToken: "push_token",
                                                    supportsCIBA: true)
        transactionPartialMock = OktaTransactionEnrollPartialMock(storageManager: mockStorageManager,
                                                                  cryptoManager: cryptoManager,
                                                                  restAPI: restAPIMock,
                                                                  enrollmentContext: enrollmentContext,
                                                                  jwkGenerator: jwkGeneratorMock,
                                                                  jwtGenerator: OktaJWTGenerator(logger: OktaLoggerMock()),
                                                                  applicationConfig: applicationConfig,
                                                                  logger: OktaLoggerMock())
        transactionPartialMock.metaData = metaData
        transactionPartialMock.orgId = ""

        var numberOfRegisterKeyCalls = 0
        transactionPartialMock.registerKeyHook = { algorithm, keyTag, reuseKey, useBiometrics, biometricSettings in
            numberOfRegisterKeyCalls += 1
            XCTAssertEqual(algorithm, Algorithm.ES256)
            switch numberOfRegisterKeyCalls {
            case 1: // popKey
                XCTAssertFalse(useBiometrics)
                XCTAssertNil(biometricSettings)
            case 2: // uvKey
                XCTAssertTrue(useBiometrics)
                XCTAssertNotNil(biometricSettings)
                XCTAssertEqual(biometricSettings!.accessControlFlags, .biometryCurrentSet)
            case 3: // uvBioOrPinKey
                XCTAssertTrue(useBiometrics)
                XCTAssertNotNil(biometricSettings)
                XCTAssertEqual(biometricSettings!.accessControlFlags, .userPresence)
            default:
                break
            }

            XCTAssertFalse(reuseKey)

            return [:]
        }

        do {
            let pushMethod = try transactionPartialMock.enrollPushFactor(serverMethod: transaction.metaData._embedded.methods[0])
            XCTAssertNotNil(pushMethod)
            XCTAssertEqual(pushMethod?.methodType, .push)
            XCTAssertNotNil(pushMethod?.proofOfPossessionKeyTag)
            XCTAssertNotNil(pushMethod?.userVerificationKeyTag)
            XCTAssertNotNil(pushMethod?.userVerificationBioOrPinKeyTag)
            XCTAssertNotNil(pushMethod?.keys)
            XCTAssertNotNil(pushMethod?.pushToken)
            XCTAssertEqual(pushMethod?.pushToken, "push_token".data(using: .utf8)?.hexString())
            XCTAssertEqual(pushMethod?.methodType, AuthenticatorMethod.push)
        } catch {
            XCTFail("Unexpected exception thrown - \(error)")
        }

        XCTAssertEqual(numberOfRegisterKeyCalls, 3)
    }

    func testEnrollPushFactor_UpdateEnrollment() {
        do {
            let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                     orgId: "orgId",
                                                                     enrollmentId: "enrollmentId",
                                                                     cryptoManager: cryptoManager,
                                                                     enrollPush: false)
            transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: enrollment, jwtGenerator: OktaJWTGenerator(logger: OktaLoggerMock()))
            transaction.metaData = metaData
            let enrollingFactor = try transaction.enrollPushFactor(serverMethod: transaction.metaData._embedded.methods[0])
            XCTAssertNotNil(enrollingFactor)
            XCTAssertNotNil(enrollingFactor?.proofOfPossessionKeyTag)
            XCTAssertNotNil(enrollingFactor?.userVerificationKeyTag)
            XCTAssertNotNil(enrollingFactor?.userVerificationBioOrPinKeyTag)
            XCTAssertNotNil(enrollingFactor?.keys)
            XCTAssertNotNil(enrollingFactor?.pushToken)
            XCTAssertEqual(enrollingFactor?.apsEnvironment, .production)
            XCTAssertEqual(enrollingFactor?.methodType, .push)
        } catch {
            XCTFail("Unexpected exception thrown - \(error)")
        }
    }

    func testEnrollPushFactor_UpdateEnrollmentWithBioOrPinKey() {
        do {
            let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                     orgId: "orgId",
                                                                     enrollmentId: "enrollmentId",
                                                                     cryptoManager: cryptoManager,
                                                                     enrollPush: false)
            enrollmentContext = createEnrollmentContext(enrollBiometricKey: true, enrollBiometricOrPinKey: true, pushToken: "push_token", supportsCIBA: true)
            transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: enrollment, jwtGenerator: OktaJWTGenerator(logger: OktaLoggerMock()))
            transaction.metaData = metaData
            let enrollingFactor = try transaction.enrollPushFactor(serverMethod: transaction.metaData._embedded.methods[0])
            XCTAssertNotNil(enrollingFactor)
            XCTAssertNotNil(enrollingFactor?.proofOfPossessionKeyTag)
            XCTAssertNotNil(enrollingFactor?.userVerificationKeyTag)
            XCTAssertNotNil(enrollingFactor?.userVerificationBioOrPinKeyTag)
            XCTAssertNotNil(enrollingFactor?.keys)
            XCTAssertNotNil(enrollingFactor?.pushToken)
            XCTAssertEqual(enrollingFactor?.apsEnvironment, .production)
            XCTAssertEqual(enrollingFactor?.methodType, .push)
        } catch {
            XCTFail("Unexpected exception thrown - \(error)")
        }
    }

    func testEnrollPushFactor_UpdateEnrollment_EnrollPush() {
        do {
            let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                     orgId: "orgId",
                                                                     enrollmentId: "enrollmentId",
                                                                     cryptoManager: cryptoManager,
                                                                     enrollPush: false)
            transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: enrollment, jwtGenerator: OktaJWTGenerator(logger: OktaLoggerMock()))
            transaction.metaData = metaData
            let enrollingFactor = try transaction.enrollPushFactor(serverMethod: transaction.metaData._embedded.methods[0])
            XCTAssertNotNil(enrollingFactor)
            XCTAssertNotNil(enrollingFactor?.pushToken)
            XCTAssertNotNil(enrollingFactor?.keys)
            XCTAssertNotNil(enrollingFactor?.proofOfPossessionKeyTag)
            XCTAssertNotNil(enrollingFactor?.userVerificationKeyTag)
            XCTAssertNotNil(enrollingFactor?.userVerificationBioOrPinKeyTag)
            XCTAssertEqual(enrollingFactor?.methodType, .push)
        } catch {
            XCTFail("Unexpected exception thrown - \(error)")
        }
    }

    func testEnrollPushFactor_UpdateEnrollment_EnrollNewMethods_PushFactorAlreadyExists() {
        do {
            let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                     orgId: "orgId",
                                                                     enrollmentId: "enrollmentId",
                                                                     cryptoManager: cryptoManager,
                                                                     enrollPush: true)
            transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: enrollment, jwtGenerator: OktaJWTGenerator(logger: OktaLoggerMock()))
            transaction.metaData = metaData
            let enrollingFactor = try transaction.enrollPushFactor(serverMethod: transaction.metaData._embedded.methods[0])
            XCTAssertNotNil(enrollingFactor)
            XCTAssertNotNil(enrollingFactor?.keys)
            XCTAssertNotNil(enrollingFactor?.pushToken)
            XCTAssertNotNil(enrollingFactor?.proofOfPossessionKeyTag)
            XCTAssertNotNil(enrollingFactor?.userVerificationKeyTag)
            XCTAssertNotNil(enrollingFactor?.userVerificationBioOrPinKeyTag)
            XCTAssertEqual(enrollingFactor?.methodType, .push)
        } catch {
            XCTFail("Unexpected exception thrown - \(error)")
        }
    }

    func testEnrollPushFactor_UpdateEnrollment_NoPushFactorInEnrollment_PolicyHasPush() {
        do {
            let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                     orgId: "orgId",
                                                                     enrollmentId: "enrollmentId",
                                                                     cryptoManager: cryptoManager,
                                                                     enrollPush: false)
            transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: enrollment, jwtGenerator: OktaJWTGenerator(logger: OktaLoggerMock()))
            transaction.metaData = metaData
            let method = transaction.metaData._embedded.methods.first { $0.type == .push }
            let enrollingFactor = try transaction.enrollPushFactor(serverMethod: method!)
            XCTAssertNotNil(enrollingFactor)
            XCTAssertNotNil(enrollingFactor?.keys)
            XCTAssertNotNil(enrollingFactor?.pushToken)
            XCTAssertNotNil(enrollingFactor?.proofOfPossessionKeyTag)
            XCTAssertNotNil(enrollingFactor?.userVerificationKeyTag)
            XCTAssertNotNil(enrollingFactor?.userVerificationBioOrPinKeyTag)
        } catch {
            XCTFail("Unexpected exception thrown - \(error)")
        }
    }

    func testEnrollPushFactor_UpdateEnrollment_PushFactorEnrolled() {
        do {
            let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                     orgId: "orgId",
                                                                     enrollmentId: "enrollmentId",
                                                                     cryptoManager: cryptoManager)
            transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: enrollment, jwtGenerator: OktaJWTGenerator(logger: OktaLoggerMock()))
            transaction.metaData = metaData
            let enrollingFactor = try transaction.enrollPushFactor(serverMethod: transaction.metaData._embedded.methods[0])
            XCTAssertNotNil(enrollingFactor)
            XCTAssertNotNil(enrollingFactor?.keys)
            XCTAssertNotNil(enrollingFactor?.pushToken)
            XCTAssertNotNil(enrollingFactor?.proofOfPossessionKeyTag)
            XCTAssertNotNil(enrollingFactor?.userVerificationKeyTag)
            XCTAssertNotNil(enrollingFactor?.userVerificationBioOrPinKeyTag)
            XCTAssertEqual(enrollingFactor?.methodType, .push)
        } catch {
            XCTFail("Unexpected exception thrown - \(error)")
        }
    }

    func testRegisterKey_ValidateParameters() {
        cryptoManager.generateHook = { algorithm, keyTag, useSecureEnclave, useBiometrics, biometricSettings in
            XCTAssertEqual(algorithm, Algorithm.ES256)
            XCTAssertEqual(keyTag, "1234")
            XCTAssertEqual(useSecureEnclave, OktaEnvironment.canUseSecureEnclave())
            XCTAssertFalse(useBiometrics)
            XCTAssertNil(biometricSettings)
            let ec256ValidPrivateKeyBase64 = "BIBwuQyPfBPU+fyXiU+i0FOqEAHtm3U5aER8gIWVnyJvw9YfSa7ylqLNpdeyTie4zUFP9UU4FXLByqcaGFR1q05at441RDVAq1aewlvnE9pKcZmCiiayoO37AxpdRYcTmA=="
            return OktaKeyGeneratorHelper.getValidSecKeyES256(ec256ValidPrivateKeyBase64, isPublic: false)!
        }

        do {
            let _ = try transaction.registerKey(with: .ES256,
                                                keyTag: "1234",
                                                useBiometrics: false,
                                                biometricSettings: nil)
        } catch {
            XCTFail("Unexpected exception thrown - \(error)")
        }

        let expectedBiometricSetting = BiometricEnrollmentSettings(accessControlFlags: .biometryCurrentSet)
        cryptoManager.generateHook = { algorithm, keyTag, useSecureEnclave, useBiometrics, biometricSettings in
            XCTAssertEqual(algorithm, Algorithm.ES256)
            XCTAssertEqual(keyTag, "4321")
            XCTAssertEqual(useSecureEnclave, OktaEnvironment.canUseSecureEnclave())
            XCTAssertTrue(useBiometrics)
            let ec256ValidPrivateKeyBase64 = "BIBwuQyPfBPU+fyXiU+i0FOqEAHtm3U5aER8gIWVnyJvw9YfSa7ylqLNpdeyTie4zUFP9UU4FXLByqcaGFR1q05at441RDVAq1aewlvnE9pKcZmCiiayoO37AxpdRYcTmA=="
            return OktaKeyGeneratorHelper.getValidSecKeyES256(ec256ValidPrivateKeyBase64, isPublic: false)!
        }

        do {
            let _ = try transaction.registerKey(with: .ES256,
                                                keyTag: "4321",
                                                useBiometrics: true,
                                                biometricSettings: expectedBiometricSetting)
        } catch {
            XCTFail("Unexpected exception thrown - \(error)")
        }
    }

    func testRegisterKey_Success_NoBiometricOption() {
        do {
            let jwk = try transaction.registerKey(with: .ES256,
                                                  keyTag: "1234",
                                                  useBiometrics: false,
                                                  biometricSettings: nil)
            XCTAssertEqual(jwk["kid"], .string("1234"))
            XCTAssertEqual(transaction.factorsKeyTags.first, "1234")
#if targetEnvironment(simulator)
            XCTAssertEqual(jwk["okta:kpr"], .string("SOFTWARE"))
#else
            if OktaEnvironment.canUseSecureEnclave() {
                XCTAssertEqual(jwk["okta:kpr"], .string("HARDWARE"))
            } else {
                XCTAssertEqual(jwk["okta:kpr"], .string("SOFTWARE"))
            }
#endif
        } catch {
            XCTFail("Unexpected exception thrown - \(error)")
        }
    }

    func testRegisterKey_Success_WithBiometricOption() {
        do {
            let jwk = try transaction.registerKey(with: .ES256,
                                                  keyTag: "1234",
                                                  useBiometrics: true,
                                                  biometricSettings: BiometricEnrollmentSettings(accessControlFlags: .biometryAny))
            XCTAssertEqual(jwk["kid"], .string("1234"))
            XCTAssertEqual(transaction.factorsKeyTags.first, "1234")
#if targetEnvironment(simulator)
XCTAssertEqual(jwk["okta:kpr"], .string("SOFTWARE"))
#else
            if OktaEnvironment.canUseSecureEnclave() {
                XCTAssertEqual(jwk["okta:kpr"], .string("HARDWARE"))
            } else {
                XCTAssertEqual(jwk["okta:kpr"], .string("SOFTWARE"))
            }
#endif
        } catch {
            XCTFail("Unexpected exception thrown - \(error)")
        }
    }

    func testRegisterKey_Success_KeyGenerationError() {
        secKeyHelperMock.generateRandomKeyHook = { _, _ in
            return nil
        }

        do {
            let _ = try transaction.registerKey(with: .ES256,
                                                keyTag: "1234",
                                                useBiometrics: false,
                                                biometricSettings: nil)
            XCTFail("Unexpected. Exception is expected")
        } catch {
            XCTAssertEqual(SecurityError.keyGenFailed(-1, "").localizedDescription, error.localizedDescription)
        }
    }

    func testRegisterKey_Success_JWKError() {
        jwkGeneratorMock.generateHook = {_, _, _, _, _ in
            throw DeviceAuthenticatorError.internalError("")
        }

        do {
            let _ = try transaction.registerKey(with: .ES256,
                                                keyTag: "1234",
                                                useBiometrics: false,
                                                biometricSettings: nil)
            XCTFail("Unexpected. Excpetion is expected")
        } catch {
            XCTAssertEqual(DeviceAuthenticatorError.internalError("").localizedDescription, error.localizedDescription)
        }
    }

    func testRegisterKey_Success_ReuseKey_Success() {
        let getKeyExpectation = expectation(description: "Get Key expectation")
        secKeyHelperMock.getKeyHook = {_, keyPointer in
            getKeyExpectation.fulfill()
            let ec256ValidPrivateKeyBase64 = "BIBwuQyPfBPU+fyXiU+i0FOqEAHtm3U5aER8gIWVnyJvw9YfSa7ylqLNpdeyTie4zUFP9UU4FXLByqcaGFR1q05at441RDVAq1aewlvnE9pKcZmCiiayoO37AxpdRYcTmA=="
            let key = OktaKeyGeneratorHelper.getValidSecKeyES256(ec256ValidPrivateKeyBase64, isPublic: false)
            keyPointer?.initialize(to: key)
            return errSecSuccess
        }
        secKeyHelperMock.generateRandomKeyHook = {_, _ in
            XCTFail("Unexpected call")
            return  nil
        }

        do {
            let _ = try transaction.registerKey(with: .ES256,
                                                keyTag: "1234",
                                                reuseKey: true,
                                                useBiometrics: false,
                                                biometricSettings: nil)
            wait(for: [getKeyExpectation], timeout: 5.0)
        } catch {
            XCTFail("Unexpected exception thrown - \(error)")
        }
    }

    func testRegisterKey_Success_ReuseKey_FailToReuseKey() {
        let getKeyExpectation = expectation(description: "Get Key expectation")
        let generateKeyExpectation = expectation(description: "Generate Key expectation")
        secKeyHelperMock.getKeyHook = {_, _ in
            getKeyExpectation.fulfill()
            return errSecBadReq
        }
        secKeyHelperMock.generateRandomKeyHook = {_, _ in
            generateKeyExpectation.fulfill()
            let ec256ValidPrivateKeyBase64 = "BIBwuQyPfBPU+fyXiU+i0FOqEAHtm3U5aER8gIWVnyJvw9YfSa7ylqLNpdeyTie4zUFP9UU4FXLByqcaGFR1q05at441RDVAq1aewlvnE9pKcZmCiiayoO37AxpdRYcTmA=="
            return  OktaKeyGeneratorHelper.getValidSecKeyES256(ec256ValidPrivateKeyBase64, isPublic: false)
        }

        do {
            let _ = try transaction.registerKey(with: .ES256,
                                                keyTag: "1234",
                                                reuseKey: true,
                                                useBiometrics: false,
                                                biometricSettings: nil)
            wait(for: [getKeyExpectation, generateKeyExpectation], timeout: 5.0)
        } catch {
            XCTFail("Unexpected exception thrown - \(error)")
        }
    }

    func testBuildDeviceModelData_NoDeviceEnrollment() {
        let deviceModel = transaction.buildDeviceModelData(customDeviceSignals: nil)
        XCTAssertNotNil(deviceModel.clientInstanceKey)
        XCTAssertNotNil(transaction.clientInstanceKeyTag)
    }

    func testBuildDeviceModelData_WithDeviceEnrollment() {
        let deviceEnrollment = OktaDeviceEnrollment(id: "id",
                                                    orgId: "tenant.okta.com",
                                                    clientInstanceId: "clientInstanceId",
                                                    clientInstanceKeyTag: "clientInstanceKeyTag")
        let decoder = JSONDecoder()
        let metaDataArray = try! decoder.decode([AuthenticatorMetaDataModel].self, from: GoldenData.authenticatorMetaData())
        let metaData = metaDataArray[0]
        let mut = createTransaction(enrollmentContext: enrollmentContext, enrollment: nil)
        mut.deviceEnrollment = deviceEnrollment
        mut.metaData = metaData
        let deviceModel = mut.buildDeviceModelData(customDeviceSignals: nil)
        XCTAssertNil(deviceModel.clientInstanceKey)
        XCTAssertNil(transaction.clientInstanceKeyTag)
        XCTAssertNotNil(deviceModel.deviceAttestation!["clientInstanceKeyAttestation"])
    }

    func testDoEnrollment_Success() {
        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)
        transaction.clientInstanceKeyTag = "clientInstanceKeyTag"
        var hookCalled = false
        restAPIMock.enrollAuthenticatorRequestHook = { _, _, _, _, _, _, completion in
            hookCalled = true
        }
        transaction.doEnrollment(factorsMetaData: enrolledFactors!) { result in
        }

        XCTAssertTrue(hookCalled)
    }

    func testDoEnrollmentWithDeviceEnrollment_Success() {
        let decoder = JSONDecoder()
        let metaDataArray = try! decoder.decode([AuthenticatorMetaDataModel].self, from: GoldenData.authenticatorMetaData())
        let deviceEnrollment = OktaDeviceEnrollment(id: "id",
                                                    orgId: "tenant.okta.com",
                                                    clientInstanceId: "clientInstanceId",
                                                    clientInstanceKeyTag: "clientInstanceKeyTag")
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: nil, jwtGenerator: OktaJWTGenerator(logger: OktaLoggerMock()))
        transaction.deviceEnrollment = deviceEnrollment
        transaction.metaData = metaDataArray[0]
        transaction.orgId = ""
        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)
        transaction.clientInstanceKeyTag = "clientInstanceKeyTag"
        var hookCalled = false
        restAPIMock.enrollAuthenticatorRequestHook = { _, _, _, _, _, _, completion in
            hookCalled = true
        }
        transaction.doEnrollment(factorsMetaData: enrolledFactors!) { result in
            if case Result.failure(_) = result {
                XCTFail("Unexpected result")
            }
        }

        XCTAssertTrue(hookCalled)
    }

    func testDoEnrollment_NoEnrollLinkInMetadataSuccess() {
        let metaData = AuthenticatorMetaDataModel(id: "",
                                                  key: "",
                                                  type: "",
                                                  status: .active,
                                                  name: nil,
                                                  settings: nil,
                                                  _links: AuthenticatorMetaDataModel.Links(enroll: AuthenticatorMetaDataModel.Links.EnrollLink(href: ""),
                                                                                           logos: nil),
                                                  _embedded: AuthenticatorMetaDataModel.Embedded(methods: []))
        let mut = createTransaction(enrollmentContext: enrollmentContext, enrollment: nil, jwtGenerator: OktaJWTGenerator(logger: OktaLoggerMock()))

        let enrolledFactors = try? transaction.enrollFactors()
        mut.metaData = metaData
        XCTAssertNotNil(enrolledFactors)

        restAPIMock.enrollAuthenticatorRequestHook = { orgHost, _, _, _, _, _, completion in
            XCTAssertEqual(orgHost.absoluteString, "tenant.okta.com")
        }

        mut.doEnrollment(factorsMetaData: enrolledFactors!) { result in
        }
    }

    #if os(iOS)
    func testCreateEnrolledPushFactor_Success() {
        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)
        let enrolledModel = createEnrolledModel(id: "factorId",
                                    type: .push)
        let factor = transaction.createEnrolledPushFactor(from: enrolledFactors!, and: enrolledModel)
        XCTAssertNotNil(factor as? OktaFactorMetadataPush)
        XCTAssertNotNil((factor as? OktaFactorMetadataPush)?.proofOfPossessionKeyTag)
        XCTAssertNotNil((factor as? OktaFactorMetadataPush)?.userVerificationKeyTag)
        XCTAssertEqual(factor?.id, "factorId")
        XCTAssertEqual(factor?.type, .push)
    }
    #endif

    func testEnrollFactors_isFipsCompliant() {
        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)

        #if os(iOS)

        if let pushFactor = enrolledFactors?.first(where: { $0.methodType == .push }) {
            XCTAssertNil(pushFactor.isFipsCompliant)
            XCTAssertEqual(pushFactor.keys?.proofOfPossession?["okta:isFipsCompliant"],
                           .bool(OktaEnvironment.isSecureEnclaveAvailable()))
            XCTAssertEqual(pushFactor.keys?.userVerification?.value()?["okta:isFipsCompliant"],
                           .bool(OktaEnvironment.isSecureEnclaveAvailable()))
        } else {
            XCTFail()
        }

        #endif
    }

    func testCreateEnrolledPushFactor_Error() {
        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)
        let enrolledModel = createEnrolledModel(id: "factorId",
                                                type: .signedNonce)
        let factor = transaction.createEnrolledPushFactor(from: [], and: enrolledModel)
        XCTAssertNil(factor)
    }

    func testFactorTypeFromAuthenticatorMethodr() {
        XCTAssertEqual(transaction.factorTypeFromAuthenticatorMethod(.signedNonce), .signedNonce)
        XCTAssertEqual(transaction.factorTypeFromAuthenticatorMethod(.push), .push)
        XCTAssertEqual(transaction.factorTypeFromAuthenticatorMethod(.totp), .totp)
        XCTAssertEqual(transaction.factorTypeFromAuthenticatorMethod(.unknown("")), .unknown)
    }

    func createEnrolledModel(id: String, type: AuthenticatorMethod, sharedSecret: String? = nil) -> EnrolledAuthenticatorModel.AuthenticatorMethods {
        let links = EnrolledAuthenticatorModel.AuthenticatorMethods.Links(pending: EnrolledAuthenticatorModel.AuthenticatorMethods.Links.ActualLink(href: "tenant.okta.com/pending"))
        return EnrolledAuthenticatorModel.AuthenticatorMethods(id: id,
                                                               type: type,
                                                               sharedSecret: sharedSecret,
                                                               status: "ACTIVE",
                                                               createdDate: nil,
                                                               lastUpdated: nil,
                                                               links: links)
    }

    func testDoUpdate_SuccessWithUserVerificationKey() {
        enrollmentContext = createEnrollmentContext(accessToken: nil,
                                                    deviceSignals: nil,
                                                    applicationSignals: nil,
                                                    enrollBiometricKey: nil,
                                                    enrollBiometricOrPinKey: nil,
                                                    pushToken: nil,
                                                    supportsCIBA: false)
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: nil)
        transaction.metaData = metaData
        let userVerificationKeyTag = "userVerificationKeyTag"
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager,
                                                                 userVerificationKeyTag: userVerificationKeyTag,
                                                                 userVerificationBioOrPinKeyTag: nil)

        let restAPIHookCalled = expectation(description: "Rest API hook expected!")
        self.restAPIMock.updateAuthenticatorRequestHook = { orgHost, _, _, _, _, _, token, context, completion in
            XCTAssertEqual(orgHost.absoluteString, "tenant.okta.com")
            if case .authenticationToken(_) = token {
                XCTAssertNotNil(token.token)
            } else {
                XCTFail()
            }
            completion(.failure(.genericError("")))
            restAPIHookCalled.fulfill()
        }

        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)

        let cryptoHookCalled = expectation(description: "Crypto hook expected!")
        cryptoManager.getHook = { type, tag, context in
            cryptoHookCalled.fulfill()
            XCTAssertEqual(tag, userVerificationKeyTag)
            self.cryptoManager.getHook = nil
            return self.cryptoManager.get(keyOf: type, with: tag, context: context)
        }
        let completionCalled = expectation(description: "Completion should be called!")
        transaction.doUpdate(enrollment: enrollment,
                             factorsMetaData: enrolledFactors!) { result in
            completionCalled.fulfill()
        }

        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testDoUpdate_SuccessWithUserVerificationBioOrPinKey() {
        enrollmentContext = createEnrollmentContext(accessToken: nil,
                                                    deviceSignals: nil,
                                                    applicationSignals: nil,
                                                    enrollBiometricKey: nil,
                                                    enrollBiometricOrPinKey: nil,
                                                    pushToken: nil,
                                                    supportsCIBA: false)
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: nil)
        transaction.metaData = metaData
        let userVerificationKeyTag = "userVerificationKeyTag"
        let userVerificationBioOrPinKeyTag = "userVerificationBioOrPinKeyTag"
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager,
                                                                 userVerificationKeyTag: userVerificationKeyTag,
                                                                 userVerificationBioOrPinKeyTag: userVerificationBioOrPinKeyTag)

        let restAPIHookCalled = expectation(description: "Rest API hook expected!")
        self.restAPIMock.updateAuthenticatorRequestHook = { orgHost, _, _, _, _, _, token, context, completion in
            XCTAssertEqual(orgHost.absoluteString, "tenant.okta.com")
            if case .authenticationToken(_) = token {
                XCTAssertNotNil(token.token)
            } else {
                XCTFail()
            }
            completion(.failure(.genericError("")))
            restAPIHookCalled.fulfill()
        }

        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)

        let cryptoHookCalled = expectation(description: "Crypto hook expected!")
        cryptoManager.getHook = { type, tag, context in
            cryptoHookCalled.fulfill()
            XCTAssertEqual(tag, userVerificationBioOrPinKeyTag)
            self.cryptoManager.getHook = nil
            return self.cryptoManager.get(keyOf: type, with: tag, context: context)
        }
        let completionCalled = expectation(description: "Completion should be called!")
        transaction.doUpdate(enrollment: enrollment,
                             factorsMetaData: enrolledFactors!) { result in
            completionCalled.fulfill()
        }

        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testDoUpdate_Success() {
        enrollmentContext = createEnrollmentContext(accessToken: nil, deviceSignals: nil, applicationSignals: nil, enrollBiometricKey: nil, pushToken: nil, supportsCIBA: false)
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: nil)
        transaction.metaData = metaData
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager,
                                                                 userVerificationKeyTag: nil)

        let hookCalled = expectation(description: "Rest API hook expected!")
        self.restAPIMock.updateAuthenticatorRequestHook = { orgHost, _, _, _, _, _, token, context, completion in
            if case .authenticationToken(_) = token {
                XCTAssertNotNil(token.token)
            } else {
                XCTFail()
            }
            completion(.failure(.genericError("")))
            hookCalled.fulfill()
        }

        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)
        let completionCalled = expectation(description: "Completion should be called!")
        transaction.doUpdate(enrollment: enrollment,
                             factorsMetaData: enrolledFactors!) { result in
            completionCalled.fulfill()
        }

        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testDoUpdate_NoPoPKeyError() {
        enrollmentContext = createEnrollmentContext(accessToken: nil, deviceSignals: nil, applicationSignals: nil, enrollBiometricKey: nil, enrollBiometricOrPinKey: nil, pushToken: nil, supportsCIBA: false)
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: nil)
        transaction.metaData = metaData
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager)
        enrollment.enrolledFactors = []
        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)
        let completionCalled = expectation(description: "Completion expected!")
        transaction.doUpdate(enrollment: enrollment,
                             factorsMetaData: enrolledFactors!) { result in
            if case Result.failure(let error) = result {
                XCTAssertEqual(error.localizedDescription, "Proof of possession key tag is not found")
            } else {
                XCTFail("Unexpected result")
            }
            completionCalled.fulfill()
        }

        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testDoUpdate_CantReadPoPKey() {
        enrollmentContext = createEnrollmentContext(accessToken: nil, deviceSignals: nil, applicationSignals: nil, enrollBiometricKey: nil, pushToken: nil, supportsCIBA: false)
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: nil)
        transaction.metaData = metaData
        cryptoManager.getHook = { type, tag, context in
            return nil
        }
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager)
        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)
        var completionCalled = false
        transaction.doUpdate(enrollment: enrollment,
                             factorsMetaData: enrolledFactors!) { result in
            if case Result.failure(let error) = result {
                if case let .securityError(error) = error {
                    XCTAssertEqual(error, SecurityError.jwtError("Failed to read private key"))
                } else {
                    XCTFail()
                }
            } else {
                XCTFail("Unexpected result")
            }
            completionCalled = true
        }

        XCTAssertTrue(completionCalled)
    }

    func testDoUpdate_FailedToGenerateRequestJWT() {
        enrollmentContext = createEnrollmentContext(accessToken: nil, deviceSignals: nil, applicationSignals: nil, enrollBiometricKey: nil, pushToken: nil, supportsCIBA: false)
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: nil)
        transaction.metaData = metaData
        jwtGeneratorMock.generateHook = { key, type, algo, kid, additionalParams in
            throw DeviceAuthenticatorError.genericError("generic error")
        }
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager)
        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)
        let completionCalled = expectation(description: "Completion should be called!")
        transaction.doUpdate(enrollment: enrollment,
                             factorsMetaData: enrolledFactors!) { result in

            if case Result.failure(let error) = result {
                if case let .securityError(error) = error {
                    XCTAssertEqual(error, SecurityError.jwtError("Failed to sign jwt"))
                } else {
                    XCTFail()
                }
            } else {
                XCTFail("Unexpected result")
            }

            completionCalled.fulfill()
        }

        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testEnroll_SuccessDoUpdateCalled() {
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager)
        let deviceEnrollment = OktaDeviceEnrollment(id: "id",
                                                    orgId: "tenant.okta.com",
                                                    clientInstanceId: "clientInstanceId",
                                                    clientInstanceKeyTag: "clientInstanceTag")
        try? mockStorageManager.storeDeviceEnrollment(deviceEnrollment, for: enrollment.orgId)
        let mockURL = URL(string: "https://example.okta.com")!
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                                                            HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!],
                                                            dataArray: [MyAccountTestData.policyResponse(), MyAccountTestData.enrollmentResponse()])
        restAPIMock = RestAPIMock(client: mockHTTPClient, logger: OktaLoggerMock())
        transactionPartialMock = OktaTransactionEnrollPartialMock(storageManager: mockStorageManager,
                                                                  cryptoManager: cryptoManager,
                                                                  restAPI: restAPIMock,
                                                                  enrollmentContext: enrollmentContext,
                                                                  enrollmentToUpdate: enrollment,
                                                                  jwkGenerator: jwkGeneratorMock,
                                                                  jwtGenerator: jwtGeneratorMock,
                                                                  applicationConfig: applicationConfig,
                                                                  logger: OktaLoggerMock())

        let enrollExpectation = expectation(description: "Do enrollment expectation")
        transactionPartialMock.doUpdateHook = { _, _, completion in
            XCTAssertNotNil(self.transactionPartialMock.deviceEnrollment)
            enrollExpectation.fulfill()
        }

        transactionPartialMock.enroll { result in
            if case Result.failure(_) = result {
                XCTFail("Unexpected result")
            }
        }

        wait(for: [enrollExpectation], timeout: 1.0)
    }

    func testCleanupOnSuccess() {
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager)
        enrollmentContext = createEnrollmentContext(deviceSignals: nil,
                                                    applicationSignals: nil,
                                                    enrollBiometricKey: false,
                                                    enrollBiometricOrPinKey: false,
                                                    pushToken: nil,
                                                    supportsCIBA: false)
        transactionPartialMock = OktaTransactionEnrollPartialMock(storageManager: mockStorageManager,
                                                                  cryptoManager: cryptoManager,
                                                                  restAPI: restAPIMock,
                                                                  enrollmentContext: enrollmentContext,
                                                                  enrollmentToUpdate: enrollment,
                                                                  jwkGenerator: jwkGeneratorMock,
                                                                  jwtGenerator: jwtGeneratorMock,
                                                                  applicationConfig: applicationConfig,
                                                                  logger: OktaLoggerMock())
        XCTAssertNotNil(enrollment.pushFactor?.factorData.userVerificationKeyTag)
        XCTAssertNotNil(enrollment.pushFactor?.factorData.userVerificationBioOrPinKeyTag)
        transactionPartialMock.cleanupOnSuccess()
        XCTAssertNil(enrollment.pushFactor?.factorData.userVerificationKeyTag)
        XCTAssertNil(enrollment.pushFactor?.factorData.userVerificationBioOrPinKeyTag)
    }

    func testCleanupOnSuccess_DoesntDeleteKeys() {
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager)
        transactionPartialMock = OktaTransactionEnrollPartialMock(storageManager: mockStorageManager,
                                                                  cryptoManager: cryptoManager,
                                                                  restAPI: restAPIMock,
                                                                  enrollmentContext: enrollmentContext,
                                                                  jwkGenerator: jwkGeneratorMock,
                                                                  jwtGenerator: jwtGeneratorMock,
                                                                  applicationConfig: applicationConfig,
                                                                  logger: OktaLoggerMock())
        XCTAssertNotNil(enrollment.pushFactor?.factorData.userVerificationKeyTag)
        XCTAssertNotNil(enrollment.pushFactor?.factorData.userVerificationBioOrPinKeyTag)
        transactionPartialMock.cleanupOnSuccess()
        XCTAssertNotNil(enrollment.pushFactor?.factorData.userVerificationKeyTag)
        XCTAssertNotNil(enrollment.pushFactor?.factorData.userVerificationBioOrPinKeyTag)
    }

    func testCreateEnrollmentAndSaveToStorage_SuccessWithExistingDeviceEnrollment() {
        mockStorageManager.deviceEnrollmentByOrgIdHook = { orgId in
            let deviceEnrollment = OktaDeviceEnrollment(id: "id",
                                                        orgId: orgId,
                                                        clientInstanceId: "clientInstanceId",
                                                        clientInstanceKeyTag: "clientInstanceKeyTag")
            return deviceEnrollment
        }
        let deviceEnrollment = OktaDeviceEnrollment(id: "id",
                                                    orgId: "https://tenant.okta.com",
                                                    clientInstanceId: "clientInstanceId",
                                                    clientInstanceKeyTag: "clientInstanceKeyTag")
        transaction.deviceEnrollment = deviceEnrollment
        transaction.orgId = "orgId"
        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel())
        try? mockStorageManager.storeAuthenticatorPolicy(policy, orgId: transaction.orgId)
        let enrollmentSummary = EnrollmentSummary(enrollmentId: "",
                                                  userId: "",
                                                  username: nil,
                                                  deviceId: "",
                                                  clientInstanceId: "",
                                                  creationDate: Date(), factors: [])
        transaction.createEnrollmentAndSaveToStorage(enrollmentSummary: enrollmentSummary) { result in
            if case Result.success(_) = result {
                XCTAssertEqual(self.mockStorageManager.allEnrollments().count, 1)
                XCTAssertNotNil(try? self.mockStorageManager.deviceEnrollmentByOrgId(self.transaction.orgId))
            } else {
                XCTFail("Unexpected result")
            }
        }
    }

    func testCreateEnrollmentAndSaveToStorage_SuccessWithNewDeviceEnrollment() {
        transaction.orgId = "orgId"
        transaction.clientInstanceKeyTag = "clientInstanceKeyTag"
        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel())
        try? mockStorageManager.storeAuthenticatorPolicy(policy, orgId: transaction.orgId)
        let enrollmentSummary = EnrollmentSummary(enrollmentId: "",
                                                  userId: "",
                                                  username: nil,
                                                  deviceId: "",
                                                  clientInstanceId: "",
                                                  creationDate: Date(), factors: [])
        transaction.createEnrollmentAndSaveToStorage(enrollmentSummary: enrollmentSummary) { result in
            if case Result.success(_) = result {
                XCTAssertEqual(self.mockStorageManager.allEnrollments().count, 1)
                XCTAssertNotNil(try? self.mockStorageManager.deviceEnrollmentByOrgId(self.transaction.orgId))
            } else {
                XCTFail("Unexpected result")
            }
        }
    }

    func testCreateEnrollmentAndSaveToStorage_SuccessWithNewDeviceEnrollment_OverrideOldDeviceEnrollment() {

        transaction.orgId = "orgId"
        transaction.clientInstanceKeyTag = "clientInstanceKeyTag"
        let deviceEnrollment = OktaDeviceEnrollment(id: "id",
                                                    orgId: "tenant.okta.com",
                                                    clientInstanceId: "clientInstanceId",
                                                    clientInstanceKeyTag: "keyTag")
        try? mockStorageManager.storeDeviceEnrollment(deviceEnrollment, for: transaction.orgId)
        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel())
        try? mockStorageManager.storeAuthenticatorPolicy(policy, orgId: transaction.orgId)
        let enrollmentSummary = EnrollmentSummary(enrollmentId: "",
                                                  userId: "",
                                                  username: nil,
                                                  deviceId: "newDeviceId",
                                                  clientInstanceId: "newClientInstanceId",
                                                  creationDate: Date(), factors: [])
        var callbackCalled = false
        transaction.createEnrollmentAndSaveToStorage(enrollmentSummary: enrollmentSummary) { result in
            callbackCalled = true
            if case Result.success(_) = result {
                XCTAssertEqual(self.mockStorageManager.allEnrollments().count, 1)
                let deviceEnrollment = try? self.mockStorageManager.deviceEnrollmentByOrgId(self.transaction.orgId)
                XCTAssertEqual(deviceEnrollment?.clientInstanceKeyTag, "clientInstanceKeyTag")
                XCTAssertEqual(deviceEnrollment?.id, enrollmentSummary.deviceId)
                XCTAssertEqual(deviceEnrollment?.clientInstanceId, enrollmentSummary.clientInstanceId)
            } else {
                XCTFail("Unexpected result")
            }
        }

        XCTAssertTrue(callbackCalled)
    }

    func testCreateEnrollmentAndSaveToStorage_SuccessWithNewDeviceEnrollment_NoClientInstanceTag() {
        transaction.orgId = "orgId"
        let enrollmentSummary = EnrollmentSummary(enrollmentId: "",
                                                  userId: "",
                                                  username: nil,
                                                  deviceId: "",
                                                  clientInstanceId: "",
                                                  creationDate: Date(), factors: [])
        transaction.createEnrollmentAndSaveToStorage(enrollmentSummary: enrollmentSummary) { result in
            if case Result.failure(let error) = result {
                XCTAssertEqual(error.errorDescription, "Failed to create device enrollment object")
            } else {
                XCTFail("Unexpected result")
            }
        }
    }

    func testCreateEnrollmentAndSaveToStorage_FailedToSaveEnrollment() {
        let storageMock = StorageMock()
        transaction = OktaTransactionEnrollPartialMock(storageManager: storageMock,
                                                       cryptoManager: cryptoManager,
                                                       restAPI: restAPIMock,
                                                       enrollmentContext: enrollmentContext,
                                                       jwkGenerator: jwkGeneratorMock,
                                                       jwtGenerator: jwtGeneratorMock,
                                                       applicationConfig: applicationConfig,
                                                       logger: OktaLoggerMock())
        transaction.metaData = metaData
        transaction.orgId = "orgId"
        transaction.clientInstanceKeyTag = "clientInstanceKeyTag"
        storageMock.storeEnrollmentHook = { enrollment in
            throw DeviceAuthenticatorError.genericError("Generic Error")
        }
        let enrollmentSummary = EnrollmentSummary(enrollmentId: "",
                                                  userId: "",
                                                  username: nil,
                                                  deviceId: "",
                                                  clientInstanceId: "",
                                                  creationDate: Date(), factors: [])
        transaction.createEnrollmentAndSaveToStorage(enrollmentSummary: enrollmentSummary) { result in
            if case Result.failure(let error) = result {
                XCTAssertEqual(error.errorDescription, "Generic Error")
            } else {
                XCTFail("Unexpected result")
            }
        }
    }

    func testUpdateEnrollment_WithoutAccessToken_UnEnrollUVKey() {
        let restAPIMock = RestAPIMock(client: HTTPClient(logger: OktaLoggerMock(), userAgent: ""), logger: OktaLoggerMock())
        restAPIMock.downloadOrgIdTypeHook = { url, completion in
            XCTFail("Unexpected call")
        }
        restAPIMock.downloadAuthenticatorMetadataHook = { _, _, _, _ in
            XCTFail("Unexpected call")
        }

        let updateAuthenticatorCompletionCalled = expectation(description: "Update authenticator expected!")
        restAPIMock.updateAuthenticatorRequestHook = { _, _, _, _, _, _, _, _, completion in
            updateAuthenticatorCompletionCalled.fulfill()
            let enrollmentSummary = EnrollmentSummary(enrollmentId: "",
                                                      userId: "",
                                                      username: nil,
                                                      deviceId: "",
                                                      clientInstanceId: "",
                                                      creationDate: Date(), factors: [])
            completion(.success(enrollmentSummary))
        }

        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager)
        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel())
        try? mockStorageManager.storeAuthenticatorPolicy(policy, orgId: enrollment.orgId)
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: enrollment, restAPI: restAPIMock, policy: policy)

        let completionCalled = expectation(description: "Completion should be called!")
        transaction.enroll(onMetadataReceived: { metadata in
            XCTFail("Unexpected call")
        }) { result in
            completionCalled.fulfill()
        }

        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testUpdateEnrollment_WithoutAccessToken_NothingToUpdate() {
        let restAPIMock = RestAPIMock(client: HTTPClient(logger: OktaLoggerMock(), userAgent: ""), logger: OktaLoggerMock())
        restAPIMock.downloadOrgIdTypeHook = { url, completion in
            XCTFail("Unexpected call")
        }
        restAPIMock.downloadAuthenticatorMetadataHook = { _, _, _, _ in
            XCTFail("Unexpected call")
        }
        restAPIMock.updateAuthenticatorRequestHook = { _, _, _, _, _, _, _, _, completion in
            XCTFail("Unexpected call")
        }

        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager,
                                                                 enrollPush: false)
        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel(id: "id",
                                                                                              userVerification: .preferred,
                                                                                              methods: []))
        try? mockStorageManager.storeAuthenticatorPolicy(policy, orgId: enrollment.orgId)
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: enrollment, restAPI: restAPIMock, policy: policy)

        var completionCalled = false
        transaction.enroll(onMetadataReceived: { metadata in
            XCTFail("Unexpected call")
        }) { result in
            if case Result.failure(let error) = result {
                XCTAssertEqual(error.errorCode, DeviceAuthenticatorError.noVerificationMethodsToEnroll.errorCode)
            } else {
                XCTFail("Unexpected result")
            }
            completionCalled = true
        }

        XCTAssertTrue(completionCalled)
    }

    func testUpdateEnrollment_WithAccessToken() {
        let restAPIMock = RestAPIMock(client: HTTPClient(logger: OktaLoggerMock(), userAgent: ""), logger: OktaLoggerMock())
        restAPIMock.downloadOrgIdTypeHook = { url, completion in
            XCTFail("Unexpected call")
        }
        restAPIMock.downloadAuthenticatorMetadataHook = { _, _, _, completion in
            let metadata = try! JSONDecoder().decode([AuthenticatorMetaDataModel].self, from: GoldenData.authenticatorMetaData())
            completion(.success(metadata[0]))
        }

        var updateAuthenticatorCompletionCalled = false
        restAPIMock.updateAuthenticatorRequestHook = { _, _, _, _, _, _, _, _, completion in
            updateAuthenticatorCompletionCalled = true
            let enrollmentSummary = EnrollmentSummary(enrollmentId: "",
                                                      userId: "",
                                                      username: nil,
                                                      deviceId: "",
                                                      clientInstanceId: "",
                                                      creationDate: Date(), factors: [])
            completion(.success(enrollmentSummary))
        }

        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager)
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: enrollment, restAPI: restAPIMock)

        var completionCalled = false
        var metaDataClosureCalled = false
        transaction.enroll(onMetadataReceived: { metadata in
            metaDataClosureCalled = true
        }) { result in
            completionCalled = true
        }

        XCTAssertTrue(completionCalled)
        XCTAssertTrue(updateAuthenticatorCompletionCalled)
        XCTAssertTrue(metaDataClosureCalled)
    }

    func testDownloadOrgIdCalled() {
        var downloadOrgIdCalled = false
        restAPIMock.downloadOrgIdTypeHook = { url, completion in
            downloadOrgIdCalled = true
            completion(nil, nil)
        }
        transaction.enroll { result in }

        XCTAssertTrue(downloadOrgIdCalled)
    }

    func testDownloadOrgId_NotCalled() {
        restAPIMock.downloadOrgIdTypeHook = { url, completion in
            XCTFail("Unexpected call")
        }
        restAPIMock.downloadAuthenticatorMetadataHook = { _, _, _, _ in
            XCTFail("Unexpected call")
        }
        let updateAuthenticatorRequestHookCalled = expectation(description: "Update authenticator request expected!")
        restAPIMock.updateAuthenticatorRequestHook = { _, _, _, _, _, _, _, _, completion in
            updateAuthenticatorRequestHookCalled.fulfill()
            let enrollmentSummary = EnrollmentSummary(enrollmentId: "",
                                                      userId: "",
                                                      username: nil,
                                                      deviceId: "",
                                                      clientInstanceId: "",
                                                      creationDate: Date(), factors: [])
            completion(.success(enrollmentSummary))
        }
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager)
        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel())
        try? mockStorageManager.storeAuthenticatorPolicy(policy, orgId: enrollment.orgId)
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: enrollment, policy: policy)
        let completionCalled = expectation(description: "Completion expected!")
        transaction.enroll { result in
            completionCalled.fulfill()
        }

        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testAuthenticatorPolicyIsSaved() {
        let testOrgId = "00otiyyDFtNCyFbnC0g4"
        XCTAssertThrowsError(try mockStorageManager.authenticatorPolicyForOrgId(testOrgId))
        restAPIMock.downloadOrgIdTypeHook = { url, completion in
            let result = HTTPURLResult(request: nil, response: nil, data: GoldenData.orgData())
            completion(result, nil)
        }
        restAPIMock.downloadAuthenticatorMetadataHook = { _, _, _, completion in
            let metadata = try! JSONDecoder().decode([AuthenticatorMetaDataModel].self, from: GoldenData.authenticatorMetaData())
            completion(.success(metadata[0]))
        }

        var enrollClosureCalled = false
        transaction.enroll { result in
            let policy = try? self.mockStorageManager.authenticatorPolicyForOrgId(testOrgId)
            XCTAssertNotNil(policy)
            enrollClosureCalled = true
        }

        XCTAssertTrue(enrollClosureCalled)
    }

    func testAuthenticatorPolicyIsRequestedFromServerWhenNotInStorage() {
        let jwtGeneratorMock = OktaJWTGeneratorMock(logger: OktaLoggerMock())
        jwtGeneratorMock.stringToReturn = "testJWT"
        let testOrgId = "00otiyyDFtNCyFbnC0g4"
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: testOrgId,
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager,
                                                                 enrollPush: false)
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: enrollment)
        restAPIMock.downloadOrgIdTypeHook = { url, completion in
            let result = HTTPURLResult(request: nil, response: nil, data: GoldenData.orgData())
            completion(result, nil)
        }
        let metadataDownloadExpectation = expectation(description: "Download metadata expectation")
        restAPIMock.downloadAuthenticatorMetadataHook = { _, _, _, completion in
            let metadata = try! JSONDecoder().decode([AuthenticatorMetaDataModel].self, from: GoldenData.authenticatorMetaData())
            completion(.success(metadata[0]))
            metadataDownloadExpectation.fulfill()
        }

        let enrollExpectation = expectation(description: "Enroll expectation")
        transaction.enroll { result in
            let policy = try? self.mockStorageManager.authenticatorPolicyForOrgId(testOrgId)
            XCTAssertNotNil(policy)
            enrollExpectation.fulfill()
        }

        wait(for: [enrollExpectation, metadataDownloadExpectation], timeout: 0.5)
    }

    func testRetryEnrollment_WithDeviceDeletedError_ResetsEnrollment() {
        let decoder = JSONDecoder()
        let metaDataArray = try! decoder.decode([AuthenticatorMetaDataModel].self, from: GoldenData.authenticatorMetaData())
        let deviceEnrollment = OktaDeviceEnrollment(id: "id",
                                                    orgId: "tenant.okta.com",
                                                    clientInstanceId: "clientInstanceId",
                                                    clientInstanceKeyTag: "clientInstanceKeyTag")
        try? mockStorageManager.storeDeviceEnrollment(deviceEnrollment, for: deviceEnrollment.orgId!)
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: nil, jwtGenerator: OktaJWTGenerator(logger: OktaLoggerMock()))
        transaction.deviceEnrollment = deviceEnrollment
        transaction.metaData = metaDataArray[0]
        transaction.orgId = ""
        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)
        transaction.clientInstanceKeyTag = "clientInstanceKeyTag"
        var hookCalled = false
        restAPIMock.enrollAuthenticatorRequestHook = { _, _, _, _, _, _, completion in
            hookCalled = true
            XCTAssertNil(self.transaction.deviceEnrollment)
        }
        let serverAPIErrorModel = ServerAPIErrorModel(errorCode: ServerErrorCode(raw: "E0000153"),
                                                      errorSummary: nil,
                                                      errorLink: nil,
                                                      errorId: nil,
                                                      status: nil,
                                                      errorCauses: nil)
        let urlResponse = HTTPURLResponse(url: URL(string: "tenant.okta.com")!, statusCode: 410, httpVersion: nil, headerFields: nil)!
        let httpResult = HTTPURLResult(request: URLRequest(url: URL(string: "tenant.okta.com")!),
                                       response: urlResponse,
                                       data: nil, error: nil)
        let error = DeviceAuthenticatorError.serverAPIError(httpResult, serverAPIErrorModel)
        transaction.retryEnrollmentIfNeeded(error: error, factorsMetaData: enrolledFactors!, onCompletion: { result in
        })
        XCTAssertTrue(hookCalled)
    }
    
    func testRetryEnrollment_WithGenericError_DoesNothing() {
        let decoder = JSONDecoder()
        let metaDataArray = try! decoder.decode([AuthenticatorMetaDataModel].self, from: GoldenData.authenticatorMetaData())
        let deviceEnrollment = OktaDeviceEnrollment(id: "id",
                                                    orgId: "tenant.okta.com",
                                                    clientInstanceId: "clientInstanceId",
                                                    clientInstanceKeyTag: "clientInstanceKeyTag")
        try? mockStorageManager.storeDeviceEnrollment(deviceEnrollment, for: deviceEnrollment.orgId!)
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: nil, jwtGenerator: OktaJWTGenerator(logger: OktaLoggerMock()))
        transaction.deviceEnrollment = deviceEnrollment
        transaction.metaData = metaDataArray[0]
        transaction.orgId = ""
        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)
        transaction.clientInstanceKeyTag = "clientInstanceKeyTag"
        var hookCalled = false
        restAPIMock.enrollAuthenticatorRequestHook = { _, _, _, _, _, _, completion in
            hookCalled = true
        }
        let error = DeviceAuthenticatorError.genericError("")
        transaction.retryEnrollmentIfNeeded(error: error, factorsMetaData: enrolledFactors!, onCompletion: { result in })
        XCTAssertFalse(hookCalled)
    }
    /*
    func testHandleServerResult_Success() {
        let urlResponse = HTTPURLResponse(url: URL(string: "tenant.okta.com")!, statusCode: 200, httpVersion: nil, headerFields: nil)!
        let result = HTTPURLResult(request: URLRequest(url: URL(string: "tenant.okta.com")!),
                                   response: urlResponse,
                                   data: GoldenData.authenticatorData(), error: nil)
        let enrollingFactors = try? transaction.enrollFactors()
        var createEnrollmentAndSaveToStorageHookCalled = false
        transactionPartialMock.createEnrollmentAndSaveToStorageHook = { _, _, completion in
            createEnrollmentAndSaveToStorageHookCalled = true
            completion(Result.failure(DeviceAuthenticatorError.genericError("")))
        }

        var completionCalled = false
        transactionPartialMock.handleServerResult(result, error: nil, factorsMetaData: enrollingFactors!) { result in
            completionCalled = true
        }
        XCTAssertTrue(createEnrollmentAndSaveToStorageHookCalled)
        XCTAssertTrue(completionCalled)
    }

    func testHandleServerResult_PassError() {
        let enrollingFactors = try? transaction.enrollFactors()
        var completionCalled = false
        transactionPartialMock.handleServerResult(nil, error: DeviceAuthenticatorError.genericError("Generic Error"), factorsMetaData: enrollingFactors!) { result in
            if case Result.failure(let error) = result {
                XCTAssertEqual(error.localizedDescription, "Generic Error")
            } else {
                XCTFail("Unexpected result")
            }
            completionCalled = true
        }
        XCTAssertTrue(completionCalled)
    }

    func testHandleServerResult_BadServerResponse() {
        let urlResponse = HTTPURLResponse(url: URL(string: "tenant.okta.com")!, statusCode: 200, httpVersion: nil, headerFields: nil)!
        let result = HTTPURLResult(request: URLRequest(url: URL(string: "tenant.okta.com")!),
                                   response: urlResponse,
                                   data: Data(), error: nil)
        let enrollingFactors = try? transaction.enrollFactors()
        var completionCalled = false
        transactionPartialMock.handleServerResult(result, error: nil, factorsMetaData: enrollingFactors!) { result in
            if case Result.failure(let error) = result {
                XCTAssertEqual(error.localizedDescription, "Server replied with empty data")
            } else {
                XCTFail("Unexpected result")
            }
            completionCalled = true
        }
        XCTAssertTrue(completionCalled)
    }

    func testHandleServerResult_DecodingError() {
        let urlResponse = HTTPURLResponse(url: URL(string: "tenant.okta.com")!, statusCode: 200, httpVersion: nil, headerFields: nil)!
        let result = HTTPURLResult(request: URLRequest(url: URL(string: "tenant.okta.com")!),
                                   response: urlResponse,
                                   data: GoldenData.authenticatorMetaData(), error: nil)
        let enrollingFactors = try? transaction.enrollFactors()
        var completionCalled = false
        transactionPartialMock.handleServerResult(result, error: nil, factorsMetaData: enrollingFactors!) { result in
            if case Result.failure(let error) = result {
                XCTAssertEqual(error.localizedDescription, "The data couldn’t be read because it isn’t in the correct format.")
            } else {
                XCTFail("Unexpected result")
            }
            completionCalled = true
        }
        XCTAssertTrue(completionCalled)
    }

    func testHandleServerResult_EmptyFactorsListFromServer() {
        let urlResponse = HTTPURLResponse(url: URL(string: "tenant.okta.com")!, statusCode: 200, httpVersion: nil, headerFields: nil)!
        let result = HTTPURLResult(request: URLRequest(url: URL(string: "tenant.okta.com")!),
                                   response: urlResponse,
                                   data: GoldenData.authenticatorDataWithEmptyMethods(), error: nil)
        let enrollingFactors = try? transaction.enrollFactors()
        var completionCalled = false
        transactionPartialMock.handleServerResult(result, error: nil, factorsMetaData: enrollingFactors!) { result in
            if case Result.failure(let error) = result {
                XCTAssertEqual(error.localizedDescription, "Server replied with unexpected enrollment data")
            } else {
                XCTFail("Unexpected result")
            }
            completionCalled = true
        }
        XCTAssertTrue(completionCalled)
    }
     */

    func createTransaction(enrollmentContext: EnrollmentContext,
                           enrollment: AuthenticatorEnrollment?,
                           restAPI: ServerAPIProtocol? = nil,
                           jwtGenerator: OktaJWTGenerator? = nil,
                           policy: AuthenticatorPolicy? = nil) -> OktaTransactionEnroll {
        return OktaTransactionEnroll(storageManager: mockStorageManager,
                                     cryptoManager: cryptoManager,
                                     restAPI: restAPI ?? restAPIMock,
                                     enrollmentContext: enrollmentContext,
                                     enrollmentToUpdate: enrollment,
                                     jwkGenerator: jwkGeneratorMock,
                                     jwtGenerator: jwtGenerator ?? jwtGeneratorMock,
                                     applicationConfig: applicationConfig,
                                     logger: OktaLoggerMock(),
                                     authenticatorPolicy: policy)
    }

    func createEnrollmentContext(accessToken: String? = "access_token",
                                 deviceSignals: DeviceSignals? = nil,
                                 applicationSignals: [String: _OktaCodableArbitaryType]? = nil,
                                 enrollBiometricKey: Bool? = nil,
                                 enrollBiometricOrPinKey: Bool? = nil,
                                 pushToken: String? = nil,
                                 supportsCIBA: Bool) -> EnrollmentContext {
        var deviceToken = DeviceToken.empty
        if let pushToken = pushToken,
           let pushTokenData = pushToken.data(using: .utf8) {
            deviceToken = .tokenData(pushTokenData)
        }
        let transactionTypes: TransactionType = supportsCIBA ? [.login, .ciba] : .login
        return EnrollmentContext(accessToken: accessToken,
                                 activationToken: nil,
                                 orgHost: URL(string: "tenant.okta.com")!,
                                 authenticatorKey: "custom_app",
                                 oidcClientId: nil,
                                 pushToken: deviceToken,
                                 enrollBiometricKey: enrollBiometricKey,
                                 enrollBiometricOrPinKey: enrollBiometricOrPinKey,
                                 deviceSignals: deviceSignals,
                                 biometricSettings: nil,
                                 biometricOrPinSettings: nil,
                                 applicationSignals: applicationSignals,
                                 transactionTypes: transactionTypes)
    }
}

fileprivate class OktaTransactionEnrollPartialMock: OktaTransactionEnroll {
    typealias doEnrollmentType = ([EnrollingFactor], (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) -> Void
    typealias doUpdateType = (AuthenticatorEnrollment, [EnrollingFactor], (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) -> Void
    typealias registerKeyType = (Algorithm, String, Bool, Bool, BiometricEnrollmentSettings?) throws -> [String: _OktaCodableArbitaryType]
    typealias createEnrollmentAndSaveToStorageType = (EnrollmentSummary, (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) -> Void

    var doEnrollmentHook: doEnrollmentType?
    var doUpdateHook: doUpdateType?
    var registerKeyHook: registerKeyType?
    var createEnrollmentAndSaveToStorageHook: createEnrollmentAndSaveToStorageType?

    override func doEnrollment(factorsMetaData: [EnrollingFactor],
                               onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        doEnrollmentHook?(factorsMetaData, onCompletion)
    }

    override func doUpdate(enrollment: AuthenticatorEnrollment,
                           factorsMetaData: [EnrollingFactor],
                           onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        if let doUpdateHook = doUpdateHook {
            doUpdateHook(enrollment, factorsMetaData, onCompletion)
        } else {
            super.doUpdate(enrollment: enrollment, factorsMetaData: factorsMetaData, onCompletion: onCompletion)
        }
    }

    override func registerKey(with algorithm: Algorithm,
                              keyTag: String,
                              reuseKey: Bool = false,
                              useBiometrics: Bool = false,
                              biometricSettings: BiometricEnrollmentSettings? = nil) throws -> [String: _OktaCodableArbitaryType] {
        return try registerKeyHook?(algorithm, keyTag, reuseKey, useBiometrics, biometricSettings) ?? [:]
    }

    override func createEnrollmentAndSaveToStorage(enrollmentSummary: EnrollmentSummary,
                                                   onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        if let createEnrollmentAndSaveToStorageHook = createEnrollmentAndSaveToStorageHook {
            createEnrollmentAndSaveToStorageHook(enrollmentSummary, onCompletion)
        } else {
            super.createEnrollmentAndSaveToStorage(enrollmentSummary: enrollmentSummary,
                                                   onCompletion: onCompletion)
        }
    }
}

fileprivate class OktaCryptoManagerMock: OktaCryptoManager {
    typealias generateType = (Algorithm, String, Bool, Bool, BiometricEnrollmentSettings?) throws -> SecKey
    typealias getType = (KeyType, String, LAContext) -> SecKey?
    typealias deleteType = (String) -> Bool

    var generateHook: generateType?
    var getHook: getType?
    var deleteHook: deleteType?

    override func generate(keyPairWith algorithm: Algorithm, with tag: String, useSecureEnclave: Bool, useBiometrics: Bool = false, isAccessibleOnOtherDevice: Bool = false, biometricSettings: BiometricEnrollmentSettings? = nil) throws -> SecKey {
        if let generateHook = generateHook {
            return try generateHook(algorithm, tag, useSecureEnclave, useBiometrics, biometricSettings)
        } else {
            return try super.generate(keyPairWith: algorithm,
                                      with: tag,
                                      useSecureEnclave: useSecureEnclave,
                                      useBiometrics: useBiometrics,
                                      isAccessibleOnOtherDevice: isAccessibleOnOtherDevice,
                                      biometricSettings: biometricSettings)
        }
    }

    override func get(keyOf type: KeyType, with tag: String, context: LAContext) -> SecKey? {
        if let getHook = getHook {
            return getHook(type, tag, context)
        } else {
            return super.get(keyOf: type, with: tag, context: context)
        }
    }

    override func delete(keyPairWith tag: String) -> Bool {
        if let deleteHook = deleteHook {
            return deleteHook(tag)
        } else {
            return super.delete(keyPairWith: tag)
        }
    }
}
