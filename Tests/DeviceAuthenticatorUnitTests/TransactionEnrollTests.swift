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
        cryptoManager = OktaCryptoManagerMock(accessGroupId: "", secKeyHelper: secKeyHelperMock, logger: OktaLoggerMock())

        let mockURL = URL(string: "https://example.okta.com")!
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                                                            HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                                                            HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!],
                                                            dataArray: [GoldenData.orgData(), GoldenData.authenticatorMetaData(), GoldenData.authenticatorData()])
        restAPIMock = RestAPIMock(client: mockHTTPClient, logger: OktaLoggerMock())

        mockStorageManager = StorageMock()

        let decoder = JSONDecoder()
        let metaDataArray = try! decoder.decode([AuthenticatorMetaDataModel].self, from: GoldenData.authenticatorMetaData())
        metaData = metaDataArray[0]
        jwkGeneratorMock = OktaJWKGeneratorMock(logger: OktaLoggerMock())
        jwtGeneratorMock = OktaJWTGeneratorMock(logger: OktaLoggerMock())
        enrollmentContext = createEnrollmentContext(enrollBiometricKey: true, pushToken: "push_token")
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
        transactionPartialMock.doEnrollmentHook = { data, factorsMetaData, completion in
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
            let pushMethod = try transactionPartialMock.enrollPushFactor(serverMethod: transaction.metaData._embedded.methods[1])
            XCTAssertNotNil(pushMethod)
            XCTAssertEqual(pushMethod?.methodType, .push)
            XCTAssertNotNil(pushMethod?.proofOfPossessionKeyTag)
            XCTAssertNotNil(pushMethod?.userVerificationKeyTag)
            XCTAssertNotNil(pushMethod?.requestModel?.pushToken)
            XCTAssertEqual(pushMethod?.requestModel?.pushToken, "push_token".data(using: .utf8)?.hexString())
            XCTAssertEqual(pushMethod?.requestModel?.type, AuthenticatorMethod.push)
        } catch {
            XCTFail("Unexpected exception thrown - \(error)")
        }

        XCTAssertEqual(numberOfRegisterKeyCalls, 2)
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
            let enrollingFactor = try transaction.enrollPushFactor(serverMethod: transaction.metaData._embedded.methods[1])
            XCTAssertNotNil(enrollingFactor)
            XCTAssertNotNil(enrollingFactor?.requestModel)
            XCTAssertNotNil(enrollingFactor?.proofOfPossessionKeyTag)
            XCTAssertNotNil(enrollingFactor?.userVerificationKeyTag)
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
            let enrollingFactor = try transaction.enrollPushFactor(serverMethod: transaction.metaData._embedded.methods[1])
            XCTAssertNotNil(enrollingFactor)
            XCTAssertNotNil(enrollingFactor?.requestModel)
            XCTAssertNotNil(enrollingFactor?.requestModel?.pushToken)
            XCTAssertNotNil(enrollingFactor?.proofOfPossessionKeyTag)
            XCTAssertNotNil(enrollingFactor?.userVerificationKeyTag)
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
            let enrollingFactor = try transaction.enrollPushFactor(serverMethod: transaction.metaData._embedded.methods[1])
            XCTAssertNotNil(enrollingFactor)
            XCTAssertNotNil(enrollingFactor?.requestModel)
            XCTAssertNotNil(enrollingFactor?.proofOfPossessionKeyTag)
            XCTAssertNotNil(enrollingFactor?.userVerificationKeyTag)
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
            XCTAssertNotNil(enrollingFactor?.proofOfPossessionKeyTag)
            XCTAssertNotNil(enrollingFactor?.userVerificationKeyTag)
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
            let enrollingFactor = try transaction.enrollPushFactor(serverMethod: transaction.metaData._embedded.methods[1])
            XCTAssertNotNil(enrollingFactor)
            XCTAssertNotNil(enrollingFactor?.requestModel)
            XCTAssertNotNil(enrollingFactor?.proofOfPossessionKeyTag)
            XCTAssertNotNil(enrollingFactor?.userVerificationKeyTag)
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
        restAPIMock.enrollAuthenticatorRequestHook = { url, data, _, completion in
            hookCalled = true
        }
        transaction.doEnrollment(
            enrollData: Data(),
            factorsMetaData: enrolledFactors!) { result in
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
        restAPIMock.enrollAuthenticatorRequestHook = { url, data, _, completion in
            hookCalled = true
        }
        transaction.doEnrollment(
            enrollData: Data(),
            factorsMetaData: enrolledFactors!) { result in
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

        restAPIMock.enrollAuthenticatorRequestHook = { url, _, _, completion in
            XCTAssertEqual(url.absoluteString, "tenant.okta.com/idp/authenticators")
        }

        mut.doEnrollment(
            enrollData: Data(),
            factorsMetaData: enrolledFactors!) { result in
        }
    }

    func testDoEnrollment_ServerError() {
        restAPIMock.enrollAuthenticatorRequestHook = { url, _, token, completion in
            XCTAssertEqual(url.absoluteString, "https://atko.oktapreview.com/idp/authenticators")
            if case .accessToken(_) = token {
                XCTAssertEqual(token.token, self.transaction.enrollmentContext.accessToken)
            } else {
                XCTFail()
            }
            completion(nil, DeviceAuthenticatorError.internalError("error"))
        }

        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)
        transaction.doEnrollment(
            enrollData: Data(),
            factorsMetaData: enrolledFactors!) { result in
                if case Result.failure(let error) = result {
                    XCTAssertEqual(error.errorCode, DeviceAuthenticatorError.internalError("").errorCode)
                } else {
                    XCTFail("Unexpected result")
                }
        }
    }

    func testDoEnrollment_EmptyData() {
        restAPIMock.enrollAuthenticatorRequestHook = { url, _, _, completion in
            completion(nil, nil)
        }

        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)
        transaction.doEnrollment(
            enrollData: Data(),
            factorsMetaData: enrolledFactors!) { result in
                if case Result.failure(let error) = result {
                    XCTAssertEqual(error.errorCode, DeviceAuthenticatorError.internalError("").errorCode)
                } else {
                    XCTFail("Unexpected result")
                }
        }
    }

    func testDoEnrollment_EmptyMethodsInPayloadError() {
        restAPIMock.enrollAuthenticatorRequestHook = { url, _, _, completion in
            let result = HTTPURLResult(request: nil, response: nil, data: GoldenData.authenticatorDataWithEmptyMethods())
            completion(result, nil)
        }

        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)
        transaction.doEnrollment(
            enrollData: Data(),
            factorsMetaData: enrolledFactors!) { result in
                if case Result.failure(let error) = result {
                    XCTAssertEqual(error.errorCode, DeviceAuthenticatorError.internalError("").errorCode)
                } else {
                    XCTFail("Unexpected result")
                }
        }
    }

    func testDoEnrollment_DecodingError() {
        restAPIMock.enrollAuthenticatorRequestHook = { url, _, _, completion in
            let result = HTTPURLResult(request: nil, response: nil, data: GoldenData.authenticatorMetaData())
            completion(result, nil)
        }

        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)
        transaction.doEnrollment(
            enrollData: Data(),
            factorsMetaData: enrolledFactors!) { result in
                if case Result.failure(let error) = result {
                    XCTAssertEqual(error.errorCode, DeviceAuthenticatorError.internalError("").errorCode)
                } else {
                    XCTFail("Unexpected result")
                }
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

        if let pushRequestModel = enrolledFactors?.first(where: { $0.methodType == .push })?.requestModel {
            XCTAssertNil(pushRequestModel.isFipsCompliant)
            XCTAssertEqual(pushRequestModel.keys?.proofOfPossession?["okta:isFipsCompliant"],
                           .bool(OktaEnvironment.isSecureEnclaveAvailable()))
            XCTAssertEqual(pushRequestModel.keys?.userVerification?.value()?["okta:isFipsCompliant"],
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
        enrollmentContext = createEnrollmentContext(accessToken: nil, deviceSignals: nil, applicationSignals: nil, enrollBiometricKey: nil, pushToken: nil)
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: nil)
        transaction.metaData = metaData
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager)

        let restAPIHookCalled = expectation(description: "Rest API hook expected!")
        self.restAPIMock.updateAuthenticatorRequestHook = { url, data, token, completion in
            XCTAssertEqual(url.absoluteString, "tenant.okta.com/idp/authenticators/enrollmentId")
            if case .authenticationToken(_) = token {
                XCTAssertNotNil(token.token)
            } else {
                XCTFail()
            }
            completion(nil, nil)
            restAPIHookCalled.fulfill()
        }

        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)

        let cryptoHookCalled = expectation(description: "Crypto hook expected!")
        cryptoManager.getHook = { type, tag, context in
            cryptoHookCalled.fulfill()
            XCTAssertEqual(tag, "userVerificationKeyTag")
            self.cryptoManager.getHook = nil
            return self.cryptoManager.get(keyOf: type, with: tag, context: context)
        }
        let completionCalled = expectation(description: "Completion should be called!")
        transaction.doUpdate(enrollData: Data(),
                             enrollment: enrollment,
                             factorsMetaData: enrolledFactors!) { result in
            completionCalled.fulfill()
        }

        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testDoUpdate_Success() {
        enrollmentContext = createEnrollmentContext(accessToken: nil, deviceSignals: nil, applicationSignals: nil, enrollBiometricKey: nil, pushToken: nil)
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: nil)
        transaction.metaData = metaData
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager,
                                                                 userVerificationKeyTag: nil)

        let hookCalled = expectation(description: "Rest API hook expected!")
        self.restAPIMock.updateAuthenticatorRequestHook = { url, data, token, completion in
            XCTAssertEqual(url.absoluteString, "tenant.okta.com/idp/authenticators/enrollmentId")
            if case .authenticationToken(_) = token {
                XCTAssertNotNil(token.token)
            } else {
                XCTFail()
            }
            completion(nil, nil)
            hookCalled.fulfill()
        }

        let enrolledFactors = try? transaction.enrollFactors()
        XCTAssertNotNil(enrolledFactors)
        let completionCalled = expectation(description: "Completion should be called!")
        transaction.doUpdate(enrollData: Data(),
                             enrollment: enrollment,
                             factorsMetaData: enrolledFactors!) { result in
            completionCalled.fulfill()
        }

        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testDoUpdate_NoPoPKeyError() {
        enrollmentContext = createEnrollmentContext(accessToken: nil, deviceSignals: nil, applicationSignals: nil, enrollBiometricKey: nil, pushToken: nil)
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
        transaction.doUpdate(enrollData: Data(),
                             enrollment: enrollment,
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
        enrollmentContext = createEnrollmentContext(accessToken: nil, deviceSignals: nil, applicationSignals: nil, enrollBiometricKey: nil, pushToken: nil)
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
        transaction.doUpdate(enrollData: Data(),
                             enrollment: enrollment,
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
        enrollmentContext = createEnrollmentContext(accessToken: nil, deviceSignals: nil, applicationSignals: nil, enrollBiometricKey: nil, pushToken: nil)
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
        transaction.doUpdate(enrollData: Data(),
                             enrollment: enrollment,
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
                                                            dataArray: [GoldenData.authenticatorMetaData(), GoldenData.authenticatorData()])
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
        transactionPartialMock.doUpdateHook = { data, enrollment, factorsMetaData, completion in
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
        enrollmentContext = createEnrollmentContext(deviceSignals: nil, applicationSignals: nil, enrollBiometricKey: false, pushToken: nil)
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
        transactionPartialMock.cleanupOnSuccess()
        XCTAssertNil(enrollment.pushFactor?.factorData.userVerificationKeyTag)
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
        transactionPartialMock.cleanupOnSuccess()
        XCTAssertNotNil(enrollment.pushFactor?.factorData.userVerificationKeyTag)
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
        let pushMetadata = OktaFactorMetadataPush(id: "id",
                                                  proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                                  userVerificationKeyTag: "userVerificationKeyTag")
        let pushFactor = OktaFactorPush(factorData: pushMetadata,
                                        cryptoManager: cryptoManager,
                                        restAPIClient: restAPIMock,
                                        logger: OktaLoggerMock())
        let enrolledAuthenticatorModel = try! JSONDecoder().decode(EnrolledAuthenticatorModel.self, from: GoldenData.authenticatorData())
        transaction.orgId = "orgId"
        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel())
        try? mockStorageManager.storeAuthenticatorPolicy(policy, orgId: transaction.orgId)
        transaction.createEnrollmentAndSaveToStorage(enrolledAuthenticatorModel: enrolledAuthenticatorModel,
                                                     enrolledFactors: [pushFactor]) { result in
            if case Result.success(_) = result {
                XCTAssertEqual(self.mockStorageManager.allEnrollments().count, 1)
                XCTAssertNotNil(try? self.mockStorageManager.deviceEnrollmentByOrgId(self.transaction.orgId))
            } else {
                XCTFail("Unexpected result")
            }
        }
    }

    func testCreateEnrollmentAndSaveToStorage_SuccessWithNewDeviceEnrollment() {
        let pushMetadata = OktaFactorMetadataPush(id: "id",
                                                  proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                                  userVerificationKeyTag: "userVerificationKeyTag")
        let pushFactor = OktaFactorPush(factorData: pushMetadata,
                                        cryptoManager: cryptoManager,
                                        restAPIClient: restAPIMock,
                                        logger: OktaLoggerMock())
        let enrolledAuthenticatorModel = try! JSONDecoder().decode(EnrolledAuthenticatorModel.self, from: GoldenData.authenticatorData())
        transaction.orgId = "orgId"
        transaction.clientInstanceKeyTag = "clientInstanceKeyTag"
        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel())
        try? mockStorageManager.storeAuthenticatorPolicy(policy, orgId: transaction.orgId)
        transaction.createEnrollmentAndSaveToStorage(enrolledAuthenticatorModel: enrolledAuthenticatorModel,
                                                     enrolledFactors: [pushFactor]) { result in
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
        let pushMetadata = OktaFactorMetadataPush(id: "id",
                                                  proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                                  userVerificationKeyTag: "userVerificationKeyTag")
        let pushFactor = OktaFactorPush(factorData: pushMetadata,
                                        cryptoManager: cryptoManager,
                                        restAPIClient: restAPIMock,
                                        logger: OktaLoggerMock())
        let enrolledAuthenticatorModel = try! JSONDecoder().decode(EnrolledAuthenticatorModel.self, from: GoldenData.authenticatorData())
        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel())
        try? mockStorageManager.storeAuthenticatorPolicy(policy, orgId: transaction.orgId)
        transaction.createEnrollmentAndSaveToStorage(enrolledAuthenticatorModel: enrolledAuthenticatorModel,
                                                     enrolledFactors: [pushFactor]) { result in
            if case Result.success(_) = result {
                XCTAssertEqual(self.mockStorageManager.allEnrollments().count, 1)
                let deviceEnrollment = try? self.mockStorageManager.deviceEnrollmentByOrgId(self.transaction.orgId)
                XCTAssertEqual(deviceEnrollment?.clientInstanceKeyTag, "clientInstanceKeyTag")
            } else {
                XCTFail("Unexpected result")
            }
        }
    }

    func testCreateEnrollmentAndSaveToStorage_SuccessWithNewDeviceEnrollment_NoClientInstanceTag() {
        let pushMetadata = OktaFactorMetadataPush(id: "id",
                                                  proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                                  userVerificationKeyTag: "userVerificationKeyTag")
        let pushFactor = OktaFactorPush(factorData: pushMetadata,
                                        cryptoManager: cryptoManager,
                                        restAPIClient: restAPIMock,
                                        logger: OktaLoggerMock())
        let enrolledAuthenticatorModel = try! JSONDecoder().decode(EnrolledAuthenticatorModel.self, from: GoldenData.authenticatorData())
        transaction.orgId = "orgId"
        transaction.createEnrollmentAndSaveToStorage(enrolledAuthenticatorModel: enrolledAuthenticatorModel,
                                                     enrolledFactors: [pushFactor]) { result in
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
        let pushMetadata = OktaFactorMetadataPush(id: "id",
                                                  proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                                  userVerificationKeyTag: "userVerificationKeyTag")
        let pushFactor = OktaFactorPush(factorData: pushMetadata,
                                        cryptoManager: cryptoManager,
                                        restAPIClient: restAPIMock,
                                        logger: OktaLoggerMock())
        let enrolledAuthenticatorModel = try! JSONDecoder().decode(EnrolledAuthenticatorModel.self, from: GoldenData.authenticatorData())
        transaction.orgId = "orgId"
        transaction.clientInstanceKeyTag = "clientInstanceKeyTag"
        storageMock.storeEnrollmentHook = { enrollment in
            throw DeviceAuthenticatorError.genericError("Generic Error")
        }
        transaction.createEnrollmentAndSaveToStorage(enrolledAuthenticatorModel: enrolledAuthenticatorModel,
                                                     enrolledFactors: [pushFactor]) { result in
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
        restAPIMock.updateAuthenticatorRequestHook = { url, data, _, completion in
            updateAuthenticatorCompletionCalled.fulfill()
            completion(nil, nil)
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
        restAPIMock.updateAuthenticatorRequestHook = { url, data, _, completion in
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
            let urlResponse = HTTPURLResponse(url: URL(string: "tenant.okta.com")!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            let result = HTTPURLResult(request: URLRequest(url: URL(string: "tenant.okta.com")!), response: urlResponse, data: GoldenData.authenticatorMetaData(), error: nil)
            completion(result, nil)
        }

        var updateAuthenticatorCompletionCalled = false
        restAPIMock.updateAuthenticatorRequestHook = { url, data, _, completion in
            updateAuthenticatorCompletionCalled = true
            completion(nil, nil)
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
        transaction.enroll{ result in
        }

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
        restAPIMock.updateAuthenticatorRequestHook = { url, data, _, completion in
            updateAuthenticatorRequestHookCalled.fulfill()
            completion(nil, nil)
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
            let result = HTTPURLResult(request: nil, response: nil, data: GoldenData.authenticatorMetaData())
            completion(result, nil)
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
            let result = HTTPURLResult(request: nil, response: nil, data: GoldenData.authenticatorMetaData())
            completion(result, nil)
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

    func testBuildEnrollmentModelData_WithAuthenticationToken() {
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager,
                                                                 enrollPush: false)
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: enrollment)
        transaction.metaData = metaData
        var requestModel = EnrollAuthenticatorRequestModel.AuthenticatorMethods(type: .signedNonce,
                                                                                pushToken: "token",
                                                                                apsEnvironment: nil,
                                                                                supportUserVerification: true,
                                                                                isFipsCompliant: nil,
                                                                                keys: nil)
        let signedNonceUpdatingFactor = OktaTransactionEnroll.EnrollingFactor(proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                                                              userVerificationKeyTag: "userVerificationKeyTag",
                                                                              methodType: .signedNonce,
                                                                              requestModel: requestModel)

        requestModel = EnrollAuthenticatorRequestModel.AuthenticatorMethods(type: .push,
                                                                            pushToken: "token",
                                                                            apsEnvironment: nil,
                                                                            supportUserVerification: true,
                                                                            isFipsCompliant: nil,
                                                                            keys: nil)
        let pushUpdatingFactor = OktaTransactionEnroll.EnrollingFactor(proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                                                       userVerificationKeyTag: "userVerificationKeyTag",
                                                                       methodType: .push,
                                                                       requestModel: requestModel)
        let data = try? transaction.buildEnrollmentModelData(factorsMetaData: [signedNonceUpdatingFactor, pushUpdatingFactor])
        XCTAssertNotNil(data)
        let decodedDictionary = try? JSONSerialization.jsonObject(with: data!, options: []) as? [String: Any]
        XCTAssertNotNil(decodedDictionary)
        XCTAssertNotNil(decodedDictionary?["methods"])
        XCTAssertTrue((decodedDictionary?["methods"] as? [Any])!.count == 2)
    }

    func testBuildEnrollmentModelData_VerifyAppSignals() {
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager,
                                                                 enrollPush: false)
        let enrollmentContext = createEnrollmentContext(deviceSignals: DeviceSignals(displayName: ""),
                                                        applicationSignals: ["deleteV1TotpOnlyEnrollment" : _OktaCodableArbitaryType.bool(true),
                                                                             "deleteV1EnrollmentByPushFactorId" : _OktaCodableArbitaryType.string("opf12345")],
                                                        enrollBiometricKey: nil,
                                                        pushToken: nil)
        transaction = createTransaction(enrollmentContext: enrollmentContext, enrollment: enrollment)
        transaction.metaData = metaData
        let requestModel = EnrollAuthenticatorRequestModel.AuthenticatorMethods(type: .signedNonce,
                                                                                pushToken: "token",
                                                                                apsEnvironment: nil,
                                                                                supportUserVerification: true,
                                                                                isFipsCompliant: nil,
                                                                                keys: nil)
        let signedNonceUpdatingFactor = OktaTransactionEnroll.EnrollingFactor(proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                                                              userVerificationKeyTag: "userVerificationKeyTag",
                                                                              methodType: .signedNonce,
                                                                              requestModel: requestModel)
        let pushUpdatingFactor = OktaTransactionEnroll.EnrollingFactor(proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                                                       userVerificationKeyTag: "userVerificationKeyTag",
                                                                       methodType: .push,
                                                                       requestModel: EnrollAuthenticatorRequestModel.AuthenticatorMethods(type: .push,
                                                                                                                                          pushToken: "token",
                                                                                                                                          apsEnvironment: nil,
                                                                                                                                          supportUserVerification: true,
                                                                                                                                          isFipsCompliant: nil,
                                                                                                                                          keys: nil))
        let data = try? transaction.buildEnrollmentModelData(factorsMetaData: [signedNonceUpdatingFactor, pushUpdatingFactor])
        XCTAssertNotNil(data)
        let decodedDictionary = try? JSONSerialization.jsonObject(with: data!, options: []) as? [String: Any]
        XCTAssertNotNil(decodedDictionary)
        XCTAssertNotNil(decodedDictionary?["appSignals"])
        let appSignalsDictionary = decodedDictionary?["appSignals"] as? [String: Any]
        XCTAssertNotNil(appSignalsDictionary?["deleteV1TotpOnlyEnrollment"])
        XCTAssertNotNil(appSignalsDictionary?["deleteV1EnrollmentByPushFactorId"])
    }

    func createTransaction(enrollmentContext: EnrollmentContext,
                           enrollment: AuthenticatorEnrollment?,
                           restAPI: OktaRestAPI? = nil,
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
                                 pushToken: String? = nil) -> EnrollmentContext {
        var deviceToken = DeviceToken.empty
        if let pushToken = pushToken,
           let pushTokenData = pushToken.data(using: .utf8) {
            deviceToken = .tokenData(pushTokenData)
        }
        return EnrollmentContext(accessToken: accessToken,
                                 activationToken: nil,
                                 orgHost: URL(string: "tenant.okta.com")!,
                                 authenticatorKey: "custom_app",
                                 oidcClientId: nil,
                                 pushToken: deviceToken,
                                 enrollBiometricKey: enrollBiometricKey,
                                 deviceSignals: deviceSignals,
                                 biometricSettings: nil,
                                 applicationSignals: applicationSignals)
    }
}

fileprivate class OktaTransactionEnrollPartialMock: OktaTransactionEnroll {
    typealias doEnrollmentType = (Data, [EnrollingFactor], (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) -> Void
    typealias doUpdateType = (Data, AuthenticatorEnrollment, [EnrollingFactor], (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) -> Void
    typealias registerKeyType = (Algorithm, String, Bool, Bool, BiometricEnrollmentSettings?) throws -> [String : _OktaCodableArbitaryType]
    typealias createEnrollmentAndSaveToStorageType = (EnrolledAuthenticatorModel,  [OktaFactor], (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) -> Void
    
    var doEnrollmentHook: doEnrollmentType?
    var doUpdateHook: doUpdateType?
    var registerKeyHook: registerKeyType?
    var createEnrollmentAndSaveToStorageHook: createEnrollmentAndSaveToStorageType?
    
    override func doEnrollment(enrollData: Data,
                               factorsMetaData: [EnrollingFactor],
                               onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        doEnrollmentHook?(enrollData, factorsMetaData, onCompletion)
    }

    override func doUpdate(enrollData: Data,
                           enrollment: AuthenticatorEnrollment,
                           factorsMetaData: [EnrollingFactor],
                           onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        if let doUpdateHook = doUpdateHook {
            doUpdateHook(enrollData, enrollment, factorsMetaData, onCompletion)
        } else {
            super.doUpdate(enrollData: enrollData, enrollment: enrollment, factorsMetaData: factorsMetaData, onCompletion: onCompletion)
        }
    }

    override func registerKey(with algorithm: Algorithm,
                              keyTag: String,
                              reuseKey: Bool = false,
                              useBiometrics: Bool = false,
                              biometricSettings: BiometricEnrollmentSettings? = nil) throws -> [String : _OktaCodableArbitaryType] {
        return try registerKeyHook?(algorithm, keyTag, reuseKey, useBiometrics, biometricSettings) ?? [:]
    }

    override func createEnrollmentAndSaveToStorage(enrolledAuthenticatorModel: EnrolledAuthenticatorModel, enrolledFactors: [OktaFactor], onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        if let createEnrollmentAndSaveToStorageHook = createEnrollmentAndSaveToStorageHook {
            createEnrollmentAndSaveToStorageHook(enrolledAuthenticatorModel, enrolledFactors, onCompletion)
        } else {
            super.createEnrollmentAndSaveToStorage(enrolledAuthenticatorModel: enrolledAuthenticatorModel,
                                                   enrolledFactors: enrolledFactors,
                                                   onCompletion: onCompletion)
        }
    }
}

fileprivate class OktaCryptoManagerMock: OktaCryptoManager {
    typealias generateType = (Algorithm, String, Bool, Bool, BiometricEnrollmentSettings?) throws -> SecKey
    var generateHook: generateType?
    typealias getType = (KeyType, String, LAContext) -> SecKey?
    var getHook: getType?
    typealias deleteType = (String) -> Bool
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
