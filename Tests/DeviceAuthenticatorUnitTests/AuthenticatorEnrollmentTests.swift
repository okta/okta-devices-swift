/*
* Copyright (c) 2020, Okta, Inc. and/or its affiliates. All rights reserved.
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
import OktaJWT
import LocalAuthentication
@testable import DeviceAuthenticator

class AuthenticatorEnrollmentTests: XCTestCase {

    var enrollment: AuthenticatorEnrollment!
    var cryptoManager: CryptoManagerMock!
    var mockHTTPClient: MockMultipleRequestsHTTPClient!
    var restAPIMock: RestAPIMock!
    var mockStorageManager: StorageMock!
    var authenticatorModel: EnrolledAuthenticatorModel!
    let mockURL = URL(string: "https://example.okta.com")!
    let applicationConfig = ApplicationConfig.init(applicationName: "Test App",
                                                   applicationVersion: "1.0.0",
                                                   applicationGroupId: ExampleAppConstants.appGroupId)

    override func setUp() {
        cryptoManager = CryptoManagerMock(keychainGroupId: ExampleAppConstants.appGroupId, logger: OktaLoggerMock())
        mockStorageManager = StorageMock()
        enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: mockURL,
                                                             orgId: "orgId",
                                                             enrollmentId: "enrollmentId",
                                                             cryptoManager: cryptoManager,
                                                             storageManager: mockStorageManager)
        restAPIMock = (enrollment.restAPIClient as! RestAPIMock)
    }

    ///  Verify that recording various error states results in the expected state
    func testEnrollmentState_RecordErrorSuccess() {
        XCTAssertEqual(enrollment.state, .active)
        enrollment.recordError(.phishingAttemptDetected)
        XCTAssertEqual(enrollment.state, .active)
        enrollment.recordError(.userSuspended)
        XCTAssertEqual(enrollment.state, .suspended)
        enrollment.recordError(.deviceSuspended)
        XCTAssertEqual(enrollment.state, .suspended)
        enrollment.recordError(.enrollmentDeleted)
        XCTAssertEqual(enrollment.state, .reset)
        enrollment.recordError(.userDeleted)
        XCTAssertEqual(enrollment.state, .deleted)
        enrollment.recordError(.deviceDeleted)
        XCTAssertEqual(enrollment.state, .reset)
        enrollment.recordError(.enrollmentNotFound)
        XCTAssertEqual(enrollment.state, .deleted)
        enrollment.recordError(.resourceNotFound)
        XCTAssertEqual(enrollment.state, .active)
        enrollment.recordSuccess()
        XCTAssertEqual(enrollment.state, .active)
    }

    func testHasFactorsWithUserVerificationKey() {
        XCTAssertTrue(enrollment.hasFactorsWithUserVerificationKey)
        enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: mockURL,
                                                             orgId: "orgId",
                                                             enrollmentId: "enrollmentId",
                                                             cryptoManager: cryptoManager,
                                                             enrollPush: false)
        XCTAssertFalse(enrollment.hasFactorsWithUserVerificationKey)
    }

    func testHasFactorsWithUserVerificationBioOrPinKey() {
        XCTAssertTrue(enrollment.hasFactorsWithUserVerificationBioOrPinKey)
        enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: mockURL,
                                                             orgId: "orgId",
                                                             enrollmentId: "enrollmentId",
                                                             cryptoManager: cryptoManager,
                                                             enrollPush: false)
        XCTAssertFalse(enrollment.hasFactorsWithUserVerificationBioOrPinKey)
    }

    func testDescription() {
        let expectedDescription: String = {
            let info: [String: Any] = [
                "orgId": enrollment.organization.id,
                "enrollmentId": enrollment.enrollmentId,
                "deviceId": "id",
                "userId": enrollment.user.id,
                "created": DateFormatter.oktaDateFormatter().string(from: enrollment.creationDate),
                "orgHost": mockURL.absoluteString,
                "OktaFactorPush": "{\n    id = \"push_id\";\n    popKey = proofOfPossessionKeyTag;\n    type = Push;\n    uvBioOrPinKey = userVerificationBioOrPinKeyTag;\n    uvKey = userVerificationKeyTag;\n}"
            ]
            return "\(info as AnyObject)"
        }()

        let actualDescription = "\(enrollment!)"

        XCTAssertEqual(expectedDescription, actualDescription)
    }

    #if os(iOS)
    func testUpdatePushTokenSuccess() {
        cryptoManager.keychainGroupId = ""
        let pushFactor = OktaFactorPush(factorData: OktaFactorMetadataPush(id: "id",
                                                                           proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                                                           transactionTypes: .login),
                                        cryptoManager: cryptoManager,
                                        restAPIClient: restAPIMock,
                                        logger: OktaLoggerMock())
        enrollment.enrolledFactors = []
        enrollment.enrolledFactors.append(pushFactor)
        var updateAuthenticatorRequestHookCalled = false
        let pushTokenToCompare = "push_token".data(using: .utf8)!
        restAPIMock.updateAuthenticatorRequestHook = { url, enrollmentId, metadata, deviceSignalsModel, allSignals, factors, _, context, completion in
            let pushMethod = factors.first(where: { $0.methodType == .push })
            let pushToken = pushMethod?.pushToken
            XCTAssertEqual(pushToken, pushTokenToCompare.hexString())
            let enrollmentSummary = EnrollmentSummary(enrollmentId: "",
                                                      userId: "",
                                                      username: nil,
                                                      deviceId: "",
                                                      clientInstanceId: "",
                                                      creationDate: Date(), factors: [])
            updateAuthenticatorRequestHookCalled = true
            completion(.success(enrollmentSummary))
        }

        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel(id: "id",
                                                                                              userVerification: .preferred,
                                                                                              methods: [.push]))
        try? mockStorageManager.storeAuthenticatorPolicy(policy, orgId: enrollment.orgId)
        let ex = expectation(description: "Completion callback expected!")
        let opaqueEnrollment = enrollment as AuthenticatorEnrollmentProtocol
        opaqueEnrollment.updateDeviceToken(pushTokenToCompare,
                                           authenticationToken: AuthToken.bearer("access_token")) { error in
            XCTAssertNil(error)
            ex.fulfill()
        }

        waitForExpectations(timeout: 1.0, handler: nil)
        XCTAssertTrue(updateAuthenticatorRequestHookCalled)
    }
    #endif

    func testUpdatePushTokenError() {
        cryptoManager.keychainGroupId = ""
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: mockURL,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager,
                                                                 storageManager: mockStorageManager)
        let ex = expectation(description: "Completion callback expected!")
        enrollment.updateDeviceToken("push_token".data(using: .utf8)!,
                                               authenticationToken: AuthToken.bearer("access_token")) { error in
            XCTAssertNotNil(error)
            XCTAssertEqual(error?.errorDescription, "Failed to fetch authenticator policy")
            ex.fulfill()
        }

        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testRetrievePushChallenges() {
        cryptoManager.keychainGroupId = ""
        let pushFactor = OktaFactorPush(factorData: OktaFactorMetadataPush(id: "id",
                                                                           proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                                                           links: OktaFactorMetadataPush.Links(pendingLink: "https://test.okta.com/pending_challenge"), transactionTypes: .login),
                                        cryptoManager: cryptoManager,
                                        restAPIClient: restAPIMock,
                                        logger: OktaLoggerMock())
        enrollment.enrolledFactors = []
        enrollment.enrolledFactors.append(pushFactor)
        var pendingChallengeRequestHookCalled = false
        restAPIMock.pendingChallengeRequestHook = { url, token, completion in
            let result = HTTPURLResult(request: URLRequest(url: URL(string: "com.okta.example")!),
                                       response: HTTPURLResponse(url: self.mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                       data: GoldenData.pendingChallengeData())
            pendingChallengeRequestHookCalled = true
            completion(result, nil)
        }

        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel(id: "id",
                                                                                              userVerification: .preferred,
                                                                                              methods: [.push]))
        try? mockStorageManager.storeAuthenticatorPolicy(policy, orgId: enrollment.orgId)
        let ex = expectation(description: "Completion callback expected!")
        let opaqueEnrollment = enrollment as AuthenticatorEnrollmentProtocol
        opaqueEnrollment.retrievePushChallenges(authenticationToken: .bearer("")) { result in
            switch result {
            case .success(let challenges):
                XCTAssertTrue(challenges.count == 1)
            case .failure(_):
                XCTFail("Unexpected completion failure")
            }
            ex.fulfill()
        }

        waitForExpectations(timeout: 1.0, handler: nil)
        XCTAssertTrue(pendingChallengeRequestHookCalled)
    }

    func testDeleteFromDevice() {
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: mockURL,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager,
                                                                 storageManager: mockStorageManager)
        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel(id: "id",
                                                                                              userVerification: .preferred,
                                                                                              methods: [.push]))
        XCTAssertNoThrow(try mockStorageManager.storeAuthenticatorPolicy(policy, orgId: enrollment.orgId))
        XCTAssertNoThrow(try mockStorageManager.storeEnrollment(enrollment))
        XCTAssertEqual(mockStorageManager.allEnrollments().count, 1)

        XCTAssertNoThrow(try enrollment.deleteFromDevice())
        XCTAssertTrue(mockStorageManager.allEnrollments().isEmpty)
        XCTAssertTrue(enrollment.cleanupCalled)
    }

    func testRecordServerResponse() {
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: mockURL,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager,
                                                                 storageManager: mockStorageManager)
        XCTAssertEqual(enrollment.state, .active)

        var error = oktaError(for: .deviceSuspended)
        enrollment.recordServerResponse(error: error)
        XCTAssertEqual(enrollment.state, .suspended)

        error = oktaError(for: .deviceDeleted)
        enrollment.recordServerResponse(error: error)
        XCTAssertEqual(enrollment.state, .reset)

        error = oktaError(for: .enrollmentSuspended)
        enrollment.recordServerResponse(error: error)
        XCTAssertEqual(enrollment.state, .suspended)

        error = oktaError(for: .userDeleted)
        enrollment.recordServerResponse(error: error)
        XCTAssertEqual(enrollment.state, .deleted)

        error = oktaError(for: .userSuspended)
        enrollment.recordServerResponse(error: error)
        XCTAssertEqual(enrollment.state, .suspended)

        error = oktaError(for: .enrollmentDeleted)
        enrollment.recordServerResponse(error: error)
        XCTAssertEqual(enrollment.state, .reset)
        
        error = oktaError(for: .phishingAttemptDetected)
        enrollment.recordServerResponse(error: error)
        XCTAssertEqual(enrollment.state, .active)

        // No err should be recorded as success
        enrollment.recordServerResponse(error: nil)
        XCTAssertEqual(enrollment.state, .active)
    }

    #if os(iOS)
    func testSetUserVerification_Success() {
        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel(id: "id",
                                                                                              userVerification: .preferred,
                                                                                              methods: [.push]))
        try? mockStorageManager.storeAuthenticatorPolicy(policy, orgId: enrollment.orgId)
        var updateAuthenticatorRequestHookCalled = false
        restAPIMock.updateAuthenticatorRequestHook = { url, data, token, _, _, enrollingFactors, _, context, completion in
            guard let enrollingPushFactor = enrollingFactors.first(where: { $0.methodType == .push }) else {
                completion(.failure(.genericError("")))
                return
            }
            
            let factorData = OktaFactorMetadataPush(id: "id", proofOfPossessionKeyTag: "popKeyTag", transactionTypes: .login)
            factorData.userVerificationKeyTag = enrollingPushFactor.userVerificationKeyTag
            let pushFactor = OktaFactorPush(factorData: factorData,
                                            cryptoManager: self.cryptoManager,
                                            restAPIClient: self.restAPIMock,
                                            logger: OktaLoggerMock())
            updateAuthenticatorRequestHookCalled = true
            let enrollmentSummary = EnrollmentSummary(enrollmentId: "",
                                                      userId: "",
                                                      username: nil,
                                                      deviceId: "",
                                                      clientInstanceId: "",
                                                      creationDate: Date(), factors: [pushFactor])
            completion(.success(enrollmentSummary))
        }

        let pushFactor = OktaFactorPush(factorData: OktaFactorMetadataPush(id: "id",
                                                                           proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                                                           transactionTypes: .login),
                                        cryptoManager: cryptoManager,
                                        restAPIClient: restAPIMock,
                                        logger: OktaLoggerMock())
        enrollment.enrolledFactors = []
        enrollment.enrolledFactors.append(pushFactor)
        var completionCalled = false
        XCTAssertFalse(enrollment.hasFactorsWithUserVerificationKey)
        XCTAssertFalse(enrollment.hasFactorsWithUserVerificationBioOrPinKey)
        enrollment.setUserVerification(authenticationToken: AuthToken.bearer(""), enable: true) { _ in
            completionCalled = true
        }

        XCTAssertTrue(completionCalled)
        XCTAssertTrue(updateAuthenticatorRequestHookCalled)
        XCTAssertTrue(enrollment.hasFactorsWithUserVerificationKey)
        XCTAssertFalse(enrollment.hasFactorsWithUserVerificationBioOrPinKey)

        completionCalled = false
        updateAuthenticatorRequestHookCalled = false
        enrollment.setUserVerification(authenticationToken: AuthToken.bearer(""), enable: false) { _ in
            completionCalled = true
        }

        XCTAssertTrue(completionCalled)
        XCTAssertTrue(updateAuthenticatorRequestHookCalled)
        XCTAssertFalse(enrollment.hasFactorsWithUserVerificationKey)
    }
    #endif

    func testSetUserVerification_NoPolicy() {
        var completionCalled = false
        enrollment.setUserVerification(authenticationToken: AuthToken.bearer(""), enable: true) { error in
            XCTAssertEqual(error?.errorDescription, "Failed to fetch authenticator policy")
            completionCalled = true
        }

        XCTAssertTrue(completionCalled)
    }

    func testRetrieveMaintenanceToken_Success() throws {
        cryptoManager.keychainGroupId = ""
        let pushFactor = OktaFactorPush(factorData: OktaFactorMetadataPush(id: "id",
                                                                           proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                                                           links: OktaFactorMetadataPush.Links(pendingLink: "https://test.okta.com/pending_challenge"), transactionTypes: .login),
                                        cryptoManager: cryptoManager,
                                        restAPIClient: restAPIMock,
                                        logger: OktaLoggerMock())
        enrollment.enrolledFactors = [pushFactor]
        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel(id: "id",
                                                                                              userVerification: .preferred,
                                                                                              methods: [.push]))
        try mockStorageManager.storeAuthenticatorPolicy(policy, orgId: enrollment.orgId)
        var retrieveMaintenaceTokenHookCalled = false
        restAPIMock.retrieveMaintenaceTokenHook = { url, oidcClientId, scopes, assertion, completion in
            retrieveMaintenaceTokenHookCalled = true
            XCTAssertEqual(url, self.enrollment.orgHost)
            XCTAssertEqual(oidcClientId, policy.metadata.settings?.oauthClientId ?? "")
            XCTAssertEqual(scopes, ["okta.myAccount.appAuthenticator.maintenance.manage", "okta.myAccount.appAuthenticator.maintenance.read"])
            let jwt = try? JSONWebToken(string: assertion)
            XCTAssertEqual(jwt?.payload["iss"] as? String, "urn:okta:devices:app:authenticator")
            XCTAssertEqual(jwt?.payload["sub"] as? String, self.enrollment.user.id)
            XCTAssertEqual(jwt?.payload["aud"] as? String, self.enrollment.orgHost.absoluteString)
            XCTAssertEqual(jwt?.payload["methodEnrollmentId"] as? String, self.enrollment.pushFactor?.id)
            XCTAssertNotNil(jwt?.payload["nbf"])
            XCTAssertNotNil(jwt?.payload["iat"])
            XCTAssertNotNil(jwt?.payload["jti"])
            XCTAssertNotNil(jwt?.payload["exp"])
            let httpResponse = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)
            completion(.success(HTTPURLResult(request: nil, response: httpResponse, data: MyAccountTestData.accessTokenResponse(), error: nil)))
        }

        let opaqueEnrollment = enrollment as AuthenticatorEnrollmentProtocol
        var retrieveMaintenanceTokenCallbackCalled = false
        opaqueEnrollment.retrieveMaintenanceToken(scopes: ["okta.myAccount.appAuthenticator.maintenance.manage",
                                                           "okta.myAccount.appAuthenticator.maintenance.read"]) { result in
            switch result {
            case .failure(_):
                XCTFail("Unexpected failure")
            case .success(let oauth2Credential):
                XCTAssertEqual(oauth2Credential.access_token, "access.token")
                XCTAssertEqual(oauth2Credential.expires_in, 3600)
                XCTAssertEqual(oauth2Credential.scope, "some.scope")
                XCTAssertEqual(oauth2Credential.refresh_token, "refresh.token")
            }
            retrieveMaintenanceTokenCallbackCalled = true
        }

        XCTAssertTrue(retrieveMaintenaceTokenHookCalled)
        XCTAssertTrue(retrieveMaintenanceTokenCallbackCalled)
    }

    func testRetrieveMaintenanceToken_Failure() throws {
        cryptoManager.keychainGroupId = ""
        let pushFactor = OktaFactorPush(factorData: OktaFactorMetadataPush(id: "id",
                                                                           proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                                                           links: OktaFactorMetadataPush.Links(pendingLink: "https://test.okta.com/pending_challenge"), transactionTypes: .login),
                                        cryptoManager: cryptoManager,
                                        restAPIClient: restAPIMock,
                                        logger: OktaLoggerMock())
        enrollment.enrolledFactors = [pushFactor]
        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel(id: "id",
                                                                                              userVerification: .preferred,
                                                                                              methods: [.push]))
        try mockStorageManager.storeAuthenticatorPolicy(policy, orgId: enrollment.orgId)
        var retrieveMaintenaceTokenHookCalled = false
        restAPIMock.retrieveMaintenaceTokenHook = { url, oidcClientId, scopes, assertion, completion in
            retrieveMaintenaceTokenHookCalled = true
            let httpResponse = HTTPURLResponse(url: url, statusCode: 401, httpVersion: nil, headerFields: nil)
            completion(.success(HTTPURLResult(request: nil, response: httpResponse, data: nil, error: nil)))
        }

        let opaqueEnrollment = enrollment as AuthenticatorEnrollmentProtocol
        var retrieveMaintenanceTokenCallbackCalled = false
        opaqueEnrollment.retrieveMaintenanceToken(scopes: ["okta.myAccount.appAuthenticator.maintenance.manage",
                                                           "okta.myAccount.appAuthenticator.maintenance.read"]) { result in
            switch result {
            case .failure(let error):
                XCTAssertEqual(error.errorCode, -5)
            case .success(_):
                XCTFail("Unexpected success")
            }
            retrieveMaintenanceTokenCallbackCalled = true
        }

        XCTAssertTrue(retrieveMaintenaceTokenHookCalled)
        XCTAssertTrue(retrieveMaintenanceTokenCallbackCalled)
    }

    func testGenerateSSWSToken_Success() {
        let authenticator = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "okta.okta.com")!,
                                                                    orgId: "orgId",
                                                                    enrollmentId: "enrollment_id",
                                                                    cryptoManager: cryptoManager)
        let ex = expectation(description: "Completion expected!")
        authenticator.generateSSWSToken { result in
            switch result {
            case .success(let token):
                XCTAssertEqual(token.split(separator: ".").count, 3)
            case .failure(let error):
                XCTFail("Unexpected failure: \(error)")
            }
            ex.fulfill()
        }
        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testGenerateSSWSToken_CantGetKey() {
        let authenticator = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "okta.okta.com")!,
                                                                    orgId: "orgId",
                                                                    enrollmentId: "enrollment_id",
                                                                    cryptoManager: OktaCryptoManager(keychainGroupId: "", logger: OktaLoggerMock()))

        let ex = expectation(description: "Completion expected!")
        authenticator.generateSSWSToken { result in
            switch result {
            case .success(_):
                XCTFail("Unexpected success")
            case .failure(let error):
                if case let .securityError(encryptionError) = error {
                    XCTAssertEqual(encryptionError, SecurityError.jwtError("Failed to read private key"))
                } else {
                    XCTFail("Unexpected error: \(error)")
                }
            }
            ex.fulfill()
        }
        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testGenerateSSWSToken_GenerationFailed() {
        let userVerificationKeyTag = "userVerificationKeyTag"
        let jwtGeneratorMock = OktaJWTGeneratorMock(logger: OktaLoggerMock())
        jwtGeneratorMock.generateHook = { jwtType, kid, payLoad, key, algo in
            XCTAssertEqual(kid, userVerificationKeyTag)
            throw DeviceAuthenticatorError.genericError("Failed to sign jwt")
        }
        let authenticator = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "okta.okta.com")!,
                                                                    orgId: "orgId",
                                                                    enrollmentId: "enrollment_id",
                                                                    cryptoManager: cryptoManager,
                                                                    userVerificationKeyTag: userVerificationKeyTag,
                                                                    userVerificationBioOrPinKeyTag: nil,
                                                                    jwtGenerator: jwtGeneratorMock)
        let ex = expectation(description: "Completion expected!")
        authenticator.generateSSWSToken { result in
            switch result {
            case .success(_):
                XCTFail("Unexpected success")
            case .failure(let error):
                if case let .securityError(encryptionError) = error {
                    XCTAssertEqual(encryptionError, SecurityError.jwtError("Failed to sign jwt"))
                } else {
                    XCTFail("Unexpected error: \(error)")
                }
            }
            ex.fulfill()
        }
        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testGenerateSSWSToken_PasscodeNotSet() {
        let userVerificationKeyTag = "userVerificationKeyTag"
        let jwtGeneratorMock = OktaJWTGeneratorMock(logger: OktaLoggerMock())
        jwtGeneratorMock.generateHook = { jwtType, kid, payLoad, key, algo in
            XCTAssertEqual(kid, userVerificationKeyTag)
            throw SecurityError.localAuthenticationPasscodeNotSet(LAError(.passcodeNotSet))
        }
        let authenticator = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "okta.okta.com")!,
                                                                    orgId: "orgId",
                                                                    enrollmentId: "enrollment_id",
                                                                    cryptoManager: cryptoManager,
                                                                    userVerificationKeyTag: userVerificationKeyTag,
                                                                    userVerificationBioOrPinKeyTag: nil,
                                                                    jwtGenerator: jwtGeneratorMock)
        let ex = expectation(description: "Completion expected!")
        authenticator.generateSSWSToken { result in
            switch result {
            case .success(_):
                XCTFail("Unexpected success")
            case .failure(let error):
                XCTAssertEqual(error, DeviceAuthenticatorError.securityError(.localAuthenticationPasscodeNotSet(LAError(.passcodeNotSet))))
                XCTAssertEqual(error.localizedDescription, "Encryption operation failed")
            }
            ex.fulfill()
        }
        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testGenerateSSWSToken_UserCancelled() {
        let userVerificationKeyTag = "userVerificationKeyTag"
        let jwtGeneratorMock = OktaJWTGeneratorMock(logger: OktaLoggerMock())
        jwtGeneratorMock.generateHook = { jwtType, kid, payLoad, key, algo in
            XCTAssertEqual(kid, userVerificationKeyTag)
            throw SecurityError.localAuthenticationCancelled(LAError(.userCancel))
        }
        let authenticator = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "okta.okta.com")!,
                                                                    orgId: "orgId",
                                                                    enrollmentId: "enrollment_id",
                                                                    cryptoManager: cryptoManager,
                                                                    userVerificationKeyTag: userVerificationKeyTag,
                                                                    userVerificationBioOrPinKeyTag: nil,
                                                                    jwtGenerator: jwtGeneratorMock)
        let ex = expectation(description: "Completion expected!")
        authenticator.generateSSWSToken { result in
            switch result {
            case .success(_):
                XCTFail("Unexpected success")
            case .failure(let error):
                XCTAssertEqual(error.userVerificationCancelled(), true)
                XCTAssertEqual(error.localizedDescription, "Encryption operation failed")
                let expectedErrorCode = DeviceAuthenticatorError.securityError(SecurityError.localAuthenticationCancelled(LAError(.userCancel))).errorCode
                XCTAssertEqual(error.errorCode, expectedErrorCode)
            }
            ex.fulfill()
        }
        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testGenerateSSWSToken_UseProofOfPossessionKeyIfUVIsNotEnrolled() {
        let jwtGeneratorMock = OktaJWTGeneratorMock(logger: OktaLoggerMock())
        jwtGeneratorMock.generateHook = { jwtType, kid, payLoad, key, algo in
            XCTAssertEqual(kid, "proofOfPossessionKeyTag")
            throw DeviceAuthenticatorError.genericError("Failed to sign jwt")
        }
        let authenticator = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "okta.okta.com")!,
                                                                    orgId: "orgId",
                                                                    enrollmentId: "enrollment_id",
                                                                    cryptoManager: cryptoManager,
                                                                    userVerificationKeyTag: nil,
                                                                    userVerificationBioOrPinKeyTag: nil,
                                                                    jwtGenerator: jwtGeneratorMock)
        let ex = expectation(description: "Completion expected!")
        authenticator.generateSSWSToken { result in
            switch result {
            case .success(_):
                XCTFail("Unexpected success")
            case .failure(let error):
                if case let .securityError(encryptionError) = error {
                    XCTAssertEqual(encryptionError, SecurityError.jwtError("Failed to sign jwt"))
                } else {
                    XCTFail("Unexpected error: \(error)")
                }
            }
            ex.fulfill()
        }
        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testGenerateSSWSToken_UseUserVerificationBioOrPinKeyIfEnrolled() {
        let userVerificationKeyTag = "userVerificationKeyTag"
        let userVerificationBioOrPinKeyTag = "userVerificationBioOrPinKeyTag"
        let jwtGeneratorMock = OktaJWTGeneratorMock(logger: OktaLoggerMock())
        jwtGeneratorMock.generateHook = { jwtType, kid, payLoad, key, algo in
            XCTAssertEqual(kid, userVerificationBioOrPinKeyTag)
            throw DeviceAuthenticatorError.genericError("Failed to sign jwt")
        }
        let authenticator = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "okta.okta.com")!,
                                                                    orgId: "orgId",
                                                                    enrollmentId: "enrollment_id",
                                                                    cryptoManager: cryptoManager,
                                                                    userVerificationKeyTag: userVerificationKeyTag,
                                                                    userVerificationBioOrPinKeyTag: userVerificationBioOrPinKeyTag,
                                                                    jwtGenerator: jwtGeneratorMock)
        let ex = expectation(description: "Completion expected!")
        authenticator.generateSSWSToken { result in
            switch result {
            case .success(_):
                XCTFail("Unexpected success")
            case .failure(let error):
                if case let .securityError(encryptionError) = error {
                    XCTAssertEqual(encryptionError, SecurityError.jwtError("Failed to sign jwt"))
                } else {
                    XCTFail("Unexpected error: \(error)")
                }
            }
            ex.fulfill()
        }
        waitForExpectations(timeout: 1.0, handler: nil)
    }

    private func oktaError(for code: ServerErrorCode) -> DeviceAuthenticatorError {
        let result = HTTPURLResult(request: nil, response: nil, data: nil, error: nil)
        let model = ServerAPIErrorModel(errorCode: code, errorSummary: nil, errorLink: nil, errorId: nil, status: nil, errorCauses: nil)
        return DeviceAuthenticatorError.serverAPIError(result, model)
    }
}
