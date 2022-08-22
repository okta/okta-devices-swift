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
import UserNotifications
@testable import DeviceAuthenticator

class OktaAuthenticatorsManagerTests: XCTestCase {
    private var mockStorageManager: StorageMock!
    private var cryptoManager: OktaCryptoManager!
    private let mockURL = URL(string: "https://example.okta.com")!
    private let deviceSignals = DeviceSignals(displayName: "Okta's phone")

    var secHelperMock: SecKeyHelperMock!
    var authenticatorManager: _OktaAuthenticatorsManager!
    var enrollmentMock: AuthenticatorEnrollment!
    var restAPI: RestAPIMock!

    override func setUp() {
        super.setUp()

        secHelperMock = SecKeyHelperMock()
        cryptoManager = OktaCryptoManager(accessGroupId: ExampleAppConstants.appGroupId, secKeyHelper: secHelperMock, logger: OktaLoggerMock())

        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!, HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!, HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!], dataArray: [GoldenData.orgData(), GoldenData.authenticatorMetaData(), GoldenData.authenticatorData()])
        restAPI = RestAPIMock(client: mockHTTPClient, logger: OktaLoggerMock())
        let config = ApplicationConfig(applicationName: "Test App",
                                       applicationVersion: "1.0.0",
                                       applicationGroupId: ExampleAppConstants.appGroupId)
        mockStorageManager = StorageMock()
        authenticatorManager = _OktaAuthenticatorsManager(applicationConfig: config,
                                                          storageManager: mockStorageManager,
                                                          cryptoManager: cryptoManager,
                                                          restAPI: restAPI,
                                                          jwkGenerator: OktaJWKGeneratorMock(logger: OktaLoggerMock()),
                                                          jwtGenerator: OktaJWTGenerator(logger: OktaLoggerMock()),
                                                          logger: OktaLoggerMock())

        enrollmentMock = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId", enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager,
                                                                 storageManager: mockStorageManager)
    }

    func testDeleteEnrollment_Success() {
        let deleteAuthenticatorRequestHookCalled = expectation(description: "Delete authenticator rrequest expected!")
        restAPI.deleteAuthenticatorRequestHook = { url, _, completion  in
            deleteAuthenticatorRequestHookCalled.fulfill()
            completion(HTTPURLResult(request: nil, response: nil, data: nil), nil)
        }
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager,
                                                                 storageManager: mockStorageManager)
        let deleteHookCalled = expectation(description: "Delete hook expected!")
        deleteHookCalled.expectedFulfillmentCount = 2
        secHelperMock.deleteKeyHook = { query in
            deleteHookCalled.fulfill()
            return noErr
        }

        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel())
        try? mockStorageManager.storeAuthenticatorPolicy(policy, orgId: enrollment.orgId)
        // add mock authenticator
        try? mockStorageManager.storeEnrollment(enrollment)
        XCTAssertEqual(mockStorageManager.allEnrollments().count, 1)

        let completionCalled = expectation(description: "Completion expected!")
        authenticatorManager._deleteEnrollment(enrollment, accessToken: "") { error in
            XCTAssertNil(error)
            completionCalled.fulfill()
        }

        waitForExpectations(timeout: 1.0, handler: nil)
        XCTAssertEqual(mockStorageManager.allEnrollments().count, 0)
    }

    func testDeleteEnrollment_Error() {
        let deleteAuthenticatorRequestHookCalled = expectation(description: "Delete authenticator rrequest expected!")
        restAPI.deleteAuthenticatorRequestHook = { url, _, completion  in
            deleteAuthenticatorRequestHookCalled.fulfill()
            completion(nil, DeviceAuthenticatorError.genericError(""))
        }
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager)
        secHelperMock.deleteKeyHook = { query in
            XCTFail("Unexpected call")
            return noErr
        }

        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel())
        try? mockStorageManager.storeAuthenticatorPolicy(policy, orgId: enrollment.orgId)
        // add mock authenticator
        try? mockStorageManager.storeEnrollment(enrollment)
        XCTAssertEqual(mockStorageManager.allEnrollments().count, 1)

        let completionCalled = expectation(description: "Completion expected!")
        authenticatorManager._deleteEnrollment(enrollment, accessToken: "") { error in
            XCTAssertNotNil(error)
            completionCalled.fulfill()
        }

        waitForExpectations(timeout: 1.0, handler: nil)

        XCTAssertEqual(mockStorageManager.allEnrollments().count, 1)
    }

    func testDeleteEnrollment_410Error() {
        let deleteAuthenticatorRequestHookCalled = expectation(description: "Delete authenticator rrequest expected!")
        restAPI.deleteAuthenticatorRequestHook = { url, _, completion  in
            let response = HTTPURLResponse(url: URL(string: "tenant.okta.com")!, statusCode: 410, httpVersion: nil, headerFields: nil)
            let result = HTTPURLResult(request: nil, response: response, data: nil)
            let serverErrorModel = ServerAPIErrorModel(errorCode: ServerErrorCode.deviceDeleted, errorSummary: nil, errorLink: nil, errorId: nil, status: nil, errorCauses: nil)
            completion(nil, DeviceAuthenticatorError.serverAPIError(result, serverErrorModel))
            deleteAuthenticatorRequestHookCalled.fulfill()
        }
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager,
                                                                 storageManager: mockStorageManager)
        let deleteKeyHookCalled = expectation(description: "Delete hook expected!")
        deleteKeyHookCalled.expectedFulfillmentCount = 2
        secHelperMock.deleteKeyHook = { query in
            deleteKeyHookCalled.fulfill()
            return noErr
        }

        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel())
        try? mockStorageManager.storeAuthenticatorPolicy(policy, orgId: enrollment.orgId)
        // add mock authenticator
        try? mockStorageManager.storeEnrollment(enrollment)
        XCTAssertEqual(mockStorageManager.allEnrollments().count, 1)

        let completionCalled = expectation(description: "Completion expected!")
        authenticatorManager._deleteEnrollment(enrollment, accessToken: "") { error in
            XCTAssertNil(error)
            completionCalled.fulfill()
        }

        waitForExpectations(timeout: 1.0, handler: nil)
        XCTAssertTrue(mockStorageManager.allEnrollments().isEmpty)
    }

    func testDeleteEnrollment_400Error_SuspendedDevice() {
        let deleteAuthenticatorRequestHookCalled = expectation(description: "Delete authenticator rrequest expected!")
        restAPI.deleteAuthenticatorRequestHook = { url, _, completion  in
            let response = HTTPURLResponse(url: URL(string: "tenant.okta.com")!, statusCode: 400, httpVersion: nil, headerFields: nil)
            let result = HTTPURLResult(request: nil, response: response, data: nil)
            let serverErrorModel = ServerAPIErrorModel(errorCode: ServerErrorCode.deviceSuspended, errorSummary: nil, errorLink: nil, errorId: nil, status: nil, errorCauses: nil)
            completion(nil, DeviceAuthenticatorError.serverAPIError(result, serverErrorModel))
            deleteAuthenticatorRequestHookCalled.fulfill()
        }
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager,
                                                                 storageManager: mockStorageManager)
        let deleteKeyHookCalled = expectation(description: "Delete hook expected!")
        deleteKeyHookCalled.expectedFulfillmentCount = 2
        secHelperMock.deleteKeyHook = { query in
            deleteKeyHookCalled.fulfill()
            return noErr
        }

        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel())
        try? mockStorageManager.storeAuthenticatorPolicy(policy, orgId: enrollment.orgId)
        // add mock authenticator
        try? mockStorageManager.storeEnrollment(enrollment)
        XCTAssertEqual(mockStorageManager.allEnrollments().count, 1)

        let completionCalled = expectation(description: "Completion expected!")
        authenticatorManager._deleteEnrollment(enrollment, accessToken: "") { error in
            XCTAssertNil(error)
            completionCalled.fulfill()
        }

        waitForExpectations(timeout: 1.0, handler: nil)
        XCTAssertTrue(mockStorageManager.allEnrollments().isEmpty)
    }

    func testEnroll_CallsRollbackForTransaction() {
        let enrollmentContext = EnrollmentContext(accessToken: "",
                                                  activationToken: nil,
                                                  orgHost: URL(string: "test.atko.com")!,
                                                  authenticatorKey: "custom_app",
                                                  oidcClientId: nil,
                                                  pushToken: DeviceToken.tokenData("token".data(using: .utf8)!),
                                                  enrollBiometricKey: true,
                                                  deviceSignals: deviceSignals,
                                                  biometricSettings: nil)
        let deleteKeyHookCalled = expectation(description: "Delete hook expected!")
        // Delete push keys(pop, uv), delete clientInstanceKey = 5 calls
        deleteKeyHookCalled.expectedFulfillmentCount = 3
        restAPI.enrollAuthenticatorRequestHook = { _, _, _, completion in
            self.secHelperMock.deleteKeyHook = { query in
                deleteKeyHookCalled.fulfill()
                return noErr
            }
            completion(nil, DeviceAuthenticatorError.genericError("Generic Error"))
        }
        authenticatorManager.enroll(with: enrollmentContext) { _ in
        }
        waitForExpectations(timeout: 1.0, handler: nil)
    }

    func testUpdateEnrollment_LifecycleErrors() {
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                       orgId: "orgId",
                                                       enrollmentId: "enrollmentId",
                                                       cryptoManager: cryptoManager)
        XCTAssertEqual(enrollment.state, .active)

        let enrollmentContext = EnrollmentContext(accessToken: nil,
                                                  activationToken: "ODTD TEST",
                                                  orgHost: URL(string: "tenant.okta.com")!,
                                                  authenticatorKey: "custom_app",
                                                  oidcClientId: nil,
                                                  pushToken: .empty,
                                                  enrollBiometricKey: nil,
                                                  deviceSignals: nil,
                                                  biometricSettings: nil)

        // suspended
        var mockHTTPClient = MockAPIResponse.response(for: .deviceSuspended)
        authenticatorManager.restAPI = OktaRestAPI(client: mockHTTPClient, logger: OktaLoggerMock())
        var ex = expectation(description: "Completion callback expected!")
        authenticatorManager.enroll(with: enrollmentContext,
                                    existingEnrollment: enrollment,
                                    onMetadataReceived: nil) { result in
            if case Result.success(_) = result {
                XCTFail("Unexpected response")
            }
            ex.fulfill()
        }
        waitForExpectations(timeout: 1.0, handler: nil)
        XCTAssertEqual(enrollment.state, .suspended)

        // deleted
        mockHTTPClient = MockAPIResponse.response(for: .userDeleted)
        authenticatorManager.restAPI = OktaRestAPI(client: mockHTTPClient, logger: OktaLoggerMock())
        ex = expectation(description: "Completion callback expected!")
        authenticatorManager.enroll(with: enrollmentContext,
                                    existingEnrollment: enrollment,
                                    onMetadataReceived: nil) { result in
            if case Result.success(_) = result {
                XCTFail("Unexpected response")
            }
            ex.fulfill()
        }
        waitForExpectations(timeout: 1.0, handler: nil)
        XCTAssertEqual(enrollment.state, .deleted)
    }

    ///  Verify that API errors during download metadata are propagated to the enrollment used
    func testDownloadMetadataForEnrollment_ApiError() {
        // reset state
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager)
        var mockHTTPClient = MockAPIResponse.response(for: .enrollmentDeleted)
        authenticatorManager.restAPI = OktaRestAPI(client: mockHTTPClient, logger: OktaLoggerMock())
        var ex = expectation(description: "Completion callback expected!")
        authenticatorManager._downloadMetadata(enrollment, authenticatorKey: "") { result in
            ex.fulfill()
        }
        waitForExpectations(timeout: 1.0, handler: nil)
        XCTAssertEqual(enrollment.state, .reset)

        // suspended state
        mockHTTPClient = MockAPIResponse.response(for: .userSuspended)
        authenticatorManager.restAPI = OktaRestAPI(client: mockHTTPClient, logger: OktaLoggerMock())
        ex = expectation(description: "Completion callback expected!")
        authenticatorManager._downloadMetadata(enrollment, authenticatorKey: "") { result in
            ex.fulfill()
        }
        waitForExpectations(timeout: 1.0, handler: nil)
        XCTAssertEqual(enrollment.state, .suspended)

        // deleted state
        mockHTTPClient = MockAPIResponse.response(for: .userDeleted)
        authenticatorManager.restAPI = OktaRestAPI(client: mockHTTPClient, logger: OktaLoggerMock())
        ex = expectation(description: "Completion callback expected!")
        authenticatorManager._downloadMetadata(enrollment, authenticatorKey: "") { result in
            ex.fulfill()
        }
        waitForExpectations(timeout: 1.0, handler: nil)
        XCTAssertEqual(enrollment.state, .deleted)
    }

    func testDownloadMetadataForEnrollment() {
        let mockHTTPClient = MockHTTPClient(
            response: HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil),
            data: GoldenData.authenticatorMetaData())
        authenticatorManager.restAPI = OktaRestAPI(client: mockHTTPClient, logger: OktaLoggerMock())

        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "enrollmentId",
                                                                 cryptoManager: cryptoManager)

        let ex = expectation(description: "Completion callback expected!")
        authenticatorManager._downloadMetadata(enrollment, authenticatorKey: "") { result in
            switch result {
            case .success(let model):
                XCTAssertTrue(model is AuthenticatorPolicy)
            case .failure(_):
                XCTFail("Unexpected result")
            }
            ex.fulfill()
        }

        waitForExpectations(timeout: 1.0, handler: nil)
    }

    #if os(iOS)
    func testParsePushNotificationResponse() {
        let pushInfo = [InternalConstants.PushJWTConstants.payloadVersionKey: InternalConstants.PushJWTConstants.payloadVersionValue,
                        "challenge": OktaJWTTestData.pushChallengeJWT()]
        let enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                                 orgId: "orgId",
                                                                 enrollmentId: "pfdg0pfyXPT6E8azd0g4",
                                                                 cryptoManager: cryptoManager)
        let policy = AuthenticatorPolicy(metadata: TestUtils.createAuthenticatorMetadataModel())
        try? mockStorageManager.storeAuthenticatorPolicy(policy, orgId: enrollment.orgId)
        XCTAssertNoThrow(try authenticatorManager.storageManager.storeEnrollment(enrollment))

        var response = UNNotificationResponse.testNotificationResponse(with: pushInfo,
                                                                       testIdentifier: InternalConstants.PushNotificationConstants.approveActionIdentifier)
        var pushChallenge = try? authenticatorManager.parse(response: response, allowedClockSkewInSeconds: 100)

        XCTAssertNotNil(pushChallenge)
        XCTAssertEqual(pushChallenge?.userResponse, .userApproved)

        response = UNNotificationResponse.testNotificationResponse(with: pushInfo,
                                                                   testIdentifier: InternalConstants.PushNotificationConstants.denyActionIdentifier)
        pushChallenge = try? authenticatorManager.parse(response: response, allowedClockSkewInSeconds: 100)

        XCTAssertNotNil(pushChallenge)
        XCTAssertEqual(pushChallenge?.userResponse, .userDenied)

        response = UNNotificationResponse.testNotificationResponse(with: pushInfo,
                                                                   testIdentifier: InternalConstants.PushNotificationConstants.userVerificationActionIdentifier)
        pushChallenge = try? authenticatorManager.parse(response: response, allowedClockSkewInSeconds: 100)

        XCTAssertNotNil(pushChallenge)
        XCTAssertEqual(pushChallenge?.userResponse, .userNotResponded)
    }
    #endif
}
