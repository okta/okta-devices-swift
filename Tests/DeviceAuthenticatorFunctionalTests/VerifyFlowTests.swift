/*
* Copyright (c) 2022-Present, Okta, Inc. and/or its affiliates. All rights reserved.
* The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
*
* You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*
* See the License for the specific language governing permissions and limitations under the License.
*/
// swiftlint:disable force_try
// swiftlint:disable force_cast
// swiftlint:disable force_unwrapping
import XCTest
@testable import DeviceAuthenticator

class VerifyFlowTests: XCTestCase {

    private let mockURL = URL(string: "https://example.okta.com")!
    private let authToken = AuthToken.bearer("testAuthToken")
    private let expectationTimeout: TimeInterval = 1.0

    private var enrollmentHelper: EnrollmentTestHelper!
    private var httpResponses: [HTTPURLResponse]!
    private var dataResponses: [Data]!

    override func setUpWithError() throws {
        enrollmentHelper = EnrollmentTestHelper(applicationName: "FuncTests",
                                                applicationVersion: "1.0.0",
                                                applicationGroupId: ExampleAppConstants.appGroupId,
                                                orgHost: "someorg.okta.com",
                                                clientId: "oidcClientId",
                                                deviceToken: "abcde12345",
                                                authToken: authToken)

        httpResponses = [HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                         HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                         HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!]
        dataResponses = [GoldenData.orgData(),
                         GoldenData.authenticatorMetaData(),
                         GoldenData.authenticatorData()]
    }

    func testParsePushNotification_Success() {

        let parsePushNotificationSuccessExpectation = expectation(description: "Parse push notification should complete")
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        let pushData = GoldenData.pendingPushChallengeData()
        let params = try! JSONSerialization.jsonObject(with: pushData, options: []) as! [String: Any]
        let notification = UNNotificationResponse.testNotificationResponse(with: params, testIdentifier: "test").notification
        do {
            try enrollmentHelper.enroll(mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(_):
                    do {
                        let _ = try self.enrollmentHelper.deviceAuthenticator.parsePushNotification(notification)
                    } catch {
                        XCTFail(error.localizedDescription)
                    }
                case .failure(let enrollmentError):
                    XCTFail(enrollmentError.errorDescription ?? enrollmentError.localizedDescription)
                }
                parsePushNotificationSuccessExpectation.fulfill()
            }
            wait(for: [parsePushNotificationSuccessExpectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testParsePushNotification_BadChallenge() {

        let parsePushNotificationBadChallengeExpectation = expectation(description: "Parse push notification should be fail: Bad challenge")
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        let jwt = FakePushChallenge.mockIDXJWT(enrollmentId: "aen1jisLwwTG7qRrH0g4", challengeContext: [:])
        let challengeInfo = ["payloadVersion": "IDXv1", "challenge": jwt]
        let notification = UNNotificationResponse.testNotificationResponse(with: challengeInfo, testIdentifier: "test").notification
        do {
            try enrollmentHelper.enroll(mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(_):
                    do {
                        let _ = try self.enrollmentHelper.deviceAuthenticator.parsePushNotification(notification)
                    }  catch let error as DeviceAuthenticatorError {
                        if case .internalError(let errorString) = error {
                            XCTAssertEqual(errorString.lowercased(), "Bad challenge".lowercased())
                        } else {
                            XCTFail(error.localizedDescription)
                        }
                    } catch {
                        XCTFail(error.localizedDescription)
                    }
                case .failure(let enrollmentError):
                    XCTFail(enrollmentError.errorDescription ?? enrollmentError.localizedDescription)
                }
                parsePushNotificationBadChallengeExpectation.fulfill()
            }
            wait(for: [parsePushNotificationBadChallengeExpectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testParsePushNotification_PushWithoutPayload() {

        let parsePushWithouPayloadExpectation = expectation(description: "Parse push notification should be fail: Empty payload")
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        let notification = UNNotificationResponse.testNotificationResponse(with: [:], testIdentifier: "test").notification
        do {
            try enrollmentHelper.enroll(mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(_):
                    do {
                        let _ = try self.enrollmentHelper.deviceAuthenticator.parsePushNotification(notification)
                    }  catch let error as DeviceAuthenticatorError {
                        XCTAssertTrue(error == .pushNotRecognized)
                    } catch {
                        XCTFail(error.localizedDescription)
                    }
                case .failure(let enrollmentError):
                    XCTFail(enrollmentError.errorDescription ?? enrollmentError.localizedDescription)
                }
                parsePushWithouPayloadExpectation.fulfill()
            }
            wait(for: [parsePushWithouPayloadExpectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testParsePushNotification_AccountNotFound() {

        struct PushChallenge: PushChallengeProtocol {
            var transactionId: String = "transactionId"
            var appInstanceName: String?
            var clientOS: String? = nil
            var clientLocation: String? = nil
            var userResponse: PushChallengeUserResponse = .userNotResponded
            var originURL: URL? = nil
            var transactionTime: Date = Date()

            func resolve(onRemediation: @escaping (RemediationStep) -> Void,
                         onCompletion: @escaping (DeviceAuthenticatorError?) -> Void) {}
        }

        let notFoundAccountExpectation = expectation(description: "Parse push notification should be fail: Account not found")
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        let jwt = FakePushChallenge.mockIDXJWT(enrollmentId: "testEnrollmentId")
        let challengeInfo = ["payloadVersion": "IDXv1", "challenge": jwt]
        let notification = UNNotificationResponse.testNotificationResponse(with: challengeInfo, testIdentifier: "test").notification
        do {
            try enrollmentHelper.enroll(mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(_):
                    do {
                        let _ = try self.enrollmentHelper.deviceAuthenticator.parsePushNotification(notification)
                    }  catch let error as DeviceAuthenticatorError {
                        let fakePush = PushChallenge()
                        XCTAssertEqual(error, .accountNotFoundForChallenge(fakePush))
                    } catch {
                        XCTFail(error.localizedDescription)
                    }
                case.failure(let enrollmentError):
                    XCTFail(enrollmentError.errorDescription ?? enrollmentError.localizedDescription)
                }
                notFoundAccountExpectation.fulfill()
            }
            wait(for: [notFoundAccountExpectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testParsePushNotification_UnsupportedPayloadVersion() {

        let unsupportedPayloadVersionExpectation = expectation(description: "Parse push notification should be fail: Unsupported payload version")
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        let jwt = FakePushChallenge.mockIDXJWT(enrollmentId: "aen1jisLwwTG7qRrH0g4")
        let challengeInfo = ["payloadVersion": "unsupported", "challenge": jwt]
        let notification = UNNotificationResponse.testNotificationResponse(with: challengeInfo, testIdentifier: "test").notification
        do {
            try enrollmentHelper.enroll(mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(let enrollment):
                    XCTAssertEqual(enrollment.enrollmentId, "aen1jisLwwTG7qRrH0g4")
                    do {
                        let _ = try self.enrollmentHelper.deviceAuthenticator.parsePushNotification(notification)
                    }  catch let error as DeviceAuthenticatorError {
                        XCTAssertEqual(error, .pushNotRecognized)
                    } catch {
                        XCTFail(error.localizedDescription)
                    }
                case .failure(let enrollmentError):
                    XCTFail(enrollmentError.errorDescription ?? enrollmentError.localizedDescription)
                }
                unsupportedPayloadVersionExpectation.fulfill()
            }
            wait(for: [unsupportedPayloadVersionExpectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testParsePushNotification_NoChallenge() {

        let noChallengeExpectation = expectation(description: "Parse push notification should be fail: Payload without challenge")
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        let challengeInfo = ["payloadVersion": "IDXv1"]
        let notification = UNNotificationResponse.testNotificationResponse(with: challengeInfo, testIdentifier: "test").notification
        do {
            try enrollmentHelper.enroll(mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(_):
                    do {
                        let _ = try self.enrollmentHelper.deviceAuthenticator.parsePushNotification(notification)
                    }  catch let error as DeviceAuthenticatorError {
                        XCTAssertEqual(error, .pushNotRecognized)
                    } catch {
                        XCTFail(error.localizedDescription)
                    }
                case .failure(let enrollmentError):
                    XCTFail(enrollmentError.errorDescription ?? enrollmentError.localizedDescription)
                }
                noChallengeExpectation.fulfill()
            }
            wait(for: [noChallengeExpectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testParsePushNotification_InvalidJWTStructure() {

        let invalidJWTStructureExpectation = expectation(description: "Parse push notification should be fail: Invalid JWT structure")
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        let jwt = FakePushChallenge.mockIDXJWT(enrollmentId: "aen1jisLwwTG7qRrH0g4")
        let header = jwt.components(separatedBy: ".").first
//        eyJ0eXAiOiAib2t0YS1wdXNoIiwiYWxnIjogIlJTMjU2In0 = {"typ": "okta-push","alg": "RS256"}
        let jwtWithIncorrectType = jwt.replacingOccurrences(of: header!, with: "eyJ0eXAiOiAib2t0YS1wdXNoIiwiYWxnIjogIlJTMjU2In0")
        let challengeInfo = ["payloadVersion": "IDXv1", "challenge": jwtWithIncorrectType]
        let notification = UNNotificationResponse.testNotificationResponse(with: challengeInfo, testIdentifier: "test").notification
        do {
            try enrollmentHelper.enroll(mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(_):
                    do {
                        let _ = try self.enrollmentHelper.deviceAuthenticator.parsePushNotification(notification)
                    }  catch let error as SecurityError {
                        if case .jwtError(let stringError) = error {
                            XCTAssertEqual(stringError.lowercased(), "Invalid JWT structure".lowercased())
                        } else {
                            XCTFail(error.localizedDescription)
                        }
                    } catch {
                        XCTFail(error.localizedDescription)
                    }
                case .failure(let enrollmentError):
                    XCTFail(enrollmentError.errorDescription ?? enrollmentError.localizedDescription)
                }
                invalidJWTStructureExpectation.fulfill()
            }
            wait(for: [invalidJWTStructureExpectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testRetrievePushChallenge_Success() {

        let retrievePushChallengeSuccessExpectation = expectation(description: "Retrieve push challenge should complete")
        httpResponses.append(HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        let jwt = FakePushChallenge.mockIDXJWT(enrollmentId: "aen1jisLwwTG7qRrH0g4")
        let challengeInfo = [["payloadVersion": "IDXv1", "challenge": jwt]]
        let data = try! JSONSerialization.data(withJSONObject: challengeInfo, options: [])
        dataResponses.append(data)
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        do {
            try enrollmentHelper.enroll(mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(let enrollment):
                    enrollment.retrievePushChallenges(authenticationToken: self.authToken) { pushChallengesResult in
                        switch pushChallengesResult {
                        case .success(let pushChallenges):
                            XCTAssertTrue(pushChallenges.count == 1)
                        case .failure(let error):
                            XCTFail(error.errorDescription ?? error.localizedDescription)
                        }
                        retrievePushChallengeSuccessExpectation.fulfill()
                    }
                case .failure(let enrollmentError):
                    XCTFail(enrollmentError.errorDescription ?? enrollmentError.localizedDescription)
                }
            }
            wait(for: [retrievePushChallengeSuccessExpectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testRetrievePushChallenges_Success() {

        let retrievePushChallengesSuccessExpectation = expectation(description: "Retrieve push challenges should complete")
        httpResponses.append(HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        let jwt = FakePushChallenge.mockIDXJWT(enrollmentId: "aen1jisLwwTG7qRrH0g4")
        let challengeInfo = [["payloadVersion": "IDXv1", "challenge": jwt], ["payloadVersion": "IDXv1", "challenge": jwt]]
        let data = try! JSONSerialization.data(withJSONObject: challengeInfo, options: [])
        dataResponses.append(data)
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        do {
            try enrollmentHelper.enroll(mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(let enrollment):
                    enrollment.retrievePushChallenges(authenticationToken: self.authToken) { pushChallengesResult in
                        switch pushChallengesResult {
                        case .success(let pushChallenges):
                            XCTAssertTrue(pushChallenges.count == 2)
                        case .failure(let error):
                            XCTFail(error.errorDescription ?? error.localizedDescription)
                        }
                        retrievePushChallengesSuccessExpectation.fulfill()
                    }
                case .failure(let error):
                    XCTFail(error.errorDescription ?? error.localizedDescription)
                }
            }
            wait(for: [retrievePushChallengesSuccessExpectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testRetrievePushChallenge_ServerReturns401() {

        let retrievePushChallengeServer401Expectation = expectation(description: "Resolve push challenge should complete")
        httpResponses.append(HTTPURLResponse(url: mockURL, statusCode: 401, httpVersion: nil, headerFields: nil)!)
        dataResponses.append(Data())
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        do {
            try enrollmentHelper.enroll(mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(let enrollment):
                    enrollment.retrievePushChallenges(authenticationToken: self.authToken) { pushChallengesResult in
                        switch pushChallengesResult {
                        case .success(_):
                            XCTFail()
                        case .failure(let error):
                            if case .serverAPIError(let result, _) = error {
                                XCTAssertEqual(result.response?.statusCode, 401)
                            } else {
                                XCTFail(error.errorDescription ?? error.localizedDescription)
                            }
                        }
                        retrievePushChallengeServer401Expectation.fulfill()
                    }
                case .failure(let error):
                    XCTFail(error.errorDescription ?? error.localizedDescription)
                }
            }
            wait(for: [retrievePushChallengeServer401Expectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testRetrievePushChallenges_ServerReturnsEmptyPayload() {

        let retrievePushChallengesEmptyPayloadExpectation = expectation(description: "Retrieve push challenges should complete")
        httpResponses.append(HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        dataResponses.append(Data())
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        do {
            try enrollmentHelper.enroll(mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(let enrollment):
                    enrollment.retrievePushChallenges(authenticationToken: self.authToken) { pushChallengesResult in
                        switch pushChallengesResult {
                        case .success(_):
                            XCTFail()
                        case .failure(let error):
                            if case .genericError(let errorString) = error {
                                XCTAssertEqual(errorString.lowercased(), "Failed to decode server payload".lowercased())
                            } else {
                                XCTFail(error.errorDescription ?? error.localizedDescription)
                            }
                        }
                        retrievePushChallengesEmptyPayloadExpectation.fulfill()
                    }
                case .failure(let error):
                    XCTFail(error.errorDescription ?? error.localizedDescription)
                }
            }
            wait(for: [retrievePushChallengesEmptyPayloadExpectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testRetrievePushChallenges_ServerReturnsIncorrectPayload() {

        let retrievePushChallengesEmptyPayloadExpectation = expectation(description: "Retrieve push challenges should complete")
        httpResponses.append(HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        let challengeInfo = [["payloadVersion": "IDXv1"]]
        let data = try! JSONSerialization.data(withJSONObject: challengeInfo, options: [])
        dataResponses.append(data)

        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        do {
            try enrollmentHelper.enroll(mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(let enrollment):
                    enrollment.retrievePushChallenges(authenticationToken: self.authToken) { pushChallengesResult in
                        switch pushChallengesResult {
                        case .success(let pushChallenges):
                            XCTAssertTrue(pushChallenges.isEmpty)
                            retrievePushChallengesEmptyPayloadExpectation.fulfill()
                        case .failure(let error):
                            XCTFail(error.errorDescription ?? error.localizedDescription)
                        }
                    }
                case .failure(let error):
                    XCTFail(error.errorDescription ?? error.localizedDescription)
                }
            }
            wait(for: [retrievePushChallengesEmptyPayloadExpectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testResolvePushChallenge_Success() {

        let notificationPushChallengeResolveSuccessExpectation = expectation(description: "Notification push challenge should resolve")
        let pushJWT = FakePushChallenge.mockIDXJWT(enrollmentId: "aen1jisLwwTG7qRrH0g4")//, keyTypes: ["userVerification"])
        let pushChallengeInfo = ["payloadVersion": "IDXv1", "challenge": pushJWT]
        let notification = UNNotificationResponse.testNotificationResponse(with: pushChallengeInfo, testIdentifier: "test").notification
        // Success approved push challenge
        httpResponses.append(HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        dataResponses.append("Approved".data(using: .utf8)!)
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        do {
            try enrollmentHelper.enroll(mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(_):
                    do {
                        let pushChallenge = try self.enrollmentHelper.deviceAuthenticator.parsePushNotification(notification)
                        XCTAssertEqual(pushChallenge.userResponse, .userNotResponded)
                        var isUserConsentStepCall = false
                        pushChallenge.resolve { remediationStep in
                            switch remediationStep {
                            case let userConsentStep as RemediationStepUserConsent:
                                userConsentStep.provide(.approved)
                                isUserConsentStepCall = true
                            default:
                                XCTFail()
                            }
                        } onCompletion: { error in
                            XCTAssertNil(error)
                            XCTAssertTrue(isUserConsentStepCall)
                            XCTAssertEqual(pushChallenge.userResponse, .userApproved)
                            notificationPushChallengeResolveSuccessExpectation.fulfill()
                        }
                    } catch {
                        XCTFail(error.localizedDescription)
                    }
                case .failure(let error):
                    XCTFail(error.errorDescription ?? error.localizedDescription)
                }
            }
            wait(for: [notificationPushChallengeResolveSuccessExpectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testResolveRetrivePushChallenge_Success() {

        let retrivePushChallengeResolveSuccessExpectation = expectation(description: "Retrive push challenge should resolve")
        // retrive push challenge
        let retriveJWT = FakePushChallenge.mockIDXJWT(enrollmentId: "aen1jisLwwTG7qRrH0g4")
        let retriveChallengeInfo = [["payloadVersion": "IDXv1", "challenge": retriveJWT]]
        let data = try! JSONSerialization.data(withJSONObject: retriveChallengeInfo, options: [])
        httpResponses.append(HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        dataResponses.append(data)
        // Success approved push challenge
        httpResponses.append(HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        dataResponses.append("Approved".data(using: .utf8)!)
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        do {
            try enrollmentHelper.enroll(mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(let enrollment):
                    enrollment.retrievePushChallenges(authenticationToken: self.authToken) { pushChallengesResult in
                        switch pushChallengesResult {
                        case .success(let pushChallenges):
                            XCTAssertTrue(pushChallenges.count == 1)
                            let pushChallenge = pushChallenges.first!
                            XCTAssertEqual(pushChallenge.userResponse, .userNotResponded)
                            var isUserConsentStepCall = false
                            pushChallenge.resolve { remediationStep in
                                switch remediationStep {
                                case let userConsentStep as RemediationStepUserConsent:
                                    userConsentStep.provide(.approved)
                                    isUserConsentStepCall = true
                                default:
                                    XCTFail()
                                }
                            } onCompletion: { error in
                                XCTAssertNil(error)
                                XCTAssertTrue(isUserConsentStepCall)
                                XCTAssertEqual(pushChallenge.userResponse, .userApproved)
                                retrivePushChallengeResolveSuccessExpectation.fulfill()
                            }
                        case .failure(let error):
                            XCTFail(error.errorDescription ?? error.localizedDescription)
                        }
                    }
                case .failure(let error):
                    XCTFail(error.errorDescription ?? error.localizedDescription)
                }
            }
            wait(for: [retrivePushChallengeResolveSuccessExpectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testResolvePushChallenge_EnrollmentUVEnabled_UVRequired_Success() {

        let notificationPushChallengeResolveSuccessExpectation = expectation(description: "Notification push challenge should resolve for user verification required")
        let pushJWT = FakePushChallenge.mockIDXJWT(enrollmentId: "aen1jisLwwTG7qRrH0g4", userVerification: .required)
        let pushChallengeInfo = ["payloadVersion": "IDXv1", "challenge": pushJWT]
        let notification = UNNotificationResponse.testNotificationResponse(with: pushChallengeInfo, testIdentifier: "test").notification
        // Success approved push challenge
        httpResponses.append(HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        dataResponses.append("Approved".data(using: .utf8)!)
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        do {
            try enrollmentHelper.enroll(userVerification: true, mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(_):
                    do {
                        let pushChallenge = try self.enrollmentHelper.deviceAuthenticator.parsePushNotification(notification)
                        XCTAssertEqual(pushChallenge.userResponse, .userNotResponded)
                        var isUserConsentStepCall = false
                        pushChallenge.resolve { remediationStep in
                            switch remediationStep {
                            case let userConsentStep as RemediationStepUserConsent:
                                userConsentStep.provide(.approved)
                                isUserConsentStepCall = true
                            default:
                                XCTFail()
                            }
                        } onCompletion: { error in
                            XCTAssertNil(error)
                            XCTAssertTrue(isUserConsentStepCall)
                            XCTAssertEqual(pushChallenge.userResponse, .userApproved)
                            notificationPushChallengeResolveSuccessExpectation.fulfill()
                        }
                    } catch {
                        XCTFail(error.localizedDescription)
                    }
                case .failure(let error):
                    XCTFail(error.errorDescription ?? error.localizedDescription)
                }
            }
            wait(for: [notificationPushChallengeResolveSuccessExpectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testResolvePushChallenge_EnrollmentUVDisabled_UVRequired_Fail() {

        let notificationPushChallengeResolveFailExpectation = expectation(description: "Notification push challenge should not resolve for user verification required")
        let pushJWT = FakePushChallenge.mockIDXJWT(enrollmentId: "aen1jisLwwTG7qRrH0g4", userVerification: .required)
        let pushChallengeInfo = ["payloadVersion": "IDXv1", "challenge": pushJWT]
        let notification = UNNotificationResponse.testNotificationResponse(with: pushChallengeInfo, testIdentifier: "test").notification
        // Success approved push challenge
        httpResponses.append(HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        dataResponses.append("Approved".data(using: .utf8)!)
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        do {
            try enrollmentHelper.enroll(userVerification: false, mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(_):
                    do {
                        let pushChallenge = try self.enrollmentHelper.deviceAuthenticator.parsePushNotification(notification)
                        XCTAssertEqual(pushChallenge.userResponse, .userNotResponded)
                        var isUserConsentStepCall = false
                        var isMessageStepCall = false
                        pushChallenge.resolve { remediationStep in
                            switch remediationStep {
                            case let userConsentStep as RemediationStepUserConsent:
                                userConsentStep.provide(.approved)
                                isUserConsentStepCall = true
                            case let messageStep as RemediationStepMessage:
                                XCTAssertEqual(messageStep.reasonType, .userVerificationKeyCorruptedOrMissing)
                                isMessageStepCall = true
                            default:
                                XCTFail()
                            }
                        } onCompletion: { error in
                            XCTAssertNil(error)
                            XCTAssertTrue(isUserConsentStepCall)
                            XCTAssertTrue(isMessageStepCall)
                            XCTAssertEqual(pushChallenge.userResponse, .userApproved)
                            notificationPushChallengeResolveFailExpectation.fulfill()
                        }
                    } catch {
                        XCTFail(error.localizedDescription)
                    }
                case .failure(let error):
                    XCTFail(error.errorDescription ?? error.localizedDescription)
                }
            }
            wait(for: [notificationPushChallengeResolveFailExpectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
}
