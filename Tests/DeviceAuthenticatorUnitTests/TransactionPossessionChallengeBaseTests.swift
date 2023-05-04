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

class TransactionPossessionChallengeBaseTests: XCTestCase {

    var storageMock: StorageMock!
    var restAPIMock: RestAPIMock!
    var cryptoManager: CryptoManagerMock!
    var applicationConfig: ApplicationConfig!
    var deviceAuthenticator: DeviceAuthenticator!

    override func setUp() {
        cryptoManager = CryptoManagerMock(keychainGroupId: ExampleAppConstants.appGroupId, logger: OktaLoggerMock())
        restAPIMock = RestAPIMock(client: HTTPClient(logger: OktaLoggerMock(), userAgent: ""), logger: OktaLoggerMock())
        storageMock = StorageMock()
        storageMock.deviceEnrollmentByOrgIdHook = { orgId in
            return OktaDeviceEnrollment(id: "id",
                                        orgId: orgId,
                                        clientInstanceId: "clientInstanceId",
                                        clientInstanceKeyTag: "clientInstanceKeyTag")
        }
        applicationConfig = ApplicationConfig(applicationName: "Test App",
                                              applicationVersion: "1.0.0",
                                              applicationGroupId: ExampleAppConstants.appGroupId)
        deviceAuthenticator = try! DeviceAuthenticatorBuilder(applicationConfig: applicationConfig).create() as! DeviceAuthenticator
        deviceAuthenticator.impl = _OktaAuthenticatorsManager(applicationConfig: applicationConfig,
                                                              storageManager: storageMock,
                                                              cryptoManager: cryptoManager,
                                                              restAPI: restAPIMock,
                                                              jwkGenerator: OktaJWKGenerator(logger: OktaLoggerMock()),
                                                              jwtGenerator: OktaJWTGenerator(logger: OktaLoggerMock()),
                                                              logger: OktaLoggerMock())


    }

    func testVerifyChallengeTransactionWithStateHandle_Success() throws {
        let completionExpectation = expectation(description: "Completion has been called!")
        let mut = try OktaTransactionPossessionChallengeBasePartialMock(applicationConfig: applicationConfig,
                                                                        challengeRequest: OktaJWTTestData.validDeviceChallengeRequestJWTWithUserMediationRequired(),
                                                                        stateHandle: "state_handle",
                                                                        httpHeaders: nil,
                                                                        loginHint: nil,
                                                                        storageManager: storageMock,
                                                                        cryptoManager: cryptoManager,
                                                                        signalsManager: SignalsManager(logger: OktaLoggerMock()),
                                                                        restAPI: restAPIMock,
                                                                        logger: OktaLoggerMock())
        mut.verify(onIdentityStep: { identityStep in
        }) { result, error, enrollment in
            XCTAssertNil(error)
            XCTAssertNotNil(result)
            let paramsToVerify = try! JSONSerialization.jsonObject(with: result!.data!, options: []) as! [String: Any]
            let verifyURL = paramsToVerify["verifyURL"] as? String
            let data = paramsToVerify["data"] as? Data
            XCTAssertNotNil(verifyURL)
            XCTAssertTrue(verifyURL!.contains("challengeResponse"))
            XCTAssertTrue(verifyURL!.contains("stateHandle"))
            XCTAssertNil(data)
            completionExpectation.fulfill()
        }

        wait(for: [completionExpectation], timeout: 3.0)
    }

    func testVerifyChallengeTransactionWithIntegrations_Success() throws {

        let completionExpectation = expectation(description: "Completion has been called!")

        let signalsManager = SignalsManager(logger: OktaLoggerMock())
        let resourcePath = Bundle(for: type(of: self)).resourcePath
        let signalPath = resourcePath! + "/pluginSignal.txt"
        var integrations: [Data] = []
        do {
            for entry in TestUtils.getValidEDRConfigs(path: signalPath) {
                integrations.append(try JSONSerialization.data(withJSONObject: entry, options: .prettyPrinted))
            }
        } catch {
            XCTFail()
        }
        signalsManager.initializeSignalPlugins(plugins: [], externalConfigs: integrations)
        let mut = try OktaTransactionPossessionChallengeBasePartialMock(applicationConfig: applicationConfig,
                                                                        challengeRequest: OktaJWTTestData.validDeviceChallengeRequestJWT(),
                                                                        stateHandle: "state_handle",
                                                                        httpHeaders: nil,
                                                                        loginHint: nil,
                                                                        storageManager: storageMock,
                                                                        cryptoManager: cryptoManager,
                                                                        signalsManager: signalsManager,
                                                                        restAPI: restAPIMock,
                                                                        logger: OktaLoggerMock())
        mut.verify(onIdentityStep: { identityStep in
        }) { result, error, enrollment in
            XCTAssertNil(error)
            XCTAssertNotNil(result)
            let paramsToVerify = try! JSONSerialization.jsonObject(with: result!.data!, options: []) as! [String: Any]
            let verifyURL = paramsToVerify["verifyURL"] as? String
            let challengeResponseJSON = self.extractChallengeResponseJSON(verifyURL: verifyURL)
            let integrations = challengeResponseJSON?["integrations"] as? [[String: Any]]
            #if os(macOS)
            XCTAssertNotNil(integrations?.first?["signal"])
            #endif
            completionExpectation.fulfill()
        }

        wait(for: [completionExpectation], timeout: 3.0)
    }

    func testVerifyChallengeTransactionWithEmptyStateHandle_Success() throws {

        let completionExpectation = expectation(description: "Completion has been called!")
        let mut = try OktaTransactionPossessionChallengeBasePartialMock(applicationConfig: applicationConfig,
                                                                        challengeRequest: OktaJWTTestData.validDeviceChallengeRequestJWTWithUserMediationRequired(),
                                                                        stateHandle: nil,
                                                                        httpHeaders: nil,
                                                                        loginHint: nil,
                                                                        storageManager: storageMock,
                                                                        cryptoManager: cryptoManager,
                                                                        signalsManager: SignalsManager(logger: OktaLoggerMock()),
                                                                        restAPI: restAPIMock,
                                                                        logger: OktaLoggerMock())
        mut.verify(onIdentityStep: { identityStep in
        }) { result, error, enrollment in
            XCTAssertNil(error)
            XCTAssertNotNil(result)
            let paramsToVerify = try! JSONSerialization.jsonObject(with: result!.data!, options: []) as! [String: Any]
            let verifyURL = paramsToVerify["verifyURL"] as? String
            let base64String = paramsToVerify["data"] as? String
            XCTAssertNotNil(verifyURL)
            XCTAssertFalse(verifyURL!.contains("challengeRequest"))
            XCTAssertFalse(verifyURL!.contains("stateHandle"))
            XCTAssertNotNil(base64String)
            let dict = try? JSONSerialization.jsonObject(with: Data(base64Encoded: base64String!)!, options: .allowFragments) as? [String: Any]
            let challengeResponse = dict?["challengeResponse"]
            XCTAssertNotNil(challengeResponse)
            completionExpectation.fulfill()
        }

        wait(for: [completionExpectation], timeout: 3.0)
    }

    func testVerifyChallengeTransaction_InvalidJWTFailure() throws {

        restAPIMock.error = DeviceAuthenticatorError.serverAPIError(HTTPURLResult(request: nil, response: nil, data: nil),
                                                                    nil)
        do {
            let _ = try OktaTransactionPossessionChallengeBasePartialMock(applicationConfig: applicationConfig,
                                                                          challengeRequest: OktaJWTTestData.invalidJWTPayload(),
                                                                          stateHandle: "state_handle",
                                                                          httpHeaders: nil,
                                                                          loginHint: nil,
                                                                          storageManager: storageMock,
                                                                          cryptoManager: cryptoManager,
                                                                          signalsManager: SignalsManager(logger: OktaLoggerMock()),
                                                                          restAPI: restAPIMock,
                                                                          logger: OktaLoggerMock())
            XCTFail("Unexpected callback call")
        } catch {
            let deviceAuthenticatorError = DeviceAuthenticatorError.oktaError(from: error)
            if case let .securityError(encryptionError) = deviceAuthenticatorError {
                XCTAssertEqual(encryptionError, SecurityError.jwtError("Invalid JWT structure"))
            } else {
                XCTFail()
            }
        }
    }

    func testVerifyChallengeTransaction_RestAPIFailure() throws {

        restAPIMock.error = DeviceAuthenticatorError.serverAPIError(HTTPURLResult(request: nil, response: nil, data: nil),
                                                   ServerAPIErrorModel(errorCode: ServerErrorCode.enrollmentDeleted,
                                                                       errorSummary: nil,
                                                                       errorLink: nil,
                                                                       errorId: nil,
                                                                       status: nil,
                                                                       errorCauses: nil))
        let authenticator = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "okta.okta.com")!,
                                                                    orgId: "myOrgId",
                                                                    enrollmentId: "enrollment_id",
                                                                    cryptoManager: cryptoManager)
        storageMock.enrollmentsByOrgIdClosure = { orgId in
            return [authenticator]
        }

        let completionExpectation = expectation(description: "Completion has been called!")
        let mut = try OktaTransactionPossessionChallengeBasePartialMock(applicationConfig: applicationConfig,
                                                                        challengeRequest: OktaJWTTestData.validDeviceChallengeRequestJWTWithUserMediationRequired(),
                                                                        stateHandle: "state_handle",
                                                                        httpHeaders: nil,
                                                                        loginHint: nil,
                                                                        storageManager: storageMock,
                                                                        cryptoManager: cryptoManager,
                                                                        signalsManager: SignalsManager(logger: OktaLoggerMock()),
                                                                        restAPI: restAPIMock,
                                                                        logger: OktaLoggerMock())
        mut.verify(onIdentityStep: { identityStep in
        }) { result, error, enrollment in
            XCTAssertNil(result)
            XCTAssertNotNil(error)
            XCTAssertEqual(error?.errorCode, -1)
            if case let DeviceAuthenticatorError.serverAPIError(_, errorModel) = error! {
                XCTAssertNotNil(errorModel)
                XCTAssertEqual(errorModel?.errorCode?.rawValue, ServerErrorCode.enrollmentDeleted.rawValue)
            } else {
                XCTFail("Incorrect error type - \(error!)")
            }
            completionExpectation.fulfill()
        }

        wait(for: [completionExpectation], timeout: 3.0)
    }

    func testVerifyChallengeTransaction_ValidationURLCheckFailure() throws {
        do {
            let _ = try OktaTransactionPossessionChallengeBasePartialMock(applicationConfig: applicationConfig,
                                                                          challengeRequest: OktaJWTTestData.payloadWithInvalidVerificationURL(),
                                                                          stateHandle: "state_handle",
                                                                          httpHeaders: nil,
                                                                          loginHint: nil,
                                                                          storageManager: storageMock,
                                                                          cryptoManager: cryptoManager,
                                                                          signalsManager: SignalsManager(logger: OktaLoggerMock()),
                                                                          restAPI: restAPIMock,
                                                                          logger: OktaLoggerMock())
            XCTFail("Unexpected callback call")
        } catch {
            let deviceAuthenticatorError = DeviceAuthenticatorError.oktaError(from: error)
            if case let .securityError(encryptionError) = deviceAuthenticatorError {
                XCTAssertEqual(encryptionError, SecurityError.jwtError("verificationUri claim is invalid in JWT payload"))
            } else {
                XCTFail()
            }
        }
    }

    func testReadSigningKeyErrorHandler_userVerificationPermanentlyUnavailable() throws {
        let mut = try OktaTransactionPossessionChallengeBasePartialMock(applicationConfig: applicationConfig,
                                                                        challengeRequest: OktaJWTTestData.validDeviceChallengeRequestJWTWithUserMediationRequired(),
                                                                        stateHandle: "state_handle",
                                                                        httpHeaders: nil,
                                                                        loginHint: nil,
                                                                        storageManager: storageMock,
                                                                        cryptoManager: cryptoManager,
                                                                        signalsManager: SignalsManager(logger: OktaLoggerMock()),
                                                                        restAPI: restAPIMock,
                                                                        logger: OktaLoggerMock())
        let transactionContext = OktaTransactionPossessionChallengeBase.TransactionContext(challengeRequest: mut.challengeRequestJWT,
                                                                                           appIdentityStepClosure: { step in
        },
                                                                                           appCompletionClosure: { jwt, error, enrollment in
        })

        var signJWTAndSendRequestHookCalled = false
        var postMessageToApplicationHookCalled = false
        mut.postMessageToApplicationHook = { message, reasonType, error, context in
            XCTAssertEqual(message, "Failed to sign with key userVerification, falling back to proofOfPossession")
            XCTAssertEqual(reasonType, .userVerificationKeyCorruptedOrMissing)
            postMessageToApplicationHookCalled = true
        }
        mut.signJWTAndSendRequestHook = { context, keyTypes in
            XCTAssertTrue(context.userConsentResponseValue == .userVerificationPermanentlyUnavailable)
            signJWTAndSendRequestHookCalled = true
        }
        mut.readSigningKeyErrorHandler(error: .securityError(.keyCorrupted(NSError())),
                                       transactionContext: transactionContext,
                                       keysRequirements: [.userVerification, .proofOfPossession])
        XCTAssertTrue(signJWTAndSendRequestHookCalled)
        XCTAssertTrue(postMessageToApplicationHookCalled)
    }

    func testReadSigningKeyErrorHandler_userVerificationTemporarilyUnavailable() throws {
        let mut = try OktaTransactionPossessionChallengeBasePartialMock(applicationConfig: applicationConfig,
                                                                        challengeRequest: OktaJWTTestData.validDeviceChallengeRequestJWTWithUserMediationRequired(),
                                                                        stateHandle: "state_handle",
                                                                        httpHeaders: nil,
                                                                        loginHint: nil,
                                                                        storageManager: storageMock,
                                                                        cryptoManager: cryptoManager,
                                                                        signalsManager: SignalsManager(logger: OktaLoggerMock()),
                                                                        restAPI: restAPIMock,
                                                                        logger: OktaLoggerMock())
        let transactionContext = OktaTransactionPossessionChallengeBase.TransactionContext(challengeRequest: mut.challengeRequestJWT,
                                                                                           appIdentityStepClosure: { step in
        },
                                                                                           appCompletionClosure: { jwt, error, enrollment in
        })

        var signJWTAndSendRequestHookCalled = false
        var postMessageToApplicationHookCalled = false
        mut.postMessageToApplicationHook = { message, reasonType, error, context in
            XCTAssertEqual(message, "Failed to sign with key userVerification, falling back to proofOfPossession")
            XCTAssertEqual(reasonType, .userVerificationFailed)
            postMessageToApplicationHookCalled = true
        }
        mut.signJWTAndSendRequestHook = { context, keyTypes in
            XCTAssertTrue(context.userConsentResponseValue == .userVerificationTemporarilyUnavailable)
            signJWTAndSendRequestHookCalled = true
        }
        mut.readSigningKeyErrorHandler(error: .securityError(.localAuthenticationFailed(NSError())),
                                       transactionContext: transactionContext,
                                       keysRequirements: [.userVerification, .proofOfPossession])
        XCTAssertTrue(signJWTAndSendRequestHookCalled)
        XCTAssertTrue(postMessageToApplicationHookCalled)
    }

    func testReadSigningKeyErrorHandler_userVerificationCancelledByUser() throws {
        let mut = try OktaTransactionPossessionChallengeBasePartialMock(applicationConfig: applicationConfig,
                                                                        challengeRequest: OktaJWTTestData.validDeviceChallengeRequestJWTWithUserMediationRequired(),
                                                                        stateHandle: "state_handle",
                                                                        httpHeaders: nil,
                                                                        loginHint: nil,
                                                                        storageManager: storageMock,
                                                                        cryptoManager: cryptoManager,
                                                                        signalsManager: SignalsManager(logger: OktaLoggerMock()),
                                                                        restAPI: restAPIMock,
                                                                        logger: OktaLoggerMock())
        let transactionContext = OktaTransactionPossessionChallengeBase.TransactionContext(challengeRequest: mut.challengeRequestJWT,
                                                                                           appIdentityStepClosure: { step in
        },
                                                                                           appCompletionClosure: { jwt, error, enrollment in
        })

        var signJWTAndSendRequestHookCalled = false
        var postMessageToApplicationHookCalled = false
        mut.postMessageToApplicationHook = { message, reasonType, error, context in
            XCTAssertEqual(message, "Failed to sign with key userVerification, falling back to proofOfPossession")
            XCTAssertEqual(reasonType, .userVerificationCancelledByUser)
            postMessageToApplicationHookCalled = true
        }
        mut.signJWTAndSendRequestHook = { context, keyTypes in
            XCTAssertTrue(context.userConsentResponseValue == .cancelledUserVerification)
            signJWTAndSendRequestHookCalled = true
        }
        mut.readSigningKeyErrorHandler(error: .securityError(.localAuthenticationCancelled(NSError())),
                                       transactionContext: transactionContext,
                                       keysRequirements: [.userVerification, .proofOfPossession])
        XCTAssertTrue(signJWTAndSendRequestHookCalled)
        XCTAssertTrue(postMessageToApplicationHookCalled)
    }

    func testReadSigningKeyErrorHandler_userVerificationKeyNotEnrolled() throws {
        let mut = try OktaTransactionPossessionChallengeBasePartialMock(applicationConfig: applicationConfig,
                                                                        challengeRequest: OktaJWTTestData.validDeviceChallengeRequestJWTWithUserMediationRequired(),
                                                                        stateHandle: "state_handle",
                                                                        httpHeaders: nil,
                                                                        loginHint: nil,
                                                                        storageManager: storageMock,
                                                                        cryptoManager: cryptoManager,
                                                                        signalsManager: SignalsManager(logger: OktaLoggerMock()),
                                                                        restAPI: restAPIMock,
                                                                        logger: OktaLoggerMock())
        let transactionContext = OktaTransactionPossessionChallengeBase.TransactionContext(challengeRequest: mut.challengeRequestJWT,
                                                                                           appIdentityStepClosure: { step in
        },
                                                                                           appCompletionClosure: { jwt, error, enrollment in
        })

        var signJWTAndSendRequestHookCalled = false
        var postMessageToApplicationHookCalled = false
        mut.postMessageToApplicationHook = { message, reasonType, error, context in
            XCTAssertEqual(message, "Failed to sign with key userVerification, falling back to proofOfPossession")
            XCTAssertEqual(reasonType, .userVerificationKeyNotEnrolled)
            postMessageToApplicationHookCalled = true
        }
        mut.signJWTAndSendRequestHook = { context, keyTypes in
            XCTAssertTrue(context.userConsentResponseValue == .approved)
            signJWTAndSendRequestHookCalled = true
        }
        mut.readSigningKeyErrorHandler(error: .genericError("UV key is not found for account"),
                                       transactionContext: transactionContext,
                                       keysRequirements: [.userVerification, .proofOfPossession])
        XCTAssertTrue(signJWTAndSendRequestHookCalled)
        XCTAssertTrue(postMessageToApplicationHookCalled)
    }

    func extractChallengeResponseJSON(verifyURL: String?) -> [String: Any]? {
        let challengeResponse = verifyURL?.slice(from: "=", to: "&")!
        let responseSections = challengeResponse!.split(separator: ".")
        var encodedPayload = "\(responseSections[1])"
        if encodedPayload.count % 4 != 0 {
            let padding = 4 - encodedPayload.count % 4
            encodedPayload += String(repeating: "=", count: padding)
        }
        let dictData = Data(base64Encoded: encodedPayload, options: [])
        return try? JSONSerialization.jsonObject(with: dictData!, options: .allowFragments) as? [String: Any]
    }
}

fileprivate class OktaTransactionPossessionChallengeBasePartialMock: OktaTransactionPossessionChallengeBase {
    typealias tryReadSigningKeyType = (OktaBindJWT.KeyType, OktaBindJWT.MethodType, AuthenticatorEnrollment, (RemediationStep) -> Void, (KeyData?, DeviceAuthenticatorError?) -> Void) -> Void
    typealias signJWTAndSendRequestType = (OktaTransaction.TransactionContext, [OktaBindJWT.KeyType]) -> Void
    typealias postMessageToApplicationType = (String, RemediationStepMessageReasonType, DeviceAuthenticatorError, OktaTransaction.TransactionContext) -> Void

    var tryReadSigningKeyHook: tryReadSigningKeyType?
    var signJWTAndSendRequestHook: signJWTAndSendRequestType?
    var postMessageToApplicationHook: postMessageToApplicationType?
    var factorIdToReturn = "12345"

    override func parseJWT(string: String) throws -> OktaBindJWT {
        return try OktaBindJWT(string: string, validatePayload: false, logger: OktaLoggerMock())
    }

    override func handleSelectAccountStep(transactionContext: TransactionContext,
                                          appEventsQueue: [RemediationEvents]) {
        transactionContext.enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "okta.okta.com")!,
                                                                                orgId: "myOrgId",
                                                                                enrollmentId: "enrollment_id",
                                                                                cryptoManager: self.cryptoManager as! OktaCryptoManager)
        triageRemediationEvents(appEventsQueue, transactionContext: transactionContext)
    }

    override func handleUserConsentStep(transactionContext: TransactionContext,
                                        appEventsQueue: [RemediationEvents]) {
        triageRemediationEvents(appEventsQueue, transactionContext: transactionContext)
    }

    override func handleDeviceSignalsStep(transactionContext: TransactionContext,
                                          appEventsQueue: [RemediationEvents]) {
        triageRemediationEvents(appEventsQueue, transactionContext: transactionContext)
    }

    override func getProofOfPossessionKeyTag(methodType: OktaBindJWT.MethodType, enrollment: AuthenticatorEnrollment) -> String? {
        return enrollment.enrolledFactors.first { $0.proofOfPossessionKeyTag != nil }.map({ $0.proofOfPossessionKeyTag! })
    }

    override func getUserVerificationKeyTag(methodType: OktaBindJWT.MethodType, enrollment: AuthenticatorEnrollment) -> String? {
        return enrollment.enrolledFactors.first { $0.userVerificationKeyTag != nil }.map({ $0.userVerificationKeyTag! })
    }

    override func getUserVerificationBioOrPinKeyTag(methodType: OktaBindJWT.MethodType, enrollment: AuthenticatorEnrollment) -> String? {
        return enrollment.enrolledFactors.first { $0.userVerificationBioOrPinKeyTag != nil }.map({ $0.userVerificationBioOrPinKeyTag! })
    }

    override func getFactorIdFromEnrollment(_ enrollment: AuthenticatorEnrollment) -> String? {
        return factorIdToReturn
    }

    override func postMessageToApplication(message: String, reason: RemediationStepMessageReasonType, error: DeviceAuthenticatorError, transactionContext: OktaTransaction.TransactionContext) {
        if let postMessageToApplicationHook = postMessageToApplicationHook {
            postMessageToApplicationHook(message, reason, error, transactionContext)
        } else {
            super.postMessageToApplication(message: message, reason: reason, error: error, transactionContext: transactionContext)
        }
    }

    override func signJWTAndSendRequest(transactionContext: OktaTransaction.TransactionContext, keysRequirements: [OktaBindJWT.KeyType]) {
        if let signJWTAndSendRequestHook = signJWTAndSendRequestHook {
            signJWTAndSendRequestHook(transactionContext, keysRequirements)
        } else {
            super.signJWTAndSendRequest(transactionContext: transactionContext, keysRequirements: keysRequirements)
        }
    }
}
