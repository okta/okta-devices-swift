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
import XCTest
import LocalAuthentication
@testable import DeviceAuthenticator

class OktaTransactionPushChallengeTests: XCTestCase {
    var storageMock: StorageMock!
    var restAPIMock: RestAPIMock!
    var cryptoManager: CryptoManagerMock!
    var enrollment: AuthenticatorEnrollmentMock!
    fileprivate var transaction: OktaTransactionPushChallengePartialMock!
    var pushChallenge: PushChallenge!
    var applicationConfig: ApplicationConfig!
    let ec256ValidPrivateKeyBase64 = "BIBwuQyPfBPU+fyXiU+i0FOqEAHtm3U5aER8gIWVnyJvw9YfSa7ylqLNpdeyTie4zUFP9UU4FXLByqcaGFR1q05at441RDVAq1aewlvnE9pKcZmCiiayoO37AxpdRYcTmA=="

    override func setUpWithError() throws {
        cryptoManager = CryptoManagerMock(keychainGroupId: ExampleAppConstants.appGroupId, logger: OktaLoggerMock())
        storageMock = StorageMock()
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [],
                                                            dataArray: [])
        restAPIMock = RestAPIMock(client: mockHTTPClient, logger: OktaLoggerMock())
        applicationConfig = ApplicationConfig(applicationName: "", applicationVersion: "", applicationGroupId: "")
        enrollment = TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "www.okta.com")!,
                                                             orgId: "ordId",
                                                             enrollmentId: "id",
                                                             cryptoManager: cryptoManager)

        let pushBindJWT = try? OktaBindJWT(string: OktaJWTTestData.pushChallengeJWT(),
                                           validatePayload: false,
                                           jwtType: InternalConstants.PushJWTConstants.pushJWTType,
                                           logger: OktaLoggerMock())
        XCTAssertNotNil(pushBindJWT)
        storageMock.enrollmentByIdHook = { enrollmentId in
            return TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                           orgId: "orgId",
                                                           enrollmentId: "enrollmentId",
                                                           cryptoManager: CryptoManagerMock(keychainGroupId: "accessGroupId", logger: OktaLoggerMock()))
        }
        let context = pushBindJWT!.jwt.payload["challengeContext"] as! [AnyHashable: Any]
        pushChallenge = PushChallenge(pushBindJWT: pushBindJWT!,
                                      challengeContext: context,
                                      storageManager: storageMock,
                                      applicationConfig: ApplicationConfig(applicationName: "", applicationVersion: "", applicationGroupId: ""),
                                      cryptoManager: CryptoManagerMock(keychainGroupId: "", logger: OktaLoggerMock()),
                                      signalsManager: SignalsManager(logger: OktaLoggerMock()),
                                      restAPI: RestAPIMock(client: HTTPClient(logger: OktaLoggerMock(), userAgent: ""), logger: OktaLoggerMock()),
                                      logger: OktaLoggerMock())
        pushChallenge.enrollment = enrollment
        transaction = try OktaTransactionPushChallengePartialMock(pushChallenge: pushChallenge,
                                                                  applicationConfig: applicationConfig,
                                                                  storageManager: storageMock,
                                                                  cryptoManager: cryptoManager,
                                                                  signalsManager: SignalsManager(logger: OktaLoggerMock()),
                                                                  restAPI: restAPIMock,
                                                                  logger: OktaLoggerMock())
        transaction.challengeRequestJWT = pushChallenge?.pushBindJWT
    }

    func testHandleSelectAccountStep_Success() {
        let context = OktaTransaction.TransactionContext(challengeRequest: transaction.challengeRequestJWT) { _ in
        } appCompletionClosure: { (_, _, _) in
        }

        var triageRemediationEventsHookCalled = false
        transaction.triageRemediationEventsHook = { _, transactionContext in
            XCTAssertNotNil(transactionContext.enrollment)
            triageRemediationEventsHookCalled = true
        }
        transaction.challengeRequestJWT = try! OktaBindJWT(string: OktaJWTTestData.validDeviceChallengeRequestJWT(),
                                                           validatePayload: false,
                                                           logger: OktaLoggerMock())

        transaction.handleSelectAccountStep(transactionContext: context, appEventsQueue: [])
        XCTAssertTrue(triageRemediationEventsHookCalled)
    }

    func testHandleSelectAccountStep_JWTValidationFailed() {
        var appCompletionClosureCalled = false
        let context = OktaTransaction.TransactionContext(challengeRequest: transaction.challengeRequestJWT) { _ in
        } appCompletionClosure: { (_, error, _) in
            appCompletionClosureCalled = true
            if case .securityError(let securityError) = error {
                if securityError != .jwtError("The JWT algorithm HS256 is not supported at this time") {
                    XCTFail("Unexpected error")
                }
            } else {
                XCTFail("Unexpected error")
            }
        }

        transaction.challengeRequestJWT = try! OktaBindJWT(string: OktaJWTTestData.validDeviceChallengeRequestJWT(),
                                                           validatePayload: true,
                                                           logger: OktaLoggerMock())

        transaction.handleSelectAccountStep(transactionContext: context, appEventsQueue: [])
        XCTAssertTrue(appCompletionClosureCalled)
    }

    func testHandleUserConsentStep_ChallengeWaitsUserInput() {
        let context = OktaTransaction.TransactionContext(challengeRequest: transaction.challengeRequestJWT) { step in
            if let step = step as? RemediationStepUserConsent {
                step.provide(.approved)
            } else {
                XCTFail("Unexpected remediation event")
            }
        } appCompletionClosure: { (_, _, _) in
        }

        var triageRemediationEventsHookCalled = false
        transaction.triageRemediationEventsHook = { _, transactionContext in
            XCTAssertNotNil(transactionContext.enrollment)
            XCTAssertTrue(transactionContext.userConsentResponseValue == .approved)
            triageRemediationEventsHookCalled = true
        }

        context.enrollment = (pushChallenge.enrollment as! AuthenticatorEnrollment)
        transaction.handleUserConsentStep(transactionContext: context, appEventsQueue: [])
        XCTAssertTrue(triageRemediationEventsHookCalled)
    }

    func testHandleUserConsentStep_ChallengeWasApproved() {
        pushChallenge.userResponse = .userApproved
        let context = OktaTransaction.TransactionContext(challengeRequest: transaction.challengeRequestJWT) { step in
            XCTFail("Unexpected call")
        } appCompletionClosure: { (_, _, _) in
        }

        var triageRemediationEventsHookCalled = false
        transaction.triageRemediationEventsHook = { _, transactionContext in
            XCTAssertNotNil(transactionContext.enrollment)
            XCTAssertTrue(transactionContext.userConsentResponseValue == .approved)
            triageRemediationEventsHookCalled = true
        }

        context.enrollment = (pushChallenge.enrollment as! AuthenticatorEnrollment)
        transaction.handleUserConsentStep(transactionContext: context, appEventsQueue: [])
        XCTAssertTrue(triageRemediationEventsHookCalled)
    }

    func testhandleDeviceSignalsStep() {
        pushChallenge.userResponse = .userApproved
        let context = OktaTransaction.TransactionContext(challengeRequest: transaction.challengeRequestJWT) { step in
            XCTFail("Unexpected call")
        } appCompletionClosure: { (_, _, _) in
        }

        var triageRemediationEventsHookCalled = false
        transaction.triageRemediationEventsHook = { _, transactionContext in
            triageRemediationEventsHookCalled = true
        }

        context.enrollment = (pushChallenge.enrollment as! AuthenticatorEnrollment)
        transaction.handleDeviceSignalsStep(transactionContext: context, appEventsQueue: [])
        XCTAssertTrue(triageRemediationEventsHookCalled)
    }

    func testSignJWTAndSendRequest_UserVerificationKey_UserAccepted() {
        pushChallenge.userResponse = .userApproved
        let context = OktaTransaction.TransactionContext(challengeRequest: transaction.challengeRequestJWT) { step in
            XCTFail("Unexpected call")
        } appCompletionClosure: { (_, _, _) in
        }
        context.enrollment = (pushChallenge.enrollment as! AuthenticatorEnrollment)

        var tryReadSigningKeyHookCalled = false
        transaction.tryReadSigningKeyHook = { _, _, userVerificationType, _, _ in
            tryReadSigningKeyHookCalled = true
        }

        transaction.signJWTAndSendRequest(transactionContext: context, keysRequirements: [.userVerification])

        XCTAssertTrue(context.userConsentResponseValue == .approvedUserVerification)
        XCTAssertTrue(tryReadSigningKeyHookCalled)
    }

    func testSignJWTAndSendRequest_UserVerificationKey_UserDenied() {
        pushChallenge.userResponse = .userDenied
        let context = OktaTransaction.TransactionContext(challengeRequest: transaction.challengeRequestJWT) { step in
            XCTFail("Unexpected call")
        } appCompletionClosure: { (_, _, _) in
        }
        context.enrollment = (pushChallenge.enrollment as! AuthenticatorEnrollment)

        var tryReadSigningKeyHookCalled = false
        transaction.tryReadSigningKeyHook = { _, _, userVerificationType, _, _ in
            tryReadSigningKeyHookCalled = true
        }

        transaction.signJWTAndSendRequest(transactionContext: context, keysRequirements: [.userVerification])

        XCTAssertTrue(context.userConsentResponseValue == .denied)
        XCTAssertTrue(tryReadSigningKeyHookCalled)
    }

    func testSignJWTAndSendRequest_ProofOfPossessionKey() {
        let context = OktaTransaction.TransactionContext(challengeRequest: transaction.challengeRequestJWT) { step in
            if let consentScreen = step as? RemediationStepUserConsent {
                consentScreen.provide(.approved)
            } else {
                XCTFail("Unexpected event")
            }
        } appCompletionClosure: { (_, _, _) in
        }
        context.enrollment = (pushChallenge.enrollment as! AuthenticatorEnrollment)

        var tryReadSigningKeyHookCalled = false
        transaction.tryReadSigningKeyHook = { _, _, userVerificationType, _, _ in
            tryReadSigningKeyHookCalled = true
        }

        transaction.signJWTAndSendRequest(transactionContext: context, keysRequirements: [.proofOfPossession])

        XCTAssertTrue(context.userConsentResponseValue == .approved)
        XCTAssertTrue(context.keyRequirements?.contains(.proofOfPossession) ?? false)
        XCTAssertTrue(tryReadSigningKeyHookCalled)
    }

    func testSignJWTAndSendRequest_NoKeys() {
        var completionCalled = false
        let context = OktaTransaction.TransactionContext(challengeRequest: transaction.challengeRequestJWT) { step in
            XCTFail("Unexpected call")
        } appCompletionClosure: { (_, error, _) in
            XCTAssertNotNil(error)
            completionCalled = true
        }
        context.enrollment = (pushChallenge.enrollment as! AuthenticatorEnrollment)

        transaction.signJWTAndSendRequest(transactionContext: context, keysRequirements: [])

        XCTAssertTrue(completionCalled)
    }

    func testTryReadUserVerificationKey() throws {

        let _ = try? cryptoManager.generate(keyPairWith: .ES256,
                                            with: "userVerificationKeyTag",
                                            useSecureEnclave: false,
                                            useBiometrics: false,
                                            biometricSettings: nil)
        let transaction = try OktaTransactionPushChallengePartialMock(pushChallenge: pushChallenge,
                                                                      applicationConfig: applicationConfig,
                                                                      storageManager: storageMock,
                                                                      cryptoManager: cryptoManager,
                                                                      signalsManager: SignalsManager(logger: OktaLoggerMock()),
                                                                      restAPI: restAPIMock,
                                                                      logger: OktaLoggerMock())

        let completionExpectation = expectation(description: "Completion has been called!")

        let authContextMock = LAContextMock()
        authContextMock.passcode = true

        transaction.localAuthenticationContext = authContextMock
        transaction.tryReadUserVerificationKey(with: enrollment.pushFactor!.factorData.userVerificationKeyTag!, enrollment: enrollment, onIdentityStep: { identityStep in
            XCTFail("Unexpected closure call")
        }) { keyData, error in
            XCTAssertEqual(keyData?.keyTag, "userVerificationKeyTag")
            XCTAssertNotNil(keyData?.key)
            XCTAssertNil(error)
            completionExpectation.fulfill()
        }

        wait(for: [completionExpectation], timeout: 3.0)
    }
}

fileprivate class OktaTransactionPushChallengePartialMock: OktaTransactionPushChallenge {
    typealias tryReadSigningKeyType = (OktaBindJWT.KeyType, OktaBindJWT.MethodType, AuthenticatorEnrollment, (RemediationStep) -> Void, (KeyData?, DeviceAuthenticatorError?) -> Void) -> Void
    typealias signJWTAndSendRequestType = (OktaTransaction.TransactionContext, [OktaBindJWT.KeyType]) -> Void
    typealias triageRemediationEventsType = ([OktaTransaction.RemediationEvents], OktaTransaction.TransactionContext) -> Void

    var tryReadSigningKeyHook: tryReadSigningKeyType?
    var signJWTAndSendRequestHook: signJWTAndSendRequestType?
    var triageRemediationEventsHook: triageRemediationEventsType?

    override func signJWTAndSendRequest(transactionContext: OktaTransaction.TransactionContext, keysRequirements: [OktaBindJWT.KeyType]) {
        if let signJWTAndSendRequestHook = signJWTAndSendRequestHook {
            signJWTAndSendRequestHook(transactionContext, keysRequirements)
        } else {
            super.signJWTAndSendRequest(transactionContext: transactionContext,
                                        keysRequirements: keysRequirements)
        }
    }

    override func triageRemediationEvents(_ events: [OktaTransaction.RemediationEvents], transactionContext: OktaTransaction.TransactionContext) {
        if let triageRemediationEventsHook = triageRemediationEventsHook {
            triageRemediationEventsHook(events, transactionContext)
        } else {
            super.triageRemediationEvents(events, transactionContext: transactionContext)
        }
    }

    override func tryReadSigningKey(with keyType: OktaBindJWT.KeyType,
                                    methodType: OktaBindJWT.MethodType,
                                    enrollment: AuthenticatorEnrollment,
                                    userVerificationType: UserVerificationChallengeRequirement? = nil,
                                    onIdentityStep: @escaping (RemediationStep) -> Void,
                                    onCompletion: @escaping ((KeyData?, DeviceAuthenticatorError?) -> Void)) {
        if let tryReadSigningKeyHook = tryReadSigningKeyHook {
            tryReadSigningKeyHook(keyType, methodType, enrollment, onIdentityStep, onCompletion)
        } else {
            super.tryReadSigningKey(with: keyType, methodType: methodType, enrollment: enrollment, userVerificationType: userVerificationType, onIdentityStep: onIdentityStep, onCompletion: onCompletion)
        }
    }
}

class LAContextMock: LAContext {

    var biometry: LABiometryType = .none
    var passcode: Bool = false

    override var biometryType: LABiometryType {
        return biometry
    }

    override func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool {
        switch policy {
        case .deviceOwnerAuthenticationWithBiometrics:
            return passcode && biometry != .none
        case .deviceOwnerAuthentication:
            return passcode
        case .deviceOwnerAuthenticationWithWatch:
            return passcode
        case .deviceOwnerAuthenticationWithBiometricsOrWatch:
            return passcode
        @unknown default:
            return passcode
        }
    }
}
