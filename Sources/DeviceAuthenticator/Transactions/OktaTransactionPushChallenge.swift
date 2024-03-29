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

import Foundation
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif

class OktaTransactionPushChallenge: OktaTransactionPossessionChallengeBase {

    let pushChallenge: PushChallenge

    init(pushChallenge: PushChallenge,
         applicationConfig: ApplicationConfig,
         storageManager: PersistentStorageProtocol,
         cryptoManager: OktaSharedCryptoProtocol,
         signalsManager: SignalsManager,
         restAPI: ServerAPIProtocol,
         logger: OktaLoggerProtocol) throws {
        self.pushChallenge = pushChallenge
        try super.init(applicationConfig: applicationConfig,
                       challengeRequest: pushChallenge.pushBindJWT.rawChallenge,
                       stateHandle: nil,
                       httpHeaders: nil,
                       loginHint: nil,
                       storageManager: storageManager,
                       cryptoManager: cryptoManager,
                       signalsManager: signalsManager,
                       restAPI: restAPI,
                       logger: logger)
    }

    override func signJWTAndSendRequest(transactionContext: TransactionContext,
                                        keysRequirements: [OktaBindJWT.KeyType]) {
        guard var keyType = keysRequirements.first else {
            let error = DeviceAuthenticatorError.internalError("No key types provided")
            logger.error(eventName: self.logEventName, message: "Error: \(error)")
            let failureInfo = TransactionResult.FailureInfo(challengeRequestJWT: challengeRequestJWT,
                                                            enrollment: transactionContext.enrollment,
                                                            userConsentResponse: nil,
                                                            error: error)
            transactionContext.appCompletionClosure(.failure(failureInfo))
            return
        }

        guard pushChallenge.userResponse != .userNotResponded else {
            triageRemediationEvents([.UserConsent], transactionContext: transactionContext)
            return
        }

        var keysRequirements = keysRequirements
        if pushChallenge.userResponse != .userApproved {
            transactionContext.userConsentResponseValue = .denied
        }
        if (keyType == .userVerification || keyType == .userVerificationBioOrPin) && pushChallenge.userResponse == .userApproved {
            transactionContext.userConsentResponseValue = .approvedUserVerification
        } else {
            // Use PoP key for the deny case
            keyType = .proofOfPossession
            keysRequirements = [.proofOfPossession]
        }

        if keyType == .proofOfPossession && transactionContext.keyRequirements == nil {
            transactionContext.keyRequirements = [.proofOfPossession]
        }

        let userVerificationType = transactionContext.challengeRequest.userVerification
        readSigningKey(with: keyType,
                       transactionContext: transactionContext,
                       keysRequirements: keysRequirements,
                       userVerificationType: userVerificationType)
    }

    // MARK: Step Handlers

    /// Find enrolled authenticator(s) based on orgId claim
    /// Request user to select an account if multiple accounts exist
    override func handleSelectAccountStep(transactionContext: TransactionContext,
                                          appEventsQueue: [RemediationEvents]) {
        guard let enrollment = pushChallenge.enrollment as? AuthenticatorEnrollment else {
            let error = DeviceAuthenticatorError.internalError("Invalid enrollment object")
            logger.error(eventName: "Push transaction failed", message: error.errorDescription)
            let failureInfo = TransactionResult.FailureInfo(challengeRequestJWT: challengeRequestJWT,
                                                            enrollment: nil,
                                                            userConsentResponse: nil,
                                                            error: error)
            transactionContext.appCompletionClosure(.failure(failureInfo))
            return
        }

        do {
            var issuer = enrollment.orgHost.absoluteString
            if let authorizationServerId = challengeRequestJWT.authorizationServerId {
                issuer = enrollment.orgHost.absoluteString + "/oauth2/" + authorizationServerId
            }
            try challengeRequestJWT.validate(with: issuer)
        } catch {
            let deviceAuthenticatorError = DeviceAuthenticatorError.oktaError(from: error)
            let failureInfo = TransactionResult.FailureInfo(challengeRequestJWT: challengeRequestJWT,
                                                            enrollment: nil,
                                                            userConsentResponse: nil,
                                                            error: deviceAuthenticatorError)
            transactionContext.appCompletionClosure(.failure(failureInfo))
            return
        }

        transactionContext.enrollment = enrollment
        self.triageRemediationEvents(appEventsQueue, transactionContext: transactionContext)
    }

    /// Ask for user's explicit consent to authenticate with a given account
    override func handleUserConsentStep(transactionContext: TransactionContext,
                                        appEventsQueue: [RemediationEvents]) {
        if pushChallenge.userResponse == .userNotResponded {
            ///  Helper function to complete the user consent step given a response
            func completeStep(with response: UserConsentResponse) {
                pushChallenge.userResponse = response == .approved ? .userApproved : .userDenied
                let consent = OktaUserConsentValue.create(response)
                transactionContext.userConsentResponseValue = consent
                self.triageRemediationEvents(appEventsQueue, transactionContext: transactionContext)
            }

            let doNotProcessClosure = {
                completeStep(with: .none)
            }
            let abstractPushChallenge = pushChallenge.transactionType == .ciba ? pushChallenge as CIBAChallengeProtocol : pushChallenge as PushChallengeProtocol
            let consentStep = RemediationStepUserConsent(challenge: abstractPushChallenge,
                                                         enrollment: transactionContext.enrollment,
                                                         logger: logger,
                                                                  defaultProcessClosure: doNotProcessClosure) { response in
                completeStep(with: response)
            }
            transactionContext.appIdentityStepClosure(consentStep)
        } else {
            transactionContext.userConsentResponseValue = pushChallenge.userResponse == .userApproved ? .approved : .denied
            self.triageRemediationEvents(appEventsQueue, transactionContext: transactionContext)
        }
    }

    /// Ask application for Device Signals
    override func handleDeviceSignalsStep(transactionContext: TransactionContext,
                                          appEventsQueue: [RemediationEvents]) {
        self.triageRemediationEvents(appEventsQueue, transactionContext: transactionContext)
    }

    override func parseJWT(string: String) throws -> OktaBindJWT {
        return pushChallenge.pushBindJWT
    }

    override func tryReadUserVerificationKey(with keyTag: String,
                                             keyType: OktaBindJWT.KeyType,
                                             userVerificationType: UserVerificationChallengeRequirement? = nil,
                                             enrollment: AuthenticatorEnrollment,
                                             onIdentityStep: @escaping (RemediationStep) -> Void,
                                             onCompletion: @escaping ((KeyData?, DeviceAuthenticatorError?) -> Void)) {
        guard keyType == .userVerification || keyType == .userVerificationBioOrPin else {
            let error = DeviceAuthenticatorError.genericError("User verification keyType (\(keyType)) mismatch")
            self.logger.error(eventName: self.logEventName, message: "Verification flow failed with error: \(error)")
            onCompletion(nil, error)
            return
        }

        let amr = OktaTransactionPossessionChallengeBase.AuthenticationMethodReference.create()
        guard let jwsKey = self.cryptoManager.get(keyOf: .privateKey, with: keyTag, context: self.localAuthenticationContext) else {
            let error = DeviceAuthenticatorError.genericError("Can't find crypto factor silent key in secure storage")
            self.logger.error(eventName: self.logEventName, message: "Verification flow failed with error: \(error)")
            onCompletion(nil, error)
            return
        }

        onCompletion(KeyData(keyTag: keyTag,
                             key: jwsKey,
                             amr: [amr],
                             keyType: keyType),
                     nil)
    }

    override func postMessageToApplication(message: String,
                                           reason: RemediationStepMessageReasonType,
                                           error: DeviceAuthenticatorError,
                                           transactionContext: TransactionContext) {
        // Surface the error via the non-blocking 'message' identity step
        let messageStep = RemediationStepMessage(type: .nonFatalError,
                                                 reasonType: reason,
                                                 message: message,
                                                 challenge: pushChallenge,
                                                 error: error,
                                                 logger: self.logger)
        transactionContext.appIdentityStepClosure(messageStep)
    }

    override func getProofOfPossessionKeyTag(methodType: OktaBindJWT.MethodType, enrollment: AuthenticatorEnrollment) -> String? {
        guard methodType == .push else {
            logger.error(eventName: self.logEventName, message: "Unexpected factor - \(methodType.rawValue)")
            return nil
        }

        if let pushFactor = enrollment.pushFactor {
            return pushFactor.factorData.proofOfPossessionKeyTag
        } else {
            logger.error(eventName: self.logEventName, message: "Can't find push factor in enrollment object")
            return nil
        }
    }

    override func getUserVerificationKeyTag(methodType: OktaBindJWT.MethodType, enrollment: AuthenticatorEnrollment) -> String? {
        guard methodType == .push else {
            logger.error(eventName: self.logEventName, message: "Unexpected factor - \(methodType.rawValue)")
            return nil
        }

        if let pushFactor = enrollment.pushFactor {
            return pushFactor.factorData.userVerificationKeyTag
        } else {
            logger.error(eventName: self.logEventName, message: "Can't find push factor in enrollment object")
            return nil
        }
    }

    override func getUserVerificationBioOrPinKeyTag(methodType: OktaBindJWT.MethodType, enrollment: AuthenticatorEnrollment) -> String? {
        guard methodType == .push else {
            logger.error(eventName: self.logEventName, message: "Unexpected factor - \(methodType.rawValue)")
            return nil
        }

        if let pushFactor = enrollment.pushFactor {
            return pushFactor.factorData.userVerificationBioOrPinKeyTag
        } else {
            logger.error(eventName: self.logEventName, message: "Can't find push factor in enrollment object")
            return nil
        }
    }

    override func getFactorIdFromEnrollment(_ enrollment: AuthenticatorEnrollment) -> String? {
        return enrollment.pushFactor?.factorData.id
    }
}
