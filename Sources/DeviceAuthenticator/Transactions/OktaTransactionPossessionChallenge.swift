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

import Foundation
import LocalAuthentication
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif

class OktaTransactionPossessionChallengeBase: OktaTransaction {
    enum AuthenticationMethodReference: String {
        case fingerPrint = "fpt"
        case faceId = "face"
        case pin = "pin"
        case none = "none"

        static func create(_ laContext: LAContext = LAContext()) -> AuthenticationMethodReference {
            let result = laContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
            if result {
                switch laContext.biometryType {
                case .faceID:
                    return .faceId
                case .touchID:
                    return .fingerPrint
                default:
                    return .pin
                }
            } else {
                return none
            }
        }
    }

    struct KeyData {
        let keyTag: String
        let key: SecKey
        let amr: [AuthenticationMethodReference]
        let keyType: OktaBindJWT.KeyType
    }

    let applicationConfig: ApplicationConfig
    let challengeRequest: String
    let httpHeaders: [ String: String]?
    var challengeRequestJWT: OktaBindJWT!
    let stateHandle: String?
    var localAuthenticationContext = LAContext()
    let signalsManager: SignalsManager
    let restAPI: ServerAPIProtocol

    init(applicationConfig: ApplicationConfig,
         challengeRequest: String,
         stateHandle: String?,
         httpHeaders: [String: String]? = nil,
         loginHint: String?,
         storageManager: PersistentStorageProtocol,
         cryptoManager: OktaSharedCryptoProtocol,
         signalsManager: SignalsManager,
         restAPI: ServerAPIProtocol,
         logger: OktaLoggerProtocol) throws {
        self.applicationConfig = applicationConfig
        self.challengeRequest = challengeRequest
        self.httpHeaders = httpHeaders
        self.stateHandle = stateHandle
        self.signalsManager = signalsManager
        self.restAPI = restAPI
        super.init(loginHint: loginHint, storageManager: storageManager, cryptoManager: cryptoManager, jwtGenerator: nil, logger: logger)
        let deviceBindJWT = try parseJWT(string: challengeRequest)
        challengeRequestJWT = deviceBindJWT
    }

    func handle(onIdentityStep: @escaping (RemediationStep) -> Void,
                onCompletion: @escaping ((String?, DeviceAuthenticatorError?, AuthenticatorEnrollment?) -> Void)) {
        let transactionContext = TransactionContext(challengeRequest: challengeRequestJWT,
                                                    appIdentityStepClosure: onIdentityStep,
                                                    appCompletionClosure: onCompletion)

        // Skip UserConsent event for initial handling. UserConsent even can be added later during key requirements evaluation
        let appEvents = [RemediationEvents.SelectAccount,
                         RemediationEvents.DeviceSignals]
        triageRemediationEvents(appEvents, transactionContext: transactionContext)
    }

    // MARK: Step Handlers

    /// Find enrolled authenticator(s) based on orgId claim
    /// Request user to select an account if multiple accounts exist
    func handleSelectAccountStep(transactionContext: TransactionContext,
                                 appEventsQueue: [RemediationEvents]) {
        assert(false, "Override")
    }

    /// Ask for user's explicit consent to authenticate with a given account
    func handleUserConsentStep(transactionContext: TransactionContext,
                               appEventsQueue: [RemediationEvents]) {
        assert(false, "Override")
    }

    /// Ask application for Device Signals
    func handleDeviceSignalsStep(transactionContext: TransactionContext,
                                 appEventsQueue: [RemediationEvents]) {
        assert(false, "Override")
    }

    /// Post information messages to application layer
    func postMessageToApplication(message: String,
                                  reason: RemediationStepMessageReasonType,
                                  error: DeviceAuthenticatorError,
                                  transactionContext: TransactionContext) {
        assert(false, "Override")
    }

    /// Try to read UV key. Ask for UV prompt customization settings via `onIdentityStep` closure
    func tryReadUserVerificationKey(with keyTag: String,
                                    userVerificationType: UserVerificationChallengeRequirement? = nil,
                                    enrollment: AuthenticatorEnrollment,
                                    onIdentityStep: @escaping (RemediationStep) -> Void,
                                    onCompletion: @escaping ((KeyData?, DeviceAuthenticatorError?) -> Void)) {
        assert(false, "Override")
    }

    func triageRemediationEvents(_ events: [RemediationEvents],
                                 transactionContext: TransactionContext) {
        var eventsCopy = events
        if let event = events.first {
            eventsCopy.removeFirst()
            switch event {
            case .SelectAccount:
                // Find account and ask application to select proper account in case if multiple accounts found
                handleSelectAccountStep(transactionContext: transactionContext, appEventsQueue: eventsCopy)
            case .UserConsent:
                // Ask application to present user consent screen
                handleUserConsentStep(transactionContext: transactionContext, appEventsQueue: eventsCopy)
            case .DeviceSignals:
                // Ask application to provide device signals
                handleDeviceSignalsStep(transactionContext: transactionContext, appEventsQueue: eventsCopy)
           }
        } else {
            handleEvaluatePolicy(transactionContext: transactionContext)
        }
    }

    /// Final Step - Evaluate key requirements and complete the transaction
    func handleEvaluatePolicy(transactionContext: TransactionContext) {
        // Collect external integration signals
        transactionContext.integrations = challengeRequestJWT.integrationNames.map({
            self.signalsManager.collectSignals(with: $0)
        })

        // Collect app-provided custom signals
        transactionContext.signalProviders = challengeRequestJWT.signalProviderNames.map({
            self.signalsManager.collectSignals(with: $0)
        })

        let challenge = transactionContext.challengeRequest
        var keyTypes: [OktaBindJWT.KeyType]
        if let keyRequirements = transactionContext.keyRequirements {
            keyTypes = keyRequirements
        } else if let userVerification = challenge.userVerification {
            switch userVerification {
            case .none, .discouraged, .unknown:
                keyTypes = [.proofOfPossession]
            case .preferred:
                keyTypes = [.userVerification, .proofOfPossession]
            case .required:
                // Add PoP key as a fallback key
                keyTypes = [.userVerification, .proofOfPossession]
            }
        } else {
            // Add PoP key as a fallback key
            keyTypes = [.proofOfPossession]
        }
        self.signJWTAndSendRequest(transactionContext: transactionContext,
                                   keysRequirements: keyTypes)
    }

    func parseJWT(string: String) throws -> OktaBindJWT {
        return try OktaBindJWT(string: string,
                               applicationGroupId: applicationConfig.applicationInfo.applicationGroupId,
                               logger: logger)
    }

    func signJWTAndSendRequest(transactionContext: TransactionContext,
                               keysRequirements: [OktaBindJWT.KeyType]) {
        guard let keyType = keysRequirements.first else {
            let error = DeviceAuthenticatorError.internalError("No key types provided")
            logger.error(eventName: self.logEventName, message: "Error: \(error)")
            transactionContext.appCompletionClosure(nil, error, transactionContext.enrollment)
            return
        }

        if keyType == .userVerification {
            transactionContext.userConsentResponseValue = .approvedUserVerification
        }

        if keyType == .proofOfPossession && transactionContext.keyRequirements == nil {
            let triageUserConsentRemediation = {
                transactionContext.keyRequirements = [.proofOfPossession]
                self.triageRemediationEvents([.UserConsent], transactionContext: transactionContext)
            }

            guard let userMediation = transactionContext.challengeRequest.userMediation else {
                // Server does not support 'userMediation'
                // Server requires PoP key only, so ask application to present user consent screen
                triageUserConsentRemediation()
                return
            }

            switch userMediation {
            case .none, .unknown:
                transactionContext.userConsentResponseValue = .none
            case .optional, .required:
                triageUserConsentRemediation()
                return
            }
        }

        let userVerificationType = transactionContext.challengeRequest.userVerification
        readSigningKey(with: keyType,
                       transactionContext: transactionContext,
                       keysRequirements: keysRequirements,
                       userVerificationType: userVerificationType)
    }

    func readSigningKey(with keyType: OktaBindJWT.KeyType,
                        transactionContext: TransactionContext,
                        keysRequirements: [OktaBindJWT.KeyType],
                        userVerificationType: UserVerificationChallengeRequirement? = nil) {
        self.tryReadSigningKey(with: keyType,
                               methodType: transactionContext.challengeRequest.methodType,
                               enrollment: transactionContext.enrollment,
                               userVerificationType: userVerificationType,
                               onIdentityStep: transactionContext.appIdentityStepClosure) { keyData, error in

            if let error = error {
                self.logger.error(eventName: self.logEventName, message: "Error: \(error)")
                self.readSigningKeyErrorHandler(error: error,
                                                transactionContext: transactionContext,
                                                keysRequirements: keysRequirements)
                return
            }
            guard let keyData = keyData else {
                let error = DeviceAuthenticatorError.internalError("Can't find encryption keys")
                self.logger.error(eventName: self.logEventName, message: "Error: \(error)")
                self.readSigningKeyErrorHandler(error: error,
                                                transactionContext: transactionContext,
                                                keysRequirements: keysRequirements)
                return
            }
            DispatchQueue.global().async {
                do {
                    let responseJWT = try self.deviceChallengeResponseJWT(with: transactionContext.challengeRequest,
                                                                          jwsKey: keyData.key,
                                                                          jwsKeyTag: keyData.keyTag,
                                                                          keyType: keyData.keyType,
                                                                          authenticatorEnrollment: transactionContext.enrollment,
                                                                          customSignals: transactionContext.deviceSignals,
                                                                          consent: transactionContext.userConsentResponseValue,
                                                                          integrations: transactionContext.integrations,
                                                                          signalProviders: transactionContext.signalProviders,
                                                                          amr: keyData.amr)
                    transactionContext.appCompletionClosure(responseJWT, nil, transactionContext.enrollment)
                } catch {
                    let error = DeviceAuthenticatorError.oktaError(from: error)
                    self.logger.error(eventName: self.logEventName, message: "Error: \(error)")
                    self.readSigningKeyErrorHandler(error: error,
                                                    transactionContext: transactionContext,
                                                    keysRequirements: keysRequirements)
                }
            }
        }
    }

    func readSigningKeyErrorHandler(error: DeviceAuthenticatorError,
                                    transactionContext: TransactionContext,
                                    keysRequirements: [OktaBindJWT.KeyType]) {
        if keysRequirements.count > 1 {
            // Fallback to next key in the array of key types
            var keyTypes = keysRequirements
            let skippedKey = keyTypes.removeFirst()
            let nextKey = keyTypes[0]

            var messageReason: RemediationStepMessageReasonType = .userVerificationKeyNotEnrolled
            if case .securityError(let encErr) = error {
                if case .keyCorrupted(_) = encErr {
                    messageReason = .userVerificationKeyCorruptedOrMissing
                } else if case .localAuthenticationCancelled(_) = encErr {
                    messageReason = .userVerificationCancelledByUser
                } else if case .localAuthenticationFailed(_) = encErr {
                    messageReason = .userVerificationFailed
                }
            }
            // Surface the error via the non-blocking 'message' identity step
            self.postMessageToApplication(message: "Failed to sign with key \(skippedKey), falling back to \(nextKey)",
                                          reason: messageReason,
                                          error: error,
                                          transactionContext: transactionContext)

            // Update consent value for cases where appropriate for error
            if skippedKey == .userVerification {
                if messageReason == .userVerificationCancelledByUser {
                    transactionContext.userConsentResponseValue = .cancelledUserVerification
                    // User cancelled biometric prompt and SDK fallbacks to PoP key. Set keyRequirements in transactionContext to avoid sending of unnecessary user consent screen event
                    transactionContext.keyRequirements = [nextKey]
                } else if messageReason == .userVerificationFailed {
                    transactionContext.userConsentResponseValue = .userVerificationTemporarilyUnavailable
                    // Local authentication failed and SDK falls back to PoP key. Set keyRequirements in transactionContext to avoid sending of unnecessary user consent screen event
                    transactionContext.keyRequirements = [nextKey]
                } else if messageReason == .userVerificationKeyCorruptedOrMissing {
                    transactionContext.userConsentResponseValue = .userVerificationPermanentlyUnavailable
                    // Local authentication failed and SDK falls back to PoP key. Set keyRequirements in transactionContext to avoid sending of unnecessary user consent screen event
                    transactionContext.keyRequirements = [nextKey]
                } else {
                    if transactionContext.challengeRequest.userVerification == .required {
                        transactionContext.userConsentResponseValue = .userVerificationPermanentlyUnavailable
                        transactionContext.keyRequirements = [nextKey]
                    } else {
                        transactionContext.userConsentResponseValue = transactionContext.userConsentResponseValue.userVerificationFailed()
                    }
                }
            }
            self.signJWTAndSendRequest(transactionContext: transactionContext,
                                       keysRequirements: keyTypes)
        } else {
            transactionContext.appCompletionClosure(nil, error, transactionContext.enrollment)
        }
    }

    func tryReadSigningKey(with keyType: OktaBindJWT.KeyType,
                           methodType: OktaBindJWT.MethodType,
                           enrollment: AuthenticatorEnrollment,
                           userVerificationType: UserVerificationChallengeRequirement? = nil,
                           onIdentityStep: @escaping (RemediationStep) -> Void,
                           onCompletion: @escaping ((KeyData?, DeviceAuthenticatorError?) -> Void)) {
        switch keyType {
        case .proofOfPossession:
            guard let proofOfPossessionKeyTag = getProofOfPossessionKeyTag(methodType: methodType, enrollment: enrollment) else {
                let error = DeviceAuthenticatorError.genericError("Can't find enrolled proof of possession key in enrollment object")
                logger.error(eventName: self.logEventName, message: "Verification flow failed with error: \(error)")
                onCompletion(nil, error)
                return
            }
            tryReadProofOfPossessionKey(with: proofOfPossessionKeyTag, onCompletion: onCompletion)
            return
        case .userVerification:
            guard let userVerificationKeyTag = getUserVerificationKeyTag(methodType: methodType, enrollment: enrollment) else {
                let error = DeviceAuthenticatorError.genericError("Can't find enrolled user verification key in enrollment object")
                logger.error(eventName: self.logEventName, message: "Verification flow failed with error: \(error)")
                onCompletion(nil, error)
                return
            }
            tryReadUserVerificationKey(with: userVerificationKeyTag,
                                       userVerificationType: userVerificationType,
                                       enrollment: enrollment,
                                       onIdentityStep: onIdentityStep,
                                       onCompletion: onCompletion)
            return
        default:
            let error = DeviceAuthenticatorError.internalError("Unknown key type provided by the server")
            logger.error(eventName: self.logEventName, message: "Verification flow failed with error: \(error)")
            onCompletion(nil, error)
        }
    }

    func getProofOfPossessionKeyTag(methodType: OktaBindJWT.MethodType, enrollment: AuthenticatorEnrollment) -> String? {
        assert(false, "Override")
        return nil
    }

    func getUserVerificationKeyTag(methodType: OktaBindJWT.MethodType, enrollment: AuthenticatorEnrollment) -> String? {
        assert(false, "Override")
        return nil
    }

    func tryReadProofOfPossessionKey(with keyTag: String,
                                     onCompletion: @escaping ((KeyData?, DeviceAuthenticatorError?) -> Void)) {
        guard let jwsKey = self.cryptoManager.get(keyOf: .privateKey, with: keyTag, context: LAContext()) else {
            let error = DeviceAuthenticatorError.genericError("Can't find crypto factor silent key in secure storage")
            logger.error(eventName: self.logEventName, message: "Verification flow failed with error: \(error)")
            onCompletion(nil, error)
            return
        }

        onCompletion(KeyData(keyTag: keyTag, key: jwsKey, amr: [], keyType: .proofOfPossession), nil)
    }

    func verify(onIdentityStep: @escaping (RemediationStep) -> Void,
                onCompletion: @escaping ((HTTPURLResult?, DeviceAuthenticatorError?, AuthenticatorEnrollment?) -> Void)) {
        self.handle(onIdentityStep: onIdentityStep) { responseJWT, error, enrollment in
            self.logger.info(eventName: "Verify challenge transaction", message: "Handling verify challenge transaction")
            guard let responseJWT = responseJWT,
                  !responseJWT.isEmpty else {
                if let error = error {
                    self.logger.error(eventName: "Verify challenge transaction", message: "Handle challenge transaction finished with error: \(error)")
                    onCompletion(nil, error, enrollment)
                } else {
                    let error = DeviceAuthenticatorError.internalError("Internal SDK error")
                    self.logger.error(eventName: "Verify challenge transaction", message: "Handle challenge transaction finished with error: \(error)")
                    onCompletion(nil, error, enrollment)
                }
                return
            }

            var verifyURL = self.challengeRequestJWT.verificationURL
            var postData: Data?
            if let stateHandle = self.stateHandle {
                guard var components = URLComponents(string: verifyURL.absoluteString) else {
                    let error = SecurityError.jwtError("Invalid verification URL in JWT payload")
                    self.logger.error(eventName: "Verify challenge transaction", message: "Handle challenge transaction finished with error: \(error)")
                    onCompletion(nil, DeviceAuthenticatorError.securityError(error), enrollment)
                    return
                }
                components.queryItems = [URLQueryItem(name: "challengeResponse", value: responseJWT)]
                components.queryItems?.append(URLQueryItem(name: "stateHandle", value: stateHandle))
                guard let verifyURLWithQueryParams = components.url else {
                    let error = SecurityError.jwtError("Invalid verification URL in JWT payload")
                    self.logger.error(eventName: "Verify challenge transaction", message: "Handle challenge transaction finished with error: \(error)")
                    onCompletion(nil, DeviceAuthenticatorError.securityError(error), enrollment)
                    return
                }
                verifyURL = verifyURLWithQueryParams
            } else {
                let encoder = JSONEncoder()
                let responseDictionary = ["method": self.challengeRequestJWT?.methodType.rawValue,
                                          "challengeResponse": responseJWT]
                postData = try? encoder.encode(responseDictionary)
            }

            self.restAPI.verifyDeviceChallenge(verifyURL: verifyURL,
                                               httpHeaders: self.httpHeaders,
                                               data: postData) { result, error in
                onCompletion(result, error, enrollment)
                if let data = result?.data,
                   let jsonString = String(data: data, encoding: .utf8) {
                    self.logger.info(eventName: "Verify challenge transaction", message: "Verify challenge response - \(jsonString)")
                }
            }
        }
    }

    func getFactorIdFromEnrollment(_ enrollment: AuthenticatorEnrollment) -> String? {
        assert(false, "Override")
        return nil
    }

    private func deviceChallengeResponseJWT(with deviceBindJWT: OktaBindJWT,
                                            jwsKey: SecKey,
                                            jwsKeyTag: String,
                                            keyType: OktaBindJWT.KeyType,
                                            authenticatorEnrollment: AuthenticatorEnrollment,
                                            customSignals: DeviceSignals?,
                                            consent: OktaUserConsentValue,
                                            integrations: [_IntegrationData]?,
                                            signalProviders: [_IntegrationData]?,
                                            amr: [AuthenticationMethodReference]) throws -> String {
        let deviceEnrollment = try self.storageManager.deviceEnrollmentByOrgId(deviceBindJWT.orgId)
        let deviceModelBuilder = OktaDeviceModelBuilder(orgHost: deviceBindJWT.iss,
                                                        applicationConfig: applicationConfig,
                                                        requestedSignals: deviceBindJWT.signals,
                                                        customSignals: customSignals,
                                                        cryptoManager: cryptoManager,
                                                        logger: logger)
        let deviceModel = deviceModelBuilder.buildForVerifyTransaction(deviceEnrollmentId: deviceEnrollment.id,
                                                                       clientInstanceKey: deviceEnrollment.clientInstanceId)
        let factorId = getFactorIdFromEnrollment(authenticatorEnrollment)
        let context = challengeContext(consent: consent, deviceBindJWT: deviceBindJWT)
        let convertedAmr = amr.map { $0.rawValue }
        let jwtResponse = try deviceBindJWT.generateDeviceChallengeResponseJWT(key: jwsKey,
                                                                               enrollmentId: authenticatorEnrollment.enrollmentId,
                                                                               sub: authenticatorEnrollment.userId,
                                                                               methodEnrollmentId: factorId ?? "",
                                                                               kid: jwsKeyTag,
                                                                               signals: deviceModel,
                                                                               context: context,
                                                                               integrations: integrations,
                                                                               signalProviders: signalProviders,
                                                                               keyType: keyType,
                                                                               amr: convertedAmr)

        return jwtResponse
    }

    private func challengeContext(consent: OktaUserConsentValue, deviceBindJWT: OktaBindJWT) -> [String: String] {
        let transactionTypeKey = "transactionType"
        var context: [String: String] = [
            "userConsent": consent.rawValue
        ]
        if let httpHeaders = self.httpHeaders,
           let value = httpHeaders["Origin"] {
            context["originHeader"] = value
        }

        // Replay transactionType sent from push challenge
        if let challengeContext = deviceBindJWT.jwt.payload["challengeContext"] as? [AnyHashable: Any],
           let rawTransactionType = challengeContext[transactionTypeKey] as? String,
           let transactionType = MethodSettingsModel.TransactionType(rawValue: rawTransactionType) {
            context[transactionTypeKey] = transactionType.rawValue
        } else {
            context[transactionTypeKey] = MethodSettingsModel.TransactionType.LOGIN.rawValue
        }
        return context
    }

    let logEventName = "TransactionPossessionChallenge"
}
