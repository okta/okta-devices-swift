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
import OktaLogger

class OktaTransaction {

    enum RemediationEvents {
        case SelectAccount
        case UserConsent
        case DeviceSignals
    }

    class TransactionContext {
        let appIdentityStepClosure: (RemediationStep) -> Void
        let appCompletionClosure: (String?, DeviceAuthenticatorError?, AuthenticatorEnrollment?) -> Void
        let challengeRequest: OktaBindJWT
        var enrollment: AuthenticatorEnrollment!
        var userConsentResponseValue: OktaUserConsentValue = .approved
        var deviceSignals: DeviceSignals?
        var keyRequirements: [OktaBindJWT.KeyType]?
        var integrations: [_IntegrationData]?
        var signalProviders: [_IntegrationData]?

        init(challengeRequest: OktaBindJWT,
             appIdentityStepClosure: @escaping (RemediationStep) -> Void,
             appCompletionClosure: @escaping (String?, DeviceAuthenticatorError?, AuthenticatorEnrollment?) -> Void) {
            self.appIdentityStepClosure = appIdentityStepClosure
            self.appCompletionClosure = appCompletionClosure
            self.challengeRequest = challengeRequest
        }
    }

    let loginHint: String?
    let storageManager: PersistentStorageProtocol
    let cryptoManager: OktaSharedCryptoProtocol
    let jwtGenerator: OktaJWTGenerator
    let logger: OktaLoggerProtocol

    init(loginHint: String?,
         storageManager: PersistentStorageProtocol,
         cryptoManager: OktaSharedCryptoProtocol,
         jwtGenerator: OktaJWTGenerator?,
         logger: OktaLoggerProtocol) {
        self.loginHint = loginHint
        self.storageManager = storageManager
        self.cryptoManager = cryptoManager
        self.jwtGenerator = jwtGenerator ?? OktaJWTGenerator(logger: logger)

        self.logger = logger
    }

    func generateAuthenticationJWTString(for enrollment: AuthenticatorEnrollment,
                                         onCompletion: @escaping (String?, DeviceAuthenticatorError?) -> Void) {
        // If no Oauth token provided try to authenticate with jwt signed by:
        // 1. User verification key, if not available:
        // 2. Proof of possession key
        // 3. If both are not available respond with error, so application can fallback to OIDC flow
        guard var keyTagToUse = findPoPKeyTagFromEnrolledFactors(enrollment: enrollment) else {
            let error = DeviceAuthenticatorError.internalError("Proof of possession key tag is not found")
            logger.error(eventName: "JWT generating error", message: "\(error)")
            onCompletion(nil, error)
            return
        }

        if let userVerificationKeyTag = findUVKeyTagFromEnrolledFactors(enrollment: enrollment) {
            keyTagToUse = userVerificationKeyTag
        }

        guard let key = cryptoManager.get(keyOf: .privateKey, with: keyTagToUse, context: LAContext()) else {
            let error = SecurityError.jwtError("Failed to read private key")
            logger.error(eventName: "JWT generating error", message: "\(error)")
            onCompletion(nil, DeviceAuthenticatorError.securityError(error))
            return
        }

        DispatchQueue.global().async {
            let updateJWTType = "okta-enrollmentupdate+jwt"
            do {
                let jwtString = try OktaAuthenticationJWTGenerator(enrollmentId: enrollment.enrollmentId,
                                                                   orgHost: enrollment.orgHost.absoluteString,
                                                                   userId: enrollment.userId,
                                                                   key: key,
                                                                   kid: keyTagToUse,
                                                                   jwtType: updateJWTType,
                                                                   cryptoManager: self.cryptoManager,
                                                                   logger: self.logger,
                                                                   jwtGenerator: self.jwtGenerator).generateJWTString()
                onCompletion(jwtString, nil)
            } catch {
                self.logger.error(eventName: "JWT generating error", message: "\(error)")
                let error = error as? SecurityError ?? SecurityError.jwtError("Failed to sign jwt")
                onCompletion(nil, DeviceAuthenticatorError.securityError(error))
            }
        }
    }

    func findPoPKeyTagFromEnrolledFactors(enrollment: AuthenticatorEnrollment) -> String? {
        let pushFactor = enrollment.enrolledFactors.first(where: { $0 is OktaFactorPush }) as? OktaFactorPush
        return pushFactor?.proofOfPossessionKeyTag
    }

    func findUVKeyTagFromEnrolledFactors(enrollment: AuthenticatorEnrollment) -> String? {
        let pushFactor = enrollment.enrolledFactors.first(where: { $0 is OktaFactorPush }) as? OktaFactorPush
        return pushFactor?.userVerificationKeyTag
    }
}
