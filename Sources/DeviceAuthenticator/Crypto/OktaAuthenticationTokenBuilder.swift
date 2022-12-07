/*
* Copyright (c) 2021, Okta, Inc. and/or its affiliates. All rights reserved.
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
import LocalAuthentication

class OktaAuthenticationTokenBuilder {
    private let cryptoManager: OktaSharedCryptoProtocol
    private let logger: OktaLoggerProtocol
    private let jwtGenerator: OktaJWTGenerator
    private let jwtType: String

    init(cryptoManager: OktaSharedCryptoProtocol,
         logger: OktaLoggerProtocol,
         jwtGenerator: OktaJWTGenerator? = nil,
         jwtType: String = "okta-enrollmentupdate+jwt") {
        self.cryptoManager = cryptoManager
        self.logger = logger
        self.jwtGenerator = jwtGenerator ?? OktaJWTGenerator(logger: logger)
        self.jwtType = jwtType
    }

    func buildAndSignBasedOnEnrollment(_ enrollment: AuthenticatorEnrollment) throws -> String {
        guard let keyTag = enrollment.enrolledFactors.first(where: { $0.proofOfPossessionKeyTag != nil })?.proofOfPossessionKeyTag else {
            let error = DeviceAuthenticatorError.internalError("Proof of possession key tag is not found")
            logger.error(eventName: "JWT generating error", message: "\(error)")
            throw error
        }

        return try generateJWT(keyTag: keyTag, enrollment: enrollment)
    }

    private func generateJWT(keyTag: String, enrollment: AuthenticatorEnrollment) throws -> String {
        guard let key = cryptoManager.get(keyOf: .privateKey,
                                          with: keyTag,
                                          context: LAContext()) else {
            let error = SecurityError.jwtError("Failed to read private key")
            logger.error(eventName: "JWT generating error", message: "\(error)")
            throw error
        }

        do {
            return try OktaAuthenticationJWTGenerator(enrollmentId: enrollment.enrollmentId,
                                                      orgHost: enrollment.organization.url.absoluteString,
                                                      userId: enrollment.user.id,
                                                      key: key,
                                                      kid: keyTag,
                                                      jwtType: jwtType,
                                                      cryptoManager: cryptoManager,
                                                      logger: logger,
                                                      jwtGenerator: jwtGenerator).generateJWTString()
        } catch {
            let error = error as? SecurityError ?? SecurityError.jwtError("Failed to sign jwt")
            logger.error(eventName: "JWT generating error", message: "\(error)")
            throw error
        }
    }
}
