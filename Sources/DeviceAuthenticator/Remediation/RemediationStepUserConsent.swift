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

///  Record of the user's response that will be passed to Okta's service
public enum UserConsentResponse: Int {
    ///  The user explicitly approved the authentication request
    case approved
    ///  The user explicitly denied the authentication request
    case denied
    ///  The user did not respond or was not shown a request
    case none
}

///  Step during verify flow to provide user's explicit consent to authenticate
public class RemediationStepUserConsent: RemediationStep {
    /// Reference to challenge that is being processed. Downcast to concrete Challenge implementation if you want to retrieve more information
    public let challenge: ChallengeProtocol
    /// Reference to enrollment for which user consent screen is required
    public let enrollment: AuthenticatorEnrollmentProtocol

    /// Complete the user consent step by providing a response
    /// - Parameters:
    ///   - response: User's consent response (e.g. approved/denied)
    public func provide(_ response: UserConsentResponse) {
        logger.info(eventName: "UserConsentEvent", message: "Provide method is called")
        completionClosure(response)
    }

    init(challenge: ChallengeProtocol,
         enrollment: AuthenticatorEnrollmentProtocol,
         logger: OktaLoggerProtocol,
         defaultProcessClosure: @escaping () -> Void,
         completionClosure: @escaping (UserConsentResponse) -> Void) {
        self.challenge = challenge
        self.enrollment = enrollment
        self.completionClosure = completionClosure
        super.init(logger: logger, defaultProcessClosure: defaultProcessClosure)
    }

    let completionClosure: (UserConsentResponse) -> Void
}

