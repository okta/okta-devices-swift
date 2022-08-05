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
import DeviceAuthenticator

typealias UserConsentHandler = ((RemediationStepUserConsent) -> Void)
typealias ChallengeResolvedHandler = (PushChallengeUserResponse) -> Void

protocol RemediationEventsHandlerProtocol {
    var onUserConsent: UserConsentHandler { get }
    var onChallengeResolved: ChallengeResolvedHandler { get }

    func handle(step: RemediationStep)
}

class RemediationEventsHandler: RemediationEventsHandlerProtocol {

    let onUserConsent: UserConsentHandler
    let onChallengeResolved: ChallengeResolvedHandler

    init(onUserConsent: @escaping UserConsentHandler, onChallengeResolved: @escaping ChallengeResolvedHandler) {
        self.onUserConsent = onUserConsent
        self.onChallengeResolved = onChallengeResolved
    }

    func handle(step: RemediationStep) {
        switch step {
        case let userConsentStep as RemediationStepUserConsent:
            // Show UX to allow the user to say "yes" or "no" to the sign-in attempt
            onUserConsent(userConsentStep)
        default:
            step.defaultProcess()
        }
    }
}
