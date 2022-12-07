/*
* Copyright (c) 2020-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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

///  Type of message surfaced by the SDK to step handler
public enum RemediationStepMessageType: Int {
    /// Informational message, to be used for analytics, etc.
    case information

    /// Automatically recovered errors, surfaced for logging or analytics purposes
    case nonFatalError
}

///  Reason of why message was sent from SDK side
public enum RemediationStepMessageReasonType: Int {
    /// User cancelled local authentication process
    case userVerificationCancelledByUser

    /// SDK can't retrieve user verification key. Key might be missing or corrupted
    case userVerificationKeyCorruptedOrMissing
}

///  Step during verify flow to surface informational messages which don't require remediation
public class RemediationStepMessage: RemediationStep {

    public let messageType: RemediationStepMessageType
    public let reasonType: RemediationStepMessageReasonType
    public let message: String?
    /// Reference to challenge that is being processed. Downcast to concrete Challenge implementation if you want to retrieve more information
    public let challenge: ChallengeProtocol?
    public let error: DeviceAuthenticatorError?

    init(type: RemediationStepMessageType,
         reasonType: RemediationStepMessageReasonType,
         message: String?,
         challenge: ChallengeProtocol,
         error: DeviceAuthenticatorError?,
         logger: OktaLoggerProtocol) {
        self.messageType = type
        self.reasonType = reasonType
        self.message = message
        self.challenge = challenge
        self.error = error
        super.init(logger: logger, defaultProcessClosure: {})
    }
}
