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

enum OktaUserConsentValue: String {
    case approved = "APPROVED_CONSENT_PROMPT"
    case denied = "DENIED_CONSENT_PROMPT"
    case approvedUserVerification = "APPROVED_USER_VERIFICATION"
    case cancelledUserVerification = "CANCELLED_USER_VERIFICATION"
    case userVerificationTemporarilyUnavailable = "UV_TEMPORARILY_UNAVAILABLE"
    case userVerificationPermanentlyUnavailable = "UV_PERMANENTLY_UNAVAILABLE"
    case none = "NONE"

    static func create(_ response: UserConsentResponse) -> OktaUserConsentValue {
        switch response {
        case .approved:
            return .approved
        case .denied:
            return .denied
        case .none:
            return .none
        }
    }

    func userVerificationFailed() -> OktaUserConsentValue {
        if self == .approvedUserVerification {
            return .none
        }
        return self
    }

    func userVerificationApproved() -> OktaUserConsentValue {
        if self == .none {
            return .approvedUserVerification
        }
        return self
    }
}
