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

struct InternalConstants {
    static let customAuthenticatorKey = "custom_app"

    struct PushJWTConstants {
        static let payloadVersionKey = "payloadVersion"
        static let payloadVersionValue = "IDXv1"
        static let oktaPayloadVersionKey = "okta.payloadVersion"
        static let challengeKey = "challenge"
        static let oktaChallengeKey = "okta.challenge"
        static let pushJWTType = "okta-pushbind+jwt"
    }

    struct PushNotificationConstants {
        static let regularPushCategoryIdentifier = "OKTA_PUSH_CHALLENGE"
        static let userVerificationPushCategoryIdentifier = "OKTA_PUSH_UV_CHALLENGE"
        static let approveActionIdentifier = "APPROVE_BUTTON"
        static let denyActionIdentifier = "DENY_BUTTON"
        static let userVerificationActionIdentifier = "REVIEW_BUTTON"
    }
}

struct FeatureFlags {
    static var totpKeyStretchingEnabled = false
}
