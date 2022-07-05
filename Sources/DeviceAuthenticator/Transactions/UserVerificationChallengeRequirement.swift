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

/// User verification setting for the transaction
public enum UserVerificationChallengeRequirement: String {
    /// User Verification should not be challenged
    case none
    /// User verification should not be challenged to minimize user friction
    case discouraged
    /// User Verification is preferred, but not a requirement. So, can fallback to silent POP key
    case preferred
    /// User Verification is required. Fail if UV key not enrolled
    case required
    /// Unknown value detected
    case unknown

    public init(rawValue: String) {
        switch rawValue {
        case "NONE":
            self = .none
        case "DISCOURAGED":
            self = .discouraged
        case "PREFERRED":
            self = .preferred
        case "REQUIRED":
            self = .required
        default:
            self = .unknown
        }
    }
}
