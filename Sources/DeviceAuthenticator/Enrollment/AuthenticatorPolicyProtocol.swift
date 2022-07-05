/*
* Copyright (c) 2022, Okta, Inc. and/or its affiliates. All rights reserved.
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

/// User verification setting in authenticator policy
public enum UserVerificationPolicySetting {
    /// User verification is optional for the policy
    case preferred
    /// Policy requires that each enrollment has user verification capability enabled
    case required
    /// Unknown setting value
    case unknown(String)
}

/// Describes authenticator policy settings and attributes
public protocol AuthenticatorPolicyProtocol {
    /// Convenience getter for User Verification setting
    var userVerificationSetting: UserVerificationPolicySetting { get }
}

public extension UserVerificationPolicySetting {
    init(raw: String) {
        switch raw.lowercased() {
        case "preferred":
            self = .preferred
        case "required":
            self = .required
        default:
            self = .unknown(raw)
        }
    }

    var rawValue: String {
        switch self {
        case .preferred:
            return "preferred"
        case .required:
            return "required"
        case .unknown(let unknown):
            return unknown
        }
    }
}

extension UserVerificationPolicySetting: Equatable {}

extension UserVerificationPolicySetting: Codable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.rawValue)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let stringValue = try container.decode(String.self)
        self = UserVerificationPolicySetting(raw: stringValue)
    }
}
