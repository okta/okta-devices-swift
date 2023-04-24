/*
* Copyright (c) 2019, Okta, Inc. and/or its affiliates. All rights reserved.
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

struct AuthenticatorSettingsModel: Codable {
    let appInstanceId: String?
    let userVerification: UserVerificationSetting?
    let userVerificationMethods: [UserVerificationMethodSetting]?
    let oauthClientId: String?

    enum UserVerificationSetting {
        case preferred
        case required
        case unknown(String)
    }

    enum UserVerificationMethodSetting {
        case pin
        case biometrics
        case unknown(String)
    }
}

extension AuthenticatorSettingsModel.UserVerificationSetting {
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

extension AuthenticatorSettingsModel.UserVerificationSetting: Equatable {}

extension AuthenticatorSettingsModel.UserVerificationSetting: Codable {
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.rawValue)
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let stringValue = try container.decode(String.self)
        self = AuthenticatorSettingsModel.UserVerificationSetting(raw: stringValue)
    }
}

extension AuthenticatorSettingsModel.UserVerificationMethodSetting {
    init(rawValue: String) {
        switch rawValue.lowercased() {
        case "pin":
            self = .pin
        case "biometrics":
            self = .biometrics
        default:
            self = .unknown(rawValue)
        }
    }

    var rawValue: String {
        switch self {
        case .pin:
            return "pin"
        case .biometrics:
            return "biometrics"
        case .unknown(let unknown):
            return unknown
        }
    }
}

extension AuthenticatorSettingsModel.UserVerificationMethodSetting: Equatable {}

extension AuthenticatorSettingsModel.UserVerificationMethodSetting: Codable {
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.rawValue)
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let rawValue = try container.decode(String.self)
        self = AuthenticatorSettingsModel.UserVerificationMethodSetting(rawValue: rawValue)
    }
}
