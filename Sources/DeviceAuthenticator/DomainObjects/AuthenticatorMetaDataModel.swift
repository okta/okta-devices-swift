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

struct AuthenticatorMetaDataModel: Codable {

    let id: String
    let key: String
    let type: String
    let status: Status?
    let name: String?
    let settings: Settings?
    let _links: Links
    let _embedded: Embedded

    struct Settings: Codable {
        let appInstanceId: String?
        let userVerification: UserVerificationSetting?
        let oauthCliendId: String?

        public enum UserVerificationSetting {
            case preferred
            case required
            case unknown(String)
        }
    }

    enum Status: String, Codable {
        case active = "ACTIVE"
        case inactive = "INACTIVE"
    }

    struct Links: Codable {
        let enroll: EnrollLink?
        let logos: [LogoLink]?

        struct EnrollLink: Codable {
            let href: String
        }
        struct LogoLink: Codable {
            let name: String
            let href: String
            let type: String
        }
    }

    struct Embedded: Codable {
        let methods: [Method]
    }

    struct Method: Codable {

        let type: AuthenticatorMethod
        let status: String
        let settings: Settings?

        struct Settings: Codable {

            // SignedNonce/Push related params
            enum CryptoAlgorithms: String, Codable {
                case RS256, ES256
            }
            enum KeyProtection: String, Codable {
                case ANY, HARDWARE
            }

            let algorithms: [CryptoAlgorithms]?
            let keyProtection: KeyProtection?

            // TOTP generation algorithm
            enum TOTPAlgorithms: String, Codable {
                case HMACSHA1, HMACSHA256, HMACSHA512
            }
            // TOTP secret encoding format
            enum TOTPSecretEncoding: String, Codable {
                case Base32
            }

            let timeIntervalInSeconds: UInt?
            let encoding: TOTPSecretEncoding?
            let algorithm: TOTPAlgorithms?
            let passCodeLength: UInt?
        }

        enum CodingKeys: String, CodingKey {
            case type
            case status
            case settings
        }
    }
}

extension AuthenticatorMetaDataModel.Settings.UserVerificationSetting {
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

extension AuthenticatorMetaDataModel.Settings.UserVerificationSetting: Equatable {}

extension AuthenticatorMetaDataModel.Settings.UserVerificationSetting: Codable {
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.rawValue)
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let stringValue = try container.decode(String.self)
        self = AuthenticatorMetaDataModel.Settings.UserVerificationSetting(raw: stringValue)
    }
}
