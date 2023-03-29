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

typealias UserVerificationEncodableValue = SigningKeysModel.UserVerificationKey
typealias APSEnvironmentEncodableValue = APSEnvironment

enum APSEnvironment: String, Encodable {
    case development
    case production
}

struct SigningKeysModel: Codable {
    let proofOfPossession: [String: _OktaCodableArbitaryType]?
    let userVerification: UserVerificationKey?
    let userVerificationBioOrPin: UserVerificationKey?

    enum UserVerificationKey: Codable {
        case null
        case keyValue([String: _OktaCodableArbitaryType])
        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .null:
                try container.encodeNil()
            case .keyValue(let kayValue):
                try container.encode(kayValue)
            }
        }

        func value() -> [String: _OktaCodableArbitaryType]? {
            switch self {
            case .null:
                return nil
            case .keyValue(let kayValue):
                return kayValue
            }
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let uvKeyValue: [String: _OktaCodableArbitaryType] = try? container.decode([String: _OktaCodableArbitaryType].self) {
                self = .keyValue(uvKeyValue)
            } else {
                self = .null
            }
        }
    }
}
