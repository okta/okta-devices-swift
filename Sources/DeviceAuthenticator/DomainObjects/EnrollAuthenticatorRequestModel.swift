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

typealias UserVerificationEncodableValue = EnrollAuthenticatorRequestModel.AuthenticatorMethods.Keys.UserVerificationKey
typealias APSEnvironmentEncodableValue = EnrollAuthenticatorRequestModel.AuthenticatorMethods.APSEnvironment

struct EnrollAuthenticatorRequestModel: Encodable {

    let authenticatorId: String
    let key: String
    let device: DeviceSignalsModel?
    let appSignals: [String: _OktaCodableArbitaryType]?
    let methods: [AuthenticatorMethods]

    struct AuthenticatorMethods: Encodable {
        let type: AuthenticatorMethod
        let pushToken: String? // For Push factor
        let apsEnvironment: APSEnvironment?
        let supportUserVerification: Bool? // For TOTP factor
        let isFipsCompliant: Bool? // For TOTP
        let keys: Keys?
        let capabilities: Capabilities?

        enum APSEnvironment: String, Encodable {
            case development
            case production
        }

        struct Keys: Encodable {
            let proofOfPossession: [String: _OktaCodableArbitaryType]?
            let userVerification: UserVerificationKey?

            enum UserVerificationKey: Encodable {
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
            }
        }

        struct Capabilities: Encodable {
            let transactionTypes: [TransactionType]
        }
    }
}
