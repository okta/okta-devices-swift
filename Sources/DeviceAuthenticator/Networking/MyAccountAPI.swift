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

struct MyAccountAPI {
    static let protocolVersion = "1.0.0"

    struct PolicyAPIResponseModel: Codable {
        let authenticatorId: String
        let orgId: String
        let key: String
        let name: String?
        let settings: AuthenticatorSettingsModel?
        let supportedMethods: [MethodResponseModel]
        let appAuthenticatorEnrollEndpoint: String
    }

    struct MethodUpdateRequestModel: Codable {
        let methods: MethodsModel

        struct MethodsModel: Codable {
            let push: PushMethodModel?

            struct PushMethodModel: Codable {
                let pushToken: String?
                let keys: SigningKeysModel?
                let capabilities: CapabilitiesModel?
            }
        }
    }

    struct AuthenticatorRequestModel: Codable {
        let authenticatorId: String
        let device: DeviceSignalsModel?
        let appSignals: [String: _OktaCodableArbitaryType]?
        let methods: AuthenticatorMethods

        struct AuthenticatorMethods: Codable {
            var push: PushMethod?

            struct PushMethod: Codable {
                let pushToken: String
                let apsEnvironment: APSEnvironment
                let capabilities: CapabilitiesModel
                let keys: SigningKeysModel
            }
        }
    }

    struct AuthenticatorResponseModel: Codable {
        let id: String
        let authenticatorId: String
        var user: User
        let createdDate: String?
        let lastUpdated: String?
        let device: Device
        var methods: AuthenticatorMethods
        let links: Links?

        struct Device: Codable {
            let id: String
            let status: String
            let createdDate: String?
            let lastUpdated: String?
            let profile: DeviceSignalsModel?
            let clientInstanceId: String
        }

        struct User: Codable {
            let id: String
            var username: String?
        }

        struct AuthenticatorMethods: Codable {
            let push: PushMethod?

            struct PushMethod: Codable {
                let id: String
                let createdDate: String?
                let lastUpdated: String?
                let links: Links?

                struct Links: Codable {
                    let pending: ActualLink?

                    struct ActualLink: Codable {
                        let href: String
                    }
                }
            }
        }

        struct Links: Codable {
            let `self`: ActualLink

            struct ActualLink: Codable {
                let href: String
            }
        }

        var creationDate: Date {
            guard let createdDateString = createdDate else {
                return Date.distantPast
            }
            return DateFormatter.oktaDateFormatter().date(from: createdDateString) ?? Date.distantPast
        }
    }
}
