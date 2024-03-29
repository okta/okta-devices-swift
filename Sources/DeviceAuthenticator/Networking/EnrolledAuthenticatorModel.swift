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

struct EnrolledAuthenticatorModel: Codable {
    let id: String
    let authenticatorId: String
    let key: String
    let status: String
    let type: String?
    var user: User
    let createdDate: String?
    let lastUpdated: String?
    let device: Device
    var methods: [AuthenticatorMethods]?

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
        let id: String
        let type: AuthenticatorMethod
        var sharedSecret: String? // TOTP base32 encoded shared secret
        let status: String?
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

    var creationDate: Date {
        guard let createdDateString = createdDate else {
            return Date.distantPast
        }
        return DateFormatter.oktaDateFormatter().date(from: createdDateString) ?? Date.distantPast
    }
}
