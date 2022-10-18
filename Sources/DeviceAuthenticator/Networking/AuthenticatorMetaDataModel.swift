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
    let settings: AuthenticatorSettingsModel?
    let _links: Links
    let _embedded: Embedded

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
        let methods: [MethodResponseModel]
    }
}
