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

/// Authentication prefixes that are included in
enum OktaAuthType: Int {
    /// Basic HTTP authentication scheme that usually requires user-id and password
    case basic
    /// Bearer HTTP authentication scheme that is  usually used for transmitting access token
    case bearer
    /// SSWS is OKTA's proprietary HTTP authentication scheme for transmitting api token or signed jwt
    case ssws
    /// OTDT is OKTA's proprietary HTTP for transmitting one-time token
    case otdt

    func toString() -> String {
        switch self {
        case .basic:
            return "Basic"
        case .bearer:
            return "Bearer"
        case .ssws:
            return "SSWS"
        case .otdt:
            return "OTDT"
        }
    }

    static func fromAuthToken(_ token: AuthToken) -> Self {
        switch token {
        case .bearer(_):
            return Self.bearer
        }
    }
}
