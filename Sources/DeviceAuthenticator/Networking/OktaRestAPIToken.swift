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
import OktaLogger

enum OktaRestAPIToken {
    case authenticationToken(String)
    case accessToken(String)
    case activationToken(String)
    case none

    /// - Description: Takes the first token which is provided (i.e. non-nil) and maps to the OktaRestAPIToken enum value
    /// - Parameters:
    ///   - authenticationToken: Authentication JWT
    ///   - authenticatorId:     Authenticator id for the request
    ///   - accessToken:         Access Token as part of the request
    init(authenticationToken: String? = nil, accessToken: String? = nil, activationToken: String? = nil) {
        if let authenticationToken = authenticationToken {
            self = .authenticationToken(authenticationToken)
        } else if let accessToken = accessToken {
            self = .accessToken(accessToken)
        } else if let activationToken = activationToken {
            self = .activationToken(activationToken)
        } else {
            self = .none
        }
    }

    /// - Description: Returns the token type
    var type: OktaAuthType {
        switch self {
        case .authenticationToken(_):
            return .ssws
        case .accessToken(_):
            return .bearer
        case .activationToken(_):
            return .otdt
        case .none:
            return .basic
        }
    }

    /// - Description: Returns the raw token string
    var token: String {
        switch self {
        case .authenticationToken(let token):
            return token
        case .accessToken(let token):
            return token
        case .activationToken(let token):
            return token
        case .none:
            return ""
        }
    }
}
