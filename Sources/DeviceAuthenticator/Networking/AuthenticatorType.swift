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

enum AuthenticatorMethod {
    case totp
    case push
    case signedNonce
    case unknown(String)
}

extension AuthenticatorMethod {
    init(raw: String) {
        switch raw {
        case "totp":
            self = .totp
        case "push":
            self = .push
        case "signed_nonce":
            self = .signedNonce
        default:
            self = .unknown(raw)
        }
    }

    var rawValue: String {
        switch self {
        case .totp:
            return "totp"
        case .push:
            return "push"
        case .signedNonce:
            return "signed_nonce"
        case .unknown(let unknown):
            return unknown
        }
    }
}

extension AuthenticatorMethod: Equatable {}

extension AuthenticatorMethod: Codable {
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.rawValue)
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let stringValue = try container.decode(String.self)
        self = AuthenticatorMethod(raw: stringValue)
    }
}
