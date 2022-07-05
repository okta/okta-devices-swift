/*
* Copyright (c) 2019-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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

class OktaJWTPayload: Encodable {
    let iss: String
    let aud: String
    let sub: String
    let iat: Int64
    let exp: Int64
    let nbf: Int64
    let jti: String

    enum JWTCodingKeys: String, CodingKey {
        case iss
        case aud
        case sub
        case iat
        case exp
        case nbf
        case jti
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: JWTCodingKeys.self)
        try container.encode(iss, forKey: .iss)
        try container.encode(aud, forKey: .aud)
        try container.encode(sub, forKey: .sub)
        try container.encode(iat, forKey: .iat)
        try container.encode(exp, forKey: .exp)
        try container.encode(nbf, forKey: .nbf)
        try container.encode(jti, forKey: .jti)
    }

    init(iss: String,
         aud: String,
         sub: String,
         iat: Int64 = Int64(Date().timeIntervalSince1970),
         timePadding: Int64 = 5 * 60, // 5mins
         jti: String = NSUUID().uuidString) {
        self.iss = iss
        self.aud = aud
        self.sub = sub
        self.iat = iat
        self.exp = self.iat + timePadding
        self.nbf = self.iat - timePadding
        self.jti = jti
    }
}
