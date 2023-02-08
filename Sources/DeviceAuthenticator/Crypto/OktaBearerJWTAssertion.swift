/*
* Copyright (c) 2023-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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

class OktaBearerJWTAssertion: OktaJWTPayload {
    let methodEnrollmentId: String

    enum JWTCodingKeys: String, CodingKey {
        case methodEnrollmentId
    }

    override func encode(to encoder: Encoder) throws {
        try super.encode(to: encoder)
        var container = encoder.container(keyedBy: JWTCodingKeys.self)
        try container.encode(methodEnrollmentId, forKey: .methodEnrollmentId)
    }

    init(iss: String,
         aud: String,
         sub: String,
         methodEnrollmentId: String) {
        self.methodEnrollmentId = methodEnrollmentId
        super.init(iss: iss, aud: aud, sub: sub)
    }
}
