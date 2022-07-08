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
@testable import DeviceAuthenticator

class OktaJWKGeneratorMock: OktaJWKGenerator {

    typealias generateType = (SecKey, KeyType, Algorithm, String, [String: _OktaCodableArbitaryType]) throws -> [String: _OktaCodableArbitaryType]?

    var generateHook: generateType?

    override func generate(for key: SecKey,
                           type: KeyType,
                           algorithm: Algorithm,
                           kid: String = NSUUID().uuidString,
                           additionalParameters: [String: _OktaCodableArbitaryType] = [: ]) throws -> [String: _OktaCodableArbitaryType]? {
        if let generateHook = generateHook {
            return try generateHook(key, type, algorithm, kid, additionalParameters)
        }

        var params = additionalParameters
        params.merge([
            "kid": .string(kid),
            "y": .string("QL3_sDhlfJdlBcT7rN_XXB7m5w9yD_OcCI5SocP14PM"),
            "x": .string("e4jw9ZELvFZWTLGA3-ASzGWxFCNlKb6xHb0yJjdqqcc"),
            "kty": .string("EC"),
            "crv": .string("P-256")
        ], uniquingKeysWith: { (_, new) in new })

        return params
    }
}
