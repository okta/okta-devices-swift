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

class OktaJWTGeneratorMock: OktaJWTGenerator {

    var stringToReturn = "jwk.payload.jws"
    var generateHook: generateType?

    typealias generateType = (String, String?, Encodable, SecKey, Algorithm) throws -> String

    override public func generate<T: Any>(with jwtType: String,
                                          kid: String? = nil,
                                          for payLoad: T,
                                          with key: SecKey,
                                          using algorithm: Algorithm) throws -> String where T: Encodable {
        if let generateHook = generateHook {
            return try generateHook(jwtType, kid, payLoad, key, algorithm)
        } else {
            return stringToReturn
        }
    }
}
