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

protocol OktaJWTGeneratorProtocol {
    func generate<T: Any>(with jwtType: String,
                          kid: String?,
                          for payLoad: T,
                          with key: SecKey,
                          using algorithm: Algorithm) throws -> String where T: Encodable
}

extension OktaJWTGeneratorProtocol {
    func generate<T: Any>(with jwtType: String,
                          kid: String? = nil,
                          for payLoad: T,
                          with key: SecKey,
                          using algorithm: Algorithm) throws -> String where T: Encodable {
        try generate(with: jwtType, kid: kid, for: payLoad, with: key, using: algorithm)
    }
}
