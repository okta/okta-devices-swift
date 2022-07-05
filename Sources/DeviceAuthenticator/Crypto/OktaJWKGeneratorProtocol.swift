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

protocol OktaJWKGeneratorProtocol {

    /// <#Description#>
    /// - Parameters:
    ///   - key: SecKey for which the JWK needs to be generated
    ///   - type: Key type
    ///   - algorithm: Algorithm for the SecKey
    func generate(for key: SecKey,
                  type: KeyType,
                  algorithm: Algorithm,
                  kid: String,
                  additionalParameters: [String: _OktaCodableArbitaryType]) throws -> [String: _OktaCodableArbitaryType]?
}

extension OktaJWKGeneratorProtocol {
   func generate(for key: SecKey,
                 type: KeyType,
                 algorithm: Algorithm,
                 kid: String,
                 additionalParameters: [String: _OktaCodableArbitaryType] = [: ]) throws -> [String: _OktaCodableArbitaryType]? {
        return try generate(for: key,
                            type: type,
                            algorithm: algorithm,
                            kid: kid,
                            additionalParameters: additionalParameters)
    }
}
