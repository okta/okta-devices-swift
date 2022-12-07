/*
* Copyright (c) 2020, Okta, Inc. and/or its affiliates. All rights reserved.
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
import LocalAuthentication
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif

/// Builds client-originated JWT for authentication with the server
class OktaAuthenticationJWTGenerator {

    let cryptoManager: OktaCryptoProtocol
    let enrollmentId: String
    let orgHost: String
    let userId: String
    let jwtType: String
    let key: SecKey
    let kid: String
    let jwtGenerator: OktaJWTGenerator
    let logger: OktaLoggerProtocol

    init(enrollmentId: String,
         orgHost: String,
         userId: String,
         key: SecKey,
         kid: String,
         jwtType: String,
         cryptoManager: OktaCryptoProtocol,
         logger: OktaLoggerProtocol,
         jwtGenerator: OktaJWTGenerator? = nil) {
        self.enrollmentId = enrollmentId
        self.orgHost = orgHost
        self.userId = userId
        self.key = key
        self.kid = kid
        self.jwtType = jwtType
        self.cryptoManager = cryptoManager
        self.jwtGenerator = jwtGenerator ?? OktaJWTGenerator(logger: logger)
        self.logger = logger
    }

    func generateJWTString() throws -> String {
        let jwt = OktaAuthenticationJWT(iss: enrollmentId,
                                        aud: orgHost,
                                        sub: userId,
                                        kid: kid)
        return try jwtGenerator.generate(with: jwtType,
                                          kid: kid,
                                          for: jwt,
                                          with: key,
                                          using: .ES256)
    }
}
