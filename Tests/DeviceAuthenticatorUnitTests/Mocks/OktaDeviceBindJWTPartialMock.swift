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
import OktaLogger
@testable import DeviceAuthenticator

class OktaDeviceBindJWTPartialMock: OktaBindJWT {

    let ignoreExpValidation: Bool
    let ignoreIatValidation: Bool
    var optionsToValidate: [String: Any] = [: ]
    typealias ValidateJWTType = (String, [String: Any], [String: String], OktaLoggerProtocol) -> Void
    var validateJWTHook: ValidateJWTType?

    init(string input: String,
         jwtType: String = "okta-devicebind+jwt",
         accessGroupId: String? = ExampleAppConstants.appGroupId,
         validatePayload: Bool = true,
         customizableHeaders: [String: String] = [:],
         ignoreExpValidation: Bool = true,
         ignoreIatValidation: Bool = true,
         allowedClockSkewInSeconds: Int = 60,
         logger: OktaLogger) throws {

        self.ignoreExpValidation = ignoreExpValidation
        self.ignoreIatValidation = ignoreIatValidation
        try super.init(string: input,
                       applicationGroupId: accessGroupId,
                       validatePayload: validatePayload,
                       customizableHeaders: customizableHeaders,
                       jwtType: jwtType,
                       allowedClockSkewInSeconds: allowedClockSkewInSeconds,
                       logger: logger)
    }

    override func validateJWT(with jwtString: String,
                              with options: [String: Any],
                              with customizableHeaders: [String: String],
                              logger: OktaLoggerProtocol) throws {
        if let validateJWTHook = validateJWTHook {
            validateJWTHook(jwtString, options, customizableHeaders, logger)
        } else {
            optionsToValidate = options
            if ignoreExpValidation {
                optionsToValidate.removeValue(forKey: OktaJWTClaims.expires.rawValue)
            }
            if ignoreIatValidation {
                optionsToValidate.removeValue(forKey: OktaJWTClaims.issuedAt.rawValue)
            }
            try super.validateJWT(with: jwtString, with: optionsToValidate, with: customizableHeaders, logger: logger)
        }
    }
}
