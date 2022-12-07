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

class OktaTransactionDeleteEnrollment: OktaTransaction {
    let enrollmentToDelete: AuthenticatorEnrollment
    let accessToken: String?
    let restAPI: ServerAPIProtocol

    init(enrollmentToDelete: AuthenticatorEnrollment,
         accessToken: String?,
         storageManager: PersistentStorageProtocol,
         cryptoManager: OktaSharedCryptoProtocol,
         restAPI: ServerAPIProtocol,
         jwtGenerator: OktaJWTGenerator,
         logger: OktaLoggerProtocol) {
        self.enrollmentToDelete = enrollmentToDelete
        self.accessToken = accessToken
        self.restAPI = restAPI
        super.init(loginHint: nil, storageManager: storageManager, cryptoManager: cryptoManager, jwtGenerator: jwtGenerator, logger: logger)
    }

    func delete(onCompletion: @escaping (DeviceAuthenticatorError?) -> Void) {
        logger.info(eventName: self.logEventName, message: "Running enrollment delete flow")

        let runDeleteRequestWithToken: (String?) -> Void = { authenticationToken in
            let token = OktaRestAPIToken(authenticationToken: authenticationToken, accessToken: self.accessToken)
            self.restAPI.deleteAuthenticatorRequest(enrollment: self.enrollmentToDelete,
                                                    token: token) { result, error in
                if let error = error {
                    self.logger.error(eventName: self.logEventName, message: error.errorDescription)
                    onCompletion(error)
                    return
                }

                guard let _ = result else {
                    let error = DeviceAuthenticatorError.genericError("No valid response from server")
                    self.logger.error(eventName: self.logEventName, message: error.errorDescription)
                    onCompletion(error)
                    return
                }

                self.logger.info(eventName: self.logEventName, message: "Delete has been successful")
                onCompletion(nil)
            }
        }

        if accessToken == nil {
            generateAuthenticationJWTString(for: enrollmentToDelete) { authenticationToken, error in
                if let authenticationToken = authenticationToken {
                    runDeleteRequestWithToken(authenticationToken)
                } else if let error = error {
                    self.logger.error(eventName: self.logEventName, message: error.errorDescription)
                    onCompletion(error)
                } else {
                    self.logger.error(eventName: self.logEventName,
                                      message: "Failed to generate authentication token")
                    onCompletion(DeviceAuthenticatorError.internalError("Failed to generate authentication token"))
                }
            }
        } else {
            runDeleteRequestWithToken(nil)
        }
    }

    let logEventName = "DeleteTransaction"
}
