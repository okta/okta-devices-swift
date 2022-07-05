/*
* Copyright (c) 2021, Okta, Inc. and/or its affiliates. All rights reserved.
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

extension _OktaAuthenticatorsManager {

    func doDownloadMetadata(orgHost: URL,
                            authenticatorKey: String,
                            oidcClientId: String?,
                            token: OktaRestAPIToken,
                            onCompletion: @escaping (Result<AuthenticatorPolicyProtocol, DeviceAuthenticatorError>) -> Void) {
        self.restAPI.downloadAuthenticatorMetadata(orgHost: orgHost,
                                                   authenticatorKey: authenticatorKey,
                                                   oidcClientId: oidcClientId,
                                                   token: token) { result, error in
            if let error = error {
                self.logger.error(eventName: "Download Authenticator Metadata", message: "\(error)")
                onCompletion(Result.failure(error))
                return
            }

            guard let result = result, let metaDataJson = result.data else {
                    let resultError = DeviceAuthenticatorError.internalError("Server replied with an empty data")
                    self.logger.error(eventName: "Download Authenticator Metadata",
                                      message: "Download metadata error - \(resultError)")
                onCompletion(Result.failure(resultError))
                return
            }

            let metaData: AuthenticatorMetaDataModel
            do {
                let metaDataArray = try JSONDecoder().decode([AuthenticatorMetaDataModel].self, from: metaDataJson).filter({
                    $0.status == .active
                })
                guard !metaDataArray.isEmpty else {
                    throw DeviceAuthenticatorError.internalError("Server replied with empty active authenticators array")
                }
                metaData = metaDataArray[0]
            } catch {
                let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
                self.logger.error(eventName: "Download Authenticator Metadata",
                                  message: "Download metadata error - \(resultError)")
                onCompletion(Result.failure(resultError))
                return
            }

            let authenticatorPolicy = AuthenticatorPolicy(metadata: metaData)
            onCompletion(Result.success(authenticatorPolicy))
        }
    }
}
