/*
* Copyright (c) 2022, Okta, Inc. and/or its affiliates. All rights reserved.
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

class LegacyServerAPI: ServerAPIProtocol {
    public let client: HTTPClientProtocol
    public let logger: OktaLoggerProtocol
    let httpAuthorizationHeaderName = "Authorization"

    public init(client: HTTPClientProtocol, logger: OktaLoggerProtocol) {
        self.client = client
        self.logger = logger
    }

    /// - Description: Downloads Authenticator MetaData
    /// - Parameters:
    ///   - orgHost:         Organization host url
    ///   - token:           Authentication token(access token, one time token or signed jwt)
    ///   - completion:      Handler to execute after the async call completes
    func downloadAuthenticatorMetadata(orgHost: URL,
                                       authenticatorKey: String,
                                       oidcClientId: String?,
                                       token: OktaRestAPIToken,
                                       completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void
    ) {
        var urlComponents = URLComponents(url: orgHost.appendingPathComponent("/api/v1/authenticators"), resolvingAgainstBaseURL: true)
        urlComponents?.queryItems = [URLQueryItem(name: "key", value: authenticatorKey),
                                     URLQueryItem(name: "expand", value: "methods")]
        if let oidcClientId = oidcClientId {
            urlComponents?.queryItems?.append(URLQueryItem(name: "oauthClientId", value: oidcClientId))
        }
        guard let metaDataURL = urlComponents?.url else {
            logger.error(eventName: "Invalid URL provided", message: nil)
            completion(nil, DeviceAuthenticatorError.internalError("Invalid URL"))
            return
        }

        //metaDataURL.query
        logger.info(eventName: "Downloading Authenticator Metadata", message: "URL: \(metaDataURL)")
        self.client
            .request(metaDataURL)
            .addHeader(name: httpAuthorizationHeaderName, value: authorizationHeaderValue(forAuthType: token.type, withToken: token.token))
            .response { (result) in
                if let error = result.error {
                    let resultError = DeviceAuthenticatorError.networkError(error)
                    self.logger.error(eventName: "API error", message: "error: \(resultError) for request at URL: \(metaDataURL)")
                    completion(result, resultError)
                    return
                }

                self.validateResult(result, for: metaDataURL, andCall: completion)
            }
    }
}
