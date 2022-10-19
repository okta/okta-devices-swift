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

class MyAccountServerAPI: ServerAPIProtocol {
    let client: HTTPClientProtocol
    let crypto: OktaSharedCryptoProtocol
    let logger: OktaLoggerProtocol
    let currentProtocolVersion = "1.0.0"
    let acceptHeaderValue: String

    public init(client: HTTPClientProtocol,
                crypto: OktaSharedCryptoProtocol,
                logger: OktaLoggerProtocol) {
        self.client = client
        self.crypto = crypto
        self.logger = logger
        acceptHeaderValue = "application/json" + "; okta-version=\(currentProtocolVersion)"
    }

    func downloadAuthenticatorMetadata(orgHost: URL,
                                       authenticatorKey: String,
                                       oidcClientId: String?,
                                       token: OktaRestAPIToken,
                                       completion: @escaping (Result<AuthenticatorMetaDataModel, DeviceAuthenticatorError>) -> Void) {
        var urlComponents = URLComponents(url: orgHost.appendingPathComponent("/.well-known/app-authenticator-configuration"), resolvingAgainstBaseURL: true)
        urlComponents?.queryItems = []
        if let oidcClientId = oidcClientId {
            urlComponents?.queryItems?.append(URLQueryItem(name: "oauthClientId", value: oidcClientId))
        }
        guard let metaDataURL = urlComponents?.url else {
            logger.error(eventName: "Invalid URL provided", message: nil)
            completion(.failure(DeviceAuthenticatorError.internalError("Invalid URL")))
            return
        }

        //metaDataURL.query
        logger.info(eventName: "Downloading Authenticator Metadata", message: "URL: \(metaDataURL)")
        self.client
            .request(metaDataURL)
            .addHeader(name: HTTPHeaderConstants.authorizationHeader, value: authorizationHeaderValue(forAuthType: token.type, withToken: token.token))
            .addHeader(name: HTTPHeaderConstants.acceptHeader, value: acceptHeaderValue)
            .response { result in
                do {
                    try self.validateResult(result, for: metaDataURL)
                } catch let oktaError as DeviceAuthenticatorError {
                    completion(.failure(oktaError))
                    return
                } catch {
                    let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
                    self.logger.error(eventName: "API error", message: "error: \(resultError) for request at URL: \(metaDataURL)")
                    completion(.failure(resultError))
                    return
                }

                guard let metaDataJson = result.data else {
                    let resultError = DeviceAuthenticatorError.internalError("Server replied with an empty data")
                    self.logger.error(eventName: "Policy request", message: "Download metadata error - \(resultError)")
                    completion(Result.failure(resultError))
                    return
                }

                do {
                    let policyModel = try JSONDecoder().decode(PolicyAPIResponseModel.self, from: metaDataJson)
                    let enrollLink = AuthenticatorMetaDataModel.Links.EnrollLink(href: policyModel.app_authenticator_enroll_endpoint)
                    let links = AuthenticatorMetaDataModel.Links(enroll: enrollLink,
                                                                 logos: nil)
                    let authenticatorSettings = AuthenticatorSettingsModel(appInstanceId: nil,
                                                                           userVerification: policyModel.settings?.userVerification,
                                                                           oauthClientId: oidcClientId)
                    let embedded = AuthenticatorMetaDataModel.Embedded(methods: policyModel.supportedMethods)
                    let metadata = AuthenticatorMetaDataModel(id: policyModel.authenticatorId,
                                                              key: policyModel.key,
                                                              type: "app",
                                                              status: nil,
                                                              name: policyModel.name,
                                                              settings: authenticatorSettings,
                                                              _links: links,
                                                              _embedded: embedded)
                    completion(Result.success(metadata))
                } catch {
                    let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
                    self.logger.error(eventName: "Policy request", message: "Download metadata error - \(resultError)")
                    completion(Result.failure(resultError))
                }
            }
    }

    func enrollAuthenticatorRequest(orgHost: URL, metadata: AuthenticatorMetaDataModel, deviceModel: DeviceSignalsModel, appSignals: [String: _OktaCodableArbitaryType]?, enrollingFactors: [EnrollingFactor], token: OktaRestAPIToken, completion: @escaping (Result<EnrollmentSummary, DeviceAuthenticatorError>) -> Void) {
        // Implement
    }

    func updateAuthenticatorRequest(orgHost: URL, enrollmentId: String, metadata: AuthenticatorMetaDataModel, deviceModel: DeviceSignalsModel, appSignals: [String: _OktaCodableArbitaryType]?, enrollingFactors: [EnrollingFactor], token: OktaRestAPIToken, completion: @escaping (Result<EnrollmentSummary, DeviceAuthenticatorError>) -> Void) {
        // Implement
    }
}
