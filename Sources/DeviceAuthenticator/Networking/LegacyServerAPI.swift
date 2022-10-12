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

    func downloadAuthenticatorMetadata(orgHost: URL,
                                       authenticatorKey: String,
                                       oidcClientId: String?,
                                       token: OktaRestAPIToken,
                                       completion: @escaping (_ result: Result<AuthenticatorMetaDataModel, DeviceAuthenticatorError>) -> Void
    ) {
        var urlComponents = URLComponents(url: orgHost.appendingPathComponent("/api/v1/authenticators"), resolvingAgainstBaseURL: true)
        urlComponents?.queryItems = [URLQueryItem(name: "key", value: authenticatorKey),
                                     URLQueryItem(name: "expand", value: "methods")]
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
            .addHeader(name: httpAuthorizationHeaderName, value: authorizationHeaderValue(forAuthType: token.type, withToken: token.token))
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

                let metaData: AuthenticatorMetaDataModel
                do {
                    let metaDataArray = try JSONDecoder().decode([AuthenticatorMetaDataModel].self, from: metaDataJson).filter({
                        $0.status == .active
                    })
                    guard !metaDataArray.isEmpty else {
                        completion(Result.failure(DeviceAuthenticatorError.internalError("Server replied with empty active authenticators array")))
                        return
                    }

                    metaData = metaDataArray[0]
                    completion(Result.success(metaData))
                } catch {
                    let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
                    self.logger.error(eventName: "Policy request", message: "Download metadata error - \(resultError)")
                    completion(Result.failure(resultError))
                }
            }
    }

    func enrollAuthenticatorRequest(orgHost: URL,
                                    metadata: AuthenticatorMetaDataModel,
                                    deviceModel: DeviceSignalsModel,
                                    appSignals: [String: _OktaCodableArbitaryType]?,
                                    enrollingFactors: [EnrollingFactor],
                                    token: OktaRestAPIToken,
                                    completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void) {
        let enrollRequestJson: Data
        do {
            logger.info(eventName: "Enroll request", message: "Building request json object")
            enrollRequestJson = try buildEnrollmentRequestData(metadata: metadata,
                                                               deviceModel: deviceModel,
                                                               appSignals: appSignals,
                                                               enrollingFactors: enrollingFactors)
        } catch {
            let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
            logger.error(eventName: "Enroll request", message: "Error: \(resultError)")
            completion(nil, resultError)
            return
        }

        let finalURL: URL
        if let enrollLink = metadata._links.enroll?.href,
            let enrollURL = URL(string: enrollLink) {
            finalURL = enrollURL
        } else {
            finalURL = orgHost.appendingPathComponent("/idp/authenticators")
        }
        logger.info(eventName: "Enrolling Authenticator", message: "URL: \(finalURL)")
        self.client
            .request(finalURL, method: .post, httpBody: enrollRequestJson, headers: [HTTPHeaderConstants.contentTypeHeader: "application/json"])
            .addHeader(name: HTTPHeaderConstants.authorizationHeader, value: authorizationHeaderValue(forAuthType: token.type, withToken: token.token))
            .response { (result) in
                if let error = result.error {
                    let resultError = DeviceAuthenticatorError.networkError(error)
                    self.logger.error(eventName: "API error", message: "error: \(resultError) for request at URL: \(finalURL)")
                    completion(result, resultError)
                    return
                }

                guard result.data != nil else {
                    let resultError = DeviceAuthenticatorError.internalError("Server replied with an empty data")
                    self.logger.error(eventName: "Policy request", message: "Download metadata error - \(resultError)")
                    completion(nil, resultError)
                    return
                }

                do {
                    try self.validateResult(result, for: finalURL)
                    completion(result, nil)
                } catch let oktaError as DeviceAuthenticatorError {
                    completion(nil, oktaError)
                    return
                } catch {
                    let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
                    self.logger.error(eventName: "API error", message: "error: \(resultError) for request at URL: \(finalURL)")
                    completion(nil, resultError)
                    return
                }
            }
    }

    func updateAuthenticatorRequest(orgHost: URL,
                                    enrollmentId: String,
                                    metadata: AuthenticatorMetaDataModel,
                                    deviceModel: DeviceSignalsModel,
                                    appSignals: [String: _OktaCodableArbitaryType]?,
                                    enrollingFactors: [EnrollingFactor],
                                    token: OktaRestAPIToken,
                                    completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void) {
        let enrollRequestJson: Data
        do {
            logger.info(eventName: "Update request", message: "Building enrollment request")
            enrollRequestJson = try buildEnrollmentRequestData(metadata: metadata,
                                                               deviceModel: deviceModel,
                                                               appSignals: appSignals,
                                                               enrollingFactors: enrollingFactors)
        } catch {
            let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
            logger.error(eventName: "Update request", message: "Error: \(resultError)")
            completion(nil, resultError)
            return
        }

        let finalURL: URL = orgHost.appendingPathComponent("/idp/authenticators/" + enrollmentId)
        logger.info(eventName: "Updating Authenticator", message: "URL: \(finalURL)")
        if case .none = token {
            completion(nil, DeviceAuthenticatorError.internalError("No token provided for update enrollment request"))
            return
        }

        self.client
            .request(finalURL, method: .put, httpBody: enrollRequestJson, headers: [HTTPHeaderConstants.contentTypeHeader: "application/json"])
            .addHeader(name: HTTPHeaderConstants.authorizationHeader, value: authorizationHeaderValue(forAuthType: token.type, withToken: token.token))
            .response { (result) in
                if let error = result.error {
                    let resultError = DeviceAuthenticatorError.networkError(error)
                    self.logger.error(eventName: "API error", message: "\(resultError), for request at URL: \(finalURL)")
                    completion(result, resultError)
                    return
                }

                do {
                    try self.validateResult(result, for: finalURL)
                    completion(result, nil)
                } catch let oktaError as DeviceAuthenticatorError {
                    completion(nil, oktaError)
                    return
                } catch {
                    let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
                    self.logger.error(eventName: "API error", message: "error: \(resultError) for request at URL: \(finalURL)")
                    completion(nil, resultError)
                    return
                }
            }
    }

    func buildEnrollmentRequestData(metadata: AuthenticatorMetaDataModel,
                                    deviceModel: DeviceSignalsModel,
                                    appSignals: [String: _OktaCodableArbitaryType]?,
                                    enrollingFactors: [EnrollingFactor]) throws -> Data {
        let methods = enrollingFactors.compactMap { factor in
            if factor.keys != nil {
                let methodModel = EnrollAuthenticatorRequestModel.AuthenticatorMethods(type: factor.methodType,
                                                                                       pushToken: factor.methodType == .push ? factor.pushToken : nil,
                                                                                       apsEnvironment: factor.methodType == .push ? factor.apsEnvironment : nil,
                                                                                       supportUserVerification: factor.supportUserVerification,
                                                                                       isFipsCompliant: factor.isFipsCompliant,
                                                                                       keys: factor.keys)

                return methodModel
            } else {
                return nil
            }
        }
        let enrollRequestModel = EnrollAuthenticatorRequestModel(authenticatorId: metadata.id,
                                                                 key: metadata.key,
                                                                 device: deviceModel,
                                                                 appSignals: appSignals,
                                                                 methods: methods)
        return try JSONEncoder().encode(enrollRequestModel)
    }
}
