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
import OktaLogger

enum OktaRestAPIToken {
    case authenticationToken(String)
    case accessToken(String)
    case activationToken(String)
    case none

    /// - Description: Takes the first token which is provided (i.e. non-nil) and maps to the OktaRestAPIToken enum value
    /// - Parameters:
    ///   - authenticationToken: Authentication JWT
    ///   - authenticatorId:     Authenticator id for the request
    ///   - accessToken:         Access Token as part of the request
    init(authenticationToken: String? = nil, accessToken: String? = nil, activationToken: String? = nil) {
        if let authenticationToken = authenticationToken {
            self = .authenticationToken(authenticationToken)
        } else if let accessToken = accessToken {
            self = .accessToken(accessToken)
        } else if let activationToken = activationToken {
            self = .activationToken(activationToken)
        } else {
            self = .none
        }
    }

    /// - Description: Returns the token type
    var type: OktaAuthType {
        switch self {
        case .authenticationToken(_):
            return .ssws
        case .accessToken(_):
            return .bearer
        case .activationToken(_):
            return .otdt
        case .none:
            return .basic
        }
    }

    /// - Description: Returns the raw token string
    var token: String {
        switch self {
        case .authenticationToken(let token):
            return token
        case .accessToken(let token):
            return token
        case .activationToken(let token):
            return token
        case .none:
            return ""
        }
    }
}

class OktaRestAPI {
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

    /// - Description: Enrolls Authenticator
    /// - Parameters:
    ///   - enrollURL:   Organization host url
    ///   - data:        Data to post
    ///   - token:       Authentication token(access token, one time token or signed jwt)
    ///   - completion:  Handler to execute after the async call completes
    func enrollAuthenticatorRequest(enrollURL: URL,
                                    data: Data,
                                    token: OktaRestAPIToken,
                                    completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void) {
        logger.info(eventName: "Enrolling Authenticator", message: "URL: \(enrollURL)")
        self.client
            .request(enrollURL, method: .post, httpBody: data, headers: ["Content-Type": "application/json"])
            .addHeader(name: httpAuthorizationHeaderName, value: authorizationHeaderValue(forAuthType: token.type, withToken: token.token))
            .response { (result) in
                if let error = result.error {
                    let resultError = DeviceAuthenticatorError.networkError(error)
                    self.logger.error(eventName: "API error", message: "error: \(resultError) for request at URL: \(enrollURL)")
                    completion(result, resultError)
                    return
                }

                self.validateResult(result, for: enrollURL, andCall: completion)
            }
    }

    /// - Description: Updates Authenticator
    /// - Parameters:
    ///   - url:         Organization host url
    ///   - data:        Data to post
    ///   - token:       Authentication token(access token, one time token or signed jwt)
    ///   - completion:  Handler to execute after the async call completes
    func updateAuthenticatorRequest(url: URL,
                                    data: Data,
                                    token: OktaRestAPIToken,
                                    completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void) {
        logger.info(eventName: "Updating Authenticator", message: "URL: \(url)")
        if case .none = token {
            completion(nil, DeviceAuthenticatorError.internalError("No token provided for update enrollment request"))
            return
        }

        self.client
            .request(url, method: .put, httpBody: data, headers: ["Content-Type": "application/json"])
            .addHeader(name: httpAuthorizationHeaderName, value: authorizationHeaderValue(forAuthType: token.type, withToken: token.token))
            .response { (result) in
                if let error = result.error {
                    let resultError = DeviceAuthenticatorError.networkError(error)
                    self.logger.error(eventName: "API error", message: "\(resultError), for request at URL: \(url)")
                    completion(result, resultError)
                    return
                }

                self.validateResult(result, for: url, andCall: completion)
            }
    }

    /// - Description: Deletes Authenticator
    /// - Parameters:
    ///   - url:         Organization host url
    ///   - token:       Authentication token(access token, one time token or signed jwt)
    ///   - completion:  Handler to execute after the async call completes
    func deleteAuthenticatorRequest(url: URL,
                                    token: OktaRestAPIToken,
                                    completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void) {
        logger.info(eventName: "Deleting Authenticator", message: "URL: \(url)")
        if case .none = token {
            completion(nil, DeviceAuthenticatorError.internalError("No token provided for update enrollment request"))
            return
        }

        self.client
            .request(url, method: .delete, httpBody: nil)
            .addHeader(name: httpAuthorizationHeaderName, value: authorizationHeaderValue(forAuthType: token.type, withToken: token.token))
            .response { (result) in
                if let error = result.error {
                    let resultError = DeviceAuthenticatorError.networkError(error)
                    self.logger.error(eventName: "API error", message: "\(resultError), for request at URL: \(url)")
                    completion(result, resultError)
                    return
                }

                self.validateResult(result, for: url, andCall: completion)
            }
    }

    /// - Description: Sends a verify device challenge request.
    /// - Parameters:
    ///   - verifyURL:   Verify URL from challengeRequest JWT
    ///   - httpHeaders: Optional http headers
    ///   - data:        Optional data for POST request
    ///   - completion:  Handler to execute after the async call completes
    func verifyDeviceChallenge(verifyURL: URL,
                               httpHeaders: [String: String]? = nil,
                               data: Data? = nil,
                               completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void
    ) {
        let allHTTPHeaders = httpHeaders ?? ["Content-Type": "application/json"]
        logger.info(eventName: "Verifying Device Challenge", message: "URL: \(verifyURL)")
        let requestType: HTTPMethod = data == nil ? .get : .post
        let request = self.client.request(
                                    verifyURL,
                                    method: requestType,
                                    httpBody: data,
                                    headers: allHTTPHeaders
        )

        request.response { result in
            if let error = result.error {
                let resultError = DeviceAuthenticatorError.networkError(error)
                self.logger.error(eventName: "API error", message: "error: \(resultError) for request at URL: \(verifyURL)")
                completion(result, resultError)
                return
            }

            self.validateResult(result, for: verifyURL, andCall: completion)
        }
    }

    /// - Description: Sends a verify device challenge request.
    /// - Parameters:
    ///   - orgURL:         Org host url
    ///   - completion:     Handler to execute after the async call completes
    func downloadOrgId(for orgURL: URL,
                       completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void
    ) {
        let orgMetaDataURL = orgURL.appendingPathComponent("/.well-known/okta-organization")
        let request = self.client.request(orgMetaDataURL,
                                          method: .get,
                                          headers: ["Content-Type": "application/json"])
        logger.info(eventName: "Downloading Org ID", message: "URL: \(orgMetaDataURL)")
        request.response { result in
            if let error = result.error {
                let resultError = DeviceAuthenticatorError.networkError(error)
                self.logger.error(eventName: "API error", message: "error: \(resultError) for request at URL: \(orgMetaDataURL)")
                completion(result, resultError)
                return
            }

            self.validateResult(result, for: orgMetaDataURL, andCall: completion)
        }
    }

    /// - Description: Requests pending challenge from the server
    /// - Parameters:
    ///   - orgURL: Org host url
    ///   - authenticationToken: Authentication token,
    func pendingChallenge(with orgURL: URL,
                          authenticationToken: AuthToken,
                          completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void) {
        self.client
        .request(orgURL)
            .addHeader(name: httpAuthorizationHeaderName, value: authorizationHeaderValue(forAuthType: OktaAuthType.fromAuthToken(authenticationToken),
                                                                                          withToken: authenticationToken.tokenValue()))
        .response { (result) in
            if let error = result.error {
                let resultError = DeviceAuthenticatorError.networkError(error)
                self.logger.error(eventName: "API error", message: "error: \(resultError) for request at URL: \(orgURL)")
                completion(result, resultError)
                return
            }

            self.validateResult(result, for: orgURL, andCall: completion)
        }
    }

    /**
    * Validate the HTTPURLResponse against a series of assertions. Calls completion at the end
    *
    * - Parameters:
    *   - result: Result of the API request
    *   - completion:  Completion closure
    */
    func validateResult(_ result: HTTPURLResult,
                        for url: URL,
                        andCall completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void) {
        do {
            try self.validateResult(result, for: url)
        } catch let oktaError as DeviceAuthenticatorError {
            self.logger.error(eventName: "API error", message: "error: \(oktaError) for request at URL: \(url)")
            completion(result, oktaError)
            return
        } catch {
            let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
            self.logger.error(eventName: "API error", message: "error: \(resultError) for request at URL: \(url)")
            completion(result, resultError)
            return
        }

        completion(result, nil)
    }

    /**
     * Validate the HTTPURLResponse against a series of assertions.
     * Throws if an error is found.
     *
     * - Parameters:
     *   - result:        Result of the API request
     */
    func validateResult(_ result: HTTPURLResult, for url: URL) throws {
        // Handle Status Codes
        guard let response = result.response else {
            let resultError = DeviceAuthenticatorError.internalError("Unable to parse the HTTPURLResponse from the Result type.")
            self.logger.error(eventName: "API error", message: "error: \(resultError) for request at URL: \(url)")
            throw resultError
        }

        let statusCode = response.statusCode
        let validStatusCodes = 200 ..< 300

        if !validStatusCodes.contains(statusCode) {
            // Invalid status code
            logger.warning(eventName: "CODE", message: "CODE: \(statusCode), for request at URL: \(url)")
            guard let data = result.data else {
                // No responseData was provided
                let resultError = DeviceAuthenticatorError.serverAPIError(result, nil)
                logger.error(eventName: "API error", message: "error: \(resultError) for request at URL: \(url)")
                throw resultError
            }

            let errorModel = try? JSONDecoder().decode(ServerAPIErrorModel.self, from: data)
            let resultError = DeviceAuthenticatorError.serverAPIError(result, errorModel)
            logger.error(eventName: "API error", message: "error: \(resultError) for request at URL: \(url)")
            throw resultError
        } else {
            logger.info(eventName: "CODE", message: "CODE: \(statusCode), for request at URL: \(url)")
        }
    }

    func authorizationHeaderValue(forAuthType: OktaAuthType, withToken: String) -> String {
        return "\(forAuthType.toString()) \(withToken)"
    }
}
