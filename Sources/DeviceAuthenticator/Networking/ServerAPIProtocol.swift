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

struct HTTPHeaderConstants {
    static let authorizationHeader = "Authorization"
    static let contentTypeHeader = "Content-Type"
}

struct EnrollingFactor {
    let proofOfPossessionKeyTag: String?
    let userVerificationKeyTag: String?
    let methodType: AuthenticatorMethod
    let apsEnvironment: APSEnvironment?
    let pushToken: String?
    let supportUserVerification: Bool?
    let isFipsCompliant: Bool?
    let keys: SigningKeysModel?
}

protocol ServerAPIProtocol {
    var client: HTTPClientProtocol { get }
    var logger: OktaLoggerProtocol { get }

    func downloadAuthenticatorMetadata(orgHost: URL,
                                       authenticatorKey: String,
                                       oidcClientId: String?,
                                       token: OktaRestAPIToken,
                                       completion: @escaping (_ result: Result<AuthenticatorMetaDataModel, DeviceAuthenticatorError>) -> Void)

    func enrollAuthenticatorRequest(orgHost: URL,
                                    metadata: AuthenticatorMetaDataModel,
                                    deviceModel: DeviceSignalsModel,
                                    appSignals: [String: _OktaCodableArbitaryType]?,
                                    enrollingFactors: [EnrollingFactor],
                                    token: OktaRestAPIToken,
                                    completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void)

    func updateAuthenticatorRequest(orgHost: URL,
                                    enrollmentId: String,
                                    metadata: AuthenticatorMetaDataModel,
                                    deviceModel: DeviceSignalsModel,
                                    appSignals: [String: _OktaCodableArbitaryType]?,
                                    enrollingFactors: [EnrollingFactor],
                                    token: OktaRestAPIToken,
                                    completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void)

    func deleteAuthenticatorRequest(url: URL,
                                    token: OktaRestAPIToken,
                                    completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void)

    func verifyDeviceChallenge(verifyURL: URL,
                               httpHeaders: [String: String]?,
                               data: Data?,
                               completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void)

    func downloadOrgId(for orgURL: URL,
                       completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void)

    func pendingChallenge(with orgURL: URL,
                          authenticationToken: AuthToken,
                          completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void)
}

extension ServerAPIProtocol {

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
            .addHeader(name: HTTPHeaderConstants.authorizationHeader, value: authorizationHeaderValue(forAuthType: token.type, withToken: token.token))
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
        let allHTTPHeaders = httpHeaders ?? [HTTPHeaderConstants.contentTypeHeader: "application/json"]
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
                                          headers: [HTTPHeaderConstants.contentTypeHeader: "application/json"])
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
            .addHeader(name: HTTPHeaderConstants.authorizationHeader, value: authorizationHeaderValue(forAuthType: OktaAuthType.fromAuthToken(authenticationToken),
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
        if let error = result.error {
            let resultError = DeviceAuthenticatorError.networkError(error)
            self.logger.error(eventName: "API error", message: "error: \(resultError) for request at URL: \(url)")
            throw resultError
        }

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
