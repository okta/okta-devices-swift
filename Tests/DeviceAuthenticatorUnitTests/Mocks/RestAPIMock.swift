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
// swiftlint:disable force_try
import Foundation
@testable import OktaLogger
@testable import DeviceAuthenticator

class RestAPIMock: ServerAPIProtocol {

    typealias enrollAuthenticatorRequestType = (URL, Data, OktaRestAPIToken, (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void) -> Void
    typealias downloadOrgIdType = (URL, (HTTPURLResult?, DeviceAuthenticatorError?) -> Void) -> Void
    typealias updateAuthenticatorRequestType = (URL, Data, OktaRestAPIToken, @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void) -> Void
    typealias downloadAuthenticatorMetadataType = (URL, String, OktaRestAPIToken, (HTTPURLResult?, DeviceAuthenticatorError?) -> Void) -> Void
    typealias deleteAuthenticatorRequestType = (URL, OktaRestAPIToken, (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void) -> Void
    typealias pendingChallengeRequestType = (URL, AuthToken, (HTTPURLResult?, DeviceAuthenticatorError?) -> Void) -> Void

    var enrollAuthenticatorRequestHook: enrollAuthenticatorRequestType?
    var downloadOrgIdTypeHook: downloadOrgIdType?
    var updateAuthenticatorRequestHook: updateAuthenticatorRequestType?
    var downloadAuthenticatorMetadataHook: downloadAuthenticatorMetadataType?
    var error: DeviceAuthenticatorError?
    var deleteAuthenticatorRequestHook: deleteAuthenticatorRequestType?
    var pendingChallengeRequestHook: pendingChallengeRequestType?

    let client: HTTPClientProtocol
    let logger: OktaLoggerProtocol
    let restAPI: ServerAPIProtocol

    init(client: HTTPClientProtocol,
         logger: OktaLoggerProtocol,
         defaultAPI: ServerAPIProtocol? = nil) {
        self.client = client
        self.logger = logger
        self.restAPI = defaultAPI ?? LegacyServerAPI(client: client, logger: logger)
    }

    func deleteAuthenticatorRequest(url: URL, token: OktaRestAPIToken, completion: @escaping (HTTPURLResult?, DeviceAuthenticatorError?) -> Void) {
        if let deleteAuthenticatorRequestHook = deleteAuthenticatorRequestHook {
            deleteAuthenticatorRequestHook(url, token, completion)
        } else {
            restAPI.deleteAuthenticatorRequest(url: url, token: token, completion: completion)
        }
    }

    public func downloadOrgId(for orgURL: URL, completion: @escaping (HTTPURLResult?, DeviceAuthenticatorError?) -> Void) {
        if let downloadOrgIdTypeHook = downloadOrgIdTypeHook {
            downloadOrgIdTypeHook(orgURL, completion)
        } else {
            restAPI.downloadOrgId(for: orgURL, completion: completion)
        }
    }

    public func downloadAuthenticatorMetadata(orgHost: URL,
                                              authenticatorKey: String,
                                              oidcClientId: String?,
                                              token: OktaRestAPIToken,
                                              completion: @escaping (HTTPURLResult?, DeviceAuthenticatorError?) -> Void) {
        if let downloadAuthenticatorMetadataHook = downloadAuthenticatorMetadataHook {
            downloadAuthenticatorMetadataHook(orgHost, authenticatorKey, token, completion)
        } else {
            restAPI.downloadAuthenticatorMetadata(orgHost: orgHost,
                                                  authenticatorKey: authenticatorKey,
                                                  oidcClientId: oidcClientId,
                                                  token: token,
                                                  completion: completion)
        }
    }

    public func enrollAuthenticatorRequest(enrollURL: URL, data: Data,
                                           token: OktaRestAPIToken,
                                           completion: @escaping (HTTPURLResult?, DeviceAuthenticatorError?) -> Void) {
        if let oktaError = error {
            completion(nil, oktaError)
            return
        }

        if let enrollAuthenticatorRequestHook = enrollAuthenticatorRequestHook {
            enrollAuthenticatorRequestHook(enrollURL, data, token, completion)
        } else {
            restAPI.enrollAuthenticatorRequest(enrollURL: enrollURL,
                                               data: data,
                                               token: token,
                                               completion: completion)
        }
    }

    public func updateAuthenticatorRequest(url: URL, data: Data, token: OktaRestAPIToken, completion: @escaping (HTTPURLResult?, DeviceAuthenticatorError?) -> Void) {
        if let oktaError = error {
            completion(nil, oktaError)
            return
        }

        if let updateAuthenticatorRequestHook = updateAuthenticatorRequestHook {
            updateAuthenticatorRequestHook(url, data, token, completion)
        } else {
            restAPI.updateAuthenticatorRequest(url: url, data: data, token: token, completion: completion)
        }
    }

    public func pendingChallenge(with orgURL: URL, authenticationToken: AuthToken, completion: @escaping (HTTPURLResult?, DeviceAuthenticatorError?) -> Void) {
        if let pendingChallengeRequestHook = pendingChallengeRequestHook {
            pendingChallengeRequestHook(orgURL, authenticationToken, completion)
        } else {
            restAPI.pendingChallenge(with: orgURL, authenticationToken: authenticationToken, completion: completion)
        }
    }

    public func verifyDeviceChallenge(verifyURL: URL,
                                      httpHeaders: [String: String]? = nil,
                                      data: Data?,
                                      completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void) {
        if let oktaError = error {
            completion(nil, oktaError)
        } else {
            var paramsToVerify: [String: Any] = ["verifyURL": verifyURL.absoluteString]
            paramsToVerify["httpHeaders"] = httpHeaders
            paramsToVerify["data"] = data?.base64EncodedString()
            let data = try! JSONSerialization.data(withJSONObject: paramsToVerify, options: .prettyPrinted)
            let urlResponse = HTTPURLResponse()
            let resut = HTTPURLResult(request: nil, response: urlResponse, data: data)
            completion(resut, nil)
        }
    }
}
