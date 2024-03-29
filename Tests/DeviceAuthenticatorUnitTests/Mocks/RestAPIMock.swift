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
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif
@testable import DeviceAuthenticator

class RestAPIMock: ServerAPIProtocol {
    typealias enrollAuthenticatorRequestType = (URL, AuthenticatorMetaDataModel, DeviceSignalsModel, [String : _OktaCodableArbitaryType]?, [EnrollingFactor], OktaRestAPIToken, (_ result: Result<EnrollmentSummary, DeviceAuthenticatorError>) -> Void) -> Void
    typealias downloadOrgIdType = (URL, (HTTPURLResult?, DeviceAuthenticatorError?) -> Void) -> Void
    typealias updateAuthenticatorRequestType = (URL, String, AuthenticatorMetaDataModel, DeviceSignalsModel, [String : _OktaCodableArbitaryType]?, [EnrollingFactor], OktaRestAPIToken, EnrollmentContext, @escaping (_ result: Result<EnrollmentSummary, DeviceAuthenticatorError>) -> Void) -> Void
    typealias downloadAuthenticatorMetadataType = (URL, String, OktaRestAPIToken, (Result<AuthenticatorMetaDataModel, DeviceAuthenticatorError>) -> Void) -> Void
    typealias deleteAuthenticatorRequestType = (AuthenticatorEnrollment, OktaRestAPIToken, (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void) -> Void
    typealias pendingChallengeRequestType = (URL, OktaRestAPIToken, (HTTPURLResult?, DeviceAuthenticatorError?) -> Void) -> Void
    typealias retrieveMaintenaceTokenType = (URL, String, [String], String,(Result<HTTPURLResult, DeviceAuthenticatorError>) -> Void) -> Void
    typealias updateDeviceTokenType = (String, URL, OktaRestAPIToken, String, (Result<Void, DeviceAuthenticatorError>) -> Void) -> Void
    typealias verifyDeviceChallengeType = (URL, [String: String]?, Data?, (HTTPURLResult?, DeviceAuthenticatorError?) -> Void) -> Void

    var enrollAuthenticatorRequestHook: enrollAuthenticatorRequestType?
    var downloadOrgIdTypeHook: downloadOrgIdType?
    var updateAuthenticatorRequestHook: updateAuthenticatorRequestType?
    var downloadAuthenticatorMetadataHook: downloadAuthenticatorMetadataType?
    var error: DeviceAuthenticatorError?
    var deleteAuthenticatorRequestHook: deleteAuthenticatorRequestType?
    var pendingChallengeRequestHook: pendingChallengeRequestType?
    var retrieveMaintenaceTokenHook: retrieveMaintenaceTokenType?
    var updateDeviceTokenHook: updateDeviceTokenType?
    var verifyDeviceChallengeHook: verifyDeviceChallengeType?

    let client: HTTPClientProtocol
    let logger: OktaLoggerProtocol
    let restAPI: ServerAPIProtocol

    init(client: HTTPClientProtocol,
         logger: OktaLoggerProtocol,
         defaultAPI: ServerAPIProtocol? = nil) {
        self.client = client
        self.logger = logger
        self.restAPI = defaultAPI ?? MyAccountServerAPI(client: client,
                                                        crypto: OktaCryptoManager(keychainGroupId: ExampleAppConstants.appGroupId,
                                                                                  logger: logger),
                                                        logger: logger)
    }

    func deleteAuthenticatorRequest(enrollment: AuthenticatorEnrollment, token: OktaRestAPIToken, completion: @escaping (HTTPURLResult?, DeviceAuthenticatorError?) -> Void) {
        if let deleteAuthenticatorRequestHook = deleteAuthenticatorRequestHook {
            deleteAuthenticatorRequestHook(enrollment, token, completion)
        } else {
            restAPI.deleteAuthenticatorRequest(enrollment: enrollment, token: token, completion: completion)
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
                                              completion: @escaping (Result<AuthenticatorMetaDataModel, DeviceAuthenticatorError>) -> Void) {
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

    public func enrollAuthenticatorRequest(orgHost: URL,
                                           metadata: AuthenticatorMetaDataModel,
                                           deviceModel: DeviceSignalsModel,
                                           appSignals: [String : _OktaCodableArbitaryType]?,
                                           enrollingFactors: [EnrollingFactor],
                                           token: OktaRestAPIToken,
                                           completion: @escaping (Result<EnrollmentSummary, DeviceAuthenticatorError>) -> Void) {
        if let oktaError = error {
            completion(.failure(oktaError))
            return
        }

        if let enrollAuthenticatorRequestHook = enrollAuthenticatorRequestHook {
            enrollAuthenticatorRequestHook(orgHost, metadata, deviceModel, appSignals, enrollingFactors, token, completion)
        } else {
            restAPI.enrollAuthenticatorRequest(orgHost: orgHost,
                                               metadata: metadata,
                                               deviceModel: deviceModel,
                                               appSignals: appSignals,
                                               enrollingFactors: enrollingFactors,
                                               token: token,
                                               completion: completion)
        }
    }

    public func updateAuthenticatorRequest(orgHost: URL,
                                           enrollmentId: String,
                                           metadata: AuthenticatorMetaDataModel,
                                           deviceModel: DeviceSignalsModel,
                                           appSignals: [String: _OktaCodableArbitaryType]?,
                                           enrollingFactors: [EnrollingFactor],
                                           token: OktaRestAPIToken,
                                           enrollmentContext: EnrollmentContext,
                                           completion: @escaping (Result<EnrollmentSummary, DeviceAuthenticatorError>) -> Void) {
        if let oktaError = error {
            completion(.failure(oktaError))
            return
        }

        if let updateAuthenticatorRequestHook = updateAuthenticatorRequestHook {
            updateAuthenticatorRequestHook(orgHost,
                                           enrollmentId,
                                           metadata,
                                           deviceModel,
                                           appSignals,
                                           enrollingFactors,
                                           token,
                                           enrollmentContext,
                                           completion)
        } else {
            restAPI.updateAuthenticatorRequest(orgHost: orgHost,
                                               enrollmentId: enrollmentId,
                                               metadata: metadata,
                                               deviceModel: deviceModel,
                                               appSignals: appSignals,
                                               enrollingFactors: enrollingFactors,
                                               token: token,
                                               enrollmentContext: enrollmentContext,
                                               completion: completion)
        }
    }

    public func pendingChallenge(with orgURL: URL, authenticationToken: OktaRestAPIToken, completion: @escaping (HTTPURLResult?, DeviceAuthenticatorError?) -> Void) {
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
        if let verifyDeviceChallengeHook = verifyDeviceChallengeHook {
            verifyDeviceChallengeHook(verifyURL, httpHeaders, data, completion)
        } else {
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

    func retrieveMaintenanceToken(with orgURL: URL,
                                  oidcClientId: String,
                                  scopes: [String],
                                  assertion: String,
                                  completion: @escaping (Result<HTTPURLResult, DeviceAuthenticatorError>) -> Void) {
        if let retrieveMaintenaceTokenHook = retrieveMaintenaceTokenHook {
            retrieveMaintenaceTokenHook(orgURL, oidcClientId, scopes, assertion, completion)
        } else {
            restAPI.retrieveMaintenanceToken(with: orgURL,
                                             oidcClientId: oidcClientId,
                                             scopes: scopes,
                                             assertion: assertion,
                                             completion: completion)
        }
    }

    public func updateDeviceToken(_ deviceToken: String,
                                  orgURL: URL,
                                  token: OktaRestAPIToken,
                                  enrollmentId: String,
                                  completion: @escaping (Result<Void, DeviceAuthenticatorError>) -> Void) {
        if let updateDeviceTokenHook = updateDeviceTokenHook {
            updateDeviceTokenHook(deviceToken, orgURL, token, enrollmentId, completion)
        } else {
            restAPI.updateDeviceToken(deviceToken, orgURL: orgURL, token: token, enrollmentId: enrollmentId, completion: completion)
        }
    }
}
