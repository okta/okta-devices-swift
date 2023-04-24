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
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif

class MyAccountServerAPI: ServerAPIProtocol {
    let client: HTTPClientProtocol
    let crypto: OktaSharedCryptoProtocol
    let logger: OktaLoggerProtocol
    let acceptHeaderValue: String
    let jsonPatchHeaderValue: String

    public init(client: HTTPClientProtocol,
                crypto: OktaSharedCryptoProtocol,
                logger: OktaLoggerProtocol) {
        self.client = client
        self.crypto = crypto
        self.logger = logger
        acceptHeaderValue = "application/json" + "; okta-version=\(MyAccountAPI.protocolVersion)"
        jsonPatchHeaderValue = "application/merge-patch+json" + "; okta-version=\(MyAccountAPI.protocolVersion)"
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
                    let policiesModel = try JSONDecoder().decode([MyAccountAPI.PolicyAPIResponseModel].self, from: metaDataJson)
                    guard let policyModel = policiesModel.first else {
                        completion(Result.failure(DeviceAuthenticatorError.genericError("Authenticator policy not found")))
                        return
                    }
                    let enrollLink = AuthenticatorMetaDataModel.Links.EnrollLink(href: policyModel.appAuthenticatorEnrollEndpoint)
                    let links = AuthenticatorMetaDataModel.Links(enroll: enrollLink,
                                                                 logos: nil)
                    let authenticatorSettings = AuthenticatorSettingsModel(appInstanceId: nil,
                                                                           userVerification: policyModel.settings?.userVerification,
                                                                           userVerificationMethods: policyModel.settings?.userVerificationMethods,
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

    func enrollAuthenticatorRequest(orgHost: URL,
                                    metadata: AuthenticatorMetaDataModel,
                                    deviceModel: DeviceSignalsModel,
                                    appSignals: [String: _OktaCodableArbitaryType]?,
                                    enrollingFactors: [EnrollingFactor],
                                    token: OktaRestAPIToken,
                                    completion: @escaping (Result<EnrollmentSummary, DeviceAuthenticatorError>) -> Void) {
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
            completion(.failure(resultError))
            return
        }

        let finalURL: URL
        if let enrollLink = metadata._links.enroll?.href,
            let enrollURL = URL(string: enrollLink) {
            finalURL = enrollURL
        } else {
            finalURL = orgHost.appendingPathComponent("/idp/myaccount/app-authenticators")
        }
        logger.info(eventName: "Enrolling Authenticator", message: "URL: \(finalURL)")
        self.client
            .request(finalURL, method: .post, httpBody: enrollRequestJson, headers: [HTTPHeaderConstants.contentTypeHeader: "application/json"])
            .addHeader(name: HTTPHeaderConstants.authorizationHeader, value: authorizationHeaderValue(forAuthType: token.type, withToken: token.token))
            .addHeader(name: HTTPHeaderConstants.acceptHeader, value: acceptHeaderValue)
            .response { result in
                if let error = result.error {
                    let resultError = DeviceAuthenticatorError.networkError(error)
                    self.logger.error(eventName: "API error", message: "error: \(resultError) for request at URL: \(finalURL)")
                    completion(.failure(resultError))
                    return
                }

                do {
                    try self.validateResult(result, for: finalURL)
                    let enrollmentSummary = try self.createEnrollmentSummary(from: result,
                                                                             metadata: metadata,
                                                                             enrollingFactorsData: enrollingFactors)
                    completion(.success(enrollmentSummary))
                } catch let oktaError as DeviceAuthenticatorError {
                    completion(Result.failure(oktaError))
                    return
                } catch {
                    let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
                    self.logger.error(eventName: "API error", message: "error: \(resultError) for request at URL: \(finalURL)")
                    completion(Result.failure(resultError))
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
                                    enrollmentContext: EnrollmentContext,
                                    completion: @escaping (Result<EnrollmentSummary, DeviceAuthenticatorError>) -> Void) {
        if case .none = token {
            completion(.failure(DeviceAuthenticatorError.internalError("No token provided for update enrollment request")))
            return
        }

        let finalURL = orgHost.appendingPathComponent("/idp/myaccount/app-authenticators/\(enrollmentId)")
        logger.info(eventName: "Updating Authenticator", message: "URL: \(finalURL)")
        guard let pushMethod = enrollingFactors.first(where: { $0.methodType == .push }) else {
            completion(.failure(.internalError("Push factor data not found in update request")))
            return
        }

        var capabilitiesModel: CapabilitiesModel?
        if let transactionTypes = enrollmentContext.transactionTypes {
            var transactionTypesRequestModel: [MethodSettingsModel.TransactionType] = [.LOGIN]
            if transactionTypes.contains(.ciba) {
                transactionTypesRequestModel.append(.CIBA)
            }
            capabilitiesModel = CapabilitiesModel(transactionTypes: transactionTypesRequestModel)
        }

        let pushTokenValue: String?
        if pushMethod.pushToken == nil || pushMethod.pushToken?.isEmpty == true {
            pushTokenValue = nil
        } else {
            pushTokenValue = pushMethod.pushToken
        }

        var keys: SigningKeysModel?
        if enrollmentContext.enrollBiometricKey != nil {
            keys = SigningKeysModel(proofOfPossession: nil,
                                    userVerification: pushMethod.keys?.userVerification,
                                    userVerificationBioOrPin: nil)
        }

        let pushUpdateModel = MyAccountAPI.MethodUpdateRequestModel.MethodsModel.PushMethodModel(
                                                                                    pushToken: pushTokenValue,
                                                                                    keys: keys,
                                                                                    capabilities: capabilitiesModel)
        let updateRequestModel = MyAccountAPI.MethodUpdateRequestModel(methods: MyAccountAPI.MethodUpdateRequestModel.MethodsModel(push: pushUpdateModel))
        let updateRequestJson: Data
        do {
            logger.info(eventName: "Update request", message: "Building update request")
            updateRequestJson = try JSONEncoder().encode(updateRequestModel)
        } catch {
            let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
            logger.error(eventName: "Update request", message: "Error: \(resultError)")
            completion(.failure(resultError))
            return
        }

        self.client
            .request(finalURL, method: .patch, httpBody: updateRequestJson, headers: [HTTPHeaderConstants.contentTypeHeader: jsonPatchHeaderValue])
            .addHeader(name: HTTPHeaderConstants.authorizationHeader, value: authorizationHeaderValue(forAuthType: token.type, withToken: token.token))
            .addHeader(name: HTTPHeaderConstants.acceptHeader, value: jsonPatchHeaderValue)
            .response { (result) in
                if let error = result.error {
                    let resultError = DeviceAuthenticatorError.networkError(error)
                    self.logger.error(eventName: "API error", message: "\(resultError), for request at URL: \(finalURL)")
                    completion(.failure(resultError))
                    return
                }

                do {
                    try self.validateResult(result, for: finalURL)
                    let enrollmentSummary = try self.createEnrollmentSummary(from: result,
                                                                             metadata: metadata,
                                                                             enrollingFactorsData: enrollingFactors)
                    completion(.success(enrollmentSummary))
                } catch let oktaError as DeviceAuthenticatorError {
                    completion(Result.failure(oktaError))
                    return
                } catch {
                    let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
                    self.logger.error(eventName: "API error", message: "error: \(resultError) for request at URL: \(finalURL)")
                    completion(Result.failure(resultError))
                    return
                }
            }
    }

    func pendingChallenge(with orgURL: URL,
                          authenticationToken: OktaRestAPIToken,
                          completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void) {
        self.client
        .request(orgURL)
        .addHeader(name: HTTPHeaderConstants.authorizationHeader, value: authorizationHeaderValue(forAuthType: authenticationToken.type,
                                                                                                  withToken: authenticationToken.token))
            .addHeader(name: HTTPHeaderConstants.acceptHeader, value: acceptHeaderValue)
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

    func deleteAuthenticatorRequest(enrollment: AuthenticatorEnrollment,
                                    token: OktaRestAPIToken,
                                    completion: @escaping (_ result: HTTPURLResult?, _ error: DeviceAuthenticatorError?) -> Void) {
        let url = enrollment.organization.url.appendingPathComponent("/idp/myaccount/app-authenticators/" + enrollment.enrollmentId)
        logger.info(eventName: "Deleting Authenticator", message: "URL: \(url)")
        if case .none = token {
            completion(nil, DeviceAuthenticatorError.internalError("No token provided for update enrollment request"))
            return
        }

        self.client
            .request(url, method: .delete, httpBody: nil)
            .addHeader(name: HTTPHeaderConstants.authorizationHeader, value: authorizationHeaderValue(forAuthType: token.type, withToken: token.token))
            .addHeader(name: HTTPHeaderConstants.acceptHeader, value: acceptHeaderValue)
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

    func buildEnrollmentRequestData(metadata: AuthenticatorMetaDataModel,
                                    deviceModel: DeviceSignalsModel,
                                    appSignals: [String: _OktaCodableArbitaryType]?,
                                    enrollingFactors: [EnrollingFactor]) throws -> Data {
        var methods = MyAccountAPI.AuthenticatorRequestModel.AuthenticatorMethods(push: nil)
        enrollingFactors.forEach { factor in
            if factor.methodType == .push {
                guard let keys = factor.keys,
                      let pushToken = factor.pushToken else {
                    self.logger.error(eventName: "Building push factor model", message: "Keys or push token are missing")
                    return
                }
                var transactionTypes: [MethodSettingsModel.TransactionType] = [.LOGIN]
                if factor.transactionTypes?.supportsCIBA == true {
                    transactionTypes.append(.CIBA)
                }
                let capabilities = CapabilitiesModel(transactionTypes: transactionTypes)
                let pushMethod = MyAccountAPI.AuthenticatorRequestModel.AuthenticatorMethods.PushMethod(pushToken: pushToken,
                                                                                                        apsEnvironment: factor.apsEnvironment ?? .production,
                                                                                                        capabilities: capabilities,
                                                                                                        keys: keys)
                methods.push = pushMethod
            }
        }

        let enrollRequestModel = MyAccountAPI.AuthenticatorRequestModel(authenticatorId: metadata.id,
                                                                        device: deviceModel,
                                                                        appSignals: appSignals,
                                                                        methods: methods)
        return try JSONEncoder().encode(enrollRequestModel)
    }

    func createFactorMetadataBasedOnServerResponse(method: MyAccountAPI.AuthenticatorResponseModel.AuthenticatorMethods.PushMethod,
                                                   metadata: AuthenticatorMetaDataModel,
                                                   enrollingFactorsData: [EnrollingFactor]) -> OktaFactor? {
        let pushFactor = self.createEnrolledPushFactor(from: enrollingFactorsData,
                                                       metadata: metadata,
                                                       and: method)
        return pushFactor
    }

    func createEnrolledPushFactor(from factorModels: [EnrollingFactor],
                                  metadata: AuthenticatorMetaDataModel,
                                  and enrolledModel: MyAccountAPI.AuthenticatorResponseModel.AuthenticatorMethods.PushMethod) -> OktaFactor? {
        guard let factorModel = factorModels.first(where: { $0.methodType == .push }),
              let proofOfPossessionKeyTag = factorModel.proofOfPossessionKeyTag else {
            return nil
        }

        let links = enrolledModel.links ?? MyAccountAPI.AuthenticatorResponseModel.AuthenticatorMethods.PushMethod.Links(pending: nil)
        let factorMetadata = OktaFactorMetadataPush(id: enrolledModel.id,
                                                    proofOfPossessionKeyTag: proofOfPossessionKeyTag,
                                                    userVerificationKeyTag: factorModel.userVerificationKeyTag,
                                                    userVerificationBioOrPinKeyTag: factorModel.userVerificationBioOrPinKeyTag,
                                                    links: OktaFactorMetadataPush.Links(pendingLink: links.pending?.href),
                                                    transactionTypes: factorModel.transactionTypes)
        let factor = OktaFactorPush(factorData: factorMetadata,
                                    cryptoManager: crypto,
                                    restAPIClient: self,
                                    logger: logger)
        return factor
    }

    func createEnrollmentSummary(from result: HTTPURLResult,
                                 metadata: AuthenticatorMetaDataModel,
                                 enrollingFactorsData: [EnrollingFactor]) throws -> EnrollmentSummary {
        guard result.data != nil,
              let resultJsonData = result.data,
              !resultJsonData.isEmpty else {
            let resultError = DeviceAuthenticatorError.internalError("Server replied with an empty data")
            self.logger.error(eventName: "Enroll request", message: "Download metadata error - \(resultError)")
            throw resultError
        }

        var enrolledFactors: [OktaFactor] = []
        let enrolledAuthenticatorModel = try JSONDecoder().decode(MyAccountAPI.AuthenticatorResponseModel.self, from: resultJsonData)
        if let pushMethod = enrolledAuthenticatorModel.methods.push {
            let factor = self.createFactorMetadataBasedOnServerResponse(method: pushMethod,
                                                                        metadata: metadata,
                                                                        enrollingFactorsData: enrollingFactorsData)
            if let factor = factor {
                self.logger.info(eventName: "Enroll request", message: "Enrolled push factor")
                enrolledFactors.append(factor)
            } else {
                self.logger.error(eventName: "Enroll request", message: "Failed to enroll push factor")
            }
        }
        guard !enrolledFactors.isEmpty else {
            let jsonString = String(data: resultJsonData, encoding: .utf8) ?? ""
            let resultError = DeviceAuthenticatorError.internalError("Server replied with unexpected enrollment data")
            self.logger.error(eventName: "Enroll request", message: "\(resultError)\n\(jsonString)")
            throw resultError
        }
        let enrollmentSummary = EnrollmentSummary(enrollmentId: enrolledAuthenticatorModel.id,
                                                  userId: enrolledAuthenticatorModel.user.id,
                                                  username: enrolledAuthenticatorModel.user.username,
                                                  deviceId: enrolledAuthenticatorModel.device.id,
                                                  clientInstanceId: enrolledAuthenticatorModel.device.clientInstanceId,
                                                  creationDate: enrolledAuthenticatorModel.creationDate,
                                                  factors: enrolledFactors)
        return enrollmentSummary
    }
}
