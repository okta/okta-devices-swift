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
    let client: HTTPClientProtocol
    let crypto: OktaSharedCryptoProtocol
    let logger: OktaLoggerProtocol
    let httpAuthorizationHeaderName = "Authorization"

    public init(client: HTTPClientProtocol,
                crypto: OktaSharedCryptoProtocol,
                logger: OktaLoggerProtocol) {
        self.client = client
        self.crypto = crypto
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
                                    completion: @escaping (_ result: Result<EnrollmentSummary, DeviceAuthenticatorError>) -> Void) {
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
            finalURL = orgHost.appendingPathComponent("/idp/authenticators")
        }
        logger.info(eventName: "Enrolling Authenticator", message: "URL: \(finalURL)")
        self.client
            .request(finalURL, method: .post, httpBody: enrollRequestJson, headers: [HTTPHeaderConstants.contentTypeHeader: "application/json"])
            .addHeader(name: HTTPHeaderConstants.authorizationHeader, value: authorizationHeaderValue(forAuthType: token.type, withToken: token.token))
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
                                    completion: @escaping (_ result: Result<EnrollmentSummary, DeviceAuthenticatorError>) -> Void) {
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
            completion(.failure(resultError))
            return
        }

        let finalURL: URL = orgHost.appendingPathComponent("/idp/authenticators/" + enrollmentId)
        logger.info(eventName: "Updating Authenticator", message: "URL: \(finalURL)")
        if case .none = token {
            completion(.failure(DeviceAuthenticatorError.internalError("No token provided for update enrollment request")))
            return
        }

        self.client
            .request(finalURL, method: .put, httpBody: enrollRequestJson, headers: [HTTPHeaderConstants.contentTypeHeader: "application/json"])
            .addHeader(name: HTTPHeaderConstants.authorizationHeader, value: authorizationHeaderValue(forAuthType: token.type, withToken: token.token))
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

    func buildEnrollmentRequestData(metadata: AuthenticatorMetaDataModel,
                                    deviceModel: DeviceSignalsModel,
                                    appSignals: [String: _OktaCodableArbitaryType]?,
                                    enrollingFactors: [EnrollingFactor]) throws -> Data {
        let methods: [EnrollAuthenticatorRequestModel.AuthenticatorMethods] = enrollingFactors.compactMap { factor in
            var capabilities: Capabilities?
            if factor.methodType == .push {
                var transactionTypes: [MethodSettingsModel.TransactionType] = [.LOGIN]
                if factor.transactionTypes.supportsCIBA {
                    transactionTypes.append(.CIBA)
                }
                capabilities = Capabilities(transactionTypes: transactionTypes)
            }
            let methodModel = EnrollAuthenticatorRequestModel.AuthenticatorMethods(type: factor.methodType,
                                                                                   pushToken: factor.methodType == .push ? factor.pushToken : nil,
                                                                                   apsEnvironment: factor.methodType == .push ? factor.apsEnvironment : nil,
                                                                                   supportUserVerification: factor.supportUserVerification,
                                                                                   isFipsCompliant: factor.isFipsCompliant,
                                                                                   keys: factor.keys,
                                                                                   capabilities: capabilities)

            return methodModel
        }
        let enrollRequestModel = EnrollAuthenticatorRequestModel(authenticatorId: metadata.id,
                                                                 key: metadata.key,
                                                                 device: deviceModel,
                                                                 appSignals: appSignals,
                                                                 methods: methods)
        return try JSONEncoder().encode(enrollRequestModel)
    }

    func createFactorMetadataBasedOnServerResponse(method: EnrolledAuthenticatorModel.AuthenticatorMethods,
                                                   metadata: AuthenticatorMetaDataModel,
                                                   enrollingFactorsData: [EnrollingFactor]) -> OktaFactor? {
        guard method.type == .push,
              let pushFactor = self.createEnrolledPushFactor(from: enrollingFactorsData,
                                                             metadata: metadata,
                                                             and: method) else {
            return nil
        }

        return pushFactor
    }

    func createEnrolledPushFactor(from factorModels: [EnrollingFactor],
                                  metadata: AuthenticatorMetaDataModel,
                                  and enrolledModel: EnrolledAuthenticatorModel.AuthenticatorMethods) -> OktaFactor? {
        guard let factorModel = factorModels.first(where: { $0.methodType == .push }),
              let proofOfPossessionKeyTag = factorModel.proofOfPossessionKeyTag else {
            return nil
        }

        let links = enrolledModel.links ?? EnrolledAuthenticatorModel.AuthenticatorMethods.Links(pending: nil)
        let factorMetadata = OktaFactorMetadataPush(id: enrolledModel.id,
                                                    proofOfPossessionKeyTag: proofOfPossessionKeyTag,
                                                    userVerificationKeyTag: factorModel.userVerificationKeyTag,
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
        let enrolledAuthenticatorModel = try JSONDecoder().decode(EnrolledAuthenticatorModel.self, from: resultJsonData)
        enrolledAuthenticatorModel.methods?.forEach({ method in
            let factor: OktaFactor?
            factor = self.createFactorMetadataBasedOnServerResponse(method: method,
                                                                    metadata: metadata,
                                                                    enrollingFactorsData: enrollingFactorsData)
            if let factor = factor {
                self.logger.info(eventName: "Enroll request", message: "Enrolled factor type: \(method.type.rawValue)")
                enrolledFactors.append(factor)
            } else {
                self.logger.error(eventName: "Enroll request", message: "Failed to enroll server method with type: \(method.type)")
            }
        })
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
