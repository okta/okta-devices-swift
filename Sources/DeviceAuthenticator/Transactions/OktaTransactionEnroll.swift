/*
* Copyright (c) 2019-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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
import OktaLogger

struct EnrollmentContext {
    let accessToken: String?
    let activationToken: String?
    let orgHost: URL
    let authenticatorKey: String
    let oidcClientId: String?
    let deviceSignals: DeviceSignals?
    let applicationSignals: [String: _OktaCodableArbitaryType]?
    let biometricSettings: BiometricEnrollmentSettings?
    let pushToken: DeviceToken
    let enrollBiometricKey: Bool?

    init(accessToken: String?,
         activationToken: String?,
         orgHost: URL,
         authenticatorKey: String,
         oidcClientId: String?,
         pushToken: DeviceToken,
         enrollBiometricKey: Bool?,
         deviceSignals: DeviceSignals?,
         biometricSettings: BiometricEnrollmentSettings?,
         applicationSignals: [String: _OktaCodableArbitaryType]? = nil) {
        self.accessToken = accessToken
        self.activationToken = activationToken
        self.orgHost = orgHost
        self.oidcClientId = oidcClientId
        self.authenticatorKey = authenticatorKey
        self.pushToken = pushToken
        self.enrollBiometricKey = enrollBiometricKey
        self.deviceSignals = deviceSignals
        self.biometricSettings = biometricSettings ?? BiometricEnrollmentSettings.default
        self.applicationSignals = applicationSignals
    }
}

class OktaTransactionEnroll: OktaTransaction {
    let jwkGenerator: OktaJWKGenerator
    let restAPI: OktaRestAPI
    let enrollmentContext: EnrollmentContext
    let enrollmentToUpdate: AuthenticatorEnrollment?
    let applicationConfig: ApplicationConfig
    let authenticatorPolicy: AuthenticatorPolicy?

    var metaData: AuthenticatorMetaDataModel!
    var deviceEnrollment: OktaDeviceEnrollment?
    var orgId: String!
    var factorsKeyTags: [String] = []
    var clientInstanceKeyTag: String?

    struct EnrollingFactor {
        let proofOfPossessionKeyTag: String?
        let userVerificationKeyTag: String?
        let methodType: AuthenticationMethodType
        let requestModel: EnrollAuthenticatorRequestModel.AuthenticatorMethods?
    }

    init(storageManager: PersistentStorageProtocol,
         cryptoManager: OktaSharedCryptoProtocol,
         restAPI: OktaRestAPI,
         enrollmentContext: EnrollmentContext,
         enrollmentToUpdate: AuthenticatorEnrollment? = nil,
         jwkGenerator: OktaJWKGenerator?,
         jwtGenerator: OktaJWTGenerator?,
         applicationConfig: ApplicationConfig,
         logger: OktaLoggerProtocol,
         authenticatorPolicy: AuthenticatorPolicy? = nil) {
        self.jwkGenerator = jwkGenerator ?? OktaJWKGenerator(logger: logger)
        self.restAPI = restAPI
        self.enrollmentContext = enrollmentContext
        self.enrollmentToUpdate = enrollmentToUpdate
        self.applicationConfig = applicationConfig
        self.authenticatorPolicy = authenticatorPolicy
        super.init(loginHint: nil,
                   storageManager: storageManager,
                   cryptoManager: cryptoManager,
                   jwtGenerator: jwtGenerator,
                   logger: logger)
    }

    func rollback() {
        logger.info(eventName: logEventName, message: "Rolling back transaction")
        factorsKeyTags.forEach { tag in
             _ = cryptoManager.delete(keyPairWith: tag)
        }

        if let clientInstanceKeyTag = clientInstanceKeyTag {
            _ = cryptoManager.delete(keyPairWith: clientInstanceKeyTag)
        }
    }

    func cleanupOnSuccess() {
        logger.info(eventName: logEventName, message: "Running cleanupOnSuccess function")
        if let enrollUserVerificationKey = enrollmentContext.enrollBiometricKey {
            if !enrollUserVerificationKey {
                enrollmentToUpdate?.enrolledFactors.forEach({ factor in
                    factor.removeUserVerificationKey()
                })
            }
        }
    }

    func enroll(onMetadataReceived: ((AuthenticatorMetaDataModel) -> Void)? = nil,
                onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        if let existingEnrollment = enrollmentToUpdate {
            logger.info(eventName: logEventName, message: "Starting update enrollment process")
            if let authenticatorPolicy = self.authenticatorPolicy {
                logger.info(eventName: logEventName, message: "Continue update enrollment process with provided policy id - \(authenticatorPolicy.metadata.id)")
                continueEnrollment(with: existingEnrollment.organization.id,
                                   metaData: authenticatorPolicy.metadata,
                                   onCompletion: onCompletion)
                return
            } else {
                logger.warning(eventName: logEventName, message: "Policy not provided. Trying to download it from server")
                if enrollmentContext.accessToken == nil && enrollmentContext.activationToken == nil {
                    generateAuthenticationJWTString(for: existingEnrollment) { authenticationToken, error in
                        if let authenticationToken = authenticationToken {
                            let token = OktaRestAPIToken(authenticationToken: authenticationToken,
                                                         accessToken: self.enrollmentContext.accessToken)
                            self.downloadMetadata(orgId: existingEnrollment.organization.id, token: token, onMetadataReceived: onMetadataReceived, onCompletion: onCompletion)
                        } else if let error = error {
                            onCompletion(Result.failure(error))
                        } else {
                            onCompletion(Result.failure(DeviceAuthenticatorError.internalError("Failed to generate authentication token")))
                        }
                    }
                } else {
                    let token = OktaRestAPIToken(authenticationToken: nil,
                                                 accessToken: self.enrollmentContext.accessToken,
                                                 activationToken: enrollmentContext.activationToken)
                    self.downloadMetadata(orgId: existingEnrollment.organization.id, token: token, onMetadataReceived: onMetadataReceived, onCompletion: onCompletion)
                }
                return
            }
        }

        logger.info(eventName: logEventName, message: "Starting new enrollment process")

        getOrgId { orgId, error in

            guard let orgId = orgId else {
                let resultError = error ?? DeviceAuthenticatorError.genericError("Failed to fetch organization data")
                self.logger.error(eventName: self.logEventName, message: "Download orgID error - \(resultError)")
                onCompletion(Result.failure(resultError))
                return
            }

            let token = OktaRestAPIToken(accessToken: self.enrollmentContext.accessToken,
                                         activationToken: self.enrollmentContext.activationToken)
            self.downloadMetadata(orgId: orgId, token: token, onMetadataReceived: onMetadataReceived, onCompletion: onCompletion)
        }
    }

    func getOrgId(onCompletion: @escaping (String?, DeviceAuthenticatorError?) -> Void) {
        if let orgId = enrollmentToUpdate?.organization.id {
            onCompletion(orgId, nil)
            return
        }

        restAPI.downloadOrgId(for: enrollmentContext.orgHost) { result, downloadError in
            var orgId: String? = nil
            var errorToReturn: DeviceAuthenticatorError? = downloadError
            defer {
                onCompletion(orgId, errorToReturn)
            }

            guard downloadError == nil else {
                return
            }

            guard let data = result?.data else {
                errorToReturn = DeviceAuthenticatorError.internalError("No data provided from server")
                self.logger.error(eventName: self.logEventName, message: errorToReturn?.errorDescription)
                return
            }

            do {
                let metaData = (try JSONSerialization.jsonObject(with: data, options: [])) as? [String: Any]
                orgId = metaData?["id"] as? String
            } catch {
                errorToReturn = DeviceAuthenticatorError.oktaError(from: error)
            }
        }
    }

    func downloadMetadata(orgId: String,
                          token: OktaRestAPIToken,
                          onMetadataReceived: ((AuthenticatorMetaDataModel) -> Void)? = nil,
                          onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        self.restAPI.downloadAuthenticatorMetadata(orgHost: enrollmentContext.orgHost,
                                                   authenticatorKey: enrollmentContext.authenticatorKey,
                                                   oidcClientId: enrollmentContext.oidcClientId,
                                                   token: token) { result, error in
            if let error = error {
                self.logger.error(eventName: self.logEventName, message: "\(error)")
                onCompletion(Result.failure(error))
                return
            }

            guard let result = result,
                  let metaDataJson = result.data else {
                    let resultError = DeviceAuthenticatorError.internalError("Server replied with an empty data")
                    self.logger.error(eventName: self.logEventName, message: "Download metadata error - \(resultError)")
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
                let authenticatorPolicy = AuthenticatorPolicy(metadata: metaData)
                try self.storageManager.storeAuthenticatorPolicy(authenticatorPolicy, orgId: orgId)
            } catch {
                let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
                self.logger.error(eventName: self.logEventName, message: "Download metadata error - \(resultError)")
                onCompletion(Result.failure(resultError))
                return
            }

            onMetadataReceived?(metaData)
            self.continueEnrollment(with: orgId,
                                    metaData: metaData,
                                    onCompletion: onCompletion)
        }
    }

    func continueEnrollment(with orgId: String,
                            metaData: AuthenticatorMetaDataModel,
                            onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        self.orgId = orgId
        self.metaData = metaData
        if enrollmentToUpdate != nil {
            // fetch device enrollment only for update authenticator cases
            self.deviceEnrollment = try? self.storageManager.deviceEnrollmentByOrgId(orgId)
        }
        let enrolledFactors: [EnrollingFactor]
        let enrollRequestJson: Data
        do {
            // #1: Build factors based on metadata requirements
            enrolledFactors = try self.enrollFactors()

            // #2: Build request model
            enrollRequestJson = try self.buildEnrollmentModelData(factorsMetaData: enrolledFactors)
        } catch let oktaError as DeviceAuthenticatorError {
            logger.error(eventName: self.logEventName, message: "Error: \(oktaError)")
            onCompletion(Result.failure(oktaError))
            return
        } catch {
            let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
            logger.error(eventName: self.logEventName, message: "Error: \(resultError)")
            onCompletion(Result.failure(resultError))
            return
        }

        // #3: Send RestAPI request
        if let enrollmentToUpdate = enrollmentToUpdate {
            doUpdate(enrollData: enrollRequestJson,
                     enrollment: enrollmentToUpdate,
                     factorsMetaData: enrolledFactors,
                     onCompletion: onCompletion)
        } else {
            doEnrollment(enrollData: enrollRequestJson,
                         factorsMetaData: enrolledFactors,
                         onCompletion: onCompletion)
        }
    }

    func buildEnrollmentModelData(factorsMetaData: [EnrollingFactor]) throws -> Data {
        logger.info(eventName: self.logEventName, message: "Building enrollment request")
        let deviceModel = buildDeviceModelData(customDeviceSignals: enrollmentContext.deviceSignals)
        let methods = factorsMetaData.compactMap { factor in
            return factor.requestModel
        }
        let enrollRequestModel = EnrollAuthenticatorRequestModel(authenticatorId: metaData.id,
                                                                 key: enrollmentContext.authenticatorKey,
                                                                 device: deviceModel,
                                                                 appSignals: enrollmentContext.applicationSignals,
                                                                 methods: methods)
        do {
            let enrollRequestJson = try JSONEncoder().encode(enrollRequestModel)
            logger.info(eventName: self.logEventName, message: nil)
            return enrollRequestJson
        } catch {
            let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
            logger.error(eventName: self.logEventName, message: "Error: \(resultError)")
            throw resultError
        }
    }

    func doEnrollment(enrollData: Data,
                      factorsMetaData: [EnrollingFactor],
                      onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        logger.info(eventName: self.logEventName, message: "Sending enrollment request")
        let finalURL: URL
        if let enrollLink = metaData._links.enroll?.href,
            let enrollURL = URL(string: enrollLink) {
            finalURL = enrollURL
        } else {
            finalURL = enrollmentContext.orgHost.appendingPathComponent("/idp/authenticators")
        }

        let token = OktaRestAPIToken(accessToken: enrollmentContext.accessToken,
                                     activationToken: enrollmentContext.activationToken)
        self.restAPI.enrollAuthenticatorRequest(enrollURL: finalURL,
                                                data: enrollData,
                                                token: token) { result, error in
            self.handleServerResult(result, error: error, factorsMetaData: factorsMetaData, andCall: onCompletion)
        }
    }

    func doUpdate(enrollData: Data,
                  enrollment: AuthenticatorEnrollment,
                  factorsMetaData: [EnrollingFactor],
                  onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        let finalURL: URL = enrollmentContext.orgHost.appendingPathComponent("/idp/authenticators/" + enrollment.enrollmentId)

        let updateRequest: (String?) -> Void = { authenticationToken in
            let token = OktaRestAPIToken(authenticationToken: authenticationToken,
                                         accessToken: self.enrollmentContext.accessToken)
            self.restAPI.updateAuthenticatorRequest(url: finalURL,
                                                    data: enrollData,
                                                    token: token) { result, error in
                self.handleServerResult(result, error: error, factorsMetaData: factorsMetaData, andCall: onCompletion)
            }
        }

        if enrollmentContext.accessToken == nil {
            generateAuthenticationJWTString(for: enrollment) { authenticationToken, error in
                if let authenticationToken = authenticationToken {
                    updateRequest(authenticationToken)
                } else if let error = error {
                    onCompletion(Result.failure(error))
                } else {
                    onCompletion(Result.failure(DeviceAuthenticatorError.internalError("Failed to generate authentication token")))
                }
            }
        } else {
            updateRequest(nil)
        }
    }

    func enrollFactors() throws -> [EnrollingFactor] {
        logger.info(eventName: self.logEventName, message: "Enroll factors called")
        var authenticatorMethods: [EnrollingFactor] = []
        do {
            try metaData._embedded.methods.forEach({ method in
                switch method.type {
                case .push:
                    if let pushMethod = try enrollPushFactor(serverMethod: method) {
                        authenticatorMethods.append(pushMethod)
                    }
                case .unknown(_):
                    logger.error(eventName: self.logEventName, message: "Unknown authenticatorType")
                default:
                    logger.info(eventName: self.logEventName, message: "Skipping enrollment of factor type: \(method)")
                }
            })
            guard !authenticatorMethods.isEmpty else {
                let resultError = DeviceAuthenticatorError.noVerificationMethodsToEnroll
                logger.error(eventName: self.logEventName, message: "Error: \(resultError)")
                throw resultError
            }

            logger.info(eventName: self.logEventName, message: "\(authenticatorMethods)")
            return authenticatorMethods
        } catch let oktaError as DeviceAuthenticatorError {
            logger.error(eventName: self.logEventName, message: "Error: \(oktaError)")
            throw oktaError
        } catch let enryptionError as SecurityError {
            let resultError = DeviceAuthenticatorError.securityError(enryptionError)
            logger.error(eventName: self.logEventName, message: "Error: \(resultError)")
            throw resultError
        } catch {
            let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
            logger.error(eventName: self.logEventName, message: "Error: \(resultError)")
            throw resultError
        }
    }

    func registerKey(with algorithm: Algorithm,
                     keyTag: String,
                     reuseKey: Bool = false,
                     useBiometrics: Bool = false,
                     biometricSettings: BiometricEnrollmentSettings? = nil) throws -> [String: _OktaCodableArbitaryType] {
        var keyProtection = "SOFTWARE"
        var useSecureEnclave = false
        if OktaEnvironment.canUseSecureEnclave() {
            keyProtection = "HARDWARE"
            useSecureEnclave = true
        }

        let secKey: SecKey
        if reuseKey,
           let existingKey = self.cryptoManager.get(keyOf: .publicKey, with: keyTag) {
            secKey = existingKey
        } else {
            self.logger.info(eventName: self.logEventName, message: "Key protection value for the factor: \(keyProtection)")
            secKey = try self.cryptoManager.generate(keyPairWith: algorithm,
                                                     with: keyTag,
                                                     useSecureEnclave: useSecureEnclave,
                                                     useBiometrics: useBiometrics,
                                                     biometricSettings: biometricSettings)
            factorsKeyTags.append(keyTag)
        }

        var additionalParameters: [String: _OktaCodableArbitaryType] = [:]

        additionalParameters["okta:kpr"] = .string(keyProtection)
        #if os(iOS)
        additionalParameters["okta:isFipsCompliant"] = .bool(OktaEnvironment.isSecureEnclaveAvailable())
        #endif

        guard let jwk = try jwkGenerator.generate(for: secKey,
                                                  type: .publicKey,
                                                  algorithm: algorithm,
                                                  kid: keyTag,
                                                  additionalParameters: additionalParameters) else {
            let resultError = SecurityError.jwkError("Failed to generate JWK with \(algorithm.toString()) algorithm")
            logger.error(eventName: self.logEventName, message: "Key generation error: \(resultError)")
            throw resultError
        }

        return jwk
    }

    func handleServerResult(_ result: HTTPURLResult?,
                            error: DeviceAuthenticatorError?,
                            factorsMetaData: [EnrollingFactor],
                            andCall onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        if let error = error {
            self.logger.error(eventName: self.logEventName, message: "Error: \(error)")
            onCompletion(Result.failure(error))
            return
        }

        guard let result = result, let resultJsonData = result.data, !resultJsonData.isEmpty else {
            let resultError = DeviceAuthenticatorError.internalError("Server replied with empty data")
            self.logger.error(eventName: self.logEventName, message: "Error: \(resultError)")
            onCompletion(Result.failure(resultError))
            return
        }

        do {
            var enrolledFactors: [OktaFactor] = []
            let enrolledAuthenticatorModel = try JSONDecoder().decode(EnrolledAuthenticatorModel.self, from: resultJsonData)
            enrolledAuthenticatorModel.methods?.forEach({ method in
                let factor: OktaFactor?
                factor = createFactorMetadataBasedOnServerResponse(method: method, enrollingFactorsData: factorsMetaData)
                if let factor = factor {
                    self.logger.info(eventName: self.logEventName, message: "Enrolled factor type: \(method.type.rawValue)")
                    enrolledFactors.append(factor)
                } else {
                    self.logger.error(eventName: self.logEventName, message: "Failed to enroll server method with type: \(method.type)")
                }
            })
            guard !enrolledFactors.isEmpty else {
                let jsonString = String(data: resultJsonData, encoding: .utf8) ?? ""
                let resultError = DeviceAuthenticatorError.internalError("Server replied with unexpected enrollment data")
                self.logger.error(eventName: self.logEventName, message: "\(resultError)\n\(jsonString)")
                onCompletion(Result.failure(resultError))
                return
            }
            self.logger.info(eventName: self.logEventName, message: "\(enrolledFactors) enrolled for org ID: \(self.orgId ?? "")")

            createEnrollmentAndSaveToStorage(enrolledAuthenticatorModel: enrolledAuthenticatorModel,
                                             enrolledFactors: enrolledFactors,
                                             onCompletion: onCompletion)
        } catch {
            let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
            self.logger.error(eventName: self.logEventName, message: "Failed to decode enrollment data - \(resultError)")
            onCompletion(Result.failure(resultError))
            return
        }
    }

    func createFactorMetadataBasedOnServerResponse(method: EnrolledAuthenticatorModel.AuthenticatorMethods,
                                                   enrollingFactorsData: [EnrollingFactor]) -> OktaFactor? {
        guard method.type == .push,
              let pushFactorMetadata = self.createEnrolledPushFactor(from: enrollingFactorsData, and: method) as? OktaFactorMetadataPush else {
            return nil
        }

        return OktaFactorPush(factorData: pushFactorMetadata, cryptoManager: cryptoManager, restAPIClient: restAPI, logger: logger)
    }

    func createEnrollmentAndSaveToStorage(enrolledAuthenticatorModel: EnrolledAuthenticatorModel,
                                          enrolledFactors: [OktaFactor],
                                          onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        do {
            var newDeviceEnrollment: OktaDeviceEnrollment! = self.deviceEnrollment
            if newDeviceEnrollment == nil {
                if let clientInstanceKeyTag = self.clientInstanceKeyTag {
                    newDeviceEnrollment = OktaDeviceEnrollment(id: enrolledAuthenticatorModel.device.id,
                                                               orgId: self.orgId,
                                                               clientInstanceId: enrolledAuthenticatorModel.device.clientInstanceId,
                                                               clientInstanceKeyTag: clientInstanceKeyTag)
                } else {
                    let resultError = DeviceAuthenticatorError.internalError("Failed to create device enrollment object")
                    self.logger.error(eventName: self.logEventName, message: "\(resultError)")
                    onCompletion(Result.failure(resultError))
                    return
                }
            }

            let enrollment = AuthenticatorEnrollment(organization: Organization(id: self.orgId, url: enrollmentContext.orgHost),
                                                     user: User(id: enrolledAuthenticatorModel.user.id, name: enrolledAuthenticatorModel.user.username),
                                                     enrollmentId: enrolledAuthenticatorModel.id,
                                                     deviceId: enrolledAuthenticatorModel.device.id,
                                                     serverError: nil,
                                                     creationDate: enrolledAuthenticatorModel.creationDate,
                                                     enrolledFactors: enrolledFactors,
                                                     cryptoManager: self.cryptoManager,
                                                     restAPIClient: self.restAPI,
                                                     storageManager: storageManager,
                                                     applicationConfig: self.applicationConfig,
                                                     logger: self.logger)
            try self.storageManager.storeEnrollment(enrollment)
            if case DeviceToken.tokenData(let deviceToken) = enrollmentContext.pushToken {
                // TODO: Remove below logic when server will implement PATCH request
                enrollment.saveDeviceToken(deviceToken)
            }
            if newDeviceEnrollment.id != self.deviceEnrollment?.id {
                if let oldDeviceEnrollment = try? self.storageManager.deviceEnrollmentByOrgId(orgId),
                   newDeviceEnrollment.clientInstanceKeyTag != oldDeviceEnrollment.clientInstanceKeyTag {
                    // Update device record in db
                    _ = cryptoManager.delete(keyPairWith: oldDeviceEnrollment.clientInstanceKeyTag)
                    try? self.storageManager.deleteDeviceEnrollmentForOrgId(enrollment.organization.id)
                }
                try? self.storageManager.storeDeviceEnrollment(newDeviceEnrollment, for: enrollment.organization.id)
            }
            onCompletion(Result.success(enrollment))
        } catch let error as DeviceAuthenticatorError {
            self.logger.error(eventName: self.logEventName, message: "Failed to store enrollment - \(error)")
            onCompletion(Result.failure(error))

        } catch {
            let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
            self.logger.error(eventName: self.logEventName, message: "Failed to store enrollment - \(resultError)")
            onCompletion(Result.failure(resultError))
            return
        }
    }

    let logEventName = "EnrollTransaction"
}
