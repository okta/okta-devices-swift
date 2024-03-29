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
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif

struct EnrollmentContext {
    let accessToken: String?
    let activationToken: String?
    let orgHost: URL
    let authenticatorKey: String
    let oidcClientId: String?
    let deviceSignals: DeviceSignals?
    let applicationSignals: [String: _OktaCodableArbitaryType]?
    let biometricSettings: BiometricEnrollmentSettings
    let biometricOrPinSettings: BiometricEnrollmentSettings
    let pushToken: DeviceToken
    let enrollBiometricKey: Bool?
    let enrollBiometricOrPinKey: Bool?
    let transactionTypes: TransactionType?

    var isCIBASupported: Bool {
        return transactionTypes?.contains(.ciba) ?? false
    }

    init(accessToken: String?,
         activationToken: String?,
         orgHost: URL,
         authenticatorKey: String,
         oidcClientId: String?,
         pushToken: DeviceToken,
         enrollBiometricKey: Bool?,
         enrollBiometricOrPinKey: Bool?,
         deviceSignals: DeviceSignals?,
         biometricSettings: BiometricEnrollmentSettings?,
         biometricOrPinSettings: BiometricEnrollmentSettings?,
         applicationSignals: [String: _OktaCodableArbitaryType]? = nil,
         transactionTypes: TransactionType?) {
        self.accessToken = accessToken
        self.activationToken = activationToken
        self.orgHost = orgHost
        self.oidcClientId = oidcClientId
        self.authenticatorKey = authenticatorKey
        self.pushToken = pushToken
        self.enrollBiometricKey = enrollBiometricKey
        self.enrollBiometricOrPinKey = enrollBiometricOrPinKey
        self.deviceSignals = deviceSignals
        self.biometricSettings = biometricSettings ?? BiometricEnrollmentSettings.default
        self.biometricOrPinSettings = biometricOrPinSettings ?? BiometricEnrollmentSettings(accessControlFlags: .userPresence)
        self.applicationSignals = applicationSignals
        self.transactionTypes = transactionTypes
    }
}

class OktaTransactionEnroll: OktaTransaction {
    let jwkGenerator: OktaJWKGenerator
    let restAPI: ServerAPIProtocol
    let enrollmentContext: EnrollmentContext
    let enrollmentToUpdate: AuthenticatorEnrollment?
    let applicationConfig: ApplicationConfig
    let authenticatorPolicy: AuthenticatorPolicy?

    var metaData: AuthenticatorMetaDataModel!
    var deviceEnrollment: OktaDeviceEnrollment?
    var orgId: String!
    var factorsKeyTags: [String] = []
    var clientInstanceKeyTag: String?

    init(storageManager: PersistentStorageProtocol,
         cryptoManager: OktaSharedCryptoProtocol,
         restAPI: ServerAPIProtocol,
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
                enrollmentToUpdate?.enrolledFactors.forEach { $0.removeUserVerificationKey() }
            }
        }

        if let enrollUserVerificationBioOrPinKey = enrollmentContext.enrollBiometricOrPinKey {
            if !enrollUserVerificationBioOrPinKey {
                enrollmentToUpdate?.enrolledFactors.forEach { $0.removeUserVerificationBioOrPinKey() }
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
                                                   token: token) { result in
            switch result {
            case .failure(let error): onCompletion(.failure(error))
            case .success(let metadata):
                let authenticatorPolicy = AuthenticatorPolicy(metadata: metadata)
                do {
                    try self.storageManager.storeAuthenticatorPolicy(authenticatorPolicy, orgId: orgId)
                } catch {
                    let resultError = DeviceAuthenticatorError.internalError(error.localizedDescription)
                    self.logger.error(eventName: self.logEventName, message: "Download metadata error - \(resultError)")
                    onCompletion(Result.failure(resultError))
                    return
                }

                onMetadataReceived?(metadata)
                self.continueEnrollment(with: orgId,
                                        metaData: metadata,
                                        onCompletion: onCompletion)
            }
        }
    }

    func continueEnrollment(with orgId: String,
                            metaData: AuthenticatorMetaDataModel,
                            onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        self.orgId = orgId
        self.metaData = metaData
        if self.deviceEnrollment == nil {
            self.deviceEnrollment = try? self.storageManager.deviceEnrollmentByOrgId(orgId)
        }
        let enrolledFactors: [EnrollingFactor]
        do {
            // Build factors based on metadata requirements
            enrolledFactors = try self.enrollFactors()
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

        // Send RestAPI request
        if let enrollmentToUpdate = enrollmentToUpdate {
            doUpdate(enrollment: enrollmentToUpdate,
                     factorsMetaData: enrolledFactors,
                     onCompletion: onCompletion)
        } else {
            doEnrollment(factorsMetaData: enrolledFactors,
                         onCompletion: onCompletion)
        }
    }

    func doEnrollment(factorsMetaData: [EnrollingFactor],
                      onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        logger.info(eventName: self.logEventName, message: "Sending enrollment request")
        let token = OktaRestAPIToken(accessToken: enrollmentContext.accessToken,
                                     activationToken: enrollmentContext.activationToken)
        let deviceModel = buildDeviceModelData(customDeviceSignals: enrollmentContext.deviceSignals)
        self.restAPI.enrollAuthenticatorRequest(orgHost: enrollmentContext.orgHost,
                                                metadata: metaData,
                                                deviceModel: deviceModel,
                                                appSignals: enrollmentContext.applicationSignals,
                                                enrollingFactors: factorsMetaData,
                                                token: token) { result in
            self.handleServerResult(result, factorsMetaData: factorsMetaData, andCall: onCompletion)
        }
    }

    /// For retrying enrollment when E0000153, is returned. This can happen when server deletes the device but client still has the deviceId
    func retryEnrollmentIfNeeded(error: DeviceAuthenticatorError,
                                 factorsMetaData: [EnrollingFactor],
                                 onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        guard case .serverAPIError(_, let serverAPIErrorModel) = error,
              let errorCode = serverAPIErrorModel?.errorCode?.rawValue,
              (ServerErrorCode(raw: errorCode) == .deviceDeleted || ServerErrorCode(raw: errorCode) == .invalidToken),
              self.enrollmentToUpdate == nil,
              self.deviceEnrollment != nil else {
            onCompletion(.failure(error))
            return
        }
        self.logger.info(eventName: logEventName, message: "Device deleted or is out of sync. Re-enrolling with no deviceId, error: \(error)")
        self.deviceEnrollment = nil
        self.doEnrollment(factorsMetaData: factorsMetaData, onCompletion: onCompletion)
    }

    func doUpdate(enrollment: AuthenticatorEnrollment,
                  factorsMetaData: [EnrollingFactor],
                  onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        let updateRequest: (String?) -> Void = { authenticationToken in
            let token = OktaRestAPIToken(authenticationToken: authenticationToken,
                                         accessToken: self.enrollmentContext.accessToken)
            let deviceModel = self.buildDeviceModelData(customDeviceSignals: self.enrollmentContext.deviceSignals)
            self.restAPI.updateAuthenticatorRequest(orgHost: self.enrollmentContext.orgHost,
                                                    enrollmentId: enrollment.enrollmentId,
                                                    metadata: self.metaData,
                                                    deviceModel: deviceModel,
                                                    appSignals: self.enrollmentContext.applicationSignals,
                                                    enrollingFactors: factorsMetaData,
                                                    token: token,
                                                    enrollmentContext: self.enrollmentContext) { result in
                self.handleServerResult(result, factorsMetaData: factorsMetaData, andCall: onCompletion)
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

    func buildDeviceModelData(customDeviceSignals: DeviceSignals?) -> DeviceSignalsModel {
        let deviceModelBuilder = OktaDeviceModelBuilder(orgHost: enrollmentContext.orgHost.absoluteString,
                                                        applicationConfig: applicationConfig,
                                                        requestedSignals: [],
                                                        customSignals: customDeviceSignals,
                                                        cryptoManager: self.cryptoManager,
                                                        jwtGenerator: jwtGenerator,
                                                        jwkGenerator: jwkGenerator,
                                                        logger: logger)
        let deviceModel: DeviceSignalsModel
        if let deviceEnrollment = deviceEnrollment {
            logger.info(eventName: self.logEventName, message: "Building device model based on existing device object")
            do {
                deviceModel = try deviceModelBuilder.buildForUpdateEnrollment(with: deviceEnrollment)
            } catch {
                logger.warning(eventName: self.logEventName, message: "Failed to build client attestation jwt")
                logger.info(eventName: self.logEventName, message: "Registering new device object")
                let clientInstanceKeyTag = UUID().uuidString
                deviceModel = deviceModelBuilder.buildForCreateEnrollment(with: clientInstanceKeyTag)
                self.clientInstanceKeyTag = clientInstanceKeyTag
            }
        } else {
            logger.info(eventName: self.logEventName, message: "Registering new device object")
            let clientInstanceKeyTag = UUID().uuidString
            deviceModel = deviceModelBuilder.buildForCreateEnrollment(with: clientInstanceKeyTag)
            self.clientInstanceKeyTag = clientInstanceKeyTag
        }

        return deviceModel
    }

    func handleServerResult(_ result: Result<EnrollmentSummary, DeviceAuthenticatorError>,
                            factorsMetaData: [EnrollingFactor],
                            andCall onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        switch result {
        case .failure(let error):
            retryEnrollmentIfNeeded(error: error,
                                    factorsMetaData: factorsMetaData,
                                    onCompletion: onCompletion)
            return
        case .success(let enrollmentSummary):
            createEnrollmentAndSaveToStorage(enrollmentSummary: enrollmentSummary,
                                             onCompletion: onCompletion)
        }
    }

    func createEnrollmentAndSaveToStorage(enrollmentSummary: EnrollmentSummary,
                                          onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        do {
            let enrollment = AuthenticatorEnrollment(organization: Organization(id: self.orgId, url: enrollmentContext.orgHost),
                                                     user: User(id: enrollmentSummary.userId, name: enrollmentSummary.username),
                                                     enrollmentId: enrollmentSummary.enrollmentId,
                                                     deviceId: enrollmentSummary.deviceId,
                                                     serverError: nil,
                                                     creationDate: enrollmentSummary.creationDate,
                                                     enrolledFactors: enrollmentSummary.factors,
                                                     cryptoManager: self.cryptoManager,
                                                     restAPIClient: self.restAPI,
                                                     storageManager: storageManager,
                                                     applicationConfig: self.applicationConfig,
                                                     logger: self.logger)
            try self.storageManager.storeEnrollment(enrollment)

            var newDeviceEnrollment: OktaDeviceEnrollment! = self.deviceEnrollment
            if newDeviceEnrollment == nil || newDeviceEnrollment.id != enrollmentSummary.deviceId {
                if let clientInstanceKeyTag = self.clientInstanceKeyTag ?? self.deviceEnrollment?.clientInstanceKeyTag {
                    newDeviceEnrollment = OktaDeviceEnrollment(id: enrollmentSummary.deviceId,
                                                               orgId: self.orgId,
                                                               clientInstanceId: enrollmentSummary.clientInstanceId,
                                                               clientInstanceKeyTag: clientInstanceKeyTag)
                } else {
                    let resultError = DeviceAuthenticatorError.internalError("Failed to create device enrollment object")
                    self.logger.error(eventName: self.logEventName, message: "\(resultError)")
                    onCompletion(Result.failure(resultError))
                    return
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
