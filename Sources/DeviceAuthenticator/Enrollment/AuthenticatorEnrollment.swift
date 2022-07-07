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
import OktaLogger

/// Internal concrete representation of authenticator enrollment (account) object
class AuthenticatorEnrollment: AuthenticatorEnrollmentProtocol {
    /// Authenticator enrollment id
    let enrollmentId: String
    /// Organization information
    var organization: Organization
    /// Enrolled user information
    var user: User
    /// Enrolled device id
    let deviceId: String
    /// Enrollment creation date
    let creationDate: Date

    var orgHost: URL { return organization.url }
    /// Organization id
    var orgId: String { return organization.id }
    /// Enrolled user id
    var userId: String { return user.id }
    /// Enrolled user name
    var userName: String? { return user.name }

    /// Checks for registered user verification keys in enrolled factors
    var hasFactorsWithUserVerificationKey: Bool {
        return enrolledFactors.first(where: { $0.enrolledWithUserVerificationKey }) != nil
    }

    /// Returns  push factor if enrolled
    var pushFactor: OktaFactorPush? {
        guard let pushFactor = self.enrolledFactors.first(where: { $0 is OktaFactorPush }) as? OktaFactorPush else {
            return nil
        }

        return pushFactor
    }

    /// Array of enrolled  verification methods
    @ThreadSafeProperty var enrolledFactors: [OktaFactor] = []

    var serverError: ServerErrorCode? = nil

    var state: EnrollmentState {
        if let error = serverError {
            return state(from: error)
        }
        return .active
    }

    let logger: OktaLoggerProtocol
    let cryptoManager: OktaSharedCryptoProtocol
    let restAPIClient: OktaRestAPI
    let storageManager: PersistentStorageProtocol
    let applicationConfig: ApplicationConfig
    let userDefaultsStorage: UserDefaults
    private let logEventName = "AuthenticatorEnrollment"

    init(organization: Organization,
         user: User,
         enrollmentId: String,
         deviceId: String,
         serverError: ServerErrorCode?,
         creationDate: Date,
         enrolledFactors: [OktaFactor],
         cryptoManager: OktaSharedCryptoProtocol,
         restAPIClient: OktaRestAPI,
         storageManager: PersistentStorageProtocol,
         applicationConfig: ApplicationConfig,
         logger: OktaLoggerProtocol) {
        self.organization = organization
        self.user = user
        self.enrollmentId = enrollmentId
        self.deviceId = deviceId
        self.serverError = serverError
        self.creationDate = creationDate
        self.cryptoManager = cryptoManager
        self.restAPIClient = restAPIClient
        self.storageManager = storageManager
        self.applicationConfig = applicationConfig
        self.enrolledFactors = enrolledFactors
        self.logger = logger
        self.userDefaultsStorage = UserDefaults()
    }

    func recordError(_ error: ServerErrorCode) {
        serverError = error
    }

    func recordSuccess() {
        serverError = nil
    }

    func updateDeviceToken(_ token: Data,
                           authenticationToken: AuthToken,
                           completion: @escaping (DeviceAuthenticatorError?) -> Void) {
        guard let policy = try? storageManager.authenticatorPolicyForOrgId(organization.id) as? AuthenticatorPolicy else {
            completion(DeviceAuthenticatorError.genericError("Failed to fetch authenticator policy"))
            return
        }
        let enrollmentContext = EnrollmentContext(accessToken: authenticationToken.tokenValue(),
                                                  activationToken: nil,
                                                  orgHost: organization.url,
                                                  authenticatorKey: policy.metadata.key,
                                                  oidcClientId: policy.metadata.settings?.oauthCliendId,
                                                  pushToken: DeviceToken.tokenData(token),
                                                  enrollBiometricKey: nil,
                                                  deviceSignals: nil,
                                                  biometricSettings: nil,
                                                  applicationSignals: nil)
        let updateTransaction = OktaTransactionPushTokenUpdate(storageManager: self.storageManager,
                                                               cryptoManager: self.cryptoManager,
                                                               restAPI: self.restAPIClient,
                                                               enrollmentContext: enrollmentContext,
                                                               enrollmentToUpdate: self,
                                                               jwkGenerator: nil,
                                                               jwtGenerator: nil,
                                                               applicationConfig: applicationConfig,
                                                               logger: self.logger,
                                                               authenticatorPolicy: policy)
        updateTransaction.enroll() { [weak self] result in
            switch result {
            case .success(_):
                updateTransaction.cleanupOnSuccess()
                self?.saveDeviceToken(token)
                self?.recordServerResponse(error: nil)
                completion(nil)
            case .failure(let error):
                self?.recordServerResponse(error: error)
                updateTransaction.rollback()
                completion(error)
            }
        }
    }

    func retrievePushChallenges(authenticationToken: AuthToken,
                                allowedClockSkewInSeconds: Int,
                                completion: @escaping (Result<[PushChallengeProtocol], DeviceAuthenticatorError>) -> Void) {
        let pullChallengeTransaction = OktaTransactionPullChallenge(enrollment: self,
                                                                    authenticationToken: authenticationToken,
                                                                    storageManager: storageManager,
                                                                    cryptoManager: cryptoManager,
                                                                    restAPI: restAPIClient,
                                                                    logger: logger)
        pullChallengeTransaction.pullChallenge(allowedClockSkewInSeconds: allowedClockSkewInSeconds, completion: completion)
    }

    func deleteFromDevice() throws {
        try storageManager.deleteEnrollment(self)
        self.cleanup()
    }

    func recordServerResponse(error: DeviceAuthenticatorError? = nil) {
        if error == nil {
            recordSuccess()
        } else if let errorCode = error?.serverErrorCode {
            recordError(errorCode)
        }
        try? self.storageManager.storeEnrollment(self)
    }

    var userVerificationEnabled: Bool {
        return hasFactorsWithUserVerificationKey
    }

    func setUserVerification(authenticationToken: AuthToken, enable: Bool, completion: @escaping (DeviceAuthenticatorError?) -> Void) {
        guard let policy = try? storageManager.authenticatorPolicyForOrgId(orgId) as? AuthenticatorPolicy else {
            completion(DeviceAuthenticatorError.genericError("Failed to fetch authenticator policy"))
            return
        }

        var deviceToken: DeviceToken = .empty
        if let deviceTokenData = readDeviceToken() {
            deviceToken = .tokenData(deviceTokenData)
        }
        let enrollmentContext = EnrollmentContext(accessToken: authenticationToken.tokenValue(),
                                                  activationToken: nil,
                                                  orgHost: orgHost,
                                                  authenticatorKey: policy.metadata.id,
                                                  oidcClientId: policy.metadata.settings?.oauthCliendId,
                                                  pushToken: deviceToken,
                                                  enrollBiometricKey: enable,
                                                  deviceSignals: nil,
                                                  biometricSettings: .default,
                                                  applicationSignals: nil)
        let enrollTransaction = OktaTransactionEnroll(storageManager: self.storageManager,
                                                      cryptoManager: self.cryptoManager,
                                                      restAPI: restAPIClient,
                                                      enrollmentContext: enrollmentContext,
                                                      enrollmentToUpdate: self,
                                                      jwkGenerator: OktaJWKGenerator(logger: logger),
                                                      jwtGenerator: OktaJWTGenerator(logger: logger),
                                                      applicationConfig: applicationConfig,
                                                      logger: self.logger,
                                                      authenticatorPolicy: policy)
        enrollTransaction.enroll(onMetadataReceived: nil) { [weak self] result in
            switch result {
            case .success(let updatedEnrollment):
                enrollTransaction.cleanupOnSuccess()
                if let enrollment = updatedEnrollment as? AuthenticatorEnrollment {
                    self?.enrolledFactors = enrollment.enrolledFactors
                }
                self?.recordServerResponse()
                completion(nil)
            case .failure(let error):
                enrollTransaction.rollback()
                self?.recordServerResponse(error: error)
                completion(error)
            }
        }
    }

    // TODO: Remove saveDeviceToken function when server will implement PATCH request
    func saveDeviceToken(_ token: Data) {
        userDefaultsStorage.set(token, forKey: "device_token_" + self.enrollmentId)
    }

    // TODO: Remove readDeviceToken function when server will implement PATCH request
    func readDeviceToken() -> Data? {
        userDefaultsStorage.data(forKey: "device_token_" + self.enrollmentId)
    }

    func cleanup() {
        logger.info(eventName: logEventName, message: "Cleanup called")
        enrolledFactors.forEach { factor in
            factor.cleanup()
        }
    }

    func state(from errorCode: ServerErrorCode) -> EnrollmentState {
        switch errorCode {
        case .userDeleted, .enrollmentNotFound:
            return .deleted
        case .resourceNotFound:
            return .active
        case .userSuspended, .deviceSuspended, .enrollmentSuspended:
            return .suspended
        case .biometricKeyEnrollmentComplianceError:
            return .active
        case .enrollmentDeleted, .deviceDeleted:
            return .reset
        case .unknown, .invalidToken:
            return .active
        }
    }
}

extension AuthenticatorEnrollment: CustomStringConvertible {

    var description: String {
        var info: [String: Any] = [
            "orgHost": organization.url,
            "enrollmentId": enrollmentId,
            "orgId": organization.id,
            "userId": user.id,
            "created": DateFormatter.oktaDateFormatter().string(from: creationDate),
            "deviceId": deviceId
        ]

        enrolledFactors.forEach { factor in
            info[String(describing: type(of: factor))] = factor.description
        }

        return "\(info as AnyObject)"
    }
}