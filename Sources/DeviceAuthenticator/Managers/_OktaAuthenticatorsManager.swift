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
import UserNotifications
import OktaLogger

public class _OktaAuthenticatorsManager {

    var logger: OktaLoggerProtocol
    var restAPI: OktaRestAPI
    var cryptoManager: OktaSharedCryptoProtocol
    var storageManager: PersistentStorageProtocol
    var jwkGenerator: OktaJWKGenerator
    var jwtGenerator: OktaJWTGenerator
    let signalsManager: SignalsManager
    let applicationConfig: ApplicationConfig

    init(applicationConfig: ApplicationConfig,
         storageManager: PersistentStorageProtocol,
         cryptoManager: OktaSharedCryptoProtocol,
         restAPI: OktaRestAPI,
         jwkGenerator: OktaJWKGenerator,
         jwtGenerator: OktaJWTGenerator,
         logger: OktaLoggerProtocol) {
        self.storageManager = storageManager
        self.cryptoManager = cryptoManager
        self.restAPI = restAPI
        self.jwkGenerator = jwkGenerator
        self.jwtGenerator = jwtGenerator
        self.applicationConfig = applicationConfig
        self.signalsManager = SignalsManager(logger: logger)
        self.logger = logger
    }

    func enroll(authenticationToken: AuthToken,
                authenticatorConfig: DeviceAuthenticatorConfig,
                enrollmentParameters: EnrollmentParameters,
                completion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        let enrollmentContext = EnrollmentContext(accessToken: authenticationToken.tokenValue(),
                                                  activationToken: nil,
                                                  orgHost: authenticatorConfig.orgURL,
                                                  authenticatorKey: authenticatorConfig.authenticatorKey,
                                                  oidcClientId: authenticatorConfig.oidcClientId,
                                                  pushToken: enrollmentParameters.deviceToken,
                                                  enrollBiometricKey: enrollmentParameters.enrollUserVerificationKey,
                                                  deviceSignals: nil,
                                                  biometricSettings: enrollmentParameters.userVerificationSettings,
                                                  applicationSignals: nil)
        enroll(with: enrollmentContext,
               existingEnrollment: nil,
               onMetadataReceived: nil,
               onCompletion: completion)
    }

    func enroll(with enrollmentContext: EnrollmentContext,
                existingEnrollment: AuthenticatorEnrollment? = nil,
                onMetadataReceived: ((AuthenticatorMetaDataModel) -> Void)? = nil,
                onCompletion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        var policy: AuthenticatorPolicy?
        if let existingEnrollment = existingEnrollment {
            policy = try? storageManager.authenticatorPolicyForOrgId(existingEnrollment.orgId) as? AuthenticatorPolicy
        }
        let enrollTransaction = OktaTransactionEnroll(storageManager: self.storageManager,
                                                      cryptoManager: self.cryptoManager,
                                                      restAPI: self.restAPI,
                                                      enrollmentContext: enrollmentContext,
                                                      enrollmentToUpdate: existingEnrollment,
                                                      jwkGenerator: self.jwkGenerator,
                                                      jwtGenerator: self.jwtGenerator,
                                                      applicationConfig: applicationConfig,
                                                      logger: self.logger,
                                                      authenticatorPolicy: policy)
        enrollTransaction.enroll(onMetadataReceived: onMetadataReceived) { result in
            switch result {
            case .success(let updatedEnrollment):
                (updatedEnrollment as? AuthenticatorEnrollment)?.recordServerResponse()
                enrollTransaction.cleanupOnSuccess()
            case .failure(let error):
                existingEnrollment?.recordServerResponse(error: error)
                enrollTransaction.rollback()
            }

            onCompletion(result)
        }
    }

    func _downloadMetadata(orgHost: URL,
                           authenticatorKey: String,
                           oidcClientId: String?,
                           accessToken: String?,
                           activationToken: String?,
                           onCompletion: @escaping (Result<AuthenticatorPolicyProtocol, DeviceAuthenticatorError>) -> Void) {
        doDownloadMetadata(orgHost: orgHost,
                           authenticatorKey: authenticatorKey,
                           oidcClientId: oidcClientId,
                           token: OktaRestAPIToken(accessToken: accessToken, activationToken: activationToken),
                           onCompletion: onCompletion)
    }

    func _downloadMetadata(_ enrollment: AuthenticatorEnrollment,
                           authenticatorKey: String,
                           onCompletion: @escaping (Result<AuthenticatorPolicyProtocol, DeviceAuthenticatorError>) -> Void) {
        let tokenBuilder = OktaAuthenticationTokenBuilder(cryptoManager: cryptoManager,
                                                          logger: logger,
                                                          jwtGenerator: jwtGenerator)
        let authenticationToken: String
        do {
            authenticationToken = try tokenBuilder.buildAndSignBasedOnEnrollment(enrollment)
        } catch let error as DeviceAuthenticatorError {
            onCompletion(Result.failure(error))
            return
        } catch {
            onCompletion(Result.failure(DeviceAuthenticatorError.internalError(error.localizedDescription)))
            return
        }

        doDownloadMetadata(orgHost: enrollment.orgHost,
                           authenticatorKey: authenticatorKey,
                           oidcClientId: nil,
                           token: OktaRestAPIToken.authenticationToken(authenticationToken)) { result in
            switch result {
            case .success(let policy):
                enrollment.recordServerResponse()
                guard let metadata = (policy as? AuthenticatorPolicy)?.metadata else {
                    onCompletion(Result.failure(DeviceAuthenticatorError.internalError("Failed to downcast Policy object")))
                    return
                }

                let policy = AuthenticatorPolicy(metadata: metadata)
                do {
                    try self.storageManager.storeAuthenticatorPolicy(policy, orgId: enrollment.orgId)
                    onCompletion(result)
                } catch let error as DeviceAuthenticatorError {
                    onCompletion(Result.failure(error))
                    return
                } catch {
                    onCompletion(Result.failure(DeviceAuthenticatorError.internalError(error.localizedDescription)))
                    return
                }
            case .failure(let error):
                enrollment.recordServerResponse(error: error)
                onCompletion(result)
            }
        }
    }

    func _deleteEnrollment(_ enrollment: AuthenticatorEnrollmentProtocol,
                           accessToken: String?,
                           onCompletion: @escaping (DeviceAuthenticatorError?) -> Void) {
        guard let enrollment = enrollment as? AuthenticatorEnrollment  else {
            onCompletion(DeviceAuthenticatorError.internalError("Invalid object type"))
            return
        }

        let deleteTransaction = OktaTransactionDeleteEnrollment(enrollmentToDelete: enrollment,
                                                                accessToken: accessToken,
                                                                storageManager: storageManager,
                                                                cryptoManager: cryptoManager,
                                                                restAPI: restAPI,
                                                                jwtGenerator: jwtGenerator,
                                                                logger: logger)
        delete(enrollment,
               accessToken: accessToken,
               deleteTransaction: deleteTransaction,
               onCompletion: onCompletion)
    }

    func delete(_ enrollment: AuthenticatorEnrollmentProtocol,
                accessToken: String?,
                deleteTransaction: OktaTransactionDeleteEnrollment,
                onCompletion: @escaping (DeviceAuthenticatorError?) -> Void) {
        let onSuccess: () -> Void = {
            do {
                try enrollment.deleteFromDevice()
                onCompletion(nil)
            } catch let error as DeviceAuthenticatorError {
                onCompletion(error)
            } catch {
                let oktaError = DeviceAuthenticatorError.internalError(error.localizedDescription)
                onCompletion(oktaError)
            }
        }
        deleteTransaction.delete { error in
            if let error = error {
                self.logger.error(eventName: "Delete flow failed", message: "Error: \(error)")
                switch error {
                case .serverAPIError(_, let errorModel):
                    if let errorCode = errorModel?.errorCode,
                       errorCode.isResourceDeleted || errorCode.isResourceSuspended {
                        self.logger.warning(eventName: "Device deleted on server",
                                            message: "Device was deleted on server side, deleting enrollment locally, status - \(errorCode.rawValue)")
                        self.logger.info(eventName: "Delete flow completed successfully", message: nil)
                        onSuccess()
                        return
                    } else {
                        onCompletion(error)
                    }
                default:
                    onCompletion(error)
                }
                return
            }

            onSuccess()
        }
    }

    func parse(notification: UNNotification, allowedClockSkewInSeconds: Int) throws -> PushChallengeProtocol {
        guard let userInfo = notification.request.content.userInfo as? [String: Any] else {
            logger.error(eventName: "Parse push challenge", message: "Failed to parse push notification")
            throw DeviceAuthenticatorError.pushNotRecognized
        }

        var validateJWT = true
#if targetEnvironment(simulator)
        validateJWT = false
#endif
        let bindJWT = try PushChallenge.parse(info: userInfo,
                                              allowedClockSkewInSeconds: allowedClockSkewInSeconds,
                                              validateJWT: validateJWT,
                                              accessGroupId: cryptoManager.accessGroupId,
                                              logger: logger)

        guard let context = bindJWT.jwt.payload["challengeContext"] as? [AnyHashable: Any],
              let enrollmentId = bindJWT.authenticatorEnrollmentId else {
            throw DeviceAuthenticatorError.internalError("Bad challenge")
        }

        let pushChallenge = PushChallenge(pushBindJWT: bindJWT,
                                          challengeContext: context,
                                          storageManager: storageManager,
                                          applicationConfig: applicationConfig,
                                          cryptoManager: cryptoManager,
                                          signalsManager: signalsManager,
                                          restAPI: restAPI,
                                          logger: logger,
                                          allowedClockSkewInSeconds: allowedClockSkewInSeconds)
        guard let enrollment = storageManager.enrollmentById(enrollmentId: enrollmentId) else {
            throw DeviceAuthenticatorError.accountNotFoundForChallenge(pushChallenge)
        }
        pushChallenge.enrollment = enrollment

        return pushChallenge
    }

    func parse(response: UNNotificationResponse, allowedClockSkewInSeconds: Int) throws -> PushChallengeProtocol {
        var pushChallenge = try parse(notification: response.notification, allowedClockSkewInSeconds: allowedClockSkewInSeconds)

        switch response.actionIdentifier {
        case InternalConstants.PushNotificationConstants.approveActionIdentifier:
            pushChallenge.userResponse = .userApproved
        case InternalConstants.PushNotificationConstants.denyActionIdentifier:
            pushChallenge.userResponse = .userDenied
        default:
            pushChallenge.userResponse = .userNotResponded
        }

        return pushChallenge
    }
}