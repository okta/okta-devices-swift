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
import UserNotifications
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif
import OktaJWT

class DeviceAuthenticator: DeviceAuthenticatorProtocol {

    var impl: _OktaAuthenticatorsManager!

    func initialize(applicationConfig: ApplicationConfig, logger: OktaLoggerProtocol?) throws {
        try doInitialize(applicationConfig: applicationConfig,
                         httpClient: nil,
                         loggerClient: logger)
    }

    func downloadPolicy(authenticationToken: AuthToken,
                        authenticatorConfig: DeviceAuthenticatorConfig,
                        completion: @escaping (Result<AuthenticatorPolicyProtocol, DeviceAuthenticatorError>) -> Void) {
        impl._downloadMetadata(orgHost: authenticatorConfig.orgURL,
                               authenticatorKey: authenticatorConfig.authenticatorKey,
                               oidcClientId: authenticatorConfig.oidcClientId,
                               accessToken: authenticationToken.tokenValue(),
                               activationToken: nil,
                               onCompletion: completion)
    }

    public func enroll(authenticationToken: AuthToken,
                       authenticatorConfig: DeviceAuthenticatorConfig,
                       enrollmentParameters: EnrollmentParameters,
                       completion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) {
        impl.enroll(authenticationToken: authenticationToken,
                    authenticatorConfig: authenticatorConfig,
                    enrollmentParameters: enrollmentParameters,
                    completion: completion)
    }

    func delete(enrollment: AuthenticatorEnrollmentProtocol,
                authenticationToken: AuthToken,
                completion: @escaping (DeviceAuthenticatorError?) -> Void) {
        impl._deleteEnrollment(enrollment, accessToken: authenticationToken.tokenValue(), onCompletion: completion)
    }

    func allEnrollments() -> [AuthenticatorEnrollmentProtocol] {
        return impl.storageManager.allEnrollments()
    }

    func parsePushNotification(_ notification: UNNotification, allowedClockSkewInSeconds: Int) throws -> PushChallengeProtocol {
        return try impl.parse(notification: notification, allowedClockSkewInSeconds: allowedClockSkewInSeconds)
    }

    func parsePushNotificationResponse(_ response: UNNotificationResponse, allowedClockSkewInSeconds: Int) throws -> PushChallengeProtocol {
        return try impl.parse(response: response, allowedClockSkewInSeconds: allowedClockSkewInSeconds)
    }

    func doInitialize(applicationConfig: ApplicationConfig,
                      httpClient: HTTPClientProtocol?,
                      loggerClient: OktaLoggerProtocol?) throws {
        var logger: OktaLoggerProtocol!
        var storageManager: PersistentStorageProtocol!
        if let loggerClient = loggerClient {
            logger = loggerClient
        } else {
            logger = Self.createLogger()
        }
        logger.info(eventName: "Initializing DeviceAuthenticator", message: nil)
        let cryptoManager = OktaCryptoManager(accessGroupId: applicationConfig.applicationInfo.applicationGroupId, logger: logger)
        let httpClientLocal = httpClient ?? HTTPClient(urlSession: nil, logger: logger, userAgent: UserAgent.standardUserAgent())
        let restAPIClient = MyAccountServerAPI(client: httpClientLocal,
                                               crypto: cryptoManager,
                                               logger: logger)
        do {
            let storage = try OktaStorageManager(restApiClient: restAPIClient,
                                                 applicationConfig: applicationConfig,
                                                 logger: logger)
            try storage.performStorageMigrationToTargetVersion()
            storageManager = storage
        } catch {
            logger.error(eventName: "Initialize OktaAuthenticator failed", message: "Error: \(error)")
            throw error
        }
        OktaJWT.RequestsAPI.setURLSession(httpClientLocal.currentSession)

        Self.registerNotificationCategories(from: applicationConfig)
        impl = _OktaAuthenticatorsManager(applicationConfig: applicationConfig,
                                          storageManager: storageManager,
                                          cryptoManager: cryptoManager,
                                          restAPI: restAPIClient,
                                          jwkGenerator: OktaJWKGenerator(logger: logger),
                                          jwtGenerator: OktaJWTGenerator(logger: logger),
                                          logger: logger)
        logger.info(eventName: "Initialized DeviceAuthenticator", message: nil)
    }

    static func createLogger() -> OktaLoggerProtocol {
        let consoleLogger = OktaLoggerConsoleLogger(identifier: "deviceSDK.console.logger", level: [.warning, .error], defaultProperties: nil)
        let logger = OktaLogger(destinations: [consoleLogger])

        return logger
    }

    static func registerNotificationCategories(from appConfig: ApplicationConfig) {
        guard (appConfig.pushSettings.approveActionTitle != nil && appConfig.pushSettings.denyActionTitle != nil) ||
                appConfig.pushSettings.userVerificationActionTitle != nil else {
            return
        }

        UNUserNotificationCenter.current().getNotificationCategories { categories in
            var categoriesSet = categories
            if let approveTitle = appConfig.pushSettings.approveActionTitle,
               let denyTitle = appConfig.pushSettings.denyActionTitle {
                let category = self.registerApproveAndDenyActions(approveTitle: approveTitle, denyTitle: denyTitle)
                categoriesSet.insert(category)
            }

            if let userVerificationTitle = appConfig.pushSettings.userVerificationActionTitle {
                let category = self.registerUserVerificationAction(userVerificationTitle: userVerificationTitle)
                categoriesSet.insert(category)
            }

            if categoriesSet.isEmpty {
                return
            }

            UNUserNotificationCenter.current().setNotificationCategories(categoriesSet)
        }
    }

    static func registerApproveAndDenyActions(approveTitle: String, denyTitle: String) -> UNNotificationCategory {
        let approveAction = UNNotificationAction(
            identifier: InternalConstants.PushNotificationConstants.approveActionIdentifier,
            title: approveTitle,
            options: .authenticationRequired
        )
        let denyAction = UNNotificationAction(
            identifier: InternalConstants.PushNotificationConstants.denyActionIdentifier,
            title: denyTitle,
            options: .authenticationRequired
        )

        return UNNotificationCategory(identifier: InternalConstants.PushNotificationConstants.regularPushCategoryIdentifier,
                                      actions: [approveAction, denyAction],
                                      intentIdentifiers: [],
                                      options: []
        )
    }

    static func registerUserVerificationAction(userVerificationTitle: String) -> UNNotificationCategory {
        let userVerificationAction = UNNotificationAction(
            identifier: InternalConstants.PushNotificationConstants.userVerificationActionIdentifier,
            title: userVerificationTitle,
            options: .foreground
        )

        return UNNotificationCategory(identifier: InternalConstants.PushNotificationConstants.userVerificationPushCategoryIdentifier,
                                      actions: [userVerificationAction],
                                      intentIdentifiers: [],
                                      options: []
        )
    }
}
