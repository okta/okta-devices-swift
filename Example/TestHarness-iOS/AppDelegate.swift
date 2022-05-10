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

import UIKit
import OktaOidc
import OktaDeviceSDK

enum GlobalConstants {
    static let appGroupId = "group.okta.qa"
}

@main
class AppDelegate: UIResponder, UIApplicationDelegate, UNUserNotificationCenterDelegate {

    var deviceAuthenticator: DeviceAuthenticatorProtocol!
    var window: UIWindow?
    var logger: LoggerManagerProtocol?
    private var accessTokenManager: AccessTokenManagerProtocol!
    
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        window = .init(frame: UIScreen.main.bounds)

        logger = LoggerManager.shared
        logger?.info(event: .appInit("application did finish launching"))

        do {
            let applicationConfig = ApplicationConfig(applicationName: "TestHarness-iOS",
                                                      applicationVersion: "1.0.0",
                                                      applicationGroupId: GlobalConstants.appGroupId)
            applicationConfig.pushSettings.apsEnvironment = .development
            applicationConfig.pushSettings.approveActionTitle = "Approve"
            applicationConfig.pushSettings.denyActionTitle = "Deny"
            deviceAuthenticator = try DeviceAuthenticatorBuilder(applicationConfig: applicationConfig).create()
        } catch {
            logger?.error(event: .appInit("Failed to initialize OktaAuthenticator SDK"))
            fatalError("Failed to initialize OktaAuthenticator SDK")
        }
        if let deviceAuthenticator = deviceAuthenticator as? LoggerContainable {
            logger?.injectFileLogger(deviceAuthenticator)
        }
        logger?.info(event: .registerPushNotifications("Request push notifications permission"))
        var authorizationOption: UNAuthorizationOptions = [.badge, .alert, .sound]
        if #available(iOS 15.0, *) {
            authorizationOption.insert(.timeSensitive)
        }
        UNUserNotificationCenter.current().requestAuthorization(options: authorizationOption) { [weak self] granted, error in
            DispatchQueue.main.async {
                if let error = error {
                    self?.logger?.error(event: .registerPushNotifications(error.localizedDescription))
                    return
                }

                if granted {
                    self?.logger?.info(event: .registerPushNotifications("Push notifications permission granted"))
                    UIApplication.shared.registerForRemoteNotifications()
                } else {
                    self?.logger?.info(event: .registerPushNotifications("Push notifications permission denied"))
                }
            }
        }
        UNUserNotificationCenter.current().delegate = self

        accessTokenManager = AccessTokenManager(deviceAuthenticator: deviceAuthenticator ,logger: logger)
        let rootManager = RootControllerManager.shared
        rootManager.deviceAuthenticator = deviceAuthenticator
        rootManager.accessTokenManager = accessTokenManager
        rootManager.window = window

        window?.rootViewController = rootManager.provideRootController()
        window?.makeKeyAndVisible()

        return true
    }

    func applicationDidBecomeActive(_ application: UIApplication) {
        retrievePushChallenges()
    }
    
    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {

        UserDefaults.save(deviceToken: deviceToken)
        self.deviceAuthenticator.allEnrollments().forEach { enrollment in
            self.accessTokenManager.loadAccessToken(for: enrollment.enrollmentId) { result in
                switch result {
                case .success(let accessToken):
                    self.logger?.info(event: .accountDetails("Load access token successfully"))
                    enrollment.updateDeviceToken(deviceToken, authenticationToken: AuthToken.bearer(accessToken)) { error in
                        if let error = error {
                            self.logger?.error(event: .pushTokenUpdate("Error: \(error.localizedDescription); enrollment: \(enrollment.enrollmentId)"))
                        } else {
                            self.logger?.info(event: .pushTokenUpdate("OktaAuthenticator.sdk push token update finished"))
                        }
                    }
                case .failure(let error):
                    let errorString = "Load access token with error: \(error.errorDescription))"
                    self.logger?.error(event: .accountDetails(errorString))
                }
            }
        }
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        logger?.error(event: .pushTokenUpdate("Failed to register for remote notifications: \(error.localizedDescription)"))
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        do {
            let pushChallenge = try deviceAuthenticator.parsePushNotificationResponse(response)
            // Handle the push challenge
            resolvePushChallenge(pushChallenge)
        } catch {
            logger?.error(event: .accountDetails(error.localizedDescription))
        }
        completionHandler()
    }
    
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        
        do {
            let pushChallenge = try deviceAuthenticator.parsePushNotification(notification)
            // Handle the push challenge
            resolvePushChallenge(pushChallenge)
        } catch {
            logger?.error(event: .accountDetails(error.localizedDescription))
        }
        // handle non-okta push notification responses here
        completionHandler([])
    }

    private func resolvePushChallenges(_ pushChallenges: [PushChallengeProtocol]) {
        pushChallenges.forEach {
            self.resolvePushChallenge($0)
        }
    }
    
    private func resolvePushChallenge(_ pushChallenge: PushChallengeProtocol) {
        guard let navigationController = self.topNavigationController() else {
            return
        }
        pushChallenge.resolve { step in
            DispatchQueue.main.async {
                let remediationEventsHandler = RemediationEventsHandler(navigationController: navigationController)
                remediationEventsHandler.handle(step)
            }
        } onCompletion: { error in
            DispatchQueue.main.async {
                if let error = error {
                    self.logger?.error(event: .accountDetails("Can not resolve push challenge: \(error.localizedDescription)"))
                } else {
                    self.logger?.info(event: .accountDetails("Success resolve push challenge"))
                }
            }
        }
    }

    private func retrievePushChallenges() {
        self.logger?.info(event: .accountDetails("Retrieve push challenges for all enrollments"))
        self.deviceAuthenticator.allEnrollments().forEach { enrollment in
            self.accessTokenManager.loadAccessToken(for: enrollment.enrollmentId) { result in
                switch result {
                case .success(let accessToken):
                    self.logger?.info(event: .accountDetails("Load access token successfully"))
                    let authToken = AuthToken.bearer(accessToken)
                    enrollment.retrievePushChallenges(authenticationToken: authToken) { [weak self] result in
                        DispatchQueue.main.async {
                            switch result {
                            case .success(let pushChallenges):
                                self?.resolvePushChallenges(pushChallenges)
                            case .failure(let error):
                                self?.logger?.error(event: .pendingChallenge(error.additionalDescription))
                            }
                        }
                    }
                case .failure(let error):
                    let errorString = "Load access token wtih error: \(error.errorDescription))"
                    self.logger?.error(event: .accountDetails(errorString))
                }
            }
        }
    }
}
