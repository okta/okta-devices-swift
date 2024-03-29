/*
* Copyright (c) 2022-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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
import UIKit
import OktaLogger
import DeviceAuthenticator

class PushNotificationService: NSObject, UNUserNotificationCenterDelegate {

    private var logger: OktaLogger?
    private let deviceAuthenticator: DeviceAuthenticatorProtocol
    private let remediationEventsHandler: RemediationEventsHandlerProtocol
    private let webAuthenticator: OktaWebAuthProtocol
    private var unhandledChallenges: Set<String> = []

    init(deviceAuthenticator: DeviceAuthenticatorProtocol,
         remediationEventsHandler: RemediationEventsHandlerProtocol,
         webAuthenticator: OktaWebAuthProtocol,
         logger: OktaLogger?) {
        self.logger = logger
        self.deviceAuthenticator = deviceAuthenticator
        self.remediationEventsHandler = remediationEventsHandler
        self.webAuthenticator = webAuthenticator
        super.init()
        UNUserNotificationCenter.current().delegate = self
    }

    private func getPermissions(completion: @escaping (Bool) -> Void) {
        UNUserNotificationCenter.current().getNotificationSettings { settings in
            switch settings.authorizationStatus {
            case .notDetermined:
                completion(false)
            case .authorized:
                completion(true)
            case .denied:
                UIApplication.shared.unregisterForRemoteNotifications()
                completion(false)
            default:
                completion(false)
            }
        }
    }

    func requestNotificationsPermissionsIfNeeded(completion: @escaping () -> Void) {
        getPermissions { isAuthorized in
            guard isAuthorized else {
                self.requestNotificationsPermissions(completion: completion)
                return
            }
            completion()
        }
    }

    private func requestNotificationsPermissions(completion: @escaping () -> Void) {
        var authorizationOptions: UNAuthorizationOptions = [.badge, .alert, .sound]
        if #available(iOS 15.0, *) {
            authorizationOptions.insert(.timeSensitive)
        }
        UNUserNotificationCenter.current().requestAuthorization(options: authorizationOptions) { granted, error in
            DispatchQueue.main.async {
                if let error = error {
                    self.logger?.error(eventName: LoggerEvent.pushService.rawValue, message: error.localizedDescription)
                    return
                }
                if granted {
                    self.logger?.info(eventName: LoggerEvent.pushService.rawValue, message: "Push notifications permissions granted")
                } else {
                    self.logger?.info(eventName: LoggerEvent.pushService.rawValue, message: "Push notifications permissions denied")
                }
                completion()
            }
        }
    }

    func updateDeviceTokenForEnrollments(data: Data) {
        UserDefaults.save(deviceToken: data)
        deviceAuthenticator.allEnrollments().forEach({ enrollment in
            getAccessToken(enrollment: enrollment) { accessToken in
                enrollment.updateDeviceToken(data, authenticationToken: AuthToken.bearer(accessToken)) { error in
                    self.logger?.info(eventName: LoggerEvent.pushService.rawValue, message: "Success update device token")
                }
            }
        })
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {

        do {
            let pushChallenge = try deviceAuthenticator.parsePushNotification(notification)
            // Handle the push challenge
            resolvePushChallenge(pushChallenge)
        } catch {
            logger?.error(eventName: LoggerEvent.account.rawValue, message: error.localizedDescription)
        }
        // handle non-okta push notification responses here
        completionHandler([])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
        do {
            let pushChallenge = try deviceAuthenticator.parsePushNotificationResponse(response)
            // Handle the push challenge
            resolvePushChallenge(pushChallenge)
        } catch {
            logger?.error(eventName: LoggerEvent.pushService.rawValue, message: error.localizedDescription)
        }
        completionHandler()
    }

    private func getAccessToken(enrollment: AuthenticatorEnrollmentProtocol, completion: @escaping (String) -> Void) {
        // Fetching maintenance access token
        enrollment.retrieveMaintenanceToken() { result in
            switch result {
            case .success(let credential):
                completion(credential.access_token)
            case .failure(let error):
                self.logger?.error(eventName: LoggerEvent.pushService.rawValue, message: "Failed to retrieve maintenance token: \(error)")
            }
        }
    }

    private func resolvePushChallenge(_ pushChallenge: PushChallengeProtocol) {
        guard shouldHandleChallenge(newChallenge: pushChallenge) else { return }
        unhandledChallenges.insert(pushChallenge.transactionId)

        pushChallenge.resolve { step in
            self.remediationEventsHandler.handle(step: step)
        } onCompletion: { [weak self] error in
            guard let self = self else { return }
            DispatchQueue.main.async {
                self.unhandledChallenges.remove(pushChallenge.transactionId)
                if let error = error {
                    self.logger?.error(eventName: LoggerEvent.account.rawValue, message: "Cannot resolve push challenge: \(error.localizedDescription)")
                } else {
                    self.remediationEventsHandler.onChallengeResolved(pushChallenge.userResponse)
                    self.logger?.info(eventName: LoggerEvent.account.rawValue, message: "Success resolving push challenge")
                }
            }
        }
    }

    /**
     Helper method to avoid showing a Consent screen twice for the same challenge delivered via push and via pending challenges call.
     Needed for the case when the app is opened via tapping a push notification: as soon as the app becomes active, it will fetch pending challenges as well via retrievePushChallenges(), therefore you will get the same challenge twice from the SDK. This methods checks if the same transactionID is already being handled.
    */
    private func shouldHandleChallenge(newChallenge: PushChallengeProtocol) -> Bool {
        return !unhandledChallenges.contains(newChallenge.transactionId)
    }

    func retrievePushChallenges() {
        logger?.info(eventName: LoggerEvent.account.rawValue, message: "Retrieve push challenges for all enrollments")
        deviceAuthenticator.allEnrollments().forEach { enrollment in
            getAccessToken(enrollment: enrollment) { accessToken in
                let authToken = AuthToken.bearer(accessToken)
                enrollment.retrievePushChallenges(authenticationToken: authToken) { [weak self] result in
                    DispatchQueue.main.async {
                        switch result {
                        case .success(let challenges):
                            challenges.forEach { challenge in
                                self?.resolvePushChallenge(challenge)
                            }
                        case .failure(let error):
                            self?.logger?.error(eventName: LoggerEvent.account.rawValue, message: error.errorDescription ?? "Unknown error")
                        }
                    }
                }
            }
        }
    }
}
