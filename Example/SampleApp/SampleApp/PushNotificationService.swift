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
import OktaDeviceSDK
import WebAuthenticationUI

class PushNotificationService: NSObject, UNUserNotificationCenterDelegate {

    private var logger: OktaLogger?
    private var deviceAuthenticator: DeviceAuthenticatorProtocol
    private let remediationEventsHandler: RemediationStepHandlerProtocol

    init(deviceAuthenticator: DeviceAuthenticatorProtocol,
         remediationEventsHandler: RemediationStepHandlerProtocol,
         logger: OktaLogger?) {
        self.logger = logger
        self.deviceAuthenticator = deviceAuthenticator
        self.remediationEventsHandler = remediationEventsHandler
        super.init()
        UNUserNotificationCenter.current().delegate = self
    }

    func requestNotificationsPermissions() {
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
                    UIApplication.shared.registerForRemoteNotifications()
                } else {
                    self.logger?.info(eventName: LoggerEvent.pushService.rawValue, message: "Push notifications permissions denied")
                }
            }
        }
    }

    func saveDeviceToken(data: Data) {
        UserDefaults.save(deviceToken: data)
        deviceAuthenticator.allEnrollments().forEach({ enrollment in
            // Need to fetch a valid accessToken in order to update DeviceToken, thus refreshing if it's expired. Completion closure will be called immediately if AC is still valid.
            Credential.default?.refreshIfNeeded { result in
                switch result {
                case .success(let token):
                    enrollment.updateDeviceToken(data, authenticationToken: AuthToken.bearer(token.accessToken)) { error in
                        self.logger?.info(eventName: LoggerEvent.pushService.rawValue, message: "Success update device token")
                    }
                case .failure(let error):
                    self.logger?.error(eventName: LoggerEvent.pushService.rawValue, message: error.localizedDescription)
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

    private func resolvePushChallenge(_ pushChallenge: PushChallengeProtocol) {
        pushChallenge.resolve { step in
            self.remediationEventsHandler.handle(step: step)
        } onCompletion: { error in
            DispatchQueue.main.async {
                if let error = error {
                    self.logger?.error(eventName: LoggerEvent.account.rawValue, message: "Cannot resolve push challenge: \(error.localizedDescription)")
                } else {
                    self.logger?.error(eventName: LoggerEvent.account.rawValue, message: "Success resolving push challenge")
                }
            }
        }
    }

    func retrievePushChallenges() {
        Credential.default?.refreshIfNeeded { result in
            switch result {
            case .success(let token):
                self.retrievePushChallenges(accessToken: token.accessToken)
            case .failure(let error):
                self.logger?.error(eventName: LoggerEvent.account.rawValue, message: error.localizedDescription)
            }
        }
    }

    private func retrievePushChallenges(accessToken: String) {
        let authToken = AuthToken.bearer(accessToken)
        logger?.info(eventName: LoggerEvent.account.rawValue, message: "Retrieve push challenges for all enrollments")
        deviceAuthenticator.allEnrollments().forEach { enrollment in
            // Using same access token for all enrollments since this is a single user app.
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
