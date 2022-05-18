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

import UIKit
import WebAuthenticationUI
import OktaDeviceSDK
import OktaLogger

@main
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?
    var rootCoordinator: RootCoordinator?
    var deviceAuthenticator: DeviceAuthenticatorProtocol!
    var pushNotificationService: PushNotificationService!
    var remediationEventsHandler: RemediationStepHandlerProtocol!
    var logger: OktaLogger!

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {

        window = .init(frame: UIScreen.main.bounds)
        
        logger = OktaLogger()
        logger.addDestination(OktaLoggerConsoleLogger(identifier: "PushSDKSampleApp.console.logger", level: .all, defaultProperties: nil))

        guard let webAuthenticator = WebAuthentication.shared else {
            logger.error(eventName: LoggerEvent.appInit.rawValue, message: "Failed to initialize WebAuthenticator SDK")
            fatalError("Couldn't initialize OktaWebAuthenticator, please review your Okta.plist settings")
            return true
        }

        initOktaDeviceAuthenticator()
        remediationEventsHandler = RemediationStepHandler()
        pushNotificationService = PushNotificationService(deviceAuthenticator: deviceAuthenticator,
                                                          remediationEventsHandler: remediationEventsHandler,
                                                          webAuthenticator: webAuthenticator,
                                                          logger: logger)

        rootCoordinator = RootCoordinator(deviceAuthenticator: deviceAuthenticator,
                                          oktaWebAuthenticator: webAuthenticator,
                                          remediationEventsHandler: remediationEventsHandler,
                                          oktaLogger: logger)
        rootCoordinator?.begin(on: window)

        pushNotificationService.requestNotificationsPermissions()
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        // Whenever iOS assigns or updates the push token, your app must pass the new deviceToken to the SDK, which will perform the update for all enrollments associated with this device.
        pushNotificationService.updateDeviceTokenForEnrollments(data: deviceToken)
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        logger.error(eventName: LoggerEvent.appInit.rawValue, message: "didFailToRegisterForRemoteNotificationsWithError-\(error.localizedDescription)")
    }

    func initOktaDeviceAuthenticator() {
        do {
            let applicationConfig = ApplicationConfig(applicationName: "PushSDKSampleApp-iOS",
                                                      applicationVersion: "1.0.0",
                                                      applicationGroupId: "group.com.okta.SampleApp")
            applicationConfig.pushSettings.apsEnvironment = .development
            applicationConfig.pushSettings.approveActionTitle = PushSettingsConstant.approveActionTitle
            applicationConfig.pushSettings.denyActionTitle = PushSettingsConstant.denyActionTitle
            applicationConfig.pushSettings.userVerificationActionTitle = PushSettingsConstant.userVerificationActionTitle
            deviceAuthenticator = try DeviceAuthenticatorBuilder(applicationConfig: applicationConfig).create()
        } catch {
            logger.error(eventName: LoggerEvent.appInit.rawValue, message: "Failed to initialize OktaAuthenticator SDK")
            fatalError("Failed to initialize OktaAuthenticator SDK")
        }
    }
    
    func applicationDidBecomeActive(_ application: UIApplication) {
        pushNotificationService.retrievePushChallenges()
    }
}


enum PushSettingsConstant {
    static let approveActionTitle = "Yes, it's me"
    static let denyActionTitle = "No, it's not me"
    static let userVerificationActionTitle = "Review"
}

enum LoggerEvent: String {
    case appInit, pushService, webSignIn, enrollment, account
}
