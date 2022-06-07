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
import OktaDeviceSDK
import OktaLogger

class RootCoordinator {

    let deviceAuthenticator: DeviceAuthenticatorProtocol
    let oktaWebAuthenticator: OktaWebAuthProtocol
    let pushNotificationService: PushNotificationService
    var remediationEventsHandler: RemediationEventsHandlerProtocol
    var logger: OktaLogger?
    var navController: UINavigationController?

    static let mainStoryboardName = "MainStoryboard"

    init(deviceAuthenticator: DeviceAuthenticatorProtocol,
         oktaWebAuthenticator: OktaWebAuthProtocol,
         pushNotificationService: PushNotificationService,
         remediationEventsHandler: RemediationEventsHandlerProtocol,
         oktaLogger: OktaLogger?) {
        self.deviceAuthenticator = deviceAuthenticator
        self.oktaWebAuthenticator = oktaWebAuthenticator
        self.pushNotificationService = pushNotificationService
        self.logger = oktaLogger
        self.remediationEventsHandler = remediationEventsHandler
    }

    func begin(on window: UIWindow?) {
        if oktaWebAuthenticator.isSignedIn {
            beginWelcomeFlow(on: window)
        } else {
            beginSignInFlow(on: window)
        }
    }
    
    private func beginWelcomeFlow(on window: UIWindow?) {
        let welcomeVC = WelcomeViewController.loadFromStoryboard(storyboardName: Self.mainStoryboardName)
        welcomeVC.viewModel = WelcomeViewModel(webAuthenticator: oktaWebAuthenticator)
        welcomeVC.didTapSettings = {
            self.beginSettingsFlow()
        }
        welcomeVC.didTapSignOut = {
            self.beginSignOut()
        }
        welcomeVC.didRequestSignInFaster = { [weak self] in
            self?.beginSignInFasterFlow()
        }
        let navController = UINavigationController(rootViewController: welcomeVC)
        navController.setNavigationBarHidden(false, animated: false)
        window?.rootViewController = navController
        self.navController = navController
        window?.makeKeyAndVisible()
    }
    
    private func beginSignInFlow(on window: UIWindow?) {
    
        let signInViewModel = SignInViewModel(deviceAuthenticator: deviceAuthenticator,
                                              oktaWebAuthProtocol: oktaWebAuthenticator,
                                              logger: logger)
        let webSignInVC = WebSignInViewController.loadFromStoryboard(storyboardName: Self.mainStoryboardName)
        webSignInVC.didSignIn = {
            self.navController?.popViewController(animated: true)
            self.begin(on: window)
        }
        webSignInVC.viewModel = signInViewModel
        let navController = UINavigationController(rootViewController: webSignInVC)
        window?.rootViewController = navController
        self.navController = navController
        window?.makeKeyAndVisible()
    }
    
    func beginUserConsentFlow(remediationStep: RemediationStepUserConsent) {
        guard let nav = navController else { return }
        let userConsentVC = UserConsentViewController.loadFromStoryboard(storyboardName: Self.mainStoryboardName)
        var viewModel = UserConsentViewModel(remediationStep: remediationStep)
        viewModel.onRemediationComplete = {
            nav.dismiss(animated: true)
        }
        userConsentVC.viewModel = viewModel
        if nav.presentedViewController != nil {
            nav.dismiss(animated: true) {
                nav.present(userConsentVC, animated: true)
            }
        } else {
            nav.present(userConsentVC, animated: true)
        }
    }
    
    func handleChallengeResponse(userResponse: PushChallengeUserResponse) {
        guard userResponse != .userNotResponded else {
            // Here you would handle if the user didn't respond to the challenge
            return
        }
        guard let nav = navController else { return }
        showVerificationAlert(didApprove: userResponse == .userApproved, nav: nav)
    }
    
    private func showVerificationAlert(didApprove: Bool, nav: UINavigationController) {
        var alertTitle: String
        var alertText: String
        if didApprove {
            alertTitle = "Continue at magentabank.com"
            alertText = "Thanks for securely verifying your identity."
        } else {
            alertTitle = "We've logged this attempt to sign in"
            alertText = "The details of this attempt have been logged for security review."
        }
        let alert = UIAlertController(title: alertTitle, message: alertText, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Ok", style: .default))
        nav.present(alert, animated: true, completion: nil)
    }

    func beginSettingsFlow() {
        let vc = SettingsViewController.loadFromStoryboard(storyboardName: Self.mainStoryboardName)
        vc.viewModel = SettingsViewModel(deviceauthenticator: deviceAuthenticator,
                                         webAuthenticator: oktaWebAuthenticator,
                                         pushNotificationService: pushNotificationService,
                                         settingsView: vc,
                                         logger: logger)
        let nav = UINavigationController(rootViewController: vc)

        navController?.present(nav, animated: true)
    }
    
    private func beginSignOut() {
        guard let window = navController?.navigationBar.window else { return }
        
        /*
         Depending on your app's behavior, you may want to delete the current enrollment from both server and device when signing out of the User's session. This to avoid receiving the wrong push notifications for the next user that may sign in into your app.
         For this sample app, we are doing this by removing the existing enrollment via the SDK's `delete` API and signing out on completion.
         */
        guard let enrollment = deviceAuthenticator.allEnrollments().first else {
            signOut(from: window)
            return
        }

        oktaWebAuthenticator.getAccessToken {[weak self] result in
            switch result {
            case .success(let token):
                self?.deviceAuthenticator.delete(enrollment: enrollment, authenticationToken: AuthToken.bearer(token.accessToken), completion: { error in
                    self?.signOut(from: window)
                    
                    if case .serverAPIError = error {
                        try? enrollment.deleteFromDevice()
                    }
                    self?.logger?.error(eventName: LoggerEvent.enrollmentDelete.rawValue, message: error?.localizedDescription)
                })
            case .failure(let error):
                self?.signOut(from: window)
                self?.logger?.error(eventName: LoggerEvent.account.rawValue, message: error.errorDescription)
            }
        }
        
    }
    
    private func signOut(from window: UIWindow) {
        oktaWebAuthenticator.signOut(from: window) { [weak self] result in
            switch result {
            case .success():
                self?.navController?.popViewController(animated: true)
                self?.begin(on: window)
            case .failure(let error):
                self?.logger?.error(eventName: LoggerEvent.webSignIn.rawValue, message: error.localizedDescription)
            }
        }
    }

    private func beginSignInFasterFlow() {
        let vc = SignInFasterViewController.loadFromStoryboard(storyboardName: Self.mainStoryboardName)
        vc.didTapSetupButton = { [weak self, weak vc] in
            vc?.dismiss(animated: true) {
                self?.beginSettingsFlow()
            }
        }
        navController?.present(vc, animated: true)
    }
}
