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
    var remediationEventsHandler: RemediationStepHandlerProtocol
    var logger: OktaLogger?
    var navController: UINavigationController?
    

    static let mainStoryboardName = "MainStoryboard"

    init(deviceAuthenticator: DeviceAuthenticatorProtocol,
         oktaWebAuthenticator: OktaWebAuthProtocol,
         remediationEventsHandler: RemediationStepHandlerProtocol,
         oktaLogger: OktaLogger?) {
        self.deviceAuthenticator = deviceAuthenticator
        self.oktaWebAuthenticator = oktaWebAuthenticator
        self.logger = oktaLogger
        self.remediationEventsHandler = remediationEventsHandler
        setupRemediationHandler()
    }

    func begin(on window: UIWindow?) {
        if oktaWebAuthenticator.isSignedIn {
            beginWelcomeFlow(on: window)
        } else {
            beginSignInFlow(on: window)
        }
    }
    
    private func setupRemediationHandler() {
        remediationEventsHandler.onUserVerification = { [weak self] step in
            // TODO: To implement UV flow
        }
        remediationEventsHandler.onUserConsent = { [weak self] step in
            guard let navController = self?.navController else { return }
            self?.beginUserConsentFlow(on: navController, remediationStep: step)
        }
    }
    
    private func beginWelcomeFlow(on window: UIWindow?) {
    
        let welcomeVC = WelcomeViewController.loadFromStoryboard(storyboardName: Self.mainStoryboardName)
        welcomeVC.viewModel = WelcomeViewModel(webAuthenticator: oktaWebAuthenticator)
        welcomeVC.didTapSettings = {
            self.beginSettingsFlow()
        }
        welcomeVC.didTapSignOut = {
            self.signOut()
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
    
    func beginUserConsentFlow(on nav: UINavigationController, remediationStep: RemediationStepUserConsent) {

        let userConsentVC = UserConsentViewController.loadFromStoryboard(storyboardName: Self.mainStoryboardName)
        var viewModel = UserConsentViewModel(remediationStep: remediationStep)
        viewModel.onCompletion = {
            nav.dismiss(animated: true)
        }
        userConsentVC.viewModel = viewModel
        nav.present(userConsentVC, animated: true)
    }
    
    func beginSettingsFlow() {

        let vc = SettingsViewController.loadFromStoryboard(storyboardName: Self.mainStoryboardName)
        vc.viewModel = SettingsViewModel(deviceauthenticator: deviceAuthenticator, webAuthenticator: oktaWebAuthenticator, logger: logger)
        let nav = UINavigationController(rootViewController: vc)

        navController?.present(nav, animated: true)
    }
    
    private func signOut() {

        guard let window = navController?.navigationBar.window else { return }
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
