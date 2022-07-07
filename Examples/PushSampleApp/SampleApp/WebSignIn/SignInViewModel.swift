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
import DeviceAuthenticator
import WebAuthenticationUI
import OktaLogger

protocol SignInViewModelProtocol {
    func onSignInTapped(on window: UIWindow)

    var isSignedIn: Bool { get }
    var infoLabelText: String { get }
    var didSignIn: ((Bool) -> Void) { get set }
    var title: String { get }
}

class SignInViewModel: SignInViewModelProtocol {

    private let authenticator: DeviceAuthenticatorProtocol
    private let oktaWebAuth: OktaWebAuthProtocol
    private var logger: OktaLogger?

    var didSignIn: ((Bool) -> Void) = { _ in }
    var didEnroll: ((EnrollmentError?) -> Void) = { _ in }

    init(deviceAuthenticator: DeviceAuthenticatorProtocol,
         oktaWebAuthProtocol: OktaWebAuthProtocol,
         logger: OktaLogger?) {
        self.oktaWebAuth = oktaWebAuthProtocol
        self.authenticator = deviceAuthenticator
        self.logger = logger
    }

    func onSignInTapped(on window: UIWindow) {
        startSignIn(on: window)
    }

    private func startSignIn(on window: UIWindow) {
        oktaWebAuth.signIn(from: window) { [weak self] result in
            switch result {
            case .success(let token):
                do {
                    try Credential.store(token)
                } catch {
                    self?.logger?.error(eventName: LoggerEvent.webSignIn.rawValue, message: "Cannot sign in - \(error.localizedDescription)")
                    self?.didSignIn(false)
                    return
                }
                self?.didSignIn(true)
            case .failure(let error):
                self?.logger?.error(eventName: LoggerEvent.webSignIn.rawValue, message: "Cannot sign in - \(error.localizedDescription)")
                self?.didSignIn(false)
            }
        }
    }


    private var isEnrolled: Bool {
        guard !authenticator.allEnrollments().isEmpty else { return false }
        return true
    }

    var isSignedIn: Bool {
        return oktaWebAuth.isSignedIn
    }

    var infoLabelText: String {
        return "Welcome"
    }
    
    var title: String {
        return "Magenta Bank"
    }
}
