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

import OktaOidc
import OktaDeviceSDK

protocol RootControllerManagerProtocol {
    func provideRootController() -> UIViewController
    func updateRoot(with controller: UIViewController)
}

class RootControllerManager: RootControllerManagerProtocol {
    static let shared = RootControllerManager()

    var window: UIWindow!
    var deviceAuthenticator: DeviceAuthenticatorProtocol!
    var accessTokenManager: AccessTokenManagerProtocol!

    private init() {}

    func provideRootController() -> UIViewController {
        let viewController = EnrollmentsViewController.loadFromStoryboard()
        let viewModel = EnrollmentsViewModel(deviceAuthenticator: deviceAuthenticator, accessTokenManager: accessTokenManager)
        viewController.viewModel = viewModel
        viewModel.view = viewController
        return viewController.embedInNavigation()
    }

    func updateRoot(with controller: UIViewController) {
        window.rootViewController = controller
    }
}
