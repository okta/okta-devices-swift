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
import UIKit
import OktaDeviceSDK

class RemediationEventsHandler {
    
    private let navigationController: UINavigationController

    init(navigationController: UINavigationController) {
        self.navigationController = navigationController
    }
    
    func handle(_ remediationStep: RemediationStep) {
        
        switch remediationStep {
        case let userConsentStep as RemediationStepUserConsent:
            // Show UX to allow the user to say "yes" or "no" to the sign-in attempt
            start(userConsentStep)
        default:
            remediationStep.doNotProcess()
        }
    }

    private func start(_ remediationStep: RemediationStepUserConsent) {
        
        let viewController = UserConsentViewController.loadFromStoryboard()
        let viewModel = PushChallengeViewModel(remediationStep: remediationStep, completion: {
            self.dissmiss()
        })
        viewController.viewModel = viewModel
        viewModel.view = viewController
        self.navigationController.pushViewController(viewController, animated: false)
    }
    
    private func dissmiss(animation: Bool = true) {
        navigationController.popViewController(animated: animation)
    }
}
