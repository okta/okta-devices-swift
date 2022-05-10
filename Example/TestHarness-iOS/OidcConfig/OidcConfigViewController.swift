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

extension UINavigationController {
    func popViewController(animated: Bool, completion: @escaping () -> Void) {
        popViewController(animated: animated)

        if animated, let coordinator = transitionCoordinator {
            coordinator.animate(alongsideTransition: nil) { _ in
                completion()
            }
        } else {
            completion()
        }
    }
}

protocol OidcConfigViewProtocol: BaseViewProtocol {
    
}

class OidcConfigViewController: UIViewController, StoryboardController, OidcConfigViewProtocol {
    var viewModel: OidcConfigViewModelProtocol!

    @IBOutlet weak var clientIdTextField: UITextField!
    @IBOutlet weak var issuerTextField: UITextField!
    @IBOutlet weak var redirectUriTextField: UITextField!
    @IBOutlet weak var logoutRedirectUriTextField: UITextField!
    @IBOutlet weak var doneButton: UIBarButtonItem!

    override func viewDidLoad() {
        super.viewDidLoad()
        doneButton.title = viewModel.doneButtonTitle
    }

    @IBAction func next(_ sender: UITextField) {
        if sender == clientIdTextField {
            issuerTextField.becomeFirstResponder()
        } else if sender == issuerTextField {
            redirectUriTextField.becomeFirstResponder()
        } else if sender == redirectUriTextField {
            logoutRedirectUriTextField.becomeFirstResponder()
        }
    }

    @IBAction func done(_ sender: UITextField) {
        view.endEditing(true)
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        viewModel.start()
    }

    func updateData() {
        clientIdTextField.text = viewModel.clientId
        issuerTextField.text = viewModel.issuer
        redirectUriTextField.text = viewModel.redirectUri
        logoutRedirectUriTextField.text = viewModel.logoutRedirectUri
    }

    @IBAction func doneButtonTapped() {
        viewModel.prepareConfig(clientId: clientIdTextField.text ?? "",
                                issuer: issuerTextField.text ?? "",
                                redirectUri: redirectUriTextField.text ?? "",
                                logoutRedirectUri: logoutRedirectUriTextField.text ?? "")
    }
}
