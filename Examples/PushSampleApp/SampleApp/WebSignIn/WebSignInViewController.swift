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

class WebSignInViewController: UIViewController, StoryboardController {

    @IBOutlet weak var infoLabel: UILabel!
    @IBOutlet weak var signInButton: UIButton!

    var viewModel: SignInViewModelProtocol!
    var didSignIn: () -> Void = {}

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .white
        navigationItem.title = viewModel.title
        addCustomNavBarAppereance()
        setUpCallbacks()
        updateUI()
    }

    private func setUpCallbacks() {
        viewModel.didSignIn = { [weak self] signInSuccess in
            guard !signInSuccess else {
                self?.didSignIn()
                return
            }
            self?.updateUI()
            self?.dismiss(animated: true)
        }
    }

    private func updateUI() {
        DispatchQueue.main.async {
            self.infoLabel.text = self.viewModel.infoLabelText
            self.signInButton.isHidden = self.viewModel.isSignedIn
        }
    }

    @IBAction func didTapSignIn() {
        guard let window = view.window else { return }
        viewModel.onSignInTapped(on: window)
    }
}

