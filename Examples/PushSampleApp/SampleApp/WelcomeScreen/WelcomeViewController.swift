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

class WelcomeViewController: UIViewController, StoryboardController {

    @IBOutlet weak var welcomeLabel: UILabel!
    var didTapSettings: () -> Void = {}
    var didTapSignOut: () -> Void = {}
    var didTapShareLogs: () -> Void = {}
    var didRequestSignInFaster: () -> Void = {}
    var viewModel: WelcomeViewModel!

    override func viewDidLoad() {
        super.viewDidLoad()
        navigationItem.largeTitleDisplayMode = .always
        navigationItem.rightBarButtonItem = UIBarButtonItem(title: "Settings", style: .plain, target: self, action: #selector(didTapSettingsButton))
        navigationItem.leftBarButtonItem = UIBarButtonItem(title: "Sign out", style: .plain, target: self, action: #selector(didTapSignOutButton))
        self.welcomeLabel.text = self.viewModel.welcomeLabelText
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        didRequestSignInFaster()
    }

    @objc func didTapSettingsButton() {
        didTapSettings()
    }

    @objc func didTapSignOutButton() {
        didTapSignOut()
    }

    @IBAction func didTapShareLogsButton() {
        didTapShareLogs()
    }
}
