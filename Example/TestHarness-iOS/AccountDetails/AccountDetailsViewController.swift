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

import UIKit

protocol AccountDetailsViewProtocol: ActivityIndicatorViewProtocol, BaseViewProtocol {
}

class AccountDetailsViewController: UIViewController, StoryboardController, AccountDetailsViewProtocol, UITableViewDataSource, UITableViewDelegate {
    struct AccountDetailsConstants {
        static let cellReuseIdentifier = "EnrolledAuthenticatorCell"
        static let cellSwitchReuseIdentifier = "UserVerificationKeyCell"
    }

    @IBOutlet weak var tableView: UITableView!
    @IBOutlet weak var actionsButton: UIBarButtonItem!

    var viewModel: AccountDetailsViewModelProtocol!

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        tableView.dataSource = self
        tableView.delegate = self
        title = viewModel.listTitle
        viewModel.start()
    }

    func updateData() {
        tableView.reloadData()
    }

    @IBAction func actionsButtonTapped() {
        viewModel.showActions(from: actionsButton)
    }

    // MARK: UITableViewDataSource
    func numberOfSections(in tableView: UITableView) -> Int {
        return 2
    }

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        switch section {
        case 0:
            return viewModel.profileInfo.count
        case 1:
            return 1
        default:
            return 0
        }
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        switch indexPath.section {
        case 0:
            return createAccountDetailsViewCell(for: indexPath)
        case 1:
            return createAccountDetailsSwitchViewCell(for: indexPath)
        default:
            fatalError("Unexpected count of sections")
        }
    }
    
    private func createAccountDetailsViewCell(for indexPath: IndexPath) -> AccountDetailsInfoViewCell {
        let reuseIdentifier = AccountDetailsConstants.cellReuseIdentifier
        guard let cell = tableView.dequeueReusableCell(withIdentifier: reuseIdentifier, for: indexPath) as? AccountDetailsInfoViewCell else {
            fatalError("Cell with id: \(reuseIdentifier) has not found")
        }
        let profileField = viewModel.profileInfo[indexPath.row]
        cell.display(title: profileField.key, details: profileField.value)
        return cell
    }
    
    private func createAccountDetailsSwitchViewCell(for indexPath: IndexPath) -> AccountDetailsSwitchViewCell {
        let reuseIdentifier = AccountDetailsConstants.cellSwitchReuseIdentifier
        guard let cell = tableView.dequeueReusableCell(withIdentifier: reuseIdentifier, for: indexPath) as? AccountDetailsSwitchViewCell else {
            fatalError("Cell with id: \(reuseIdentifier) has not found")
        }
        cell.display(title: "User verification", isOn: viewModel.isEnableUserVerification) { [weak self] newValue in
            self?.viewModel.setUserVerification(enable: newValue)
        }
        return cell
    }

    // MARK: UITableViewDelegate
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
    }
}
