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

protocol SettingsViewUpdatable: AnyObject {
    func showAlert(alertTitle: String, alertText: String)
    func updateView(shouldShowSpinner: Bool)
}

class SettingsViewController: UIViewController, StoryboardController, UITableViewDelegate, UITableViewDataSource, SettingsViewUpdatable {

    @IBOutlet weak var settingsTableView: UITableView!
    @IBOutlet weak var spinner: UIActivityIndicatorView!
    var viewModel: SettingsViewModelProtocol!

    override func viewDidLoad() {
        super.viewDidLoad()
        addCustomNavBarAppereance()
        setupTableView()
        navigationItem.title = viewModel.title
    }

    private func setupTableView() {
        settingsTableView.delegate = self
        settingsTableView.dataSource = self
    }

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return viewModel.numberOfRows
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        guard let cell = tableView.dequeueReusableCell(withIdentifier: SettingsCell.cellId) as? SettingsCell else { return UITableViewCell() }
        viewModel.setup(cell: cell, with: indexPath.row)
        return cell
    }

    func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat {
        return 70
    }

    func showAlert(alertTitle: String, alertText: String) {
        DispatchQueue.main.async {
            let alert = UIAlertController(title: alertTitle, message: alertText, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Ok", style: .default))
            self.present(alert, animated: true, completion: nil)
        }
    }

    func updateView(shouldShowSpinner: Bool) {
        DispatchQueue.main.async {
            guard shouldShowSpinner else {
                self.spinner.stopAnimating()
                self.settingsTableView.reloadData()
                return
            }
            self.spinner.startAnimating()
        }
    }
}
