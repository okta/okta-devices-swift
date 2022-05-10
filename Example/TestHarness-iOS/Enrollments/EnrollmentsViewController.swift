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

protocol EnrollmentsViewProtocol: ActivityIndicatorViewProtocol, BaseViewProtocol {
    func showAccountDetails(_ viewController: UIViewController)
    func updateData()
    func updateUI()
}

class EnrollmentsViewController: UIViewController, StoryboardController, EnrollmentsViewProtocol, UITableViewDataSource, UITableViewDelegate {
    struct EnrollmentsConstants {
        static let cellReuseIdentifier = "EnrolledAuthenticatorCell"
    }

    @IBOutlet weak var enrollButton: UIBarButtonItem!
    @IBOutlet weak var tableView: UITableView!
    @IBOutlet weak var noContentLabel: UILabel!
    @IBOutlet weak var actionsButton: UIBarButtonItem!

    var viewModel: EnrollmentsViewModelProtocol!

    override func viewDidLoad() {
        super.viewDidLoad()
        tableView.dataSource = self
        tableView.delegate = self
        title = viewModel.listTitle
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        viewModel.start()
    }

    @IBAction func actionsButtonTapped() {
        viewModel.showActions(from: actionsButton)
    }

    @IBAction func enrollButtonTapped() {
        viewModel.startEnrollment(on: self)
    }

    func updateData() {
        tableView.reloadData()
    }

    func updateUI() {
        tableView.isHidden = !viewModel.hasEnrolledAuthenticators
        noContentLabel.isHidden = viewModel.hasEnrolledAuthenticators
    }

    func showAccountDetails(_ viewController: UIViewController) {
        push(viewController)
    }

    // MARK: UITableViewDataSource
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        guard section == 0 else { return 0 }
        return viewModel.enrollmentsCount
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: EnrollmentsConstants.cellReuseIdentifier) ?? UITableViewCell(style: .subtitle, reuseIdentifier: EnrollmentsConstants.cellReuseIdentifier)

        let authenticator = viewModel.enrolledAuthenticators[indexPath.row]
        cell.textLabel?.text = "User name: \(authenticator.user.name ?? "")"
        cell.detailTextLabel?.numberOfLines = 0
        cell.detailTextLabel?.text = "User id: \(authenticator.user.id)\nEnrollment id: \(authenticator.enrollmentId)"

        return cell
    }

    //MARK: UITableViewDelegate
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)

        let enrollment = viewModel.enrolledAuthenticators[indexPath.row]
        viewModel.showAccountDetails(for: enrollment)
    }

    func tableView(_ tableView: UITableView, trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
        let contextualAction = UIContextualAction(style: .destructive, title: "Delete") { [weak self] _, _, completionHandler in
            guard let enrollment = self?.viewModel.enrolledAuthenticators[indexPath.row] else {
                completionHandler(false)
                return
            }
            self?.viewModel.delete(enrollment: enrollment)
            completionHandler(true)
        }
        return UISwipeActionsConfiguration(actions: [contextualAction])
    }
}
