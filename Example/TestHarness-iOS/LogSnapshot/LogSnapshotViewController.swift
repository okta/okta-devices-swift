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

protocol LogSnapshotViewProtocol: BaseViewProtocol {
    func updateUI()
}

class LogSnapshotViewController: UIViewController, StoryboardController, LogSnapshotViewProtocol {

    @IBOutlet private var emptyLabel: UILabel!
    @IBOutlet private var logsTextView: UITextView!

    var viewModel: LogSnapshotViewModelProtocol!

    override func viewDidLoad() {
        super.viewDidLoad()
        viewModel.start()
    }

    func updateUI() {
        emptyLabel.isHidden = !viewModel.isLogsFileEmpty
        logsTextView.isHidden = viewModel.isLogsFileEmpty
        let range = NSRange(location: viewModel.logsString.count - 1, length: 0)
        logsTextView.scrollRangeToVisible(range)
    }

    func updateData() {
        logsTextView.text = viewModel.logsString
    }
}

class LogSnapshot {

    static func show(from logger: LoggerManagerProtocol, in view: BaseViewProtocol) {
        let viewModel = LogSnapshotViewModel(logger: logger)
        let logSnapshotView = LogSnapshotViewController.loadFromStoryboard()
        logSnapshotView.viewModel = viewModel
        viewModel.view = logSnapshotView
        view.push(logSnapshotView)
    }
}
