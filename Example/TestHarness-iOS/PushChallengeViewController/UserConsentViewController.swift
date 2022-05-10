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

protocol UserConsentViewProtocol: BaseViewProtocol {
    
}

class UserConsentViewController: UIViewController, StoryboardController, UserConsentViewProtocol {

    var viewModel: PushChallengeViewModelProtocol!

    @IBOutlet weak var clientLocationLabel: UILabel!
    @IBOutlet weak var clientOSLabel: UILabel!
    @IBOutlet weak var originalURLLabel: UILabel!
    @IBOutlet weak var dateLabel: UILabel!
    @IBOutlet weak var timeLabel: UILabel!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        viewModel.start()
    }

    func updateData() {
        title = viewModel.titleString
        clientLocationLabel.text = viewModel.clientLocationString
        clientOSLabel.text = viewModel.clientOSString
        originalURLLabel.text = viewModel.urlString
        dateLabel.text = viewModel.dateString
        timeLabel.text = viewModel.timeString
    }

    @IBAction func approveButtonTapped() {
        viewModel.approveChallenge()
    }

    @IBAction func deniedButtonTapped() {
        viewModel.denyChallenge()
    }
}

