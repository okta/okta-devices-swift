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

class UserConsentViewController: UIViewController, StoryboardController {

    @IBOutlet weak var clientLocationLabel: UILabel!
    
    @IBOutlet weak var clientOSLabel: UILabel!
    
    @IBOutlet weak var urlLabel: UILabel!

    @IBOutlet weak var dateLabel: UILabel!

    @IBOutlet weak var timeLabel: UILabel!
    
    var viewModel: UserConsentViewModel!

    override func viewDidLoad() {
        super.viewDidLoad()
        updateUI()
    }
    
    @IBAction func didTapApproveButton(_ sender: Any) {
        viewModel.didTapApproveChallenge()
    }
    
    @IBAction func didTapDenyButton(_ sender: Any) {
        viewModel.didTapDenyChallenge()
    }
    
    func updateUI() {
        title = viewModel.titleString
        clientLocationLabel.text = viewModel.clientLocationString
        clientOSLabel.text = viewModel.clientOSString
        urlLabel.text = viewModel.urlString
        dateLabel.text = viewModel.dateString
        timeLabel.text = viewModel.timeString
    }
}
