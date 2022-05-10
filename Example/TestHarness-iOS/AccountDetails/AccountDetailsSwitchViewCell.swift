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

class AccountDetailsSwitchViewCell: UITableViewCell {

    @IBOutlet private var titleLabel: UILabel!
    @IBOutlet private var toggle: UISwitch!
    private var callback: ((Bool)->())?

    override func prepareForReuse() {
        super.prepareForReuse()
        titleLabel.text = nil
        toggle.isOn = false
        callback = nil
    }

    func display(title: String, isOn: Bool, toggleAction: @escaping ((Bool)->())) {
        titleLabel.text = title
        toggle.isOn = isOn
        callback = toggleAction
    }

    @IBAction private func toggleAction(_ sender: UISwitch) {
        callback?(sender.isOn)
    }
}
