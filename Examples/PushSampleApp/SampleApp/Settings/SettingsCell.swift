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

class SettingsCell: UITableViewCell {

    @IBOutlet weak var titleLabel: UILabel!
    @IBOutlet weak var subtitleLabel: UILabel!
    @IBOutlet weak var actionableView: UIView!
    @IBOutlet weak var swithControl: UISwitch!

    static let cellId: String = "SettingsCell"

    override func awakeFromNib() {
        super.awakeFromNib()
    }

    var didSwitchToggle: ((Bool) -> Void)?

    func setup(cellModel: SettingsCellProtocol) {
        titleLabel.text = cellModel.title
        subtitleLabel.text = cellModel.subtitle
        swithControl.isHidden = !cellModel.shouldShowSwitch
        swithControl.isOn = cellModel.isEnabled ?? false
        didSwitchToggle = cellModel.didToggleSwitch
    }

    @IBAction func onSwitchToggle() {
        didSwitchToggle?(swithControl.isOn)
    }
}
