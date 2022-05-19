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

import Foundation

enum SettingsCellType {
    case email, pushSignIn, userVerification
}

protocol SettingsCellProtocol {
    var title: String? { get }
    var subtitle: String? { get }
    var type: SettingsCellType { get }
    var isEnabled: Bool? { get }
    var didToggleSwitch: ((Bool) -> Void)? { get }
    var shouldShowSwitch: Bool { get }
}

struct EmailSettingsCellModel: SettingsCellProtocol {
    var title: String? = "Email address"
    var subtitle: String?
    var type: SettingsCellType = .email
    var isEnabled: Bool? = false
    var shouldShowSwitch: Bool = false
    var didToggleSwitch: ((Bool) -> Void)?
    init(email: String?) {
        subtitle = email
    }
}

struct PushSettingsCellModel: SettingsCellProtocol {
    var title: String? = ""
    var subtitle: String? = "Sign in with push notification"
    var type: SettingsCellType = .pushSignIn
    var isEnabled: Bool?
    var shouldShowSwitch: Bool = true
    var didToggleSwitch: ((Bool) -> Void)?

    init(isEnabled: Bool, didToggleSwitch: @escaping (Bool) -> Void) {
        self.isEnabled = isEnabled
        self.didToggleSwitch = didToggleSwitch
    }
}

struct UserVerificationCellModel: SettingsCellProtocol {
    var title: String? = ""
    var subtitle: String? = "Enable biometrics"
    var type: SettingsCellType = .userVerification
    var isEnabled: Bool?
    var shouldShowSwitch: Bool = true
    var didToggleSwitch: ((Bool) -> Void)?

    init(isEnabled: Bool, didToggleSwitch: @escaping (Bool) -> Void) {
        self.isEnabled = isEnabled
        self.didToggleSwitch = didToggleSwitch
    }
}
