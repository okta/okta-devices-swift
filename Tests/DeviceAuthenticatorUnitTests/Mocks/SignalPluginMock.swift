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
import OktaLogger
@testable import DeviceAuthenticator

struct IntegritySignalMock: Codable {
    var debug = false
    var jailbreak = false
    var hook = false
    var repackage = false
}

class SignalPluginMock: _SignalPluginProtocol {

    var config = _SignalPluginConfig(name: "name", description: "desc", type: "type", typeData: [: ])

    var available = false
    func isAvailable() -> Bool {
        return available
    }

    var signals = _IntegrationData.error(SignalPluginMock.mockError)
    func collectSignals() -> _IntegrationData {
        return signals
    }

    static let mockError = _PluginSignalError(name: "mock", error: "mock error")
}
