/*
* Copyright (c) 2021, Okta, Inc. and/or its affiliates. All rights reserved.
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

class FileTypeSignalPlugin: _SignalPluginProtocol {

    let config: _SignalPluginConfig
    let configuration: _DeviceChallengeTokenConfiguration
    var location: String = ""
    var format: String = ""

    init(signalPluginConfig: _SignalPluginConfig) {
        self.config = signalPluginConfig
        if let location = signalPluginConfig.typeData["location"] {
            self.location = location
        }
        if let format = signalPluginConfig.typeData["format"] {
            self.format = format
        }
        configuration = _DeviceChallengeTokenConfiguration(type: signalPluginConfig.type, format: self.format)
    }

    func isAvailable() -> Bool {
        if !location.isEmpty {
            return FileManager.default.fileExists(atPath: location)
        }
        return false
    }

    func collectSignals() -> _IntegrationData {
        do {
            let signal = try String(contentsOfFile: self.location, encoding: .utf8)
            if let strData = signal.data(using: .utf8) {
                let signal = _PluginSignalData(name: config.name, configuration: configuration, signal: strData.base64EncodedString(), timeCollected: Int(Date().timeIntervalSince1970))
                return _IntegrationData.signal(signal)
            } else {
                let error = DeviceAuthenticatorError.genericError("Signal collection failed")
                let errorSignal = _PluginSignalError(name: config.name, edrError: "\(error)")
                return _IntegrationData.error(errorSignal)
            }
        } catch {
            let error = DeviceAuthenticatorError.genericError("Signal collection failed")
            let errorSignal = _PluginSignalError(name: config.name, edrError: "\(error)")
            return _IntegrationData.error(errorSignal)
        }
    }
}
