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
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif

/// Represents a collection of all plugin configs that have been read in from manifest file
class SignalPluginConfigCollection {
    var signalPluginConfigMap: [String: _SignalPluginConfig] = [:]
    let logger: OktaLoggerProtocol
    // - Description: Constructs SignalPluginConfigCollection instance.
    /// - Parameters:
    ///   - edrConfigs: list of edrconfig JSONs as data. Should have all keys required for an EDRConfiguration
    ///   - logger: OktaLoggerProtocol
    init(signalPluginConfigs: [Data], logger: OktaLoggerProtocol) {
        self.logger = logger
        updateAll(signalPluginConfigs: signalPluginConfigs)
    }
    // - Description: deletes old integration map and manager factory and replaces them with new values
    /// - Parameters:
    ///   - edrConfigs: list of edrconfig JSONs as data. Should have all keys required for an EDRConfiguration
    func updateAll(signalPluginConfigs: [Data]) {
        var configurationMap: [String: _SignalPluginConfig] = [:]
        if signalPluginConfigs.isEmpty {
            logger.info(eventName: "", message: "no manifest file values passed in")
        }
        // loop through all the integration configuration dictionaries recieved from manifest file
        for config in signalPluginConfigs {
            do {
                let decodedConfig = try JSONDecoder().decode(IntegrationsConfig.self, from: config)
                // translate read in data to proper format
                let pluginConfig = _SignalPluginConfig(name: decodedConfig.name, description: decodedConfig.description, type: decodedConfig.type, typeData: ["location": decodedConfig.location, "format": decodedConfig.format])
                configurationMap[decodedConfig.name] = pluginConfig
            } catch {
                logger.error(eventName: "manifestFileReadError", message: "unable to decode config JSON")
            }
        }
        signalPluginConfigMap = configurationMap
    }
}
