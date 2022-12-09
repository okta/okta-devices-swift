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

class DefaultSignalPlugin: _SignalPluginProtocol {

    var config: _SignalPluginConfig

    init(config: _SignalPluginConfig) {
        self.config = config
    }

    func isAvailable() -> Bool {
        return false
    }

    func collectSignals() -> _IntegrationData {
        let error = DeviceAuthenticatorError.genericError("Collection failed: default handler not yet implemented")
        let signalError = _PluginSignalError(name: config.name, error: "\(error)")
        return _IntegrationData.error(signalError)
    }
}

enum SignalPluginConfigType: String {
    case file = "FILE"
    case none = ""
}

class SignalPluginFactory {
    var signalPluginMap: [String: _SignalPluginProtocol] = [:]
    var signalPluginConfigCollection: SignalPluginConfigCollection

    init(plugins: [_SignalPluginProtocol], externalConfigs: [Data], logger: OktaLoggerProtocol) {
        self.signalPluginConfigCollection = SignalPluginConfigCollection(signalPluginConfigs: externalConfigs, logger: logger)
        updateAll(signalPluginConfigMap: signalPluginConfigCollection.signalPluginConfigMap, plugins: plugins)
    }

    // - Description: Creates a signal manager for the given configuration. Returns existing manager if one already existed
    /// - Parameters:
    ///   - edrConfiguration: edr configuration for which to create signal manager
    func create(signalPluginConfig: _SignalPluginConfig) -> _SignalPluginProtocol {
        //TODO: add more signal manager types. For now file type is only existing type
        // create signal manager on the map if one does exist for the integration
        guard let pluginType = SignalPluginConfigType(rawValue: signalPluginConfig.type.uppercased()) else {
            let handler = DefaultSignalPlugin(config: signalPluginConfig)
            signalPluginMap[signalPluginConfig.name] = handler
            return handler
        }
        switch pluginType {
        case .file:
            if let handler = signalPluginMap[signalPluginConfig.name] {
                return handler
            } else {
                // file type manager is only supported on macOS, so if using iOS just assign default manager
                #if os(macOS)
                let handler = FileTypeSignalPlugin(signalPluginConfig: signalPluginConfig)
                signalPluginMap[signalPluginConfig.name] = handler
                return handler
                #else
                let handler = DefaultSignalPlugin(config: signalPluginConfig)
                signalPluginMap[signalPluginConfig.name] = handler
                return handler
                #endif
            }
        default:
            // there is no generic signal manager right now. Will discuss with EDR team how non file type signals should be handled. Will also create enum for different signal types at that point
            if let handler = signalPluginMap[signalPluginConfig.name] {
                return handler
            } else {
                let handler = DefaultSignalPlugin(config: signalPluginConfig)
                signalPluginMap[signalPluginConfig.name] = handler
                return handler
            }
        }
    }

    // - Description: Removes all current handlers and adds new ones based on map
    /// - Parameters:
    ///   - signalPluginConfigMap: map of all signal plugin configurations to create handlers for
    func updateAll(signalPluginConfigMap: [String: _SignalPluginConfig], plugins: [_SignalPluginProtocol]) {
        signalPluginConfigCollection.signalPluginConfigMap = signalPluginConfigMap
        signalPluginMap = [:]
        for (_, config) in signalPluginConfigMap {
            _ = create(signalPluginConfig: config)
        }
        for plugin in plugins {
            signalPluginMap[plugin.config.name] = plugin
        }
    }

    // - Description: Removes all current handlers and adds new ones based list of configs
    /// - Parameters:
    ///   - signalPluginConfigs: list of all encoded signal plugin configurations to create handlers for
    func updateAll(plugins: [_SignalPluginProtocol], externalConfigs: [Data]) {
        signalPluginConfigCollection.updateAll(signalPluginConfigs: externalConfigs)
        updateAll(signalPluginConfigMap: signalPluginConfigCollection.signalPluginConfigMap,
                  plugins: plugins)
    }

    // - Description: updates signal manager for given integration
    /// - Parameters:
    ///   - signalPluginConfig: signal plugin configuration for which to update signal manager
    func update(signalPluginConfig: _SignalPluginConfig, customPlugin: _SignalPluginProtocol) {
        signalPluginMap[signalPluginConfig.name] = customPlugin
    }

    // - Description: gets plugin for given integration name
    /// - Parameters:
    ///   - name: name for which to get signal plugin
    func signalManagerByName(name: String) -> _SignalPluginProtocol? {
        return signalPluginMap[name]
    }
}

