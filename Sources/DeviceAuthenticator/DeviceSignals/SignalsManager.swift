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

/// handles creation of plugin configs and collection of plugin signals
class SignalsManager {
    var signalPluginFactory: SignalPluginFactory?
    let logger: OktaLoggerProtocol
    var defaultSignalPluginManager: AnyObject?

    init(logger: OktaLoggerProtocol) {
        self.logger = logger
    }

    func initializeSignalPlugins(plugins: [_SignalPluginProtocol], externalConfigs: [Data]) {
        self.signalPluginFactory = SignalPluginFactory(plugins: plugins,
                                                       externalConfigs: externalConfigs,
                                                       logger: self.logger)
    }

    func collectSignals(with name: String) -> _IntegrationData {
        guard let factory = signalPluginFactory else {
            let error = DeviceAuthenticatorError.genericError("Collection failed: signal plugins not yet initialized")
            logger.error(eventName: "", message: "\(error)")
            let signalError = _PluginSignalError(name: name, error: "\(error)")
            return _IntegrationData.error(signalError)
        }
        guard let handler = factory.signalPluginMap[name] else {
            let pluginError = _PluginSignalError.notFoundError(name: name)
            return _IntegrationData.error(pluginError)
        }
        return handler.collectSignals()
    }

    func updateAll(plugins: [_SignalPluginProtocol], externalConfigs: [Data]) {
        if let managerFactory = self.signalPluginFactory {
            managerFactory.updateAll(plugins: plugins, externalConfigs: externalConfigs)
        } else {
            signalPluginFactory = SignalPluginFactory(plugins: plugins, externalConfigs: externalConfigs, logger: logger)
        }
    }
    //TODO: add manifest change monitor to detect change to manifest file and update configuration collection accordingly
}
