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

/// Provides functionality for retrieving plugin signals for a given configuration
public protocol _SignalPluginProtocol {
    /// Configuration details for this plugin
    var config: _SignalPluginConfig { get }
    /// checks if integration corresponding to plugin exists on machine
    func isAvailable() -> Bool
    /// retrieves signal data for plugin
    /// - Returns: signal data
    func collectSignals() -> _IntegrationData
}
