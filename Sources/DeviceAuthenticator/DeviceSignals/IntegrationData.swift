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

// Represents serializable signal data collected from plugin.
// N.B. This is an API contract, don't change the field names
public struct _PluginSignalData: Encodable {
    let name: String
    let configuration: _DeviceChallengeTokenConfiguration
    let signal: String
    let timeCollected: Int

    public init(name: String, configuration: _DeviceChallengeTokenConfiguration, signal: String, timeCollected: Int) {
        self.name = name
        self.configuration = configuration
        self.signal = signal
        self.timeCollected = timeCollected
    }
}

// Represents serializable signal error when plugin signal cannot be collected
// N.B. This is an API contract, don't change the field names
public class _PluginSignalError: Encodable {
    let name: String
    let configuration: _DeviceChallengeTokenConfiguration?
    let error: String
    let errorCode: Int?

    public init(name: String, error: String, errorCode: Int? = nil) {
        self.name = name
        self.error = error
        self.configuration = nil
        self.errorCode = errorCode
    }

    public init(name: String, configuration: _DeviceChallengeTokenConfiguration? = nil, edrError: String, errorCode: Int? = nil) {
        self.configuration = configuration
        self.error = edrError.data(using: .utf8)?.base64EncodedString() ?? ""
        self.name = name
        self.errorCode = errorCode
    }

    public static func notFoundError(name: String) -> _PluginSignalError {
        return _PluginSignalError(name: name,
                                 error: "\(DeviceAuthenticatorError.genericError("configuration not found"))")
    }
}

// Configuration to be included in challenge token
// N.B. This is an API contract, don't change the field names
public struct _DeviceChallengeTokenConfiguration: Encodable {
    let type: String
    let format: String

    public static let local = _DeviceChallengeTokenConfiguration(type: "DEFAULT", format: "JSON")
}

// Represents serialized data or error from plugin. Included in challenge response
public enum _IntegrationData: Encodable {
    case signal(_PluginSignalData)
    case error(_PluginSignalError)

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .signal(let signalData):
            try container.encode(signalData)
        case .error(let errorData):
            try container.encode(errorData)
        }
    }
}
