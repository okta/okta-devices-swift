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
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif

/// Builder class for configuring and instantiating DeviceAuthenticatorProtocol instance
public class DeviceAuthenticatorBuilder {

    /// - Description: Creates DeviceAuthenticatorProtocol instance
    /// - Parameters:
    ///   - applicationConfig: Application information, for example application name, application version and etc.
    private let applicationConfig: ApplicationConfig

    public init(applicationConfig: ApplicationConfig) {
        self.applicationConfig = applicationConfig
    }

    /// - Returns: Instance of the DeviceAuthenticatorBuilder
    /// - Description: Override the default instance of Logger
    /// - Parameters:
    ///   - logger: This variable can be used to override the default Logger, if needed.
    private var logger: OktaLoggerProtocol? = nil

    public func addLogger(_ logger: OktaLoggerProtocol) -> DeviceAuthenticatorBuilder {
        self.logger = logger
        return self
    }

    /// Creates device authenticator instance
    /// - Returns: Instance that implements DeviceAuthenticatorProtocol
    public func create() throws -> DeviceAuthenticatorProtocol {
        let authenticator = DeviceAuthenticator()
        try authenticator.initialize(applicationConfig: applicationConfig, logger: logger)
        return authenticator
    }
}
