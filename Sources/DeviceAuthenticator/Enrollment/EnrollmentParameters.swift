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

/// Set of parameters for the enrollment flow
public struct EnrollmentParameters {
    /// Constructs enrollment parameters object with provided device token
    /// - Parameter deviceToken: Current device token value. Can be .empty if device token is not available yet
    public init(deviceToken: DeviceToken) {
        self.deviceToken = deviceToken
    }

    /// Enables/disables user verification capabilities for the enrollment
    /// - Parameters:
    ///   - enable: Boolean for enable/disable user verification capabilties
    ///   - userVerificationSettings: User verification settings for the enrollment
    public mutating func enableUserVerification(enable: Bool, userVerificationSettings: BiometricEnrollmentSettings = .default) {
        self.enrollUserVerificationKey = enable
        self.userVerificationSettings = userVerificationSettings
    }

    /// Enables/disables CIBA transactions (Transactional MFA) for the enrollment in addition to Login transactions. By default is true
    /// By disabling it, this device won't receive CIBA transactions via Push or Pending challenges.
    /// - Parameters:
    ///     - enable: Boolean for enabling/disabling CIBA transactions for this enrollment.
    public mutating func enableCIBATransactions(enable: Bool) {
        self.isCIBAEnabled = enable
    }

    let deviceToken: DeviceToken
    var enrollUserVerificationKey: Bool?
    var userVerificationSettings: BiometricEnrollmentSettings?
    var isCIBAEnabled: Bool = true
}
