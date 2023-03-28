/*
* Copyright (c) 2019-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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

/// Defines biometric settings for enrollment. Use this structure when user wants to add user verification capability for the enrollment
public struct BiometricEnrollmentSettings {
    /// Accessibility attribute for the user verification key that is being enrolled
    public let accessControlFlags: SecAccessControlCreateFlags

    // - Description: Constructs OktaBiometricEnrollmentSettings instance
    /// - Parameters:
    ///   - accessControlFlags: Defines access rights for stored enrollment items
    public init(accessControlFlags: SecAccessControlCreateFlags) {
        self.accessControlFlags = accessControlFlags
    }

    // - Description: Constructs default BiometricEnrollmentSettings instance
    public static var `default`: BiometricEnrollmentSettings {
        var accessControl = SecAccessControlCreateFlags()
        accessControl.update(with: SecAccessControlCreateFlags.biometryCurrentSet)
        let settings = BiometricEnrollmentSettings(accessControlFlags: accessControl)
        return settings
    }

    // - Description: Constructs a BiometricEnrollmentSettings instance with enabled bio or passcode settings
    public static var userPresence: BiometricEnrollmentSettings {
        return BiometricEnrollmentSettings(accessControlFlags: .userPresence)
    }
}
