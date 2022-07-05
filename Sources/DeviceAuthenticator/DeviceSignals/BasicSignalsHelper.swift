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
import LocalAuthentication

enum ScreenLockValue: String, Codable {
    case none = "NONE"
    case passcode = "PASSCODE"
    case biometric = "BIOMETRIC"
}

/// Helper for generating basic device signals on iOS/macOS
protocol BasicSignalsHelperProtocol {
    /// Has the user set a passcode and additionally biometrics
    var screenLockType: ScreenLockValue { get }
    /// Does this device support secure enclave operations (private keys which never leave the device)
    var secureHardwarePresent: Bool { get }
    /// Device's OS version in the form major.minor.patch (e.g. "15.2.0")
    var osVersion: String { get }
    /// Device manufacturer (currently always "APPLE")
    var manufacturer: String { get }
    /// Device Model (Eg; iPhone12,4)
    var deviceModel: String { get }
    /// Team identifier from apple signing ( e.g. "B7F62B65BN")
    var teamIdentifier: String? { get }
}

class BasicSignalsHelper: BasicSignalsHelperProtocol {

    var screenLockType: ScreenLockValue {
        if localAuthContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) {
            return .biometric
        }

        if localAuthContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) {
            return .passcode
        }

        return .none
    }

    var secureHardwarePresent: Bool {
        return OktaEnvironment.canUseSecureEnclave()
    }

    var osVersion: String {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        return "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
    }

    var manufacturer: String {
        return "APPLE"
    }

    var deviceModel: String {
        #if targetEnvironment(simulator)
        return ProcessInfo().environment["SIMULATOR_MODEL_IDENTIFIER"] ?? "Simulator"
        #else
        var system = utsname()
        uname(&system)
        let model = withUnsafePointer(to: &system.machine.0) { ptr in
            return String(cString: ptr)
        }
        return model
        #endif
    }

    var teamIdentifier: String? {
        return Bundle.teamIdentifier
    }

    var localAuthContext = LAContext()
}
