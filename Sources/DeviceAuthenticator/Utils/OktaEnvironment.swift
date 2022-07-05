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
#if os(iOS)
import CryptoKit
#endif

class OktaEnvironment {

    struct Constants {
        static let keychainAccessibilityFlag = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    }

    class func canUseSecureEnclave(laContext: LAContext = LAContext()) -> Bool {
#if targetEnvironment(simulator)
            return false
#else
            var error: NSError?
            // Checks if the device has biometric login setup(like TouchID) in which case we know the device also supports secure enclave
            if laContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
                return true
            }
            // For cases where the device supports biometrics but the user hasn't setup one yet, we also need to verify the error code to be sure
            if let error = error, error.code == LAError.biometryNotAvailable.rawValue {
                return false
            } else {
                return true
            }
#endif
    }

    class func isSecureEnclaveAvailable() -> Bool {
#if os(iOS)
    #if targetEnvironment(simulator)
        return false
    #else
        return SecureEnclave.isAvailable
    #endif
#endif
        return false
    }

    class func hasUserVerificationCapabilites(laContext: LAContext = LAContext()) -> (result: Bool, error: NSError?) {
        var error: NSError?
        let result = laContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
        return (result: result, error: error)
    }
}
