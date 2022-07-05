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
import UIKit
import OktaLogger

class OktaUnmanagedDeviceSignals {
    class func retrieveDeviceSignals(requestedSignals: Set<RequestableSignal>,
                                     customDeviceSignals: DeviceSignals?,
                                     logger: OktaLoggerProtocol,
                                     signalsHelper: BasicSignalsHelperProtocol = BasicSignalsHelper()) -> DeviceSignalsModel {

        let helper = signalsHelper

        let deviceSignals = DeviceSignalsModel(platform: nil, osVersion: nil, displayName: nil)

        if requestedSignals.contains(.displayName) {
            let rawName = customDeviceSignals?.displayName ?? deviceDisplayName() ?? helper.deviceModel
            deviceSignals.displayName = rawName.stripHTMLTags()
        }

        if requestedSignals.contains(.platform) {
            deviceSignals.platform = .iOS
        }

        if requestedSignals.contains(.manufacturer) {
            deviceSignals.manufacturer = "APPLE"
        }

        if requestedSignals.contains(.model) {
            deviceSignals.model = helper.deviceModel
        }

        if requestedSignals.contains(.osVersion) {
            deviceSignals.osVersion = helper.osVersion
        }

        if requestedSignals.contains(.udid) {
            let udid: String? = customDeviceSignals?.udid
            deviceSignals.udid = udid ?? UIDevice.current.identifierForVendor?.uuidString
        }

        if requestedSignals.contains(.secureHardwarePresent) {
            deviceSignals.secureHardwarePresent = helper.secureHardwarePresent
        }

        if requestedSignals.contains(.deviceAttestation) {
            deviceSignals.deviceAttestation = customDeviceSignals?.deviceAttestation
        }

        let screenLockType = helper.screenLockType
        if requestedSignals.contains(.diskEncryptionType) {
            deviceSignals.diskEncryptionType = diskEncryptionType(with: screenLockType)
        }

        if requestedSignals.contains(.screenLockType) {
            deviceSignals.screenLockType = screenLockType
        }

        return deviceSignals
    }

    class func deviceDisplayName() -> String? {
        return UIDevice.current.name
    }

    class func diskEncryptionType(logger: OktaLoggerProtocol, signalsHelper: BasicSignalsHelper) -> DiskEncryptionValue? {
        return diskEncryptionType(with: signalsHelper.screenLockType)
    }

    class func screenLockType(logger: OktaLoggerProtocol, signalsHelper: BasicSignalsHelperProtocol) -> ScreenLockValue {
        return signalsHelper.screenLockType
    }

    /// iOS devices are encrypted-at-rest as long as a passcode is set
    /// https://support.apple.com/guide/security/passcodes-and-passwords-sec20230a10d/1/web/1
    private class func diskEncryptionType(with screenLockType: ScreenLockValue) -> DiskEncryptionValue {
        switch screenLockType {
        case .none:
            return .none
        case .passcode, .biometric:
            return .full
        }
    }
}
