/*
* Copyright (c) 2019, Okta, Inc. and/or its affiliates. All rights reserved.
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

enum DiskEncryptionValue: String, Codable {
    case none = "NONE"
    case full = "FULL"
    case allInternal = "ALL_INTERNAL_VOLUMES"
    case systemVolume = "SYSTEM_VOLUME"
}

enum PlatformValue: String, Codable {
    case iOS = "IOS"
    case macOS = "MACOS"
}

enum RequestableSignal: String {
    case displayName
    case platform
    case manufacturer
    case model
    case osVersion
    case serialNumber
    case udid
    case sid
    case imei
    case meid
    case secureHardwarePresent
    case deviceAttestation
    case diskEncryptionType
    case screenLockType
    case clientInstanceBundleId
    case clientInstanceDeviceSdkVersion
    case clientInstanceId
    case clientInstanceVersion

    ///  List of device signals which can be logged (No PII)
    ///  Update DeviceSignalsModel properties if making changes to this list
    static var loggableSignals: Set<String> {
        Set<String>([
            RequestableSignal.platform.rawValue,
            RequestableSignal.manufacturer.rawValue,
            RequestableSignal.model.rawValue,
            RequestableSignal.osVersion.rawValue,
            RequestableSignal.secureHardwarePresent.rawValue,
            RequestableSignal.diskEncryptionType.rawValue,
            RequestableSignal.screenLockType.rawValue,
            RequestableSignal.clientInstanceBundleId.rawValue,
            RequestableSignal.clientInstanceDeviceSdkVersion.rawValue,
            RequestableSignal.clientInstanceId.rawValue,
            RequestableSignal.clientInstanceVersion.rawValue
        ])
    }
}

struct DeviceSignalsResponseModel: Codable {
    let id: String
    let status: String
    let created: String?
    let lastUpdated: String?
    let profile: DeviceSignalsModel?
    let clientInstanceId: String
}

class DeviceSignalsModel: Codable, CustomStringConvertible {
    var platform: PlatformValue?
    var osVersion: String?
    var displayName: String?
    var id: String?
    var manufacturer: String?
    var model: String?
    var serialNumber: String?
    var udid: String?
    var meid: String?
    var imei: String?
    var sid: String?
    var secureHardwarePresent: Bool?
    var screenLockType: ScreenLockValue?
    var diskEncryptionType: DiskEncryptionValue?
    var deviceAttestation: [String: _OktaCodableArbitaryType]?
    var clientInstanceId: String?
    var clientInstanceKey: [String: _OktaCodableArbitaryType]?
    var clientInstanceBundleId: String?
    var clientInstanceVersion: String?
    var clientInstanceDeviceSdkVersion: String?
    var authenticatorAppKey: String?

    init(platform: PlatformValue?, osVersion: String?, displayName: String?) {
        self.platform = platform
        self.osVersion = osVersion
        self.displayName = displayName
    }

    var description: String {
        var desc = ""
        let mirror = Mirror(reflecting: self)
        let properties = mirror.children
        for property in properties {
            guard let label = property.label else {
                continue
            }
            if case Optional<Any>.some(_) = property.value {
                if RequestableSignal.loggableSignals.contains(label) {
                    desc = "\(desc), \(label): \(property.value)"
                } else {
                    desc = "\(desc), \(label): <REDACTED>"
                }
            }
        }
        return desc
    }
}

