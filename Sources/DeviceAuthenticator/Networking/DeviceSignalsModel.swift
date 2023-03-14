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
}

struct DeviceSignalsResponseModel: Codable {
    let id: String
    let status: String
    let created: String?
    let lastUpdated: String?
    let profile: DeviceSignalsModel?
    let clientInstanceId: String
}

/*
 "platformSSO": {
         "keys": {
           "deviceSigningKey": {
             "x": "hFr-xcGSMHbWKq2_SUAOMkif1ARYAU-X_8ZGprOhxfw",
             "y": "HVqAxDCiGcV7H0QAQas6CMbh2wyG-cPU_cwXv3kPqcI",
             "kty": "EC",
             "crv": "P-256",
             "kid": "2078892D-BC96-4C8C-A3FA-34045C002C4A"
           },
           "encryptionKey": {
             "x": "V0p-5JFpcen4Iep94ihs00Kjezw9sblfMSUW-cJxTRk",
             "y": "wgJ9SFT3iaT6cqS08TBIBg_K-20r_4FMGFUlN2BXFJc",
             "kty": "EC",
             "crv": "P-256",
             "kid": "80D6AC7B-B640-4899-A32C-CA7B98BE0AE6"
           }
         }
     }
 */

class DeviceSignalsModel: Codable {
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
    var platformSSO: PlatformSSOPayload?

    struct PlatformSSOPayload: Codable {
        let keys: KeysPayload
        let userOSAccount: String

        struct KeysPayload: Codable {
            let deviceSigningKey: [String: _OktaCodableArbitaryType]
            let encryptionKey: [String: _OktaCodableArbitaryType]
            let deviceEncryptionKey: [String: _OktaCodableArbitaryType]
        }
    }

    init(platform: PlatformValue?, osVersion: String?, displayName: String?) {
        self.platform = platform
        self.osVersion = osVersion
        self.displayName = displayName
    }
}

