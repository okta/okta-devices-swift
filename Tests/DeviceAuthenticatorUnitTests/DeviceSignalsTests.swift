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
// swiftlint:disable force_try
import XCTest
import OktaLogger
@testable import DeviceAuthenticator

class DeviceSignalsTests: XCTestCase {

    func testDeviceSignalsDecoding() {
        let decoder = JSONDecoder()
        let deviceSignalsData = try! decoder.decode(DeviceSignalsResponseModel.self, from: GoldenData.deviceSignalsData())
        XCTAssertEqual(deviceSignalsData.id, "guotmkiKzYBTnhnC40g4")
        XCTAssertEqual(deviceSignalsData.status, "ACTIVE")
        XCTAssertEqual(deviceSignalsData.created, "2019-12-03T18:39:46.000Z")
        XCTAssertEqual(deviceSignalsData.lastUpdated, "2019-12-03T19:59:43.000Z")
        XCTAssertEqual(deviceSignalsData.profile?.platform, .iOS)
        XCTAssertEqual(deviceSignalsData.profile?.displayName, "Test Device")
        XCTAssertEqual(deviceSignalsData.profile?.manufacturer, "APPLE")
        XCTAssertEqual(deviceSignalsData.profile?.model, "iPhone X")
        XCTAssertEqual(deviceSignalsData.profile?.osVersion, "10.1.2")
        XCTAssertEqual(deviceSignalsData.profile?.serialNumber, "2fc4b5912826ad1")
        XCTAssertEqual(deviceSignalsData.profile?.imei, "abcd")
        XCTAssertEqual(deviceSignalsData.profile?.meid, "abcd")
        XCTAssertEqual(deviceSignalsData.profile?.udid, "2b6f0cc904d137be2e1730235f5664094b831186")
        XCTAssertEqual(deviceSignalsData.profile?.sid, "abcd")
        XCTAssertEqual(deviceSignalsData.clientInstanceId, "cli1zEPrHHW0w4i0ALF0")
        XCTAssertEqual(deviceSignalsData.profile?.screenLockType, ScreenLockValue.biometric)
        XCTAssertEqual(deviceSignalsData.profile?.diskEncryptionType, .full)
    }

    #if os(macOS)
    func testdiskEncryptionTypeForVolume() {
        let volumeURL = URL(fileURLWithPath: "/")

        //base case
        var values = URLResourceValues().allValues
        var diskEncryptionStatus = OktaUnmanagedDeviceSignals.diskEncryptionTypeForVolume(values: values, volumeURL: volumeURL, logger: OktaLogger())
        XCTAssertNil(diskEncryptionStatus.isVolumeEncrypted)

        //test when volume is hidden
        values.updateValue(true, forKey: URLResourceKey.isHiddenKey)
        diskEncryptionStatus = OktaUnmanagedDeviceSignals.diskEncryptionTypeForVolume(values: values, volumeURL: volumeURL, logger: OktaLogger())
        XCTAssertNil(diskEncryptionStatus.isVolumeEncrypted)

        //test when volume is ejectable
        values.updateValue(false, forKey: URLResourceKey.isHiddenKey)
        values.updateValue(true, forKey: URLResourceKey.volumeIsEjectableKey)
        diskEncryptionStatus = OktaUnmanagedDeviceSignals.diskEncryptionTypeForVolume(values: values, volumeURL: volumeURL, logger: OktaLogger())
        XCTAssertNil(diskEncryptionStatus.isVolumeEncrypted)

        //test when volume is removable
        values.updateValue(false, forKey: URLResourceKey.volumeIsEjectableKey)
        values.updateValue(true, forKey: URLResourceKey.volumeIsRemovableKey)
        diskEncryptionStatus = OktaUnmanagedDeviceSignals.diskEncryptionTypeForVolume(values: values, volumeURL: volumeURL, logger: OktaLogger())
        XCTAssertNil(diskEncryptionStatus.isVolumeEncrypted)

        //test when volume is not internal
        values.updateValue(false, forKey: URLResourceKey.volumeIsRemovableKey)
        values.updateValue(false, forKey: URLResourceKey.volumeIsInternalKey)
        diskEncryptionStatus = OktaUnmanagedDeviceSignals.diskEncryptionTypeForVolume(values: values, volumeURL: volumeURL, logger: OktaLogger())
        XCTAssertNil(diskEncryptionStatus.isVolumeEncrypted)

        //test when volume is automounted
        values.updateValue(true, forKey: URLResourceKey.volumeIsInternalKey)
        values.updateValue(true, forKey: URLResourceKey.volumeIsAutomountedKey)
        diskEncryptionStatus = OktaUnmanagedDeviceSignals.diskEncryptionTypeForVolume(values: values, volumeURL: volumeURL, logger: OktaLogger())
        XCTAssertNil(diskEncryptionStatus.isVolumeEncrypted)

        //check scenarios for older OS when fileProtectionKey was not available
        values.updateValue(false, forKey: URLResourceKey.volumeIsAutomountedKey)

        //test when volume is not encrypted and not system volume
        values.updateValue(false, forKey: URLResourceKey.volumeIsEncryptedKey)
        values.updateValue(false, forKey: URLResourceKey.volumeIsRootFileSystemKey)
        diskEncryptionStatus = OktaUnmanagedDeviceSignals.diskEncryptionTypeForVolume(values: values, volumeURL: volumeURL, logger: OktaLogger())
        XCTAssertNotNil(diskEncryptionStatus.isVolumeEncrypted)
        XCTAssertNotNil(diskEncryptionStatus.isSystemVolume)
        if let isVolumeEncrypted = diskEncryptionStatus.isVolumeEncrypted,
           let isSystemVolume = diskEncryptionStatus.isSystemVolume {
            XCTAssertFalse(isVolumeEncrypted)
            XCTAssertFalse(isSystemVolume)
        }

        //test when volume is not encrypted and system volume
        values.updateValue(false, forKey: URLResourceKey.volumeIsEncryptedKey)
        values.updateValue(true, forKey: URLResourceKey.volumeIsRootFileSystemKey)
        diskEncryptionStatus = OktaUnmanagedDeviceSignals.diskEncryptionTypeForVolume(values: values, volumeURL: volumeURL, logger: OktaLogger())
        XCTAssertNotNil(diskEncryptionStatus.isVolumeEncrypted)
        XCTAssertNotNil(diskEncryptionStatus.isSystemVolume)
        if let isVolumeEncrypted = diskEncryptionStatus.isVolumeEncrypted,
           let isSystemVolume = diskEncryptionStatus.isSystemVolume {
            XCTAssertFalse(isVolumeEncrypted)
            XCTAssertTrue(isSystemVolume)
        }

        //test when volume is encrypted but not system volume
        values.updateValue(true, forKey: URLResourceKey.volumeIsEncryptedKey)
        values.updateValue(false, forKey: URLResourceKey.volumeIsRootFileSystemKey)
        diskEncryptionStatus = OktaUnmanagedDeviceSignals.diskEncryptionTypeForVolume(values: values, volumeURL: volumeURL, logger: OktaLogger())
        XCTAssertNotNil(diskEncryptionStatus.isVolumeEncrypted)
        XCTAssertNotNil(diskEncryptionStatus.isSystemVolume)
        if let isVolumeEncrypted = diskEncryptionStatus.isVolumeEncrypted,
           let isSystemVolume = diskEncryptionStatus.isSystemVolume {
            XCTAssertTrue(isVolumeEncrypted)
            XCTAssertFalse(isSystemVolume)
        }

        //test when volume is encrypted and system volume
        values.updateValue(true, forKey: URLResourceKey.volumeIsEncryptedKey)
        values.updateValue(true, forKey: URLResourceKey.volumeIsRootFileSystemKey)
        diskEncryptionStatus = OktaUnmanagedDeviceSignals.diskEncryptionTypeForVolume(values: values, volumeURL: volumeURL, logger: OktaLogger())
        XCTAssertNotNil(diskEncryptionStatus.isVolumeEncrypted)
        XCTAssertNotNil(diskEncryptionStatus.isSystemVolume)
        if let isVolumeEncrypted = diskEncryptionStatus.isVolumeEncrypted,
           let isSystemVolume = diskEncryptionStatus.isSystemVolume {
            XCTAssertTrue(isVolumeEncrypted)
            XCTAssertTrue(isSystemVolume)
        }

        //check scenarios when fileProtectionKey was  available
        if #available(OSX 11.0, *) {
            //test when volume is not encrypted and not system volume
            values.updateValue(false, forKey: URLResourceKey.volumeIsRootFileSystemKey)
            values.updateValue(FileProtectionType.none, forKey: URLResourceKey.fileProtectionKey)
            diskEncryptionStatus = OktaUnmanagedDeviceSignals.diskEncryptionTypeForVolume(values: values, volumeURL: volumeURL, logger: OktaLogger())
            XCTAssertNotNil(diskEncryptionStatus.isVolumeEncrypted)
            XCTAssertNotNil(diskEncryptionStatus.isSystemVolume)
            if let isVolumeEncrypted = diskEncryptionStatus.isVolumeEncrypted,
               let isSystemVolume = diskEncryptionStatus.isSystemVolume {
                XCTAssertFalse(isVolumeEncrypted)
                XCTAssertFalse(isSystemVolume)
            }

            //test when volume is not encrypted and system volume
            values.updateValue(FileProtectionType.none, forKey: URLResourceKey.fileProtectionKey)
            values.updateValue(true, forKey: URLResourceKey.volumeIsRootFileSystemKey)
            diskEncryptionStatus = OktaUnmanagedDeviceSignals.diskEncryptionTypeForVolume(values: values, volumeURL: volumeURL, logger: OktaLogger())
            XCTAssertNotNil(diskEncryptionStatus.isVolumeEncrypted)
            XCTAssertNotNil(diskEncryptionStatus.isSystemVolume)
            if let isVolumeEncrypted = diskEncryptionStatus.isVolumeEncrypted,
               let isSystemVolume = diskEncryptionStatus.isSystemVolume {
                XCTAssertFalse(isVolumeEncrypted)
                XCTAssertTrue(isSystemVolume)
            }

            //test when volume is encrypted but not system volume
            values.updateValue(FileProtectionType.complete, forKey: URLResourceKey.fileProtectionKey)
            values.updateValue(false, forKey: URLResourceKey.volumeIsRootFileSystemKey)
            diskEncryptionStatus = OktaUnmanagedDeviceSignals.diskEncryptionTypeForVolume(values: values, volumeURL: volumeURL, logger: OktaLogger())
            XCTAssertNotNil(diskEncryptionStatus.isVolumeEncrypted)
            XCTAssertNotNil(diskEncryptionStatus.isSystemVolume)
            if let isVolumeEncrypted = diskEncryptionStatus.isVolumeEncrypted,
               let isSystemVolume = diskEncryptionStatus.isSystemVolume {
                XCTAssertTrue(isVolumeEncrypted)
                XCTAssertFalse(isSystemVolume)
            }

            //test when volume is encrypted and system volume
            values.updateValue(FileProtectionType.complete, forKey: URLResourceKey.fileProtectionKey)
            values.updateValue(true, forKey: URLResourceKey.volumeIsRootFileSystemKey)
            diskEncryptionStatus = OktaUnmanagedDeviceSignals.diskEncryptionTypeForVolume(values: values, volumeURL: volumeURL, logger: OktaLogger())
            XCTAssertNotNil(diskEncryptionStatus.isVolumeEncrypted)
            XCTAssertNotNil(diskEncryptionStatus.isSystemVolume)
            if let isVolumeEncrypted = diskEncryptionStatus.isVolumeEncrypted,
               let isSystemVolume = diskEncryptionStatus.isSystemVolume {
                XCTAssertTrue(isVolumeEncrypted)
                XCTAssertTrue(isSystemVolume)
            }
        }
    }
    #endif
}
