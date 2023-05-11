/*
* Copyright (c) 2022, Okta, Inc. and/or its affiliates. All rights reserved.
* The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
*
* You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*
* See the License for the specific language governing permissions and limitations under the License.
*/

import XCTest
@testable import DeviceAuthenticator

class BasicSignalsHelperMock: BasicSignalsHelperProtocol {
    var screenLockType: ScreenLockValue
    var secureHardwarePresent: Bool
    var osVersion: String
    var manufacturer: String
    var deviceModel: String
    var teamIdentifier: String?

    init(screenLockType: ScreenLockValue, secureHardwarePresent: Bool, osVersion: String, manufacturer: String, deviceModel: String, teamIdentifier: String? = nil) {
        self.screenLockType = screenLockType
        self.secureHardwarePresent = secureHardwarePresent
        self.osVersion = osVersion
        self.manufacturer = manufacturer
        self.deviceModel = deviceModel
        self.teamIdentifier = teamIdentifier
    }
}

class OktaUnmanagedDeviceSignalsTests: XCTestCase {

    var basicSignalsHelperMock: BasicSignalsHelperMock!

    override func setUp() {
        super.setUp()
        basicSignalsHelperMock = BasicSignalsHelperMock(screenLockType: .biometric,
                                                        secureHardwarePresent: true,
                                                        osVersion: "13.0",
                                                        manufacturer: "APPLE",
                                                        deviceModel: "iPhone12,4")
    }

    func testRequestableSignals_MinimalSubset() throws {

        let requestedSignals: Set<RequestableSignal> = [RequestableSignal.displayName,
                                                        RequestableSignal.platform,
                                                        RequestableSignal.osVersion,
                                                        RequestableSignal.screenLockType,
                                                        RequestableSignal.secureHardwarePresent,
                                                        RequestableSignal.model,
                                                        RequestableSignal.manufacturer]

        let deviceSignals = DeviceSignals(displayName: "test device")

        let deviceSignalModel = OktaUnmanagedDeviceSignals.retrieveDeviceSignals(requestedSignals: requestedSignals,
                                                                                 customDeviceSignals: deviceSignals,
                                                                                 logger: OktaLoggerMock(),
                                                                                 signalsHelper: basicSignalsHelperMock)

        XCTAssertEqual(ScreenLockValue.biometric, deviceSignalModel.screenLockType)
        XCTAssertEqual(true, deviceSignalModel.secureHardwarePresent)
        XCTAssertEqual("13.0", deviceSignalModel.osVersion)
        #if os(iOS)
        XCTAssertEqual(PlatformValue.iOS, deviceSignalModel.platform)
        XCTAssertEqual("iPhone12,4", deviceSignalModel.model)
        #else
        XCTAssertEqual(PlatformValue.macOS, deviceSignalModel.platform)
        #endif
        XCTAssertEqual("APPLE", deviceSignalModel.manufacturer)
        XCTAssertEqual("test device", deviceSignalModel.displayName)
    }

    func testRequestableSignals_NoSignalsRequested() throws {

        let requestedSignals: Set<RequestableSignal> = []

        let deviceSignals = DeviceSignals(displayName: "test device")

        let deviceSignalModel = OktaUnmanagedDeviceSignals.retrieveDeviceSignals(requestedSignals: requestedSignals, customDeviceSignals: deviceSignals, logger: OktaLoggerMock(), signalsHelper: basicSignalsHelperMock)

        XCTAssertNil(deviceSignalModel.screenLockType)
        XCTAssertNil(deviceSignalModel.secureHardwarePresent)
        XCTAssertNil(deviceSignalModel.osVersion)
        XCTAssertNil(deviceSignalModel.manufacturer)
        XCTAssertNil(deviceSignalModel.platform)
        XCTAssertNil(deviceSignalModel.udid)
        XCTAssertNil(deviceSignalModel.displayName)
        XCTAssertNil(deviceSignalModel.model)
    }

    func testRetrieveSignals_CustomSignalsOnly() throws {

        let requestedSignals: Set<RequestableSignal> = []

        var deviceSignals = DeviceSignals(displayName: "test device")
        deviceSignals.deviceAttestation = ["da": _OktaCodableArbitaryType.int(10)]
        deviceSignals.udid = "ABC"

        let deviceSignalModel = OktaUnmanagedDeviceSignals.retrieveDeviceSignals(requestedSignals: requestedSignals, customDeviceSignals: deviceSignals, logger: OktaLoggerMock(), signalsHelper: basicSignalsHelperMock)

        XCTAssertNil(deviceSignalModel.screenLockType)
        XCTAssertNil(deviceSignalModel.secureHardwarePresent)
        XCTAssertNil(deviceSignalModel.osVersion)
        XCTAssertNil(deviceSignalModel.manufacturer)
        XCTAssertNil(deviceSignalModel.platform)
        XCTAssertNil(deviceSignalModel.udid)
        XCTAssertNil(deviceSignalModel.deviceAttestation)
        XCTAssertNil(deviceSignalModel.displayName)
        XCTAssertNil(deviceSignalModel.model)
    }

    func test_retrieve_singnalsFromEnrollment() throws {

        let requestedSignals = OktaDeviceModelBuilder.enrollmentSignals

        let deviceSignals = DeviceSignals(displayName: "test device")
        let deviceSignalModel = OktaUnmanagedDeviceSignals.retrieveDeviceSignals(requestedSignals: requestedSignals, customDeviceSignals: deviceSignals, logger: OktaLoggerMock(), signalsHelper: basicSignalsHelperMock)

        XCTAssertEqual(true, deviceSignalModel.secureHardwarePresent)
        XCTAssertEqual("13.0", deviceSignalModel.osVersion)
        #if os(iOS)
        XCTAssertEqual("APPLE", deviceSignalModel.manufacturer)
        XCTAssertEqual(PlatformValue.iOS, deviceSignalModel.platform)
        XCTAssertEqual("iPhone12,4", deviceSignalModel.model)
        #else
        XCTAssertEqual("APPLE", deviceSignalModel.manufacturer)
        XCTAssertEqual(PlatformValue.macOS, deviceSignalModel.platform)
        XCTAssertNotNil(deviceSignalModel.serialNumber)
        #endif
        XCTAssertEqual("test device", deviceSignalModel.displayName)
        XCTAssertEqual(ScreenLockValue.biometric, deviceSignalModel.screenLockType)
        XCTAssertNil(deviceSignalModel.udid)
        XCTAssertNil(deviceSignalModel.sid)
        XCTAssertNil(deviceSignalModel.imei)
        XCTAssertNil(deviceSignalModel.meid)
        XCTAssertNil(deviceSignalModel.deviceAttestation)
        XCTAssertNil(deviceSignalModel.clientInstanceBundleId)
        XCTAssertNil(deviceSignalModel.clientInstanceDeviceSdkVersion)
        XCTAssertNil(deviceSignalModel.clientInstanceId)
        XCTAssertNil(deviceSignalModel.clientInstanceVersion)
    }
}
