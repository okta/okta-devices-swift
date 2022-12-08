/*
* Copyright (c) 2020, Okta, Inc. and/or its affiliates. All rights reserved.
* The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
*
* You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*
* See the License for the specific language governing permissions and limitations under the License.
*/
#if os(iOS)
import UIKit
#elseif os(macOS)
import SystemConfiguration
#endif
import XCTest
@testable import DeviceAuthenticator
import LocalAuthentication

class OktaDeviceModelBuilderTests: XCTestCase {

    private var mockStorageManager: StorageMock!
    private var cryptoManager: CryptoManagerMock!
    private var jwkGenerator: OktaJWKGeneratorMock!
    private var jwtGenerator: OktaJWTGeneratorMock!
    private let mockURL = URL(string: "https://example.okta.com")!

    var applicationConfig: ApplicationConfig!

    override func setUp() {
        super.setUp()

        let secKeyHelperMock = SecKeyHelperMock()
        cryptoManager = CryptoManagerMock(keychainGroupId: "", secKeyHelper: secKeyHelperMock, logger: OktaLoggerMock())
        jwkGenerator = OktaJWKGeneratorMock(logger: OktaLoggerMock())
        jwtGenerator = OktaJWTGeneratorMock(logger: OktaLoggerMock())
        applicationConfig = ApplicationConfig(applicationName: "Test App",
                                              applicationVersion: "1.0.0",
                                              applicationGroupId: ExampleAppConstants.appGroupId)
        mockStorageManager = StorageMock()
    }

    func testBuildForEnrollment() {
        let mut = OktaDeviceModelBuilder(orgHost: "https://tenant.okta.com",
                                         applicationConfig: applicationConfig,
                                         requestedSignals: ["diskEncryptionType", "screenLockType"],
                                         customSignals: nil,
                                         cryptoManager: cryptoManager,
                                         jwtGenerator: jwtGenerator,
                                         jwkGenerator: jwkGenerator,
                                         logger: OktaLoggerMock())
        let deviceSignalsModel = mut.buildForCreateEnrollment(with: "keyTag")
        XCTAssertFalse(deviceSignalsModel.clientInstanceKey!.isEmpty)
        XCTAssertNotNil(deviceSignalsModel.clientInstanceKey!["okta:kpr"])
        #if os(macOS)
        XCTAssertNil(deviceSignalsModel.clientInstanceKey!["okta:isFipsCompliant"])
        XCTAssertNotNil(deviceSignalsModel.screenLockType)
        #else
        XCTAssertEqual(deviceSignalsModel.clientInstanceKey!["okta:isFipsCompliant"],
                       _OktaCodableArbitaryType.bool(OktaEnvironment.isSecureEnclaveAvailable()))
        XCTAssertNil(deviceSignalsModel.diskEncryptionType)
        XCTAssertEqual(deviceSignalsModel.screenLockType, BasicSignalsHelper().screenLockType)
        #endif
        XCTAssertNil(deviceSignalsModel.id)
        XCTAssertNil(deviceSignalsModel.deviceAttestation)
        XCTAssertNil(deviceSignalsModel.clientInstanceId)
        validateDeviceSignals(deviceSignalsModel)
    }

    func testBuildForUpdate() {
        let mut = OktaDeviceModelBuilder(orgHost: "https://tenant.okta.com",
                                         applicationConfig: applicationConfig,
                                         requestedSignals: [],
                                         customSignals: nil,
                                         cryptoManager: cryptoManager,
                                         jwtGenerator: jwtGenerator,
                                         jwkGenerator: jwkGenerator,
                                         logger: OktaLoggerMock())
        let deviceEnrollment = OktaDeviceEnrollment(id: "id", orgId: "orgIdentifier", clientInstanceId: "clientInstanceId", clientInstanceKeyTag: "clientInstanceKeyTag")
        _ = try? cryptoManager.generate(keyPairWith: .ES256,
                                        with: "clientInstanceKeyTag",
                                        useSecureEnclave: false,
                                        useBiometrics: false,
                                        biometricSettings: nil)
        let deviceSignalsModel = mut.buildForUpdateEnrollment(with: deviceEnrollment)
        XCTAssertEqual(deviceSignalsModel.clientInstanceId, "clientInstanceId")
        XCTAssertEqual(deviceSignalsModel.id, "id")
        XCTAssertNotNil(deviceSignalsModel.deviceAttestation)
        XCTAssertEqual(deviceSignalsModel.deviceAttestation!["clientInstanceKeyAttestation"], _OktaCodableArbitaryType.string(jwtGenerator.stringToReturn))
        validateDeviceSignals(deviceSignalsModel)
    }

    func testBuildForRotateClientInstanceKey() {
        let mut = OktaDeviceModelBuilder(orgHost: "https://tenant.okta.com",
                                         applicationConfig: applicationConfig,
                                         requestedSignals: [],
                                         customSignals: nil,
                                         cryptoManager: cryptoManager,
                                         jwtGenerator: jwtGenerator,
                                         jwkGenerator: jwkGenerator,
                                         logger: OktaLoggerMock())
        let deviceEnrollment = OktaDeviceEnrollment(id: "id", orgId: mockURL.absoluteString, clientInstanceId: "clientInstanceId", clientInstanceKeyTag: "clientInstanceKeyTag")
        let deviceSignalsModel = mut.buildForRotateClientInstanceKey(with: deviceEnrollment, and: "keyTag")
        XCTAssertFalse(deviceSignalsModel.clientInstanceKey!.isEmpty)
        XCTAssertEqual(deviceSignalsModel.clientInstanceId, "clientInstanceId")
        XCTAssertEqual(deviceSignalsModel.id, "id")
        XCTAssertNotNil(deviceSignalsModel.deviceAttestation)
        XCTAssertEqual(deviceSignalsModel.deviceAttestation!["clientInstanceKeyAttestation"], _OktaCodableArbitaryType.string(jwtGenerator.stringToReturn))
        validateDeviceSignals(deviceSignalsModel)
    }

    func testBuildForVerifyTransaction() {
        let mut = OktaDeviceModelBuilder(orgHost: "https://tenant.okta.com",
                                         applicationConfig: applicationConfig,
                                         requestedSignals: [RequestableSignal.displayName.rawValue,
                                                            RequestableSignal.udid.rawValue,
                                                            RequestableSignal.secureHardwarePresent.rawValue,
                                                            RequestableSignal.manufacturer.rawValue,
                                                            RequestableSignal.clientInstanceBundleId.rawValue,
                                                            RequestableSignal.clientInstanceVersion.rawValue,
                                                            RequestableSignal.clientInstanceDeviceSdkVersion.rawValue,
                                                            RequestableSignal.diskEncryptionType.rawValue,
                                                            RequestableSignal.serialNumber.rawValue,
                                                            RequestableSignal.screenLockType.rawValue],
                                         customSignals: nil,
                                         cryptoManager: cryptoManager,
                                         jwtGenerator: jwtGenerator,
                                         jwkGenerator: jwkGenerator,
                                         logger: OktaLoggerMock())
        let deviceEnrollment = OktaDeviceEnrollment(id: "id", orgId: mockURL.absoluteString, clientInstanceId: "clientInstanceId", clientInstanceKeyTag: "clientInstanceKeyTag")
        let deviceSignalsModel = mut.buildForVerifyTransaction(deviceEnrollmentId: deviceEnrollment.id,
                                                               clientInstanceKey: deviceEnrollment.clientInstanceId)
        XCTAssertNil(deviceSignalsModel.clientInstanceKey)
        XCTAssertEqual(deviceSignalsModel.clientInstanceId, "clientInstanceId")
        XCTAssertNotNil(deviceSignalsModel.screenLockType)
        XCTAssertEqual(deviceSignalsModel.id, "id")
        XCTAssertNil(deviceSignalsModel.deviceAttestation)
        validateDeviceSignals(deviceSignalsModel)
    }

    // Verify that requested unmanaged signals are ignored if not requested
    func testBuildForVerifyTransaction_Unmanaged_NotRequested() {
        let mut = OktaDeviceModelBuilder(orgHost: "https://tenant.okta.com",
                                         applicationConfig: applicationConfig,
                                         requestedSignals: [RequestableSignal.osVersion.rawValue,
                                                            RequestableSignal.clientInstanceVersion.rawValue],
                                         customSignals: nil,
                                         cryptoManager: cryptoManager,
                                         jwtGenerator: jwtGenerator,
                                         jwkGenerator: jwkGenerator,
                                         logger: OktaLoggerMock())
        let deviceEnrollment = OktaDeviceEnrollment(id: "id", orgId: mockURL.absoluteString, clientInstanceId: "clientInstanceId", clientInstanceKeyTag: "clientInstanceKeyTag")
        let deviceSignalsModel = mut.buildForVerifyTransaction(deviceEnrollmentId: deviceEnrollment.id,
                                                               clientInstanceKey: deviceEnrollment.clientInstanceId)
        XCTAssertEqual(deviceSignalsModel.screenLockType, nil)
        XCTAssertEqual(deviceSignalsModel.diskEncryptionType, nil)
        // Existing signals should remain
        XCTAssertNotNil(deviceSignalsModel.osVersion)
        XCTAssertNotNil(deviceSignalsModel.clientInstanceVersion, applicationConfig.applicationInfo.applicationVersion)
    }

    func testBuildForCreate_WithCustomSignals() {
        var customSignals = DeviceSignals(displayName: "customDisplayName")
        customSignals.udid = "udid"
        customSignals.deviceAttestation = ["managementHint": _OktaCodableArbitaryType.string("managementHint")]

        let mut = OktaDeviceModelBuilder(orgHost: "https://tenant.okta.com",
                                         applicationConfig: applicationConfig,
                                         requestedSignals: ["screenLockType"],
                                         customSignals: customSignals,
                                         cryptoManager: cryptoManager,
                                         jwtGenerator: jwtGenerator,
                                         jwkGenerator: jwkGenerator,
                                         logger: OktaLoggerMock())
        let deviceSignalsModel = mut.buildForCreateEnrollment(with: "keyTag")

        XCTAssertEqual(deviceSignalsModel.udid, "udid")
        XCTAssertEqual(deviceSignalsModel.displayName, "customDisplayName")
        XCTAssertEqual(deviceSignalsModel.deviceAttestation!["managementHint"], _OktaCodableArbitaryType.string("managementHint"))
    }

    func testBuildForVerify_WithCustomSignals() {
        var customSignals = DeviceSignals(displayName: "customDisplayName")
        customSignals.udid = "udid"
        customSignals.deviceAttestation = ["managementHint": _OktaCodableArbitaryType.string("managementHint")]

        let mut = OktaDeviceModelBuilder(orgHost: "https://tenant.okta.com",
                                         applicationConfig: applicationConfig,
                                         requestedSignals: [RequestableSignal.screenLockType.rawValue,
                                                            RequestableSignal.deviceAttestation.rawValue,
                                                            RequestableSignal.udid.rawValue,
                                                            RequestableSignal.displayName.rawValue],
                                         customSignals: customSignals,
                                         cryptoManager: cryptoManager,
                                         jwtGenerator: jwtGenerator,
                                         jwkGenerator: jwkGenerator,
                                         logger: OktaLoggerMock())
        let deviceSignalsModel = mut.buildForVerifyTransaction(deviceEnrollmentId: "deviceEnrollment.id",
                                                               clientInstanceKey: "deviceEnrollment.clientInstanceId")

        XCTAssertEqual(deviceSignalsModel.udid, "udid")
        XCTAssertEqual(deviceSignalsModel.displayName, "customDisplayName")
        let localAuthContext = LAContext()
        var screenLockValue: ScreenLockValue = .none
        if localAuthContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) {
            screenLockValue = .biometric
        } else if localAuthContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) {
            screenLockValue = .passcode
        }
        #if os(macOS)
        XCTAssertNotNil(deviceSignalsModel.screenLockType)
        #else
        XCTAssertEqual(deviceSignalsModel.screenLockType, screenLockValue)
        #endif
        XCTAssertEqual(deviceSignalsModel.deviceAttestation!["managementHint"], _OktaCodableArbitaryType.string("managementHint"))
    }

    func validateDeviceSignals(_ deviceSignalsModel: DeviceSignalsModel) {
        #if os(iOS)
        let displayName = UIDevice.current.name
        #else
        let displayName = (SCDynamicStoreCopyComputerName(nil, nil) as String?) ?? (SCDynamicStoreCopyLocalHostName(nil) as String?) ?? "macOS device"
        #endif
        XCTAssertNotNil(deviceSignalsModel.secureHardwarePresent)
        XCTAssertEqual(deviceSignalsModel.secureHardwarePresent!, OktaEnvironment.canUseSecureEnclave())
        XCTAssertEqual(deviceSignalsModel.manufacturer, "APPLE")
        XCTAssertEqual(deviceSignalsModel.clientInstanceBundleId, "Test App")
        XCTAssertEqual(deviceSignalsModel.clientInstanceVersion, "1.0.0")
        XCTAssertEqual(deviceSignalsModel.clientInstanceDeviceSdkVersion, "DeviceAuthenticator 0.0.1")
        XCTAssertNil(deviceSignalsModel.meid)
        XCTAssertNil(deviceSignalsModel.imei)
        XCTAssertNil(deviceSignalsModel.sid)
        #if os(iOS)
        XCTAssertEqual(UIDevice.current.identifierForVendor?.uuidString, deviceSignalsModel.udid)
        XCTAssertNil(deviceSignalsModel.serialNumber)
        XCTAssertEqual(displayName, deviceSignalsModel.displayName)
        #else
        XCTAssertNotNil(deviceSignalsModel.udid)
        XCTAssertNotNil(deviceSignalsModel.serialNumber)
        XCTAssertEqual(displayName, deviceSignalsModel.displayName)
        #endif
    }
}
