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
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif
#if os(iOS)
import UIKit
#endif

class OktaDeviceModelBuilder {

    let orgHost: String
    let applicationConfig: ApplicationConfig
    let customSignals: DeviceSignals?
    let cryptoManager: OktaSharedCryptoProtocol
    let jwtGenerator: OktaJWTGenerator
    let jwkGenerator: OktaJWKGenerator
    let logger: OktaLoggerProtocol
    let requestedSignals: [String]

    static let enrollmentSignals: Set<RequestableSignal> = [.displayName,
                                                            .platform,
                                                            .manufacturer,
                                                            .model,
                                                            .osVersion,
                                                            .serialNumber,
                                                            .udid,
                                                            .sid,
                                                            .imei,
                                                            .meid,
                                                            .secureHardwarePresent,
                                                            .deviceAttestation,
                                                            .clientInstanceBundleId,
                                                            .clientInstanceDeviceSdkVersion,
                                                            .clientInstanceId,
                                                            .screenLockType,
                                                            .clientInstanceVersion]

    init(orgHost: String,
         applicationConfig: ApplicationConfig,
         requestedSignals: [String],
         customSignals: DeviceSignals?,
         cryptoManager: OktaSharedCryptoProtocol,
         jwtGenerator: OktaJWTGenerator? = nil,
         jwkGenerator: OktaJWKGenerator? = nil,
         logger: OktaLoggerProtocol) {
        self.orgHost = orgHost
        self.applicationConfig = applicationConfig
        self.requestedSignals = requestedSignals
        self.customSignals = customSignals
        self.cryptoManager = cryptoManager
        self.jwtGenerator = jwtGenerator ?? OktaJWTGenerator(logger: logger)
        self.jwkGenerator = jwkGenerator ?? OktaJWKGenerator(logger: logger)
        self.logger = logger
    }

    func buildForCreateEnrollment(with clientIntanceKeyTag: String) -> DeviceSignalsModel {
        logger.info(eventName: logEventName, message: "Building device model for new enrollment")
        var deviceModel = buildBaseDeviceModel(with: Self.enrollmentSignals)
        addJWKPart(to: &deviceModel, clientIntanceKeyTag: clientIntanceKeyTag)

        return deviceModel
    }

    func buildForUpdateEnrollment(with deviceEnrollment: OktaDeviceEnrollment) throws -> DeviceSignalsModel {
        logger.info(eventName: logEventName, message: "Building device model for update enrollment")
        var deviceModel = buildBaseDeviceModel(with: Self.enrollmentSignals)
        try addJWTPart(to: &deviceModel, deviceEnrollment: deviceEnrollment)

        return deviceModel
    }

    func buildForVerifyTransaction(deviceEnrollmentId: String,
                                   clientInstanceKey: String) -> DeviceSignalsModel {
        logger.info(eventName: logEventName, message: "Building device model for verify flow")
        let requestedSignalsArray = requestedSignals.compactMap { RequestableSignal(rawValue: $0) }
        let deviceModel = buildBaseDeviceModel(with: signalsSet(with: requestedSignalsArray))
        deviceModel.id = deviceEnrollmentId
        deviceModel.clientInstanceId = clientInstanceKey

        return deviceModel
    }

    func buildForKeyReenroll(with deviceEnrollment: OktaDeviceEnrollment) -> DeviceSignalsModel {
        logger.info(eventName: logEventName, message: "Building device model for client instance key reenroll")
        var deviceModel = buildBaseDeviceModel(with: Self.enrollmentSignals)
        var existingClientInstanceKey: SecKey?
        if self.cryptoManager.isPrivateKeyAvailable(deviceEnrollment.clientInstanceKeyTag),
           let clientInstanceKey = self.cryptoManager.get(keyOf: .publicKey,
                                                          with: deviceEnrollment.clientInstanceKeyTag,
                                                          context: LAContext()) {
            logger.info(eventName: logEventName, message: "Existing key is healthy, reusing same key...")
            existingClientInstanceKey = clientInstanceKey
        } else {
            logger.info(eventName: logEventName, message: "Can't read the key, calling delete to avoid conflicts for new key")
            _ = cryptoManager.delete(keyPairWith: deviceEnrollment.clientInstanceKeyTag)
        }

        addJWKPart(to: &deviceModel, clientIntanceKeyTag: deviceEnrollment.clientInstanceKeyTag, existingKey: existingClientInstanceKey)
        deviceModel.id = deviceEnrollment.id
        deviceModel.clientInstanceId = deviceEnrollment.clientInstanceId
        deviceModel.deviceAttestation = deviceModel.deviceAttestation ?? [:]

        return deviceModel
    }

    func buildBaseDeviceModel(with requestedSignals: Set<RequestableSignal>) -> DeviceSignalsModel {
        let deviceModel: DeviceSignalsModel
        deviceModel = retrieveDeviceSignals(customDeviceSignals: customSignals, requestedSignals: requestedSignals)

        if requestedSignals.contains(.clientInstanceBundleId) {
            deviceModel.clientInstanceBundleId = applicationConfig.applicationInfo.applicationName
        }

        if requestedSignals.contains(.clientInstanceVersion) {
            deviceModel.clientInstanceVersion = applicationConfig.applicationInfo.applicationVersion
        }

        if requestedSignals.contains(.clientInstanceDeviceSdkVersion) {
            deviceModel.clientInstanceDeviceSdkVersion = DeviceAuthenticatorConstants.name + " " + DeviceAuthenticatorConstants.version
        }

        #if os(iOS)
        deviceModel.authenticatorAppKey = applicationConfig.applicationInfo.applicationInstallationId ?? UIDevice.current.identifierForVendor?.uuidString
        #endif

        return deviceModel
    }

    private func addJWTPart(to deviceModel: inout DeviceSignalsModel,
                            deviceEnrollment: OktaDeviceEnrollment) throws {
        let payload = OktaJWTPayload(iss: deviceEnrollment.clientInstanceId, aud: orgHost, sub: deviceEnrollment.id)
        if let clientInstanceKey = self.cryptoManager.get(keyOf: .privateKey,
                                                          with: deviceEnrollment.clientInstanceKeyTag,
                                                          context: LAContext()) {
            let jwt = try jwtGenerator.generate(with: "",
                                                kid: deviceEnrollment.clientInstanceKeyTag,
                                                for: payload,
                                                with: clientInstanceKey,
                                                using: .ES256)

            deviceModel.id = deviceEnrollment.id
            deviceModel.clientInstanceId = deviceEnrollment.clientInstanceId
            deviceModel.deviceAttestation = deviceModel.deviceAttestation ?? [:]
            deviceModel.deviceAttestation?["clientInstanceKeyAttestation"] = _OktaCodableArbitaryType.string(jwt)
        } else {
            logger.error(eventName: logEventName, message: "Failed to build client instance key JWT")
            throw DeviceAuthenticatorError.securityError(.jwtError("Failed to build client instance key attestation"))
        }
    }

    private func addJWKPart(to deviceModel: inout DeviceSignalsModel,
                            clientIntanceKeyTag: String,
                            existingKey: SecKey? = nil) {
        var additionalParameters: [String: _OktaCodableArbitaryType] = [:]
        additionalParameters["okta:kpr"] = .string(OktaEnvironment.canUseSecureEnclave() ? "HARDWARE" : "SOFTWARE")
        #if os(iOS)
        additionalParameters["okta:isFipsCompliant"] = .bool(OktaEnvironment.isSecureEnclaveAvailable())
        #endif

        var clientInstanceKey = existingKey
        if clientInstanceKey == nil {
            clientInstanceKey = try? cryptoManager.generate(keyPairWith: .ES256,
                                                            with: clientIntanceKeyTag,
                                                            useSecureEnclave: OktaEnvironment.canUseSecureEnclave(),
                                                            useBiometrics: false,
                                                            biometricSettings: nil)
        }
        if let secKey = clientInstanceKey,
           let jwk = try? jwkGenerator.generate(for: secKey,
                                                type: .publicKey,
                                                algorithm: .ES256,
                                                kid: clientIntanceKeyTag,
                                                additionalParameters: additionalParameters) {
            deviceModel.clientInstanceKey = jwk
        } else {
            logger.error(eventName: logEventName, message: "Failed to build client instance key JWK")
        }
    }

    private func retrieveDeviceSignals(customDeviceSignals: DeviceSignals?, requestedSignals: Set<RequestableSignal>) -> DeviceSignalsModel {
        logger.info(eventName: logEventName, message: "Retrieving device signals")
        let deviceSignals = OktaUnmanagedDeviceSignals.retrieveDeviceSignals(requestedSignals: requestedSignals,
                                                                             customDeviceSignals: customDeviceSignals,
                                                                             logger: logger)
        return deviceSignals
    }

    func signalsSet(with array: [RequestableSignal]) -> Set<RequestableSignal> {
        return Set(array.map { $0.self })
    }

    private let logEventName = "DeviceModelBuilder"
}
