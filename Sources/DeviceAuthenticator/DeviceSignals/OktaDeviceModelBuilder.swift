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
import CryptoKit
import OktaLogger

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
        if let platformSSOData = customSignals?.platformSSO {
            addPlatformSSOPayload(to: &deviceModel, platformSSOData: platformSSOData)
        }

        return deviceModel
    }

    func buildForUpdateEnrollment(with deviceEnrollment: OktaDeviceEnrollment) -> DeviceSignalsModel {
        logger.info(eventName: logEventName, message: "Building device model for update enrollment")
        var deviceModel = buildBaseDeviceModel(with: Self.enrollmentSignals)
        addJWTPart(to: &deviceModel, deviceEnrollment: deviceEnrollment)
        if let platformSSOData = customSignals?.platformSSO {
            addPlatformSSOPayload(to: &deviceModel, platformSSOData: platformSSOData)
        }

        return deviceModel
    }

    func buildForRotateClientInstanceKey(with deviceEnrollment: OktaDeviceEnrollment,
                                         and clientIntanceKeyTag: String) -> DeviceSignalsModel {
        logger.info(eventName: logEventName, message: "Building device model for rotating client instance key")
        var deviceModel = buildForCreateEnrollment(with: clientIntanceKeyTag)
        addJWTPart(to: &deviceModel, deviceEnrollment: deviceEnrollment)

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

        return deviceModel
    }

    private func addJWTPart(to deviceModel: inout DeviceSignalsModel,
                            deviceEnrollment: OktaDeviceEnrollment) {
        deviceModel.id = deviceEnrollment.id
        deviceModel.clientInstanceId = deviceEnrollment.clientInstanceId
        deviceModel.deviceAttestation = deviceModel.deviceAttestation ?? [:]
        let payload = OktaJWTPayload(iss: deviceEnrollment.clientInstanceId, aud: orgHost, sub: deviceEnrollment.id)
        if let clientInstanceKey = self.cryptoManager.get(keyOf: .privateKey,
                                                          with: deviceEnrollment.clientInstanceKeyTag,
                                                          context: LAContext()),
           let jwt = try? jwtGenerator.generate(with: "",
                                                kid: deviceEnrollment.clientInstanceKeyTag,
                                                for: payload,
                                                with: clientInstanceKey,
                                                using: .ES256) {
            deviceModel.deviceAttestation?["clientInstanceKeyAttestation"] = _OktaCodableArbitaryType.string(jwt)
        } else {
            logger.error(eventName: logEventName, message: "Failed to build client instance key JWT")
        }
    }

    private func addJWKPart(to deviceModel: inout DeviceSignalsModel,
                            clientIntanceKeyTag: String) {
        var additionalParameters: [String: _OktaCodableArbitaryType] = [:]
        additionalParameters["okta:kpr"] = .string(OktaEnvironment.canUseSecureEnclave() ? "HARDWARE" : "SOFTWARE")
        #if os(iOS)
        additionalParameters["okta:isFipsCompliant"] = .bool(OktaEnvironment.isSecureEnclaveAvailable())
        #endif

        if let secKey = try? cryptoManager.generate(keyPairWith: .ES256,
                                                    with: clientIntanceKeyTag,
                                                    useSecureEnclave: OktaEnvironment.canUseSecureEnclave(),
                                                    useBiometrics: false,
                                                    biometricSettings: nil),
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

    private func addPlatformSSOPayload(to deviceModel: inout DeviceSignalsModel,
                                       platformSSOData: PlatformSSOData) {
        // Calculate kid for keys
        var hashBytes = Array(SHA256.hash(data: platformSSOData.deviceSigningKey).makeIterator())
        let deviceSigningKeyKID = Data(hashBytes).base64EncodedString()
        hashBytes = Array(SHA256.hash(data: platformSSOData.deviceEncryptionKey).makeIterator())
        let deviceEncryptionKeyKID = Data(hashBytes).base64EncodedString()

        let deviceSigningJWK = try? jwkGenerator.generate(for: platformSSOData.deviceSigningKey,
                                                          type: .publicKey,
                                                          algorithm: .ES256,
                                                          kid: deviceSigningKeyKID,
                                                          additionalParameters: [:])
        let deviceEncryptionJWK = try? jwkGenerator.generate(for: platformSSOData.deviceEncryptionKey,
                                                             type: .publicKey,
                                                             algorithm: .ES256,
                                                             kid: deviceEncryptionKeyKID,
                                                             additionalParameters: [:])
        guard let deviceSigningJWK = deviceSigningJWK,
              let deviceEncryptionJWK = deviceEncryptionJWK else {
            logger.error(eventName: logEventName, message: "Failed to build platform SSO payload")
            return
        }

        let keysPayload = DeviceSignalsModel.PlatformSSOPayload.KeysPayload(deviceSigningKey: deviceSigningJWK, encryptionKey: deviceEncryptionJWK, deviceEncryptionKey: deviceEncryptionJWK)
        deviceModel.platformSSO = DeviceSignalsModel.PlatformSSOPayload(keys: keysPayload, userOSAccount: "None")
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
