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

class OktaDeviceBindJWTPayload: OktaJWTPayload, CustomStringConvertible {
    let tx: String?
    let amr: [String]
    let deviceSignals: DeviceSignalsModel
    let nonce: String
    let methodEnrollmentId: String?
    let keyType: String?
    let challengeResponseContext: [String: _OktaCodableArbitaryType]?
    let integrations: [_IntegrationData]?
    let signalProviders: [_IntegrationData]?

    enum DeviceBindCodingKeys: String, CodingKey {
        case tx
        case amr
        case deviceSignals
        case nonce
        case methodEnrollmentId
        case keyType
        case challengeResponseContext
        case integrations
        case signalProviders
    }

    override public func encode(to encoder: Encoder) throws {
        try super.encode(to: encoder)
        var container = encoder.container(keyedBy: DeviceBindCodingKeys.self)
        try container.encode(tx, forKey: .tx)
        try container.encode(amr, forKey: .amr)
        try container.encode(deviceSignals, forKey: .deviceSignals)
        try container.encode(nonce, forKey: .nonce)
        try container.encode(methodEnrollmentId, forKey: .methodEnrollmentId)
        try container.encode(keyType, forKey: .keyType)
        try container.encode(challengeResponseContext, forKey: .challengeResponseContext)
        try container.encode(integrations, forKey: .integrations)
        try container.encode(signalProviders, forKey: .signalProviders)
    }

    init(iss: String,
         aud: String,
         sub: String,
         tx: String?,
         amr: [String],
         deviceSignals: DeviceSignalsModel,
         nonce: String,
         methodEnrollmentId: String?,
         keyType: String?,
         challengeResponseContext: [String: _OktaCodableArbitaryType]?,
         integrations: [_IntegrationData]?,
         signalProviders: [_IntegrationData]?) {
        self.tx = tx
        self.amr = amr
        self.deviceSignals = deviceSignals
        self.nonce = nonce
        self.methodEnrollmentId = methodEnrollmentId
        self.keyType = keyType
        self.challengeResponseContext = challengeResponseContext
        self.integrations = integrations
        self.signalProviders = signalProviders
        super.init(iss: iss, aud: aud, sub: sub)
    }

    var description: String {
        guard let jsonData = try? JSONEncoder().encode(self),
              var descDict = try? JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any] else {
            return "OktaDeviceBindJWTPayload<REDACTED>"
        }

        // Redact sensitive signals (for logging purposes)
        if var signals = descDict[DeviceBindCodingKeys.deviceSignals.rawValue] as? [String: Any] {
            let loggableSignals = RequestableSignal.loggableSignals
            for key in signals.keys {
                if !loggableSignals.contains(key) {
                    signals[key] = "<REDACTED>"
                }
            }
            descDict[DeviceBindCodingKeys.deviceSignals.rawValue] = signals
        }

        if let integrations = descDict[DeviceBindCodingKeys.integrations.rawValue] as? [[String: Any]] {
            let loggableSignals = loggableSignalProviderKeys()

            var redactedIntegrations: [[String: Any]] = []
            for var integration in integrations {
                for key in integration.keys {
                    if !loggableSignals.contains(key) {
                        integration[key] = "<REDACTED>"
                    }
                }
                redactedIntegrations.append(integration)
            }
            descDict[DeviceBindCodingKeys.integrations.rawValue] = redactedIntegrations
        }

        if let signalProviders = descDict[DeviceBindCodingKeys.signalProviders.rawValue] as? [[String: Any]] {
            let loggableSignals = loggableSignalProviderKeys()
            var redactedSignalProviders: [[String: Any]] = []
            for var provider in signalProviders {
                for key in provider.keys {
                    if !loggableSignals.contains(key) {
                        provider[key] = "<REDACTED>"
                    }
                }
                redactedSignalProviders.append(provider)
            }
            descDict[DeviceBindCodingKeys.signalProviders.rawValue] = redactedSignalProviders
        }

        // Redact PII from top level keys (for logging purposes)
        let loggableKeys = loggableJWTKeys()
        for key in descDict.keys {
            if !loggableKeys.contains(key) {
                descDict.removeValue(forKey: key)
            }
        }

        if let reserializedData = try? JSONSerialization.data(withJSONObject: descDict as NSDictionary, options: .prettyPrinted),
           let json = String(data: reserializedData, encoding: .utf8) {
            return json
        }

        return "OktaDeviceBindJWTPayload<REDACTED>"
    }
}

extension OktaDeviceBindJWTPayload {

    ///  List of Bind JWT keys which are safe to log (No PII)
    func loggableJWTKeys() -> Set<String> {
        Set<String>([
            // OktaJWTPayload properties
            JWTCodingKeys.aud.rawValue,
            JWTCodingKeys.iss.rawValue,
            JWTCodingKeys.sub.rawValue,
            JWTCodingKeys.iat.rawValue,
            JWTCodingKeys.exp.rawValue,
            JWTCodingKeys.nbf.rawValue,
            JWTCodingKeys.jti.rawValue,
            JWTCodingKeys.aud.rawValue,
            // OktaDeviceBindJWTPayload
            DeviceBindCodingKeys.tx.rawValue,
            DeviceBindCodingKeys.amr.rawValue,
            DeviceBindCodingKeys.nonce.rawValue,
            DeviceBindCodingKeys.methodEnrollmentId.rawValue,
            DeviceBindCodingKeys.keyType.rawValue,
            DeviceBindCodingKeys.challengeResponseContext.rawValue,
            DeviceBindCodingKeys.deviceSignals.rawValue, // individual signals redacted
            DeviceBindCodingKeys.integrations.rawValue,
            DeviceBindCodingKeys.signalProviders.rawValue,
        ])
    }

    ///  List of device signals which can be logged (No PII)
    func loggableSignalProviderKeys() -> Set<String> {
        Set<String>([
            "name",
            "error",
            "timeCollected",
        ])
    }
}
