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
import OktaJWT
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif

enum OktaJWTClaims {
    case typ
    case orgId
    case nonce
    case issuer
    case audience
    case issuedAt
    case expires
    case verificationURI
    case mdmAttestationIssuers
    case keyTypes // deprecated, use userVerification and userPresence to determine set of required keys.
    case transactionId
    case signals
    case integrations
    case signalProviders
    case method
    case appInstanceName
    case loginHint
    case userId
    case userVerification
    case userMediation
    case authenticatorEnrollmentId
    case requestReferrer
}

class OktaBindJWT {

    enum KeyType: String, RawRepresentable {
        case unknown
        case proofOfPossession
        case userVerification
    }

    enum MethodType: String, RawRepresentable {
        case unknown
        case signedNonce = "signed_nonce"
        case push
    }

    let jwt: JSONWebToken
    let nonce: String
    let verificationURL: URL
    let orgId: String
    let iss: String
    let aud: String
    let iat: Int
    let exp: Int
    let transactionId: String
    let jwtType: String
    let accessGroupId: String?
    let rawChallenge: String
    let validatePayload: Bool
    let allowedClockSkewInSeconds: Int
    let customizableHeaders: [String: String]

    lazy var signals: [String] = {
        if let signals = self.jwt.payload[OktaJWTClaims.signals.rawValue] as? [String] {
            return signals
        } else {
            return []
        }
    }()

    lazy var requestedSignalIntegrations: [[String: String]] = {
        if let requestedSignalIntegrations = self.jwt.payload[OktaJWTClaims.integrations.rawValue] as? [[String: String]] {
            return requestedSignalIntegrations
        } else {
            return []
        }
    }()

    lazy var requestedSignalProviders: [[String: String]] = {
        return self.jwt.payload[OktaJWTClaims.signalProviders.rawValue] as? [[String: String]] ?? []
    }()

    lazy var mdmAttestationIssuers: [Any] = {
        if let mdmAttestationIssuers = self.jwt.payload[OktaJWTClaims.mdmAttestationIssuers.rawValue] as? [Any] {
            return mdmAttestationIssuers
        } else {
            return []
        }
    }()

    lazy var keyTypes: [KeyType] = {
        guard let typesArray = self.jwt.payload[OktaJWTClaims.keyTypes.rawValue] as? [String] else {
            return []
        }

        let keyTypes = typesArray.compactMap({ KeyType(rawValue: $0) ?? nil })
        return keyTypes
    }()

    lazy var methodType: MethodType = {
        guard let typeString = self.jwt.payload[OktaJWTClaims.method.rawValue] as? String else {
            return .unknown
        }

        return MethodType(rawValue: typeString) ?? MethodType.unknown
    }()

    lazy var appInstanceName: String? = {
        return self.jwt.payload[OktaJWTClaims.appInstanceName.rawValue] as? String
    }()

    lazy var loginHint: String? = {
        return self.jwt.payload[OktaJWTClaims.loginHint.rawValue] as? String
    }()

    lazy var userId: String? = {
        return self.jwt.payload[OktaJWTClaims.userId.rawValue] as? String
    }()

    lazy var userVerification: UserVerificationChallengeRequirement? = {
        guard let uvString = self.jwt.payload[OktaJWTClaims.userVerification.rawValue] as? String else {
            return nil
        }

        return UserVerificationChallengeRequirement(rawValue: uvString)
    }()

    lazy var userMediation: _UserMediationType? = {
        guard let userMediationString = self.jwt.payload[OktaJWTClaims.userMediation.rawValue] as? String else {
            return nil
        }

        return _UserMediationType(rawValue: userMediationString)
    }()

    lazy var authenticatorEnrollmentId: String? = {
        return self.jwt.payload[OktaJWTClaims.authenticatorEnrollmentId.rawValue] as? String
    }()

    lazy var requestReferrer: String? = {
        return self.jwt.payload[OktaJWTClaims.requestReferrer.rawValue] as? String
    }()

    init(string input: String,
         accessGroupId: String? = nil,
         validatePayload: Bool = true,
         customizableHeaders: [String: String] = [: ],
         jwtType: String = "okta-devicebind+jwt",
         allowedClockSkewInSeconds: Int = 60,
         logger: OktaLoggerProtocol) throws {

        do {
            jwt = try JSONWebToken(string: input, typeHeader: jwtType)
        }
        catch {
            logger.error(eventName: logEventName, message: "Failed to decode JWT - \(error)")
            throw SecurityError.jwtError("Invalid JWT structure")
        }

        self.rawChallenge = input
        self.jwtType = jwtType
        self.accessGroupId = accessGroupId
        self.logger = logger
        self.orgId = try Self.get(claim: OktaJWTClaims.orgId,
                                  from: jwt,
                                  expectedType: String.self,
                                  logger: logger)
        self.nonce = try Self.get(claim: OktaJWTClaims.nonce,
                                  from: jwt,
                                  expectedType: String.self,
                                  logger: logger)
        let verificationURI = try Self.get(claim: OktaJWTClaims.verificationURI,
                                           from: jwt,
                                           expectedType: String.self,
                                           logger: logger)
        guard let verificationURL = URL(string: verificationURI) else {
            let resultError = SecurityError.jwtError("\(OktaJWTClaims.verificationURI.rawValue) claim is invalid in JWT payload")
            logger.error(eventName: logEventName, message: "Error: \(resultError)")
            throw resultError
        }
        self.verificationURL = verificationURL

        self.iss = try Self.get(claim: OktaJWTClaims.issuer,
                                from: jwt,
                                expectedType: String.self,
                                logger: logger)
        self.aud = try Self.get(claim: OktaJWTClaims.audience,
                                from: jwt,
                                expectedType: String.self,
                                logger: logger)
        self.iat = try Self.get(claim: OktaJWTClaims.issuedAt,
                                from: jwt,
                                expectedType: Int.self,
                                logger: logger)
        self.exp = try Self.get(claim: OktaJWTClaims.expires,
                                from: jwt,
                                expectedType: Int.self,
                                logger: logger)
        self.transactionId = try Self.get(claim: OktaJWTClaims.transactionId,
                                          from: jwt,
                                          expectedType: String.self,
                                          logger: logger)
        self.validatePayload = validatePayload
        self.allowedClockSkewInSeconds = allowedClockSkewInSeconds
        self.customizableHeaders = customizableHeaders
    }

    func validate(with issuer: String) throws {
        if validatePayload {
            let leeway = allowedClockSkewInSeconds // number of seconds leeway value if there is a clock skew
            let options = [
                OktaJWTClaims.typ.rawValue: jwtType,
                OktaJWTClaims.issuer.rawValue: issuer, // OktaJWT uses this claim for signature verification. It raises exception if claim is not provided
                OktaJWTClaims.expires.rawValue: true,
                OktaJWTClaims.issuedAt.rawValue: true,
                "leeway": leeway
                ] as [String: Any]
            try validateJWT(with: rawChallenge, with: options, with: customizableHeaders, logger: logger)
        }
    }

    func generateDeviceChallengeResponseJWT(key: SecKey,
                                            enrollmentId: String,
                                            sub: String,
                                            methodEnrollmentId: String,
                                            kid: String,
                                            signals: DeviceSignalsModel,
                                            context: [String: String]?,
                                            integrations: [_IntegrationData]?,
                                            signalProviders: [_IntegrationData]?,
                                            keyType: OktaBindJWT.KeyType,
                                            amr: [String] = []) throws -> String {
        let jwtGenerator = OktaJWTGenerator(logger: logger)
        let payload = OktaDeviceBindJWTPayload(iss: enrollmentId,
                                               aud: self.iss,
                                               sub: sub,
                                               tx: self.transactionId,
                                               amr: amr,
                                               deviceSignals: signals,
                                               nonce: self.nonce,
                                               methodEnrollmentId: methodEnrollmentId,
                                               keyType: keyType.rawValue,
                                               challengeResponseContext: context,
                                               integrations: integrations,
                                               signalProviders: signalProviders)

        logger.info(eventName: "Generating Challenge Response JWT with Payload", message: payload.description)
        return try jwtGenerator.generate(with: jwtType, kid: kid, for: payload, with: key, using: .ES256)
    }

    func validateJWT(with jwtString: String,
                     with options: [String: Any],
                     with customizableHeaders: [String: String],
                     logger: OktaLoggerProtocol) throws {
        // Use OktaJWTLib to validate JWT
        var validator = OktaJWTValidator(options, jwk: customizableHeaders)
        var validationOptions = OktaJWTValidator.ValidationOptions.allOptions
        validationOptions.remove(.issuer)
        validator.validationOptionsSet = validationOptions
        validator.keyStorageManager = try? KeyStore(with: self.accessGroupId, logger: logger)
        do {
            _ = try validator.isValid(jwtString)
        } catch let error as OktaJWTVerificationError {
            let resultError = SecurityError.jwtError(error.errorDescription ?? "JWT verification failed")
            logger.error(eventName: logEventName, message: "Error: \(resultError)")
            throw resultError
        } catch {
            let resultError = SecurityError.jwtError("JWT verification failed")
            logger.error(eventName: logEventName, message: "Error: \(resultError)")
            throw resultError
        }
    }

    private class func get<T>(claim: OktaJWTClaims,
                              from jwt: JSONWebToken,
                              expectedType: T.Type,
                              logger: OktaLoggerProtocol) throws -> T {
        guard let value = jwt.payload[claim.rawValue] as? T else {
            let resultError = SecurityError.jwtError("\(claim.rawValue) claim isn't present in JWT payload")
            logger.error(eventName: "Bind JWT error", message: "Error: \(resultError)")
            throw resultError
        }

        return value
    }

    private let logger: OktaLoggerProtocol
    private let logEventName = "OktaBindJWT"
}

extension OktaJWTClaims {
    var rawValue: String {
        switch self {
        case .typ:
            return "typ"
        case .orgId:
            return "orgId"
        case .nonce:
            return "nonce"
        case .verificationURI:
            return "verificationUri"
        case .mdmAttestationIssuers:
            return "mdmAttestationIssuers"
        case .issuer:
            return "iss"
        case .audience:
            return "aud"
        case .issuedAt:
            return "iat"
        case .expires:
            return "exp"
        case .keyTypes:
            return "keyTypes"
        case .transactionId:
            return "transactionId"
        case .signals:
            return "signals"
        case .method:
            return "method"
        case .appInstanceName:
            return "appInstanceName"
        case .integrations:
            return "integrations"
        case .loginHint:
            return "loginHint"
        case .userId:
            return "userId"
        case .userVerification:
            return "userVerification"
        case .userMediation:
            return "userMediation"
        case .signalProviders:
            return "signalProviders"
        case .authenticatorEnrollmentId:
            return "authenticatorEnrollmentId"
        case .requestReferrer:
            return "requestReferrer"
        }
    }
}

extension OktaBindJWT {
    var signalProviderNames: [String] {
        return extractNames(with: requestedSignalProviders)
    }

    var integrationNames: [String] {
        return extractNames(with: requestedSignalIntegrations)
    }

    private func extractNames(with integrationArray: [[String: String]]) -> [String] {
        var names: [String] = []
        for entry in integrationArray {
            if let name = entry["name"] {
                names.append(name)
            }
        }
        return names
    }
}

///  Public key store overrider (otherwise defaults to keychain)
class KeyStore: PublicKeyStorageProtocol {
    let userDefaults: UserDefaults
    var logger: OktaLoggerProtocol

    init(with appGroupId: String?, logger: OktaLoggerProtocol) throws {
        guard let userDefault = UserDefaults(suiteName: appGroupId) else {
            let error = DeviceAuthenticatorError.storageError(StorageError.missingAppGroupEntitlement)
            logger.error(eventName: "Create storage failed", message: "Failed to create UserDefaults storage - \(error)")
            throw error
        }
        self.userDefaults = userDefault
        self.logger = logger
    }

    func save(data: Data, with key: String) throws {
        logger.info(eventName: "KeyStore", message: "Saving key with id: \(key)")
        userDefaults.set(data, forKey: key)
    }

    func data(with key: String) throws -> Data {
        guard let data = userDefaults.data(forKey: key) else {
            logger.info(eventName: "KeyStore", message: "Can't find key with id: \(key)")
            throw DeviceAuthenticatorError.storageError(StorageError.itemNotFound)
        }

        return data
    }

    func delete(with key: String) throws {
        logger.info(eventName: "KeyStore", message: "Deleting key with id: \(key)")
        userDefaults.removeObject(forKey: key)
    }
}
