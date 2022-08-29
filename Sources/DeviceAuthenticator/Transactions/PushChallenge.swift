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

import Foundation
import OktaJWT
import OktaLogger

/// Represents push challenge details
class PushChallenge: PushChallengeProtocol {

    ///  User's response to the transaction, populated by application
    var userResponse: PushChallengeUserResponse = .userNotResponded

    ///  Org url that originated the challenge
    lazy var originURL: URL? = {
        return URL(string: pushBindJWT.iss)
    }()

    ///  Identifier of the transaction, used for deduplication
    lazy var transactionId: String = {
        return pushBindJWT.transactionId
    }()

    /// Read this flag when building UI for presenting push challenge. If flag is true then present location information to the user
    lazy var showClientLocation: Bool = {
        return challengeContext["showUserLocationInNotification"] as? Bool ?? false
    }()

    /// User's device operating system
    lazy var clientOS: String? = {
        return challengeContext["clientOS"] as? String
    }()

    /// Free-form location information provided by the server
    lazy var clientLocation: String? = {
        return challengeContext["clientLocation"] as? String
    }()

    /// Date/time of the transaction. Use this value for checking outdated challenges
    lazy var transactionTime: Date = {
        let transactionDateTime = Date(timeIntervalSince1970: Double(pushBindJWT.iat))
        return transactionDateTime
    }()

    /// Transaction type associated with this push challenge, usually - LOGIN
    lazy var transactionType: String? = {
        return challengeContext["transactionType"] as? String
    }()

    /// Application name
    lazy var appInstanceName: String? = {
        return pushBindJWT.appInstanceName
    }()

    var isExpired: Bool {
        let expirationDate = Date(timeIntervalSince1970: Double(pushBindJWT.exp))
        return OktaJWTVerifier.isExpired(expirationDate, leeway: Int(allowedClockSkewInSeconds))
    }

    let challengeContext: [AnyHashable: Any]
    let pushBindJWT: OktaBindJWT
    var enrollment: AuthenticatorEnrollmentProtocol?
    let storageManager: PersistentStorageProtocol
    let applicationConfig: ApplicationConfig
    let cryptoManager: OktaSharedCryptoProtocol
    let signalsManager: SignalsManager
    let restAPI: ServerAPIProtocol
    let logger: OktaLoggerProtocol
    let allowedClockSkewInSeconds: Int

    init(pushBindJWT: OktaBindJWT,
         challengeContext: [AnyHashable: Any],
         storageManager: PersistentStorageProtocol,
         applicationConfig: ApplicationConfig,
         cryptoManager: OktaSharedCryptoProtocol,
         signalsManager: SignalsManager,
         restAPI: ServerAPIProtocol,
         logger: OktaLoggerProtocol,
         allowedClockSkewInSeconds: Int = 300) {
        self.pushBindJWT = pushBindJWT
        self.challengeContext = challengeContext
        self.storageManager = storageManager
        self.applicationConfig = applicationConfig
        self.cryptoManager = cryptoManager
        self.signalsManager = signalsManager
        self.restAPI = restAPI
        self.logger = logger
        self.allowedClockSkewInSeconds = allowedClockSkewInSeconds
    }

    func resolve(onRemediation: @escaping (RemediationStep) -> Void,
                 onCompletion: @escaping (DeviceAuthenticatorError?) -> Void) {
        if isExpired {
            onCompletion(DeviceAuthenticatorError.securityError(SecurityError.jwtError("Push challenge expired")))
            return
        }

        do {
            let pushChallengeTransaction = try OktaTransactionPushChallenge(pushChallenge: self,
                                                                            applicationConfig: applicationConfig,
                                                                            storageManager: storageManager,
                                                                            cryptoManager: cryptoManager,
                                                                            signalsManager: signalsManager,
                                                                            restAPI: restAPI,
                                                                            logger: logger)
            pushChallengeTransaction.verify(onIdentityStep: onRemediation) { result, error, enrollment in
                onCompletion(error)
            }
        } catch {
            let deviceAuthenticatorError = DeviceAuthenticatorError.oktaError(from: error)
            onCompletion(deviceAuthenticatorError)
        }
    }

    static func parse(info: [String: Any],
                      allowedClockSkewInSeconds: Int,
                      validateJWT: Bool = true,
                      accessGroupId: String,
                      logger: OktaLoggerProtocol) throws -> OktaBindJWT {
        var versionKey = info[InternalConstants.PushJWTConstants.payloadVersionKey] as? String
        versionKey = versionKey ?? info[InternalConstants.PushJWTConstants.oktaPayloadVersionKey] as? String
        let expectedPayloadVersionValue = InternalConstants.PushJWTConstants.payloadVersionValue
        guard versionKey == expectedPayloadVersionValue else {
            logger.error(eventName: "Parse push challenge", message: "Push notification has unsupported payload version")
            throw DeviceAuthenticatorError.pushNotRecognized
        }

        var challengeJWT: String! = info[InternalConstants.PushJWTConstants.challengeKey] as? String
        challengeJWT = challengeJWT ?? info[InternalConstants.PushJWTConstants.oktaChallengeKey] as? String
        guard challengeJWT != nil else {
            logger.error(eventName: "Parse push challenge", message: "Failed to parse push challenge")
            throw DeviceAuthenticatorError.pushNotRecognized
        }

        return try OktaBindJWT(string: challengeJWT,
                               accessGroupId: accessGroupId,
                               validatePayload: validateJWT,
                               jwtType: InternalConstants.PushJWTConstants.pushJWTType,
                               allowedClockSkewInSeconds: allowedClockSkewInSeconds,
                               logger: logger)
    }
}
