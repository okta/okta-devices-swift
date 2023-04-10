/*
* Copyright (c) 2022-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif

class OktaTransactionPullChallenge: OktaTransaction {
    let restAPI: ServerAPIProtocol
    let enrollment: AuthenticatorEnrollment
    let authenticationToken: OktaRestAPIToken
    let applicationConfig: ApplicationConfig

    init(enrollment: AuthenticatorEnrollment,
         authenticationToken: OktaRestAPIToken,
         storageManager: PersistentStorageProtocol,
         cryptoManager: OktaSharedCryptoProtocol,
         restAPI: ServerAPIProtocol,
         applicationConfig: ApplicationConfig,
         logger: OktaLoggerProtocol) {
        self.restAPI = restAPI
        self.enrollment = enrollment
        self.authenticationToken = authenticationToken
        self.applicationConfig = applicationConfig
        super.init(loginHint: nil,
                   storageManager: storageManager,
                   cryptoManager: cryptoManager,
                   jwtGenerator: OktaJWTGenerator(logger: logger),
                   logger: logger)
    }

    func pullChallenge(allowedClockSkewInSeconds: Int, completion: @escaping (([PushChallengeProtocol], [[String: Any]], DeviceAuthenticatorError?) -> Void)) {
        guard let link = enrollment.pushFactor?.factorData.pushLinks?.pendingLink,
              let url = URL(string: link) else {
            let error = DeviceAuthenticatorError.internalError("Failed to read update push token url")
            logger.error(eventName: "Pull challenge failed", message: "Error: \(error)")
            completion([], [], error)
            return
        }

        restAPI.pendingChallenge(with: url,
                                 authenticationToken: authenticationToken) { result, error in
            DispatchQueue.global().async {
                if let error = error {
                    self.logger.error(eventName: "Pull challenge failed", message: "Error: \(error)")
                    completion([], [], error)
                    return
                }

                guard let result = result,
                      let data = result.data else {
                    let error = DeviceAuthenticatorError.genericError("Server replied with empty response")
                    self.logger.error(eventName: "Pull challenge failed", message: "Error: \(error)")
                    completion([], [], error)
                    return
                }

                guard let payload = (try? JSONSerialization.jsonObject(with: data, options: [])) as? [[String: Any]] else {
                    let error = DeviceAuthenticatorError.genericError("Failed to decode server payload")
                    self.logger.error(eventName: "Pull challenge failed", message: "Error: \(error)")
                    completion([], [], error)
                    return
                }

                var challenges = [PushChallenge]()
                var unrecognizedChallenges = [[String: Any]]()
                payload.forEach { challengeDictionary in
                    guard let pushBindJWT = self.parsePushBindJWT(info: challengeDictionary, allowedClockSkewInSeconds: allowedClockSkewInSeconds),
                          let context = pushBindJWT.jwt.payload["challengeContext"] as? [AnyHashable: Any] else {
                        self.logger.warning(eventName: "Pull challenge failed", message: "Failed to parse JWT. Payload is invalid or expired")
                        unrecognizedChallenges.append(challengeDictionary)
                        return
                    }

                    let pushChallenge = PushChallenge(pushBindJWT: pushBindJWT,
                                                      challengeContext: context,
                                                      storageManager: self.storageManager,
                                                      applicationConfig: self.enrollment.applicationConfig,
                                                      cryptoManager: self.cryptoManager,
                                                      signalsManager: SignalsManager(logger: self.logger),
                                                      restAPI: self.restAPI,
                                                      logger: self.logger,
                                                      allowedClockSkewInSeconds: allowedClockSkewInSeconds)

                    pushChallenge.enrollment = self.enrollment
                    challenges.append(pushChallenge)
                }

                completion(challenges, unrecognizedChallenges, nil)
            }
        }
    }

    func parsePushBindJWT(info: [String: Any], allowedClockSkewInSeconds: Int) -> OktaBindJWT? {
        var validateJWT = true
#if targetEnvironment(simulator)
        validateJWT = false
#endif
        return try? PushChallenge.parse(info: info,
                                        allowedClockSkewInSeconds: allowedClockSkewInSeconds,
                                        validateJWT: validateJWT,
                                        applicationGroupId: applicationConfig.applicationInfo.applicationGroupId,
                                        logger: logger)
    }
}
