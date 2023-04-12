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
import LocalAuthentication
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif

/// Represents Push factor
class OktaFactorPush: OktaFactor {
    /// Push factor server side id
    var id: String {
        return factorData.id
    }

    /// Checks whether factor was enrolled with user verification key
    /// - Returns: true if factor enrolled with user verification key
    var enrolledWithUserVerificationKey: Bool {
        return userVerificationKeyTag != nil
    }

    /// Checks whether factor was enrolled with bio or pin user verification key
    /// - Returns: true if factor enrolled with bio or pin user verification key
    var enrolledWithUserVerificationBioOrPinKey: Bool {
        return userVerificationBioOrPinKeyTag != nil
    }

    /// Unique id of proof of possession key. Used to read SecKey reference from the keychain
    var proofOfPossessionKeyTag: String? {
        return factorData.proofOfPossessionKeyTag
    }

    /// Unique id of user verification key. Used to read SecKey reference from the keychain
    var userVerificationKeyTag: String? {
        return factorData.userVerificationKeyTag
    }

    /// Unique id of user verification using bio or pin key. Used to read SecKey reference from the keychain
    var userVerificationBioOrPinKeyTag: String? {
        return factorData.userVerificationBioOrPinKeyTag
    }

    var enrolledWithCIBASupport: Bool {
        return factorData.transactionTypes?.supportsCIBA ?? false
    }

    var description: String {
        let info: [String: Any] =  ["type": "Push",
                                    "id": factorData.id,
                                    "popKey": factorData.proofOfPossessionKeyTag,
                                    "uvKey": factorData.userVerificationKeyTag ?? "",
                                    "uvBioOrPinKey": factorData.userVerificationBioOrPinKeyTag ?? ""]
        return "\(info as AnyObject)"
    }

    init(factorData: OktaFactorMetadataPush,
         cryptoManager: OktaSharedCryptoProtocol,
         restAPIClient: ServerAPIProtocol,
         logger: OktaLoggerProtocol) {
        self.logger = logger
        self.cryptoManager = cryptoManager
        self.restAPIClient = restAPIClient
        self.factorData = factorData
    }

    func cleanup() {
        _ = cryptoManager.delete(keyPairWith: factorData.proofOfPossessionKeyTag)
        removeUserVerificationKey()
    }

    func removeUserVerificationKey() {
        if let userVerificationKeyTag = factorData.userVerificationKeyTag {
            _ = cryptoManager.delete(keyPairWith: userVerificationKeyTag)
            factorData.userVerificationKeyTag = nil
        }
    }

    let logger: OktaLoggerProtocol
    let cryptoManager: OktaSharedCryptoProtocol
    let restAPIClient: ServerAPIProtocol
    let factorData: OktaFactorMetadataPush
    private let logEventName = "PushFactor"
}
