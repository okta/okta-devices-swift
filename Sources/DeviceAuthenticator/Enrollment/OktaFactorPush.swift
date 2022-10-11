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
import OktaLogger

/// Represents Push factor
class OktaFactorPush: OktaFactor {
    /// Push factor server side id
    var id: String {
        return factorData.id
    }
    /// Checks whether factor was enrolled with user verification key
    /// - Returns: true if factor enrolled with user verification key
    override var enrolledWithUserVerificationKey: Bool {
        return userVerificationKeyTag != nil
    }

    /// Unique id of proof of possession key. Used to read SecKey reference from the keychain
    override var proofOfPossessionKeyTag: String {
        return factorData.proofOfPossessionKeyTag
    }

    /// Unique id of user verification key. Used to read SecKey reference from the keychain
    override var userVerificationKeyTag: String? {
        return factorData.userVerificationKeyTag
    }

    var enrolledWithCIBASupport: Bool {
        return factorData.transactionTypes?.supportsCIBA ?? false
    }

    override var description: String {
        let info: [String: Any] =  ["type": "Push",
                                    "id": factorData.id,
                                    "popKey": factorData.proofOfPossessionKeyTag,
                                    "uvKey": factorData.userVerificationKeyTag ?? ""]
        return "\(info as AnyObject)"
    }

    init(factorData: OktaFactorMetadataPush,
         cryptoManager: OktaSharedCryptoProtocol,
         restAPIClient: ServerAPIProtocol,
         logger: OktaLoggerProtocol) {
        self.factorData = factorData
        super.init(cryptoManager: cryptoManager, restAPIClient: restAPIClient, logger: logger)
    }

    override func cleanup() {
        super.cleanup()
        _ = cryptoManager.delete(keyPairWith: factorData.proofOfPossessionKeyTag)
        removeUserVerificationKey()
        factorData.transactionTypes = .login
    }

    override func removeUserVerificationKey() {
        super.removeUserVerificationKey()
        if let userVerificationKeyTag = factorData.userVerificationKeyTag {
            _ = cryptoManager.delete(keyPairWith: userVerificationKeyTag)
            factorData.userVerificationKeyTag = nil
        }
    }

    /// Factor specific data and settings
    let factorData: OktaFactorMetadataPush
    private let logEventName = "PushFactor"
}
