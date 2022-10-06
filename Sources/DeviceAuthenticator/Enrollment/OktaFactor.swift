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
import OktaLogger

/// Factor base class. SignedNonce, Push, TOTP factor inherit from this class
class OktaFactor: CustomStringConvertible {

    init(cryptoManager: OktaSharedCryptoProtocol,
         restAPIClient: ServerAPIProtocol,
         logger: OktaLoggerProtocol) {
        self.logger = logger
        self.cryptoManager = cryptoManager
        self.restAPIClient = restAPIClient
    }

    /// Unique id of proof of possession key. Used to read SecKey reference from the keychain
    var proofOfPossessionKeyTag: String? {
        return nil
    }

    /// Unique id of user verification key. Used to read SecKey reference from the keychain
    var userVerificationKeyTag: String? {
        return nil
    }

    var enrolledWithUserVerificationKey: Bool {
        // override
        return false
    }

    var enrolledWithCibaSupport: Bool {
        // override
        return false
    }

    var description: String {
        return ""
    }

    func cleanup() {
        // no-op - override
    }

    func removeUserVerificationKey() {
        // no-op - override
    }

    let logger: OktaLoggerProtocol
    let cryptoManager: OktaSharedCryptoProtocol
    let restAPIClient: ServerAPIProtocol
}
