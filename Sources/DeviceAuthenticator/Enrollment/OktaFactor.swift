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
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif

/// Factor base class. SignedNonce, Push, TOTP factor inherit from this class
protocol OktaFactor: CustomStringConvertible {
    var logger: OktaLoggerProtocol { get }
    var cryptoManager: OktaSharedCryptoProtocol { get }
    var restAPIClient: ServerAPIProtocol { get }

    /// Server side id
    var id: String { get }

    /// Unique id of proof of possession key. Used to read SecKey reference from the keychain
    var proofOfPossessionKeyTag: String? { get }

    /// Unique id of user verification key. Used to read SecKey reference from the keychain
    var userVerificationKeyTag: String? { get }

    /// Unique id of user verification using bio or pin key. Used to read SecKey reference from the keychain
    var userVerificationBioOrPinKeyTag: String? { get }

    /// Returns true if factor owns user verification key
    var enrolledWithUserVerificationKey: Bool { get }

    /// Returns true if factor owns bio or pin user verification key
    var enrolledWithUserVerificationBioOrPinKey: Bool { get }

    /// Debug description
    var description: String { get }

    /// Forces factor to do the cleanup: remove all keys for example
    func cleanup()

    /// Removes user verification key
    func removeUserVerificationKey()

    /// Removes user verification bio or pin key
    func removeUserVerificationBioOrPinKey()
}
