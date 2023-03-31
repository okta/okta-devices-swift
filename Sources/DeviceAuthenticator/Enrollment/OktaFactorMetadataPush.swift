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

/// Represents Push factor
class OktaFactorMetadataPush: OktaFactorMetadata {

    struct Links: Codable {
        let pendingLink: String?
    }

    /// Unique id of proof of possession key. Used to read SecKey reference from the keychain
    let proofOfPossessionKeyTag: String
    /// Unique id of user verification key. Used to read SecKey reference from the keychain
    var userVerificationKeyTag: String?
    /// Unique id of user verification bio or pin key. Used to read SecKey reference from the keychain
    var userVerificationBioOrPinKeyTag: String?

    var transactionTypes: TransactionType?

    let pushLinks: Links?

    init(id: String,
         proofOfPossessionKeyTag: String,
         userVerificationKeyTag: String? = nil,
         userVerificationBioOrPinKeyTag: String? = nil,
         links: Links? = nil,
         transactionTypes: TransactionType?) {
        self.pushLinks = links
        self.proofOfPossessionKeyTag = proofOfPossessionKeyTag
        self.userVerificationKeyTag = userVerificationKeyTag
        self.userVerificationBioOrPinKeyTag = userVerificationBioOrPinKeyTag
        self.transactionTypes = transactionTypes
        super.init(id: id)
        type = .push
    }

    enum CodingKeys: String, CodingKey {
        case pushToken
        case links
        case proofOfPossessionKeyTag
        case pushUserVerificationKey
        case userVerificationBioOrPinKey
        case transactionTypes
    }

    override func encode(to encoder: Encoder) throws {
        try super.encode(to: encoder)
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode("", forKey: .pushToken)
        try container.encode(EnrolledAuthenticatorModel.AuthenticatorMethods.Links(pending: nil), forKey: .links)
        try container.encode(proofOfPossessionKeyTag, forKey: .proofOfPossessionKeyTag)
        try container.encode(userVerificationKeyTag, forKey: .pushUserVerificationKey)
        try container.encode(userVerificationBioOrPinKeyTag, forKey: .userVerificationBioOrPinKey)
        try container.encode(transactionTypes?.rawValue, forKey: .transactionTypes)
    }

    required init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.pushLinks = nil
        proofOfPossessionKeyTag = try container.decode(String.self, forKey: .proofOfPossessionKeyTag)
        userVerificationKeyTag = try container.decodeIfPresent(String.self, forKey: .pushUserVerificationKey)
        userVerificationBioOrPinKeyTag = try container.decodeIfPresent(String.self, forKey: .userVerificationBioOrPinKey)
        if let rawTransactionType = try container.decodeIfPresent(Int.self, forKey: .transactionTypes) {
            transactionTypes = TransactionType(rawValue: rawTransactionType)
        } else {
            transactionTypes = .login
        }
        try super.init(from: decoder)
    }
}
