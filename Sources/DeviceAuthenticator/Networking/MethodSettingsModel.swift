/*
* Copyright (c) 2022, Okta, Inc. and/or its affiliates. All rights reserved.
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

struct MethodResponseModel: Codable {

    let type: AuthenticatorMethod
    let status: String
    let settings: MethodSettingsModel?

    enum CodingKeys: String, CodingKey {
        case type
        case status
        case settings
    }
}

struct MethodSettingsModel: Codable {

    let algorithms: [CryptoAlgorithms]?
    let keyProtection: KeyProtection?
    let timeIntervalInSeconds: UInt?
    let encoding: TOTPSecretEncoding?
    let algorithm: TOTPAlgorithms?
    let passCodeLength: UInt?
    let transactionTypes: [TransactionType]?

    // SignedNonce/Push related params
    enum CryptoAlgorithms: String, Codable {
        case RS256, ES256
    }
    enum KeyProtection: String, Codable {
        case ANY, HARDWARE
    }
    // TOTP generation algorithm
    enum TOTPAlgorithms: String, Codable {
        case HMACSHA1, HMACSHA256, HMACSHA512
    }
    // TOTP secret encoding format
    enum TOTPSecretEncoding: String, Codable {
        case Base32
    }

    enum TransactionType: String, Codable {
        case LOGIN
        case CIBA
    }
}
