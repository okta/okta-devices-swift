/*
* Copyright (c) 2019, Okta, Inc. and/or its affiliates. All rights reserved.
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

/// JWK generator that converts a SecKey into JWK format
class OktaJWKGenerator {
    let logger: OktaLoggerProtocol

    init(logger: OktaLoggerProtocol) {
        self.logger = logger
    }

    /// Generates a JWK string for a given key
    /// - Parameters:
    ///   - key: SecKey for which the JWK needs to be generated
    ///   - type: Key type
    ///   - algorithm: Algorithm for the SecKey
    ///   - kid: Random unique id to be included in the key
    /// - Throws: Throws error of type OktaEncryptionError
    func generate(for key: SecKey,
                  type: KeyType,
                  algorithm: Algorithm,
                  kid: String = NSUUID().uuidString,
                  additionalParameters: [String: _OktaCodableArbitaryType] = [: ]) throws -> [String: _OktaCodableArbitaryType]? {
        logger.info(eventName: "Starting JWK generation", message: nil)
        guard algorithm == Algorithm.ES256 else {
            let resultError = SecurityError.generalEncryptionError(-1, nil, "Only ES256 algorithm supported for JWK")
            logger.error(eventName: "JWK string error", message: "Error: \(resultError)")
            throw resultError
        }

        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(key, &error) else {
            let resultError = SecurityError.generalEncryptionError(-1, error?.takeRetainedValue(), "Not able to retrieve public key")
            logger.error(eventName: "JWK string error", message: "Error: \(resultError)")
            throw resultError
        }

        let data = publicKeyData as Data
        var publicKeyBytes = [UInt8](data)
        publicKeyBytes.removeFirst()
        let pointSize = publicKeyBytes.count / 2
        let xBytes = publicKeyBytes[0..<pointSize]
        let yBytes = publicKeyBytes[pointSize..<pointSize * 2]

        var parameters = additionalParameters
        parameters["kty"] = .string("EC")
        parameters["crv"] = .string("P-256")
        parameters["kid"] = .string(kid)
        parameters["x"] = .string(urlEncode(data: Data(xBytes)))
        parameters["y"] = .string(urlEncode(data: Data(yBytes)))

        logger.info(eventName: "JWK generation done", message: nil)
        return parameters
    }

    private func urlEncode(data: Data) -> String {
        return data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    }
}
