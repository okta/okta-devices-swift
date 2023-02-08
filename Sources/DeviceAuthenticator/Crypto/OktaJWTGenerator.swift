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
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif

/// Generates JWT
class OktaJWTGenerator: OktaJWTGeneratorProtocol {
    let logger: OktaLoggerProtocol
    var encoder: JSONEncoder

    init(logger: OktaLoggerProtocol) {
        self.logger = logger
        self.encoder = JSONEncoder()
    }

    func generate<T: Any>(with jwtType: String,
                          kid: String? = nil,
                          for payLoad: T,
                          with key: SecKey,
                          using algorithm: Algorithm) throws -> String where T: Encodable {
        logger.info(eventName: "Starting JWT generation", message: nil)
        guard algorithm == Algorithm.ES256 else {
            let resultError = SecurityError.generalEncryptionError(-1, nil, "Only ES256 algorithm supported for JWS")
            logger.error(eventName: "JWT string error", message: "Error: \(resultError)")
            throw resultError
        }

        let encodedPayload = try encoder.encode(payLoad)
        guard let payloadJSON = String(data: encodedPayload, encoding: .utf8), let payloadData = payloadJSON.data(using: .utf8) else {
            let resultError = SecurityError.generalEncryptionError(-1, nil, "Cannot parse json payload object")
            logger.error(eventName: "JWT string error", message: "Error: \(resultError)")
            throw resultError
        }
        var header = JWTHeader()
        header.typ = jwtType
        if let kid = kid {
            header.kid = kid
        }
        let encodedHeader = try encoder.encode(header)
        guard let headerJSON = String(data: encodedHeader, encoding: .utf8), let headerData = headerJSON.data(using: .utf8) else {
            let resultError = SecurityError.generalEncryptionError(-1, nil, "Cannot create json object from jsonData")
            logger.error(eventName: "JWT string error", message: "Error: \(resultError)")
            throw resultError
        }

        let base64EncodedHeader = toUrlSafeBase64(base64EncodedStr: headerData.base64EncodedString())
        let base64EncodedPayload = toUrlSafeBase64(base64EncodedStr: payloadData.base64EncodedString())
        let signerInput = "\(base64EncodedHeader).\(base64EncodedPayload)"
        guard let signerInputData = signerInput.data(using: .ascii) else {
            let resultError = SecurityError.generalEncryptionError(-1, nil, "Error formatting data for signing")
            logger.error(eventName: "JWT string error", message: "Error: \(resultError)")
            throw resultError
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key,
                                                    .ecdsaSignatureMessageX962SHA256,
                                                    signerInputData as CFData,
                                                    &error) else {
            let resultError = SecurityError.create(with: error)
            logger.error(eventName: "JWT string error", message: "Error: \(resultError)")
            throw resultError
        }

        // This code is taken from the JOSE Swift library
        // unpack BER encoded ASN.1 format signature to raw format as specified for JWS
        let ecSignatureTLV = [UInt8](signature as Data)
        let ecSignature = try ecSignatureTLV.read(.sequence)
        let varlenR = try Data(ecSignature.read(.integer))
        let varlenS = try Data(ecSignature.skip(.integer).read(.integer))
        let fixlenR = toRaw(varlenR, of: 32)
        let fixlenS = toRaw(varlenS, of: 32)
        let signedData = fixlenR + fixlenS

        let jwk = "\(base64EncodedHeader)"
        let payload = "\(base64EncodedPayload)"
        let jws = "\(toUrlSafeBase64(base64EncodedStr: signedData.base64EncodedString()))"
        let jwt = "\(jwk).\(payload).\(jws)"

        logger.info(eventName: "Generate JWT done", message: nil)
        return jwt
    }

    private struct JWTHeader: Codable {
        var alg: String = "ES256"
        var typ: String = "JWT"
        var kid: String?
    }

    private func toUrlSafeBase64(base64EncodedStr: String) -> String {
        let replacedEncodedStr = base64EncodedStr.replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
        return replacedEncodedStr
    }
}
