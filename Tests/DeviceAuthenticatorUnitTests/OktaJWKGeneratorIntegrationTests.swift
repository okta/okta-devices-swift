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

import XCTest
@testable import DeviceAuthenticator

class OktaJWKGeneratorIntegrationTests: XCTestCase {
    let ec256ValidPublicKeyBase64 = "BHuI8PWRC7xWVkyxgN/gEsxlsRQjZSm+sR29MiY3aqnHQL3/sDhlfJdlBcT7rN/XXB7m5w9yD/OcCI5SocP14PM="
    var mut: OktaJWKGenerator!

    override func setUp() {
        super.setUp()
        mut = OktaJWKGenerator(logger: OktaLoggerMock())
    }

    func testJWKGeneratorFromEC256() {
        if let publicKey:SecKey = OktaKeyGeneratorHelper.getValidSecKeyES256(ec256ValidPublicKeyBase64, isPublic: true) {
            do {
                let kid = "test_id"
                guard let jwkDictionary = try mut.generate(for: publicKey,
                                                           type: .publicKey,
                                                           algorithm: .ES256,
                                                           kid: kid,
                                                           additionalParameters: ["okta:kpr": .string("SOFTWARE")]) else {
                        XCTFail("OktaJWKGenerator Generate should not fail")
                        return
                }
                let expectedJWKObj: [String: _OktaCodableArbitaryType] = [
                    "kid": .string(kid),
                    "y": .string("QL3_sDhlfJdlBcT7rN_XXB7m5w9yD_OcCI5SocP14PM"),
                    "x": .string("e4jw9ZELvFZWTLGA3-ASzGWxFCNlKb6xHb0yJjdqqcc"),
                    "kty": .string("EC"),
                    "crv": .string("P-256"),
                    "okta:kpr": .string("SOFTWARE")
                ]
                XCTAssertEqual(expectedJWKObj, jwkDictionary)
            } catch {
                XCTFail("Unexpected error from OktaJWKGenerator generate \(error)")
            }
        } else {
            XCTFail("Sec key parsing should not fail")
        }
    }

    func toJWKObj(_ jwkJSONStr: String) -> [String: String] {
        guard let data = jwkJSONStr.data(using: .utf8),
          let jwkDict = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: String] else {
          return [:]
        }

        return jwkDict
    }
}
