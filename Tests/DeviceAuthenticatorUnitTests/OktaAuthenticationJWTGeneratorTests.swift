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
// swiftlint:disable force_unwrapping
import XCTest
@testable import DeviceAuthenticator

class OktaAuthenticationJWTGeneratorTests: XCTestCase {

    func testCodingAndDecodingOfUpdateDeviceTokenJWT() {
        let secHelper = SecKeyHelperMock()
        var privateKey: SecKey?
        var publicKey: SecKey?
        _ = secHelper.generateKeyPair([:] as CFDictionary, &publicKey, &privateKey)
        XCTAssertNotNil(privateKey)
        let loggerMock = OktaLoggerMock()
        let cryptoManager = CryptoManagerMock(accessGroupId: "", secKeyHelper: secHelper, logger: loggerMock)
        let jwtGeneratorMock = OktaJWTGeneratorMock(logger: loggerMock)
        var hookCalled = false
        jwtGeneratorMock.generateHook = { jwtType, kid, jwt, key, algo in
            XCTAssertEqual(jwtType, "jwtType")
            XCTAssertEqual(kid, "kid")
            XCTAssertEqual(algo, .ES256)
            hookCalled = true
            return ""
        }
        let generator = OktaAuthenticationJWTGenerator(enrollmentId: "enrollmentId",
                                                       orgHost: "www.okta.com",
                                                       userId: "userId",
                                                       key: privateKey!,
                                                       kid: "kid",
                                                       jwtType: "jwtType",
                                                       cryptoManager: cryptoManager,
                                                       logger: loggerMock,
                                                       jwtGenerator: jwtGeneratorMock)
        do {
            _ = try generator.generateJWTString()
        } catch {
            XCTFail()
        }
        XCTAssertTrue(hookCalled)
    }
}
