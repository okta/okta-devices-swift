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
import XCTest
@testable import DeviceAuthenticator

class EnrollAuthenticatorRequestModelTests: XCTestCase {

    func testEnrollAuthenticatorRequestModelEncoding() {
        let signals = DeviceSignalsModel(platform: .iOS, osVersion: "10", displayName: "Test Device")
        signals.deviceAttestation = ["key": _OktaCodableArbitaryType.string("value")]
        let pushMethod = EnrollAuthenticatorRequestModel.AuthenticatorMethods(type: .push,
                                                                              pushToken: "samplePushToken",
                                                                              apsEnvironment: .production,
                                                                              supportUserVerification: false,
                                                                              isFipsCompliant: nil,
                                                                              keys: nil,
                                                                              capabilities: nil)
        let signedNonceMethod = EnrollAuthenticatorRequestModel.AuthenticatorMethods(type: .signedNonce,
                                                                                     pushToken: nil,
                                                                                     apsEnvironment: nil,
                                                                                     supportUserVerification: false,
                                                                                     isFipsCompliant: nil,
                                                                                     keys: nil,
                                                                                    capabilities: nil)
        let totpMethod = EnrollAuthenticatorRequestModel.AuthenticatorMethods(type: .totp,
                                                                              pushToken: nil,
                                                                              apsEnvironment: nil,
                                                                              supportUserVerification: false,
                                                                              isFipsCompliant: true,
                                                                              keys: nil,
                                                                              capabilities: nil)

        let requestModel = EnrollAuthenticatorRequestModel(authenticatorId: "autuowpr5VjVjQPU30g3",
                                                           key: "okta_verify",
                                                           device: signals,
                                                           appSignals: nil,
                                                           methods: [pushMethod, signedNonceMethod, totpMethod])

        XCTAssertNotNil(try? JSONEncoder().encode(requestModel))
    }

    func testKeysEncoding() {
        // test user verification `null` value
        var keysModel = SigningKeysModel(proofOfPossession: ["key": .string("value")],
                                         userVerification: SigningKeysModel.UserVerificationKey.null,
                                         userVerificationBioOrPin: SigningKeysModel.UserVerificationKey.null)
        let encoder = JSONEncoder()
        var encodedData = try? encoder.encode(keysModel)
        XCTAssertNotNil(encodedData)
        var encodedString = String(data: encodedData!, encoding: .utf8)
        XCTAssertTrue(encodedString!.contains("\"userVerification\":null"))

        // test user verification with jwt
        keysModel = SigningKeysModel(proofOfPossession: ["key": .string("value")],
                                     userVerification: SigningKeysModel.UserVerificationKey.keyValue(["uvKey": .string("uvValue")]),
                                     userVerificationBioOrPin: SigningKeysModel.UserVerificationKey.keyValue(["uvBioOrPinKey": .string("uvBioOrPinKey")]))
        encodedData = try? encoder.encode(keysModel)
        XCTAssertNotNil(encodedData)
        encodedString = String(data: encodedData!, encoding: .utf8)
        XCTAssertTrue(encodedString!.contains("\"userVerification\":{\"uvKey\":\"uvValue\""))
        XCTAssertTrue(encodedString!.contains("\"userVerificationBioOrPin\":{\"uvBioOrPinKey\":\"uvBioOrPinKey\""))
    }
}
