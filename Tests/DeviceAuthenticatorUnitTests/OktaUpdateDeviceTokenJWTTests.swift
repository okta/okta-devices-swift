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

import XCTest
@testable import DeviceAuthenticator

class OktaUpdateDeviceTokenJWTTests: XCTestCase {

    func testCodingAndDecodingOfUpdateDeviceTokenJWT() {
        let jwtModel = OktaAuthenticationJWT(iss: "iss", aud: "aud", sub: "sub", kid: "kid")
        let encodedData = try? JSONEncoder().encode(jwtModel)
        XCTAssertNotNil(encodedData)
        let decodedString = String(data: encodedData!, encoding: .utf8)
        XCTAssertTrue(decodedString!.contains("\"iss\":\"iss\""))
        XCTAssertTrue(decodedString!.contains("\"aud\":\"aud\""))
        XCTAssertTrue(decodedString!.contains("\"sub\":\"sub\""))
        XCTAssertTrue(decodedString!.contains("\"kid\":\"kid\""))
    }
}
