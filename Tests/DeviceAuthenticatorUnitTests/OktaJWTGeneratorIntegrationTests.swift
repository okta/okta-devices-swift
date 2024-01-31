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

class OktaJWTGeneratorIntegrationTests: XCTestCase {
    private let cryptoManager = OktaCryptoManager(keychainGroupId: "", logger: OktaLoggerMock())
    private var mut: OktaJWTGenerator!
    private let ec256ValidPrivateKeyBase64 = "BIBwuQyPfBPU+fyXiU+i0FOqEAHtm3U5aER8gIWVnyJvw9YfSa7ylqLNpdeyTie4zUFP9UU4FXLByqcaGFR1q05at441RDVAq1aewlvnE9pKcZmCiiayoO37AxpdRYcTmA=="

    override func setUp() {
        super.setUp()
        mut = OktaJWTGenerator(logger: OktaLoggerMock())
    }

    func testJWTGeneratorFromEC256() {
        guard let secKey = OktaKeyGeneratorHelper.getValidSecKeyES256(ec256ValidPrivateKeyBase64, isPublic: false) else {
            XCTFail("Sec key is nil")
            return
        }
        let user = UserMock(userID: nil, userName: nil)
        do {
            let jwt = try mut.generate(with: "JWT", for: user, with: secKey, using: .ES256)
            let jwtArray = jwt.components(separatedBy: ".")
            XCTAssertEqual(jwtArray.count, 3)
            XCTAssertEqual(jwtArray[1], "e30")
            XCTAssertTrue(jwtArray[0] == "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9" || jwtArray[0] == "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9")
        } catch {
            XCTFail("Unexpected error from OktaJWTGenerator generate \(error)")
        }
    }
}
