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

final class TransactionTypeTests: XCTestCase {

    override func setUpWithError() throws {}

    func testTransactionType_With0_ReturnsNone() {
        let transactionTypes = TransactionType(rawValue: 0)
        XCTAssertFalse(transactionTypes.contains(.login))
        XCTAssertFalse(transactionTypes.contains(.ciba))
    }

    func testTransactionType_With1_ReturnsLogin() {
        let transactionTypes = TransactionType(rawValue: 1)
        XCTAssertTrue(transactionTypes.contains(.login))
        XCTAssertFalse(transactionTypes.contains(.ciba))
    }
    
    func testTransactionType_with2_ReturnsCIBA() {
        let transactionTypes = TransactionType(rawValue: 2)
        XCTAssertFalse(transactionTypes.contains(.login))
        XCTAssertTrue(transactionTypes.contains(.ciba))
    }
    
    func testTransactionType_3_ReturnCIBAAndLogin() {
        let transactionTypes = TransactionType(rawValue: 3)
        XCTAssertTrue(transactionTypes.contains(.login))
        XCTAssertTrue(transactionTypes.contains(.ciba))
        XCTAssertEqual(transactionTypes, [.login, .ciba])
    }
}
