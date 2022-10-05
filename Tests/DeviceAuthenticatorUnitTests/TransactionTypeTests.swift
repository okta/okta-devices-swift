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
        let transactionType = TransactionType(rawValue: 0)
        XCTAssertFalse(transactionType.contains(.login))
        XCTAssertFalse(transactionType.contains(.ciba))
    }

    func testTransactionType_With1_ReturnsLogin() {
        let transactionType = TransactionType(rawValue: 1)
        XCTAssertTrue(transactionType.contains(.login))
        XCTAssertFalse(transactionType.contains(.ciba))
    }
    
    func testTransactionType_with2_ReturnsCiba() {
        let transactionType = TransactionType(rawValue: 2)
        XCTAssertFalse(transactionType.contains(.login))
        XCTAssertTrue(transactionType.contains(.ciba))
    }
    
    func testTransactionType_3_ReturnCibaAndLogin() {
        let transactionType = TransactionType(rawValue: 3)
        XCTAssertTrue(transactionType.contains(.login))
        XCTAssertTrue(transactionType.contains(.ciba))
    }
}
