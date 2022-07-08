/*
* Copyright (c) 2021-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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

class ServerErrorCodesTests: XCTestCase {
    
    ///  Verify that API errors which indicate permanent failure are marked as deleted
    func testIsResourceDeleted() {
        var errorCode = ServerErrorCode(raw: "E0000154")
        XCTAssertTrue(errorCode.isResourceDeleted)
        errorCode = ServerErrorCode(raw: "E0000156")
        XCTAssertTrue(errorCode.isResourceDeleted)
        errorCode = ServerErrorCode(raw: "E0000153")
        XCTAssertTrue(errorCode.isResourceDeleted)
        errorCode = ServerErrorCode(raw: "E0000008")
        XCTAssertTrue(errorCode.isResourceDeleted)
        errorCode = ServerErrorCode(raw: "E0000007")
        XCTAssertFalse(errorCode.isResourceDeleted)
        errorCode = ServerErrorCode(raw: "E0000152")
        XCTAssertFalse(errorCode.isResourceDeleted)
    }

    ///  Verify that API errors which indicate temporary failure are marked as such
    func testIsResourceSuspended() {
        var errorCode = ServerErrorCode(raw: "E0000152")
        XCTAssertTrue(errorCode.isResourceSuspended)
        errorCode = ServerErrorCode(raw: "E0000155")
        XCTAssertTrue(errorCode.isResourceSuspended)
        errorCode = ServerErrorCode(raw: "E0000154")
        XCTAssertFalse(errorCode.isResourceSuspended)
        errorCode = ServerErrorCode(raw: "E0000180")
        XCTAssertFalse(errorCode.isResourceDeleted)
    }
    
    ///  Verify that expected errors match those listed
    ///  https://developer.okta.com/docs/reference/error-codes/
    func testErrorExpectations() {
        verifyErrorCode("E0000007", expected: .resourceNotFound)
        verifyErrorCode("E0000008", expected: .enrollmentNotFound)
        verifyErrorCode("E0000011", expected: .invalidToken)
        verifyErrorCode("E0000152", expected: .deviceSuspended)
        verifyErrorCode("E0000153", expected: .deviceDeleted)
        verifyErrorCode("E0000154", expected: .enrollmentDeleted)
        verifyErrorCode("E0000155", expected: .userSuspended)
        verifyErrorCode("E0000156", expected: .userDeleted)
        verifyErrorCode("E0000180", expected: .enrollmentSuspended)
    }
    
    private func verifyErrorCode(_ code: String, expected: ServerErrorCode) {
        XCTAssertEqual(code, expected.rawValue)
        let errorCode = ServerErrorCode(raw: code)
        XCTAssertEqual(errorCode.rawValue, expected.rawValue)
    }
}
