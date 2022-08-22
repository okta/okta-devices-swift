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
import LocalAuthentication
import CryptoTokenKit
@testable import DeviceAuthenticator

class OktaEncryptionErrorTests: XCTestCase {

    func testCreateWithSigningError() throws {
        // LAError.Code.userCancel
        var cfError = CFErrorCreate(kCFAllocatorDefault, LAErrorDomain as CFString, LAError.Code.userCancel.rawValue, nil)
        var encryptionError = SecurityError.create(with: Unmanaged<CFError>.passRetained(cfError!))
        if case SecurityError.localAuthenticationCancelled(let error) = encryptionError {
            let nsError = error as Error as NSError
            XCTAssertTrue(nsError.code == LAError.Code.userCancel.rawValue)
            XCTAssertTrue(nsError.domain == LAErrorDomain)
        } else {
            XCTFail("Unexpected error type")
        }

        // TKError.Code.corruptedData
        cfError = CFErrorCreate(kCFAllocatorDefault, TKErrorDomain as CFString, TKError.Code.corruptedData.rawValue, nil)
        encryptionError = SecurityError.create(with: Unmanaged<CFError>.passRetained(cfError!))
        if case SecurityError.keyCorrupted(let error) = encryptionError {
            let nsError = error as Error as NSError
            XCTAssertTrue(nsError.code == TKError.Code.corruptedData.rawValue)
            XCTAssertTrue(nsError.domain == TKErrorDomain)
        } else {
            XCTFail("Unexpected error type")
        }

        // Some other error
        cfError = CFErrorCreate(kCFAllocatorDefault, TKErrorDomain as CFString, TKError.Code.communicationError.rawValue, nil)
        encryptionError = SecurityError.create(with: Unmanaged<CFError>.passRetained(cfError!))
        if case SecurityError.generalEncryptionError(let status, let error, let description) = encryptionError {
            let nsError = error! as NSError
            XCTAssertTrue(nsError.code == TKError.Code.communicationError.rawValue)
            XCTAssertTrue(nsError.domain == TKErrorDomain)
            XCTAssertTrue(status == -1)
            XCTAssertEqual(description, "Error signing JWT with key")
        } else {
            XCTFail("Unexpected error type")
        }
    }
}
