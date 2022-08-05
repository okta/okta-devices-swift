/*
* Copyright (c) 2021, Okta, Inc. and/or its affiliates. All rights reserved.
* The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
*
* You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*
* See the License for the specific language governing permissions and limitations under the License.
*/
// swiftlint:disable force_try
// swiftlint:disable force_unwrapping
import XCTest
import LocalAuthentication
import CryptoTokenKit
@testable import DeviceAuthenticator

class OktaSQLiteEncryptionManagerTests: XCTestCase {

    func testEncryptDecryptSecureEnclaveEnabled() {
        encryptDecrypt(prefersSecureEnclaveUsage: true)
    }

    func testEncryptDecryptSecureEnclaveDisabled() {
        encryptDecrypt(prefersSecureEnclaveUsage: false)
    }

    func encryptDecrypt(prefersSecureEnclaveUsage: Bool) {
        let cryptoManager = OktaCryptoManager(accessGroupId: ExampleAppConstants.appGroupId, logger: OktaLoggerMock())
        let manager = OktaSQLiteEncryptionManager(cryptoManager: cryptoManager, prefersSecureEnclaveUsage: prefersSecureEnclaveUsage)

        let originalString = "Hello there"
        let originalStringData = originalString.data(using: .utf8)!
        let encrypted = try! manager.encryptedColumnData(from: originalStringData)
        XCTAssertNotEqual(originalStringData, encrypted)
        let decryptedData = try! manager.decryptedColumnData(from: encrypted)
        var decryptedString: String! = String(data: decryptedData, encoding: .utf8)
        XCTAssertEqual(decryptedString, originalString)

        let encryptedStringData = try! manager.encryptedColumnUTF8Data(from: originalString)
        XCTAssertNotEqual(originalString.data(using: .utf8), encryptedStringData)
        decryptedString = try! manager.decryptedColumnString(from: encryptedStringData)
        XCTAssertEqual(decryptedString, originalString)

        let emptyString = ""
        let encryptedEmptyStringData = try! manager.encryptedColumnUTF8Data(from: emptyString)
        XCTAssertNotEqual(emptyString.data(using: .utf8), encryptedEmptyStringData)
        let decryptedEmptyString = try! manager.decryptedColumnString(from: encryptedEmptyStringData)
        XCTAssertEqual(decryptedEmptyString, emptyString)

        let unicodeString = "Unicode ✅🆗"
        let encryptedUnicodeStringData = try! manager.encryptedColumnUTF8Data(from: unicodeString)
        XCTAssertNotEqual(unicodeString.data(using: .utf8), encryptedUnicodeStringData)
        let decryptedUnicodeString = try! manager.decryptedColumnString(from: encryptedUnicodeStringData)
        XCTAssertEqual(decryptedUnicodeString, unicodeString)

        let longString = String.init(repeating: "Long string ", count: 10000)
        let encryptedLongStringData = try! manager.encryptedColumnUTF8Data(from: longString)
        XCTAssertNotEqual(longString.data(using: .utf8), encryptedLongStringData)
        let decryptedLongString = try! manager.decryptedColumnString(from: encryptedLongStringData)
        XCTAssertEqual(decryptedLongString, longString)
    }
}
