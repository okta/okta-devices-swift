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
import LocalAuthentication
@testable import DeviceAuthenticator

class OktaFactorPushTests: XCTestCase {

    var factor: OktaFactorPush!
    var cryptoManager: CryptoManagerMock!
    var secKeyHelper: SecKeyHelperMock!
    var factorData: OktaFactorMetadataPush!
    var restAPIClient: MyAccountServerAPI!

    override func setUp() {
        secKeyHelper = SecKeyHelperMock()
        cryptoManager = CryptoManagerMock(keychainGroupId: "", secKeyHelper: secKeyHelper, logger: OktaLoggerMock())
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [], dataArray: [])
        restAPIClient = MyAccountServerAPI(client: mockHTTPClient,
                                           crypto: OktaCryptoManager(keychainGroupId: ExampleAppConstants.appGroupId,
                                                                     logger: OktaLoggerMock()),
                                           logger: OktaLoggerMock())
        factorData = OktaFactorMetadataPush(id: "id",
                                            proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                            userVerificationKeyTag: "userVerificationKeyTag",
                                            userVerificationBioOrPinKeyTag: "userVerificationBioOrPinKeyTag",
                                            transactionTypes: .login)
        factor = OktaFactorPush(factorData: factorData,
                                cryptoManager: cryptoManager,
                                restAPIClient: restAPIClient,
                                logger: OktaLoggerMock())
    }

    func testEnrolledWithUserVerificationKey() {
        XCTAssertTrue(factor.enrolledWithUserVerificationKey)
        factor.factorData.userVerificationKeyTag = nil
        XCTAssertFalse(factor.enrolledWithUserVerificationKey)
    }

    func testEnrolledWithUserVerificationBioOrPinKey() {
        XCTAssertTrue(factor.enrolledWithUserVerificationBioOrPinKey)
        factor.factorData.userVerificationBioOrPinKeyTag = nil
        XCTAssertFalse(factor.enrolledWithUserVerificationBioOrPinKey)
    }

    func testCleanup() {
        factor.cleanup()
        XCTAssertEqual(secKeyHelper.deleteCallCount, 3) // pop, uv, uvBioOrPin
    }

    func testCleanupNoUserVerificationKeyTag() {
        factor.factorData.userVerificationKeyTag = nil
        factor.cleanup()
        XCTAssertEqual(secKeyHelper.deleteCallCount, 2) // pop, uvBioOrPin
    }

    func testCleanupNoUserVerificationBioOrPinKeyTag() {
        factor.factorData.userVerificationBioOrPinKeyTag = nil
        factor.cleanup()
        XCTAssertEqual(secKeyHelper.deleteCallCount, 2) // pop, uv
    }

    func testCleanupNoUserVerificationKeyTags() {
        factor.factorData.userVerificationKeyTag = nil
        factor.factorData.userVerificationBioOrPinKeyTag = nil
        factor.cleanup()
        XCTAssertEqual(secKeyHelper.deleteCallCount, 1) // pop
    }

    func testRemoveUserVerificationKey() {
        factor.removeUserVerificationKey()
        XCTAssertEqual(secKeyHelper.deleteCallCount, 1)
    }

    func testRemoveUserVerificationBioOrPinKey() {
        factor.removeUserVerificationBioOrPinKey()
        XCTAssertEqual(secKeyHelper.deleteCallCount, 1)
    }

    func removeAllUserVerificationKeys() {
        factor.removeUserVerificationKey()
        factor.removeUserVerificationBioOrPinKey()
        XCTAssertEqual(secKeyHelper.deleteCallCount, 2)
    }

    func testEnrolledWithLoginTransactionTypes() {
        XCTAssertFalse(factor.enrolledWithCIBASupport)
    }
    
    func testEnrolledWithCibaAndLoginTransactionTypes() {
        factor.cleanup()
        factor.factorData.transactionTypes = [.login, .ciba]
        XCTAssertTrue(factor.enrolledWithCIBASupport)
    }
}
