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
    var restAPIClient: LegacyServerAPI!

    override func setUp() {
        secKeyHelper = SecKeyHelperMock()
        cryptoManager = CryptoManagerMock(accessGroupId: "", secKeyHelper: secKeyHelper, logger: OktaLoggerMock())
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [], dataArray: [])
        restAPIClient = LegacyServerAPI(client: mockHTTPClient,
                                        crypto: OktaCryptoManager(accessGroupId: ExampleAppConstants.appGroupId,
                                                                  logger: OktaLoggerMock()),
                                        logger: OktaLoggerMock())
        factorData = OktaFactorMetadataPush(id: "id",
                                            proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                            userVerificationKeyTag: "userVerificationKeyTag")
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

    func testCleanup() {
        factor.cleanup()
        XCTAssertEqual(secKeyHelper.deleteCallCount, 2)
        factor.factorData.userVerificationKeyTag = nil
        secKeyHelper.deleteCallCount = 0
        factor.cleanup()
        XCTAssertEqual(secKeyHelper.deleteCallCount, 1)
    }

    func testRemoveUserVerificationKey() {
        factor.removeUserVerificationKey()
        XCTAssertEqual(secKeyHelper.deleteCallCount, 1)
    }
}
