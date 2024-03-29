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

class OktaFactorTests: XCTestCase {

    func testCreation() {
        let cryptoManager = CryptoManagerMock(keychainGroupId: "", secKeyHelper: SecKeyHelperMock(), logger: OktaLoggerMock())
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [], dataArray: [])
        let restAPIClient = MyAccountServerAPI(client: mockHTTPClient,
                                               crypto: cryptoManager,
                                               logger: OktaLoggerMock())
        let factor = OktaFactorPush(factorData: OktaFactorMetadataPush(id: "", proofOfPossessionKeyTag: "", transactionTypes: nil),
                                    cryptoManager: cryptoManager,
                                    restAPIClient: restAPIClient,
                                    logger: OktaLoggerMock())
        XCTAssertFalse(factor.enrolledWithUserVerificationKey)
        XCTAssertFalse(factor.enrolledWithUserVerificationBioOrPinKey)
    }
}
