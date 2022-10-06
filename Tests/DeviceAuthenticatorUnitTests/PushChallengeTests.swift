/*
* Copyright (c) 2022-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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

class PushChallengeTests: XCTestCase {

    var storageMock: StorageMock!

    override func setUpWithError() throws {
        storageMock = StorageMock()
    }
    
    func testPushChallenge_LoginType() {
        let pushBindJWT = try? OktaBindJWT(string: OktaJWTTestData.pushChallengeJWT(),
                                           validatePayload: false,
                                           jwtType: "okta-pushbind+jwt",
                                           logger: OktaLoggerMock())
        XCTAssertNotNil(pushBindJWT)

        let context = pushBindJWT!.jwt.payload["challengeContext"] as! [AnyHashable: Any]
        let pushChallenge = PushChallenge(pushBindJWT: pushBindJWT!,
                                          challengeContext: context,
                                          storageManager: storageMock,
                                          applicationConfig: ApplicationConfig(applicationName: "", applicationVersion: "", applicationGroupId: ""),
                                          cryptoManager: CryptoManagerMock(accessGroupId: "", logger: OktaLoggerMock()),
                                          signalsManager: SignalsManager(logger: OktaLoggerMock()),
                                          restAPI: RestAPIMock(client: HTTPClient(logger: OktaLoggerMock(),
                                                                                  userAgent: ""),
                                                               logger: OktaLoggerMock()),
                                          logger: OktaLoggerMock())
        XCTAssertNotNil(pushChallenge)
        XCTAssertEqual(pushChallenge.transactionType, TransactionTypesModel.login)
    }
    
    func testPushChallenge_CibaType() {
        let pushBindJWT = try? OktaBindJWT(string: OktaJWTTestData.pushChallengeCIBAJWT(),
                                           validatePayload: false,
                                           jwtType: "okta-pushbind+jwt",
                                           logger: OktaLoggerMock())
        XCTAssertNotNil(pushBindJWT)

        let context = pushBindJWT!.jwt.payload["challengeContext"] as! [AnyHashable: Any]
        let pushChallenge = PushChallenge(pushBindJWT: pushBindJWT!,
                                          challengeContext: context,
                                          storageManager: storageMock,
                                          applicationConfig: ApplicationConfig(applicationName: "", applicationVersion: "", applicationGroupId: ""),
                                          cryptoManager: CryptoManagerMock(accessGroupId: "", logger: OktaLoggerMock()),
                                          signalsManager: SignalsManager(logger: OktaLoggerMock()),
                                          restAPI: RestAPIMock(client: HTTPClient(logger: OktaLoggerMock(),
                                                                                  userAgent: ""),
                                                               logger: OktaLoggerMock()),
                                          logger: OktaLoggerMock())
        XCTAssertNotNil(pushChallenge)
        XCTAssertEqual(pushChallenge.transactionType, TransactionTypesModel.ciba)
        XCTAssertEqual(pushChallenge.bindingMessage, "Did you make a $300 purchase?")
    }
}
