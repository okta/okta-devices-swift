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

class FactorChallengeTests: XCTestCase {

    var storageMock: StorageMock!

    override func setUp() {
        storageMock = StorageMock()
    }

    func testInit_Success() {
        let pushBindJWT = try? OktaBindJWT(string: OktaJWTTestData.pushChallengeJWT(),
                                           validatePayload: false,
                                           jwtType: "okta-pushbind+jwt",
                                           logger: OktaLoggerMock())
        XCTAssertNotNil(pushBindJWT)
        storageMock.enrollmentByIdHook = { enrollmentId in
            return TestUtils.createAuthenticatorEnrollment(orgHost: URL(string: "tenant.okta.com")!,
                                                           orgId: "orgId",
                                                           enrollmentId: "enrollmentId",
                                                           cryptoManager: CryptoManagerMock(accessGroupId: "accessGroupId", logger: OktaLoggerMock()))

        }
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
        XCTAssertTrue(pushChallenge.showClientLocation)
        XCTAssertEqual(pushChallenge.clientLocation, "Unknown location")
        XCTAssertEqual(pushChallenge.transactionType, .login)
        XCTAssertEqual(pushChallenge.clientOS, "UNKNOWN")
        XCTAssertEqual(pushChallenge.appInstanceName, "TestApp")
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
        dateFormatter.timeZone = TimeZone(identifier: "UTC")
        let dateString = dateFormatter.string(from: pushChallenge.transactionTime)
        XCTAssertEqual(dateString, "2022-02-24T17:23:20.000+0000")
    }

    func testParse_Success() {
        let pushInfo = [InternalConstants.PushJWTConstants.payloadVersionKey: InternalConstants.PushJWTConstants.payloadVersionValue,
                        "challenge": OktaJWTTestData.pushChallengeJWT()]
        XCTAssertNoThrow(try PushChallenge.parse(info: pushInfo,
                                                 allowedClockSkewInSeconds: 300,
                                                 validateJWT: false,
                                                 accessGroupId: "",
                                                 logger: OktaLoggerMock()))
    }

    func testParse_WrongVersion() {
        let pushInfo = [InternalConstants.PushJWTConstants.payloadVersionKey: "V1",
                        "challenge": OktaJWTTestData.pushChallengeJWT()]
        XCTAssertThrowsError(try PushChallenge.parse(info: pushInfo,
                                                     allowedClockSkewInSeconds: 300,
                                                     validateJWT: false,
                                                     accessGroupId: "",
                                                     logger: OktaLoggerMock()))
    }

    func testParse_NoChallenge() {
        let pushInfo = [InternalConstants.PushJWTConstants.payloadVersionKey: InternalConstants.PushJWTConstants.payloadVersionValue]
        XCTAssertThrowsError(try PushChallenge.parse(info: pushInfo,
                                                     allowedClockSkewInSeconds: 300,
                                                     validateJWT: false,
                                                     accessGroupId: "",
                                                     logger: OktaLoggerMock()))
    }
}
