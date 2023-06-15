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
import LocalAuthentication
@testable import DeviceAuthenticator

fileprivate class OktaTransactionPullChallengePartialMock: OktaTransactionPullChallenge {
    var allowedClockSkewInSeconds: Int = 0

    override func parsePushBindJWT(info: [String: Any], allowedClockSkewInSeconds: Int) -> OktaBindJWT? {
        self.allowedClockSkewInSeconds = allowedClockSkewInSeconds
        return try? OktaBindJWT(string: info[InternalConstants.PushJWTConstants.challengeKey] as? String ?? "",
                                validatePayload: false,
                                customizableHeaders: [: ],
                                jwtType: "okta-pushbind+jwt",
                                allowedClockSkewInSeconds: allowedClockSkewInSeconds,
                                logger: logger)
    }
}

class TransactionPullChallengeTests: XCTestCase {

    var cryptoManager: CryptoManagerMock!
    var secKeyHelper: SecKeyHelperMock!
    var restAPIClient: MyAccountServerAPI!
    let entitiesGenerator = OktaStorageEntitiesGenerator()
    var storageMock: StorageMock!
    var applicationConfig: ApplicationConfig!

    override func setUp() {
        secKeyHelper = SecKeyHelperMock()
        cryptoManager = CryptoManagerMock(keychainGroupId: "", secKeyHelper: secKeyHelper, logger: OktaLoggerMock())
        storageMock = StorageMock()
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [], dataArray: [])
        restAPIClient = MyAccountServerAPI(client: mockHTTPClient,
                                           crypto: cryptoManager,
                                           logger: OktaLoggerMock())
        applicationConfig = ApplicationConfig(applicationName: "AppName",
                                              applicationVersion: "1.0.0",
                                              applicationGroupId: "")
        
    }

    func testPendingChallenge_Success() {
        _ = try? cryptoManager.generate(keyPairWith: .ES256,
                                        with: "proofOfPossessionKeyTag",
                                        useSecureEnclave: false,
                                        useBiometrics: false,
                                        biometricSettings: nil)
        var mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [HTTPURLResponse(url: URL(string: "tenant.okta.com")!,
                                                                                            statusCode: 200,
                                                                                            httpVersion: nil,
                                                                                            headerFields: nil)!],
                                                            dataArray: [GoldenData.pendingChallengeData()])
        var restAPIClient = MyAccountServerAPI(client: mockHTTPClient,
                                               crypto: cryptoManager,
                                               logger: OktaLoggerMock())
        let authenticator = entitiesGenerator.createAuthenticator(orgHost: "okta.okta.com",
                                                                  orgId: "testOrgId1",
                                                                  userId: "email@okta.com",
                                                                  methodTypes: [.push])
        var pullChallengeTransaction = try! OktaTransactionPullChallengePartialMock(enrollment: authenticator,
                                                                                    authenticationToken: OktaRestAPIToken.accessToken("access_token"),
                                                                                    storageManager: storageMock,
                                                                                    cryptoManager: cryptoManager,
                                                                                    restAPI: restAPIClient,
                                                                                    applicationConfig: applicationConfig,
                                                                                    logger: OktaLoggerMock())
        var completionExpectation = expectation(description: "callback should be called")
        pullChallengeTransaction.pullChallenge(
            allowedClockSkewInSeconds: 300) { pushChallenges, allChallenges, error in
                XCTAssertEqual(pullChallengeTransaction.allowedClockSkewInSeconds, 300)
                XCTAssertEqual(pushChallenges.count, 1)
                XCTAssertNil(error)
                completionExpectation.fulfill()
        }
        wait(for: [completionExpectation], timeout: 1)

        mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [HTTPURLResponse(url: URL(string: "tenant.okta.com")!,
                                                                                        statusCode: 200,
                                                                                        httpVersion: nil,
                                                                                        headerFields: nil)!],
                                                            dataArray: [GoldenData.pendingChallengeData_WithMultipleChallenges()])
        restAPIClient = MyAccountServerAPI(client: mockHTTPClient,
                                           crypto: cryptoManager,
                                           logger: OktaLoggerMock())
        pullChallengeTransaction = try! OktaTransactionPullChallengePartialMock(enrollment: authenticator,
                                                                                authenticationToken: OktaRestAPIToken.accessToken("access_token"),
                                                                                storageManager: storageMock,
                                                                                cryptoManager: cryptoManager,
                                                                                restAPI: restAPIClient,
                                                                                applicationConfig: applicationConfig,
                                                                                logger: OktaLoggerMock(),
                                                                                endpointURL: URL(string: "tenant.okta.com/notifications")!)
        XCTAssertNotNil(pullChallengeTransaction.endpointURL)
        XCTAssertEqual(pullChallengeTransaction.endpointURL.absoluteString, "tenant.okta.com/notifications")
        completionExpectation = expectation(description: "callback should be called")
        pullChallengeTransaction.pullChallenge(
            allowedClockSkewInSeconds: 300) { pushChallenges, allChallenges, error in
                XCTAssertEqual(pushChallenges.count, 1)
                XCTAssertEqual(allChallenges.count, 2)
                XCTAssertNil(error)
                completionExpectation.fulfill()
        }

        wait(for: [completionExpectation], timeout: 1)
    }

    func testPendingChallenge_CIBA_Success() {
        _ = try? cryptoManager.generate(keyPairWith: .ES256,
                                        with: "proofOfPossessionKeyTag",
                                        useSecureEnclave: false,
                                        useBiometrics: false,
                                        biometricSettings: nil)
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [HTTPURLResponse(url: URL(string: "tenant.okta.com")!,
                                                                                            statusCode: 200,
                                                                                            httpVersion: nil,
                                                                                            headerFields: nil)!],
                                                            dataArray: [GoldenData.pendingChallengeCIBAData()])
        let restAPIClient = MyAccountServerAPI(client: mockHTTPClient,
                                               crypto: cryptoManager,
                                               logger: OktaLoggerMock())
        let authenticator = entitiesGenerator.createAuthenticator(orgHost: "okta.okta.com",
                                                                  orgId: "testOrgId1",
                                                                  userId: "email@okta.com",
                                                                  methodTypes: [.push])
        let pullChallengeTransaction = try! OktaTransactionPullChallengePartialMock(enrollment: authenticator,
                                                                                    authenticationToken: OktaRestAPIToken.accessToken("access_token"),
                                                                                    storageManager: storageMock,
                                                                                    cryptoManager: cryptoManager,
                                                                                    restAPI: restAPIClient,
                                                                                    applicationConfig: applicationConfig,
                                                                                    logger: OktaLoggerMock())
        let completionExpectation = expectation(description: "callback should be called")
        pullChallengeTransaction.pullChallenge(
            allowedClockSkewInSeconds: 300) { pushChallenges, allChallenges, error in
                XCTAssertEqual(pullChallengeTransaction.allowedClockSkewInSeconds, 300)
                XCTAssertEqual(pushChallenges.count, 1)
                XCTAssertNil(error)
                completionExpectation.fulfill()
        }
        wait(for: [completionExpectation], timeout: 1)
    }

    func testPendingChallenge_NoLink() {
        _ = try? cryptoManager.generate(keyPairWith: .ES256,
                                        with: "proofOfPossessionKeyTag",
                                        useSecureEnclave: false,
                                        useBiometrics: false,
                                        biometricSettings: nil)
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [HTTPURLResponse(url: URL(string: "tenant.okta.com")!,
                                                                                            statusCode: 200,
                                                                                            httpVersion: nil,
                                                                                            headerFields: nil)!],
                                                            dataArray: [GoldenData.pendingChallengeData()])
        let restAPIClient = MyAccountServerAPI(client: mockHTTPClient,
                                               crypto: cryptoManager,
                                               logger: OktaLoggerMock())
        let links = OktaFactorMetadataPush.Links(pendingLink: nil)
        let factorData = OktaFactorMetadataPush(id: "id",
                                                proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                                userVerificationKeyTag: "userVerificationKeyTag",
                                                links: links,
                                                transactionTypes: .login)
        let pushFactor = OktaFactorPush(factorData: factorData,
                                        cryptoManager: cryptoManager,
                                        restAPIClient: restAPIClient,
                                        logger: OktaLoggerMock())
        let authenticator = entitiesGenerator.createAuthenticator(orgHost: "okta.okta.com",
                                                                  orgId: "testOrgId1",
                                                                  userId: "email@okta.com",
                                                                  enrolledFactors: [pushFactor])
        do {
            let _ = try OktaTransactionPullChallengePartialMock(enrollment: authenticator,
                                                                authenticationToken: OktaRestAPIToken.accessToken("access_token"),
                                                                storageManager: storageMock,
                                                                cryptoManager: cryptoManager,
                                                                restAPI: restAPIClient,
                                                                applicationConfig: applicationConfig,
                                                                logger: OktaLoggerMock())
            XCTFail("Unexpected success")
        } catch {
            if case DeviceAuthenticatorError.internalError(let description) = error {
                XCTAssertEqual(description, "Failed to construct pending challenge URL")
            } else {
                XCTFail("Unexpected error type - \(error.localizedDescription)")
            }
        }
    }

    func testPendingChallenge_RestAPIError() {
        _ = try? cryptoManager.generate(keyPairWith: .ES256,
                                        with: "proofOfPossessionKeyTag",
                                        useSecureEnclave: false,
                                        useBiometrics: false,
                                        biometricSettings: nil)
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [HTTPURLResponse(url: URL(string: "tenant.okta.com")!,
                                                                                            statusCode: 401,
                                                                                            httpVersion: nil,
                                                                                            headerFields: nil)!],
                                                            dataArray: [GoldenData.pendingChallengeData()])
        let restAPIClient = MyAccountServerAPI(client: mockHTTPClient,
                                               crypto: cryptoManager,
                                               logger: OktaLoggerMock())
        let authenticator = entitiesGenerator.createAuthenticator(orgHost: "okta.okta.com",
                                                                  orgId: "testOrgId1",
                                                                  userId: "email@okta.com",
                                                                  methodTypes: [.push])
        let pullChallengeTransaction = try! OktaTransactionPullChallengePartialMock(enrollment: authenticator,
                                                                                    authenticationToken: OktaRestAPIToken.accessToken("access_token"),
                                                                                    storageManager: storageMock,
                                                                                    cryptoManager: cryptoManager,
                                                                                    restAPI: restAPIClient,
                                                                                    applicationConfig: applicationConfig,
                                                                                    logger: OktaLoggerMock())
        let completionExpectation = expectation(description: "callback should be called")
        pullChallengeTransaction.pullChallenge(
            allowedClockSkewInSeconds: 300) { pushChallenges, allChallenges, error in
                XCTAssertEqual(error?.localizedDescription, "Server call has failed")
                XCTAssertTrue(pushChallenges.isEmpty)
                XCTAssertTrue(allChallenges.isEmpty)
                completionExpectation.fulfill()
        }
        wait(for: [completionExpectation], timeout: 1)
    }

    func testPendingChallenge_BadServerPayload() {
        _ = try? cryptoManager.generate(keyPairWith: .ES256,
                                        with: "proofOfPossessionKeyTag",
                                        useSecureEnclave: false,
                                        useBiometrics: false,
                                        biometricSettings: nil)
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [HTTPURLResponse(url: URL(string: "tenant.okta.com")!,
                                                                                            statusCode: 200,
                                                                                            httpVersion: nil,
                                                                                            headerFields: nil)!],
                                                            dataArray: [])
        let restAPIClient = MyAccountServerAPI(client: mockHTTPClient,
                                               crypto: cryptoManager,
                                               logger: OktaLoggerMock())
        let authenticator = entitiesGenerator.createAuthenticator(orgHost: "okta.okta.com",
                                                                  orgId: "testOrgId1",
                                                                  userId: "email@okta.com",
                                                                  methodTypes: [.push])
        let pullChallengeTransaction = try! OktaTransactionPullChallengePartialMock(enrollment: authenticator,
                                                                                    authenticationToken: OktaRestAPIToken.accessToken("access_token"),
                                                                                    storageManager: storageMock,
                                                                                    cryptoManager: cryptoManager,
                                                                                    restAPI: restAPIClient,
                                                                                    applicationConfig: applicationConfig,
                                                                                    logger: OktaLoggerMock())
        let completionExpectation = expectation(description: "callback should be called")
        pullChallengeTransaction.pullChallenge(
            allowedClockSkewInSeconds: 300) { pushChallenges, allChallenges, error in
                XCTAssertEqual(error?.localizedDescription, "Failed to decode server payload")
                XCTAssertTrue(pushChallenges.isEmpty)
                XCTAssertTrue(allChallenges.isEmpty)
                completionExpectation.fulfill()
        }
        wait(for: [completionExpectation], timeout: 1)
    }

    func testPendingChallenge_NoIdxChallengeInPayload() {
        _ = try? cryptoManager.generate(keyPairWith: .ES256,
                                        with: "proofOfPossessionKeyTag",
                                        useSecureEnclave: false,
                                        useBiometrics: false,
                                        biometricSettings: nil)
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [HTTPURLResponse(url: URL(string: "tenant.okta.com")!,
                                                                                            statusCode: 200,
                                                                                            httpVersion: nil,
                                                                                            headerFields: nil)!],
                                                            dataArray: [GoldenData.pendingChallenge_Empty()])
        let restAPIClient = MyAccountServerAPI(client: mockHTTPClient,
                                               crypto: cryptoManager,
                                               logger: OktaLoggerMock())
        let authenticator = entitiesGenerator.createAuthenticator(orgHost: "okta.okta.com",
                                                                  orgId: "testOrgId1",
                                                                  userId: "email@okta.com",
                                                                  methodTypes: [.push])
        let pullChallengeTransaction = try! OktaTransactionPullChallengePartialMock(enrollment: authenticator,
                                                                                    authenticationToken: OktaRestAPIToken.accessToken("access_token"),
                                                                                    storageManager: storageMock,
                                                                                    cryptoManager: cryptoManager,
                                                                                    restAPI: restAPIClient,
                                                                                    applicationConfig: applicationConfig,
                                                                                    logger: OktaLoggerMock())
        let completionExpectation = expectation(description: "callback should be called")
        pullChallengeTransaction.pullChallenge(
            allowedClockSkewInSeconds: 300) { pushChallenges, allChallenges, error in
                XCTAssertNil(error)
                XCTAssertTrue(pushChallenges.isEmpty)
                XCTAssertEqual(allChallenges.count, 1)
                completionExpectation.fulfill()
        }
        wait(for: [completionExpectation], timeout: 1)
    }

    func testPendingChallenge_PayloadWithBadBindJWT() {
        _ = try? cryptoManager.generate(keyPairWith: .ES256,
                                        with: "proofOfPossessionKeyTag",
                                        useSecureEnclave: false,
                                        useBiometrics: false,
                                        biometricSettings: nil)
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [HTTPURLResponse(url: URL(string: "tenant.okta.com")!,
                                                                                            statusCode: 200,
                                                                                            httpVersion: nil,
                                                                                            headerFields: nil)!],
                                                            dataArray: [GoldenData.pendingChallengeData_NoChallengeContextInBindJWT()])
        let restAPIClient = MyAccountServerAPI(client: mockHTTPClient,
                                               crypto: cryptoManager,
                                               logger: OktaLoggerMock())
        let authenticator = entitiesGenerator.createAuthenticator(orgHost: "okta.okta.com",
                                                                  orgId: "testOrgId1",
                                                                  userId: "email@okta.com",
                                                                  methodTypes: [.push])
        let pullChallengeTransaction = try! OktaTransactionPullChallengePartialMock(enrollment: authenticator,
                                                                                    authenticationToken: OktaRestAPIToken.accessToken("access_token"),
                                                                                    storageManager: storageMock,
                                                                                    cryptoManager: cryptoManager,
                                                                                    restAPI: restAPIClient,
                                                                                    applicationConfig: applicationConfig,
                                                                                    logger: OktaLoggerMock())
        let completionExpectation = expectation(description: "callback should be called")
        pullChallengeTransaction.pullChallenge(
            allowedClockSkewInSeconds: 300) { pushChallenges, allChallenges, error in
                XCTAssertNil(error)
                XCTAssertTrue(pushChallenges.isEmpty)
                XCTAssertEqual(allChallenges.count, 1)
                completionExpectation.fulfill()
        }
        wait(for: [completionExpectation], timeout: 1)
    }
}
