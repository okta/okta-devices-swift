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
    var restAPIClient: LegacyServerAPI!
    let entitiesGenerator = OktaStorageEntitiesGenerator()
    var storageMock: StorageMock!

    override func setUp() {
        secKeyHelper = SecKeyHelperMock()
        cryptoManager = CryptoManagerMock(accessGroupId: "", secKeyHelper: secKeyHelper, logger: OktaLoggerMock())
        storageMock = StorageMock()
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [], dataArray: [])
        restAPIClient = LegacyServerAPI(client: mockHTTPClient, logger: OktaLoggerMock())
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
        var restAPIClient = LegacyServerAPI(client: mockHTTPClient, logger: OktaLoggerMock())
        let authenticator = entitiesGenerator.createAuthenticator(orgHost: "okta.okta.com",
                                                                  orgId: "testOrgId1",
                                                                  userId: "email@okta.com",
                                                                  methodTypes: [.push])
        var pullChallengeTransaction = OktaTransactionPullChallengePartialMock(enrollment: authenticator,
                                                                               authenticationToken: AuthToken.bearer("access_token"),
                                                                               storageManager: storageMock,
                                                                               cryptoManager: cryptoManager,
                                                                               restAPI: restAPIClient,
                                                                               logger: OktaLoggerMock())
        var completionExpectation = expectation(description: "callback should be called")
        pullChallengeTransaction.pullChallenge(allowedClockSkewInSeconds: 300) { result in
            switch result {
            case .success(let pushChallenges):
                XCTAssertEqual(pullChallengeTransaction.allowedClockSkewInSeconds, 300)
                XCTAssertEqual(pushChallenges.count, 1)
            case .failure(let error):
                XCTFail("Unexpected error - \(error.errorDescription ?? "")")
            }
            completionExpectation.fulfill()
        }
        wait(for: [completionExpectation], timeout: 1)

        mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [HTTPURLResponse(url: URL(string: "tenant.okta.com")!,
                                                                                        statusCode: 200,
                                                                                        httpVersion: nil,
                                                                                        headerFields: nil)!],
                                                            dataArray: [GoldenData.pendingChallengeData_WithMultipleChallenges()])
        restAPIClient = LegacyServerAPI(client: mockHTTPClient, logger: OktaLoggerMock())
        pullChallengeTransaction = OktaTransactionPullChallengePartialMock(enrollment: authenticator,
                                                                           authenticationToken: AuthToken.bearer("access_token"),
                                                                           storageManager: storageMock,
                                                                           cryptoManager: cryptoManager,
                                                                           restAPI: restAPIClient,
                                                                           logger: OktaLoggerMock())
        completionExpectation = expectation(description: "callback should be called")
        pullChallengeTransaction.pullChallenge(allowedClockSkewInSeconds: 300) { result in
            switch result {
            case .success(let pushChallenges):
                XCTAssertEqual(pushChallenges.count, 1)
            case .failure(let error):
                XCTFail("Unexpected error - \(error.errorDescription ?? "")")
            }

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
        let restAPIClient = LegacyServerAPI(client: mockHTTPClient, logger: OktaLoggerMock())
        let links = OktaFactorMetadataPush.Links(pendingLink: nil)
        let factorData = OktaFactorMetadataPush(id: "id",
                                                proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                                userVerificationKeyTag: "userVerificationKeyTag",
                                                links: links)
        let pushFactor = OktaFactorPush(factorData: factorData,
                                        cryptoManager: cryptoManager,
                                        restAPIClient: restAPIClient,
                                        logger: OktaLoggerMock())
        let authenticator = entitiesGenerator.createAuthenticator(orgHost: "okta.okta.com",
                                                                  orgId: "testOrgId1",
                                                                  userId: "email@okta.com",
                                                                  enrolledFactors: [pushFactor])
        let pullChallengeTransaction = OktaTransactionPullChallengePartialMock(enrollment: authenticator,
                                                                               authenticationToken: AuthToken.bearer("access_token"),
                                                                               storageManager: storageMock,
                                                                               cryptoManager: cryptoManager,
                                                                               restAPI: restAPIClient,
                                                                               logger: OktaLoggerMock())
        pullChallengeTransaction.pullChallenge(allowedClockSkewInSeconds: 300) { result in
            switch result {
            case .success(_):
                XCTFail("Unexpected success result")
            case .failure(let error):
                XCTAssertEqual(error.localizedDescription, "Failed to read update push token url")
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
        let restAPIClient = LegacyServerAPI(client: mockHTTPClient, logger: OktaLoggerMock())
        let authenticator = entitiesGenerator.createAuthenticator(orgHost: "okta.okta.com",
                                                                  orgId: "testOrgId1",
                                                                  userId: "email@okta.com",
                                                                  methodTypes: [.push])
        let pullChallengeTransaction = OktaTransactionPullChallengePartialMock(enrollment: authenticator,
                                                                               authenticationToken: AuthToken.bearer("access_token"),
                                                                               storageManager: storageMock,
                                                                               cryptoManager: cryptoManager,
                                                                               restAPI: restAPIClient,
                                                                               logger: OktaLoggerMock())
        pullChallengeTransaction.pullChallenge(allowedClockSkewInSeconds: 300) { result in
            switch result {
            case .success(_):
                XCTFail("Unexpected success result")
            case .failure(let error):
                XCTAssertEqual(error.localizedDescription, "Server call has failed")
            }
        }
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
        let restAPIClient = LegacyServerAPI(client: mockHTTPClient, logger: OktaLoggerMock())
        let authenticator = entitiesGenerator.createAuthenticator(orgHost: "okta.okta.com",
                                                                  orgId: "testOrgId1",
                                                                  userId: "email@okta.com",
                                                                  methodTypes: [.push])
        let pullChallengeTransaction = OktaTransactionPullChallengePartialMock(enrollment: authenticator,
                                                                               authenticationToken: AuthToken.bearer("access_token"),
                                                                               storageManager: storageMock,
                                                                               cryptoManager: cryptoManager,
                                                                               restAPI: restAPIClient,
                                                                               logger: OktaLoggerMock())
        pullChallengeTransaction.pullChallenge(allowedClockSkewInSeconds: 300) { result in
            switch result {
            case .success(_):
                XCTFail("Unexpected success result")
            case .failure(let error):
                XCTAssertEqual(error.localizedDescription, "Failed to decode server payload")
            }
        }
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
        let restAPIClient = LegacyServerAPI(client: mockHTTPClient, logger: OktaLoggerMock())
        let authenticator = entitiesGenerator.createAuthenticator(orgHost: "okta.okta.com",
                                                                  orgId: "testOrgId1",
                                                                  userId: "email@okta.com",
                                                                  methodTypes: [.push])
        let pullChallengeTransaction = OktaTransactionPullChallengePartialMock(enrollment: authenticator,
                                                                               authenticationToken: AuthToken.bearer("access_token"),
                                                                               storageManager: storageMock,
                                                                               cryptoManager: cryptoManager,
                                                                               restAPI: restAPIClient,
                                                                               logger: OktaLoggerMock())
        pullChallengeTransaction.pullChallenge(allowedClockSkewInSeconds: 300) { result in
            switch result {
            case .success(let pushChallenges):
                XCTAssert(pushChallenges.isEmpty)
            case .failure(let error):
                XCTFail("Unexpected error - \(error.errorDescription ?? "")")
            }
        }
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
        let restAPIClient = LegacyServerAPI(client: mockHTTPClient, logger: OktaLoggerMock())
        let authenticator = entitiesGenerator.createAuthenticator(orgHost: "okta.okta.com",
                                                                  orgId: "testOrgId1",
                                                                  userId: "email@okta.com",
                                                                  methodTypes: [.push])
        let pullChallengeTransaction = OktaTransactionPullChallengePartialMock(enrollment: authenticator,
                                                                               authenticationToken: AuthToken.bearer("access_token"),
                                                                               storageManager: storageMock,
                                                                               cryptoManager: cryptoManager,
                                                                               restAPI: restAPIClient,
                                                                               logger: OktaLoggerMock())
        pullChallengeTransaction.pullChallenge(allowedClockSkewInSeconds: 300) { result in
            switch result {
            case .success(let pushChallenges):
                XCTAssert(pushChallenges.isEmpty)
            case .failure(let error):
                XCTFail("Unexpected error - \(error.errorDescription ?? "")")
            }
        }
    }
}
