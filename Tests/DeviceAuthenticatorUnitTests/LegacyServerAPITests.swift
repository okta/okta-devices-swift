/*
* Copyright (c) 2022, Okta, Inc. and/or its affiliates. All rights reserved.
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

final class LegacyServerAPITests: XCTestCase {
    var crypto: OktaCryptoManager!
    let mockURL = URL(string: "https://example.okta.com")!
    let deviceSignals = DeviceSignalsModel(platform: .iOS, osVersion: "15.0", displayName: "default")
    let metadata = try! JSONDecoder().decode([AuthenticatorMetaDataModel].self, from: GoldenData.authenticatorMetaData()).first!

    override func setUpWithError() throws {
        crypto = OktaCryptoManager(accessGroupId: ExampleAppConstants.appGroupId, logger: OktaLoggerMock())
    }

    func testDownloadAuthenticatorMetadata_Success() throws {
        let httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                       response: HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                       data: GoldenData.authenticatorMetaData())
        let httpClient = MockHTTPClient(result: httpResult)
        httpClient.requestHook = { url, httpMethod, urlParameters, data, httpHeaders, timeInterval in
            XCTAssertEqual(url.absoluteString, "https://example.okta.com/api/v1/authenticators?key=custom_app&expand=methods&oauthClientId=oidcClientId")
            XCTAssertTrue(httpMethod == .get)
            let mockURLRequest = MockURLRequest(result: httpResult, headers: httpHeaders)
            mockURLRequest.requestHeadersHook = { key, value in
                XCTAssertEqual(key, "Authorization")
                XCTAssertEqual(value, "Bearer accessToken")
            }

            return mockURLRequest
        }
        let legacyAPI = LegacyServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        var closureCalled = false
        legacyAPI.downloadAuthenticatorMetadata(orgHost: mockURL,
                                                authenticatorKey: "custom_app",
                                                oidcClientId: "oidcClientId",
                                                token: .accessToken("accessToken")) { result in
            switch result {
            case .failure(_):
                XCTFail("Unexpected failure")
            case .success(let metadata):
                XCTAssertEqual(metadata.id, "autuowpr5VjVjQPU30g3")
            }
            closureCalled = true
        }

        XCTAssertTrue(closureCalled)
    }

    func testEnrollAuthenticatorRequest_Success() throws {
        let httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                       response: HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                       data: GoldenData.authenticatorData())
        let httpClient = MockHTTPClient(result: httpResult)
        httpClient.requestHook = { url, httpMethod, urlParameters, data, httpHeaders, timeInterval in
            XCTAssertEqual(url.absoluteString, "https://atko.oktapreview.com/idp/authenticators")
            XCTAssertTrue(httpMethod == .post)
            let mockURLRequest = MockURLRequest(result: httpResult, headers: httpHeaders)
            mockURLRequest.requestHeadersHook = { key, value in
                XCTAssertEqual(key, "Authorization")
                XCTAssertEqual(value, "Bearer accessToken")
            }

            return mockURLRequest
        }
        let legacyAPI = LegacyServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        var closureCalled = false
        let signingKeys = SigningKeysModel(proofOfPossession: nil, userVerification: nil)
        let enrollingFactor = EnrollingFactor(proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                              userVerificationKeyTag: "userVerificationKeyTag",
                                              methodType: .push, apsEnvironment: .development,
                                              pushToken: "pushToken",
                                              supportUserVerification: true,
                                              isFipsCompliant: nil,
                                              keys: signingKeys,
                                              transactionTypes: .login)
        legacyAPI.enrollAuthenticatorRequest(orgHost: mockURL,
                                             metadata: metadata,
                                             deviceModel: deviceSignals,
                                             appSignals: nil,
                                             enrollingFactors: [enrollingFactor],
                                             token: .accessToken("accessToken")) { result in
            switch result {
            case .failure(_):
                XCTFail("Unexpected failure")
            case .success(let enrollmentSummary):
                XCTAssertNotNil(enrollmentSummary.factors.first(where: {$0 is OktaFactorPush}))
            }
            closureCalled = true
        }

        XCTAssertTrue(closureCalled)
    }

    func testUpdateAuthenticatorRequest_Success() throws {
        let httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                       response: HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                       data: GoldenData.authenticatorData())
        let httpClient = MockHTTPClient(result: httpResult)
        httpClient.requestHook = { url, httpMethod, urlParameters, data, httpHeaders, timeInterval in
            XCTAssertEqual(url.absoluteString, "https://example.okta.com/idp/authenticators/enrollmentId")
            XCTAssertTrue(httpMethod == .put)
            let mockURLRequest = MockURLRequest(result: httpResult, headers: httpHeaders)
            mockURLRequest.requestHeadersHook = { key, value in
                XCTAssertEqual(key, "Authorization")
                XCTAssertEqual(value, "Bearer accessToken")
            }

            return mockURLRequest
        }
        let legacyAPI = LegacyServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        var closureCalled = false
        let signingKeys = SigningKeysModel(proofOfPossession: nil, userVerification: nil)
        let enrollingFactor = EnrollingFactor(proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                              userVerificationKeyTag: "userVerificationKeyTag",
                                              methodType: .push, apsEnvironment: .development,
                                              pushToken: "pushToken",
                                              supportUserVerification: true,
                                              isFipsCompliant: nil,
                                              keys: signingKeys,
                                              transactionTypes: .login)
        legacyAPI.updateAuthenticatorRequest(orgHost: mockURL,
                                             enrollmentId: "enrollmentId",
                                             metadata: metadata,
                                             deviceModel: deviceSignals,
                                             appSignals: nil,
                                             enrollingFactors: [enrollingFactor],
                                             token: .accessToken("accessToken")) { result in
            switch result {
            case .failure(_):
                XCTFail("Unexpected failure")
            case .success(let enrollmentSummary):
                XCTAssertNotNil(enrollmentSummary.factors.first(where: {$0 is OktaFactorPush}))
            }
            closureCalled = true
        }

        XCTAssertTrue(closureCalled)
    }

    func testPendingChallenge_Success() throws {
        let httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                       response: HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                       data: GoldenData.pendingChallengeData_NoChallengeContextInBindJWT())
        let httpClient = MockHTTPClient(result: httpResult)
        httpClient.requestHook = { url, httpMethod, urlParameters, data, httpHeaders, timeInterval in
            XCTAssertEqual(url.absoluteString, "https://example.okta.com/push/pending")
            XCTAssertTrue(httpMethod == .get)
            let mockURLRequest = MockURLRequest(result: httpResult, headers: httpHeaders)
            mockURLRequest.requestHeadersHook = { key, value in
                XCTAssertEqual(key, "Authorization")
                XCTAssertEqual(value, "Bearer accessToken")
            }

            return mockURLRequest
        }
        let legacyAPI = LegacyServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        var closureCalled = false
        legacyAPI.pendingChallenge(with: URL(string: "https://example.okta.com/push/pending")!,
                                   authenticationToken: .accessToken("accessToken")) { result, error in
            XCTAssertNil(error)
            XCTAssertNotNil(result)
            closureCalled = true
        }

        XCTAssertTrue(closureCalled)
    }

    func testDelete_Success() throws {
        let httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                       response: HTTPURLResponse(url: mockURL, statusCode: 204, httpVersion: nil, headerFields: nil)!,
                                       data: nil)
        let httpClient = MockHTTPClient(result: httpResult)
        httpClient.requestHook = { url, httpMethod, urlParameters, data, httpHeaders, timeInterval in
            XCTAssertEqual(url.absoluteString, "https://example.okta.com/push/pending")
            XCTAssertTrue(httpMethod == .delete)
            let mockURLRequest = MockURLRequest(result: httpResult, headers: httpHeaders)
            mockURLRequest.requestHeadersHook = { key, value in
                XCTAssertEqual(key, "Authorization")
                XCTAssertEqual(value, "Bearer accessToken")
            }

            return mockURLRequest
        }
        let legacyAPI = LegacyServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        var closureCalled = false
        legacyAPI.deleteAuthenticatorRequest(url: URL(string: "https://example.okta.com/push/pending")!,
                                             token: .accessToken("accessToken")) { result, error in
            XCTAssertNil(error)
            XCTAssertNotNil(result)
            closureCalled = true
        }

        XCTAssertTrue(closureCalled)
    }

    func testBuildEnrollmentRequestData() {
        let httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                       response: HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                       data: GoldenData.authenticatorData())
        let httpClient = MockHTTPClient(result: httpResult)
        let legacyAPI = LegacyServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        let signingKeys = SigningKeysModel(proofOfPossession: ["key": .string("value")], userVerification: .keyValue(["key": .string("value")]))
        let enrollingFactor = EnrollingFactor(proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                              userVerificationKeyTag: "userVerificationKeyTag",
                                              methodType: AuthenticatorMethod.push,
                                              apsEnvironment: .development,
                                              pushToken: "pushToken",
                                              supportUserVerification: true,
                                              isFipsCompliant: nil,
                                              keys: signingKeys,
                                              transactionTypes: .login)
        let enrollmentData = try? legacyAPI.buildEnrollmentRequestData(metadata: metadata,
                                                                       deviceModel: deviceSignals,
                                                                       appSignals: nil,
                                                                       enrollingFactors: [enrollingFactor])
        XCTAssertNotNil(enrollmentData)
        let enrollmentRequestModel = try! JSONSerialization.jsonObject(with: enrollmentData!, options: []) as! [String: Any]
        let methods = enrollmentRequestModel["methods"] as! [[String: Any]]
        let pushMethod = methods.first!
        XCTAssertEqual(pushMethod["type"] as! String, "push")
        XCTAssertEqual(pushMethod["pushToken"] as! String, "pushToken")
        XCTAssertEqual(pushMethod["apsEnvironment"] as! String, "development")
        XCTAssertEqual(pushMethod["supportUserVerification"] as! Bool, true)
        let keys = pushMethod["keys"] as! [String: Any]
        let popKeyJWK = keys["proofOfPossession"] as! [String: Any]
        let uvKeyJWK = keys["userVerification"] as! [String: Any]
        XCTAssertEqual(popKeyJWK["key"] as! String, "value")
        XCTAssertEqual(uvKeyJWK["key"] as! String, "value")
    }

    func testDownloadAuthenticatorMetadata_Failure() throws {
        // Validate response with 401 code
        var httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                       response: HTTPURLResponse(url: mockURL, statusCode: 401, httpVersion: nil, headerFields: nil)!,
                                       data: GoldenData.authenticatorMetaData())
        var httpClient = MockHTTPClient(result: httpResult)
        var legacyAPI = LegacyServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        var closureCalled = false
        legacyAPI.downloadAuthenticatorMetadata(orgHost: mockURL,
                                                authenticatorKey: "custom_app",
                                                oidcClientId: "oidcClientId",
                                                token: .accessToken("accessToken")) { result in
            switch result {
            case .failure(let error):
                XCTAssertEqual(error.errorCode, -1)
            case .success(_):
                XCTFail("Unexpected success")
            }
            closureCalled = true
        }

        XCTAssertTrue(closureCalled)

        // Validate response with 200 code and empty data
        httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                   response: HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                   data: nil)
        httpClient = MockHTTPClient(result: httpResult)
        legacyAPI = LegacyServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        closureCalled = false
        legacyAPI.downloadAuthenticatorMetadata(orgHost: mockURL,
                                                authenticatorKey: "custom_app",
                                                oidcClientId: "oidcClientId",
                                                token: .accessToken("accessToken")) { result in
            switch result {
            case .failure(let error):
                XCTAssertEqual(error.errorCode, -6)
            case .success(_):
                XCTFail("Unexpected success")
            }
            closureCalled = true
        }

        XCTAssertTrue(closureCalled)

        // Validate response with empty methods array
        httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                   response: HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                   data: GoldenData.authenticatorDataWithEmptyMethods())
        httpClient = MockHTTPClient(result: httpResult)
        legacyAPI = LegacyServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        closureCalled = false
        legacyAPI.downloadAuthenticatorMetadata(orgHost: mockURL,
                                                authenticatorKey: "custom_app",
                                                oidcClientId: "oidcClientId",
                                                token: .accessToken("accessToken")) { result in
            switch result {
            case .failure(let error):
                XCTAssertEqual(error.errorCode, -6)
            case .success(_):
                XCTFail("Unexpected success")
            }
            closureCalled = true
        }

        XCTAssertTrue(closureCalled)
    }

    func testEnrollAuthenticatorRequest_Failure() throws {
        // Validate response with 401 code
        var httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                       response: HTTPURLResponse(url: mockURL, statusCode: 401, httpVersion: nil, headerFields: nil)!,
                                       data: GoldenData.resourceNotFoundError())
        var httpClient = MockHTTPClient(result: httpResult)
        var legacyAPI = LegacyServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        var closureCalled = false
        let signingKeys = SigningKeysModel(proofOfPossession: nil, userVerification: nil)
        let enrollingFactor = EnrollingFactor(proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                              userVerificationKeyTag: "userVerificationKeyTag",
                                              methodType: .push, apsEnvironment: .development,
                                              pushToken: "pushToken",
                                              supportUserVerification: true,
                                              isFipsCompliant: nil,
                                              keys: signingKeys,
                                              transactionTypes: .login)
        legacyAPI.enrollAuthenticatorRequest(orgHost: mockURL,
                                             metadata: metadata,
                                             deviceModel: deviceSignals,
                                             appSignals: nil,
                                             enrollingFactors: [enrollingFactor],
                                             token: .accessToken("accessToken")) { result in
            switch result {
            case .failure(let error):
                XCTAssertEqual(error.errorCode, -1)
            case .success(_):
                XCTFail("Unexpected success")
            }
            closureCalled = true
        }

        XCTAssertTrue(closureCalled)

        // Validate response with 200 code and empty data
        httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                       response: HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                       data: nil)
        httpClient = MockHTTPClient(result: httpResult)
        legacyAPI = LegacyServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        closureCalled = false
        legacyAPI.enrollAuthenticatorRequest(orgHost: mockURL,
                                             metadata: metadata,
                                             deviceModel: deviceSignals,
                                             appSignals: nil,
                                             enrollingFactors: [enrollingFactor],
                                             token: .accessToken("accessToken")) { result in
            switch result {
            case .failure(let error):
                XCTAssertEqual(error.errorCode, -6)
            case .success(_):
                XCTFail("Unexpected success")
            }
            closureCalled = true
        }

        XCTAssertTrue(closureCalled)

        // Validate response with empty enrolled factors array
        httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                   response: HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                   data: GoldenData.authenticatorDataWithEmptyMethods())
        httpClient = MockHTTPClient(result: httpResult)
        legacyAPI = LegacyServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        closureCalled = false
        legacyAPI.enrollAuthenticatorRequest(orgHost: mockURL,
                                             metadata: metadata,
                                             deviceModel: deviceSignals,
                                             appSignals: nil,
                                             enrollingFactors: [enrollingFactor],
                                             token: .accessToken("accessToken")) { result in
            switch result {
            case .failure(let error):
                XCTAssertEqual(error.errorCode, -6)
                XCTAssertEqual(error.errorDescription, "Server replied with unexpected enrollment data")
            case .success(_):
                XCTFail("Unexpected success")
            }
            closureCalled = true
        }

        XCTAssertTrue(closureCalled)
    }

    func testUpdateAuthenticatorRequest_Failure() throws {
        // Validate response with 401 code
        var httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                       response: HTTPURLResponse(url: mockURL, statusCode: 401, httpVersion: nil, headerFields: nil)!,
                                       data: GoldenData.resourceNotFoundError())
        var httpClient = MockHTTPClient(result: httpResult)
        var legacyAPI = LegacyServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        var closureCalled = false
        let signingKeys = SigningKeysModel(proofOfPossession: nil, userVerification: nil)
        let enrollingFactor = EnrollingFactor(proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                              userVerificationKeyTag: "userVerificationKeyTag",
                                              methodType: .push, apsEnvironment: .development,
                                              pushToken: "pushToken",
                                              supportUserVerification: true,
                                              isFipsCompliant: nil,
                                              keys: signingKeys,
                                              transactionTypes: .login)
        legacyAPI.updateAuthenticatorRequest(orgHost: mockURL,
                                             enrollmentId: "enrollmentId",
                                             metadata: metadata,
                                             deviceModel: deviceSignals,
                                             appSignals: nil,
                                             enrollingFactors: [enrollingFactor],
                                             token: .accessToken("accessToken")) { result in
            switch result {
            case .failure(let error):
                XCTAssertEqual(error.errorCode, -1)
            case .success(_):
                XCTFail("Unexpected success")
            }
            closureCalled = true
        }

        XCTAssertTrue(closureCalled)

        // Validate response with 200 code and empty data
        httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                       response: HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                       data: nil)
        httpClient = MockHTTPClient(result: httpResult)
        legacyAPI = LegacyServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        closureCalled = false
        legacyAPI.updateAuthenticatorRequest(orgHost: mockURL,
                                             enrollmentId: "enrollmentId",
                                             metadata: metadata,
                                             deviceModel: deviceSignals,
                                             appSignals: nil,
                                             enrollingFactors: [enrollingFactor],
                                             token: .accessToken("accessToken")) { result in
            switch result {
            case .failure(let error):
                XCTAssertEqual(error.errorCode, -6)
            case .success(_):
                XCTFail("Unexpected success")
            }
            closureCalled = true
        }

        XCTAssertTrue(closureCalled)

        // Validate response with unexpected data
        httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                       response: HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                       data: GoldenData.authenticatorDataWithEmptyMethods())
        httpClient = MockHTTPClient(result: httpResult)
        legacyAPI = LegacyServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        closureCalled = false
        legacyAPI.updateAuthenticatorRequest(orgHost: mockURL,
                                             enrollmentId: "enrollmentId",
                                             metadata: metadata,
                                             deviceModel: deviceSignals,
                                             appSignals: nil,
                                             enrollingFactors: [enrollingFactor],
                                             token: .accessToken("accessToken")) { result in
            switch result {
            case .failure(let error):
                XCTAssertEqual(error.errorCode, -6)
                XCTAssertEqual(error.errorDescription, "Server replied with unexpected enrollment data")
            case .success(_):
                XCTFail("Unexpected success")
            }
            closureCalled = true
        }

        XCTAssertTrue(closureCalled)
    }

    func testPendingChallenge_Failure() throws {
        let httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                       response: HTTPURLResponse(url: mockURL, statusCode: 401, httpVersion: nil, headerFields: nil)!,
                                       data: GoldenData.authenticatorMetaData())
        let httpClient = MockHTTPClient(result: httpResult)
        httpClient.requestHook = { url, httpMethod, urlParameters, data, httpHeaders, timeInterval in
            XCTAssertEqual(url.absoluteString, "https://example.okta.com/push/pending")
            XCTAssertTrue(httpMethod == .get)
            let mockURLRequest = MockURLRequest(result: httpResult, headers: httpHeaders)
            mockURLRequest.requestHeadersHook = { key, value in
                XCTAssertEqual(key, "Authorization")
                XCTAssertEqual(value, "Bearer accessToken")
            }

            return mockURLRequest
        }
        let legacyAPI = LegacyServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        var closureCalled = false
        legacyAPI.pendingChallenge(with: URL(string: "https://example.okta.com/push/pending")!,
                                   authenticationToken: .accessToken("accessToken")) { result, error in
            XCTAssertNotNil(error)
            XCTAssertEqual(error?.errorCode, -1)
            XCTAssertNotNil(result)
            closureCalled = true
        }

        XCTAssertTrue(closureCalled)
    }

    func testDelete_Failure() throws {
        let httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                       response: HTTPURLResponse(url: mockURL, statusCode: 404, httpVersion: nil, headerFields: nil)!,
                                       data: GoldenData.authenticatorMetaData())
        let httpClient = MockHTTPClient(result: httpResult)
        httpClient.requestHook = { url, httpMethod, urlParameters, data, httpHeaders, timeInterval in
            XCTAssertEqual(url.absoluteString, "https://example.okta.com/push/pending")
            XCTAssertTrue(httpMethod == .delete)
            let mockURLRequest = MockURLRequest(result: httpResult, headers: httpHeaders)
            mockURLRequest.requestHeadersHook = { key, value in
                XCTAssertEqual(key, "Authorization")
                XCTAssertEqual(value, "Bearer accessToken")
            }

            return mockURLRequest
        }
        let legacyAPI = LegacyServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        var closureCalled = false
        legacyAPI.deleteAuthenticatorRequest(url: URL(string: "https://example.okta.com/push/pending")!,
                                             token: .accessToken("accessToken")) { result, error in
            XCTAssertNotNil(error)
            XCTAssertEqual(error?.errorCode, -1)
            XCTAssertNotNil(result)
            closureCalled = true
        }

        XCTAssertTrue(closureCalled)
    }
}
