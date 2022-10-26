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

final class MyAccountServerAPITests: XCTestCase {
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
                                       data: MyAccountTestData.policyResponse())
        let httpClient = MockHTTPClient(result: httpResult)
        var numberOfHTTPHeaders = 0
        httpClient.requestHook = { url, httpMethod, urlParameters, data, httpHeaders, timeInterval in
            XCTAssertEqual(url.absoluteString, "https://example.okta.com/.well-known/app-authenticator-configuration?oauthClientId=oidcClientId")
            XCTAssertTrue(httpMethod == .get)
            let mockURLRequest = MockURLRequest(result: httpResult, headers: httpHeaders)
            mockURLRequest.requestHeadersHook = { key, value in
                if key == "Authorization" {
                    XCTAssertEqual(value, "Bearer accessToken")
                    numberOfHTTPHeaders += 1
                } else if key == "Accept" {
                    XCTAssertEqual(value, "application/json; okta-version=1.0.0")
                    numberOfHTTPHeaders += 1
                }
            }
            
            return mockURLRequest
        }
        let myAccountAPI = MyAccountServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        var closureCalled = false
        myAccountAPI.downloadAuthenticatorMetadata(orgHost: mockURL,
                                                   authenticatorKey: "custom_app",
                                                   oidcClientId: "oidcClientId",
                                                   token: .accessToken("accessToken")) { result in
            switch result {
            case .failure(_):
                XCTFail("Unexpected failure")
            case .success(let metadata):
                XCTAssertEqual(metadata.id, "aut6nfu6soyk3GD2U0g4")
                XCTAssertEqual(metadata._embedded.methods[0].settings?.transactionTypes?.count, 2)
                XCTAssertEqual(metadata._links.enroll?.href, "https://your-org.okta.com/idp/myaccount/app-authenticator")
            }
            closureCalled = true
        }
        
        XCTAssertTrue(closureCalled)
        XCTAssertEqual(numberOfHTTPHeaders, 2)
    }

    func testDownloadAuthenticatorMetadata_Failure() throws {
        // Validate response with 401 code
        var httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                       response: HTTPURLResponse(url: mockURL, statusCode: 401, httpVersion: nil, headerFields: nil)!,
                                       data: MyAccountTestData.policyResponse())
        var httpClient = MockHTTPClient(result: httpResult)
        var myAccountAPI = MyAccountServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        var closureCalled = false
        myAccountAPI.downloadAuthenticatorMetadata(orgHost: mockURL,
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
        myAccountAPI = MyAccountServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        closureCalled = false
        myAccountAPI.downloadAuthenticatorMetadata(orgHost: mockURL,
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

        // Validate response with unexpected data
        httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                   response: HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                   data: GoldenData.authenticatorDataWithEmptyMethods())
        httpClient = MockHTTPClient(result: httpResult)
        myAccountAPI = MyAccountServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        closureCalled = false
        myAccountAPI.downloadAuthenticatorMetadata(orgHost: mockURL,
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

    func testUpdateAuthenticatorRequest_Success() throws {
        let httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                       response: HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                                       data: MyAccountTestData.enrollmentResponse())
        let httpClient = MockHTTPClient(result: httpResult)
        var numberOfHTTPHeaders = 0
        httpClient.requestHook = { url, httpMethod, urlParameters, data, httpHeaders, timeInterval in
            XCTAssertEqual(url.absoluteString, (self.metadata._links.enroll?.href ?? "") + "/enrollmentId")
            XCTAssertTrue(httpMethod == .patch)
            //let decodedRequest: MethodUpdateRequestModel? = try? JSONDecoder().decode(MethodUpdateRequestModel.self, from: data!)
            let decodedRequest = try? JSONSerialization.jsonObject(with: data!, options: []) as? [String: Any]
            let decodedMehtods = decodedRequest?["methods"] as? [String: Any]
            let decodedPushMethod = decodedMehtods?["push"] as? [String: Any]
            let decodedKeys = decodedPushMethod?["keys"] as? [String: Any]
            let decodedCapabilites = decodedPushMethod?["capabilities"] as? [String: Any]
            let decodedTransactionTypes = decodedCapabilites?["transactionTypes"] as? [String]
            XCTAssertEqual(decodedPushMethod?["pushToken"] as! String, "pushToken")
            XCTAssertNotNil(decodedTransactionTypes?.contains("LOGIN"))
            XCTAssertNotNil(decodedTransactionTypes?.contains("CIBA"))
            XCTAssertNotNil(decodedKeys?["userVerification"])
            XCTAssertNil(decodedKeys?["proofOfPossession"])
            let mockURLRequest = MockURLRequest(result: httpResult, headers: httpHeaders)
            mockURLRequest.requestHeadersHook = { key, value in
                if key == "Authorization" {
                    XCTAssertEqual(value, "Bearer accessToken")
                    numberOfHTTPHeaders += 1
                } else if key == "Accept" {
                    XCTAssertEqual(value, "application/merge-patch+json; okta-version=1.0.0")
                    numberOfHTTPHeaders += 1
                }
            }

            return mockURLRequest
        }
        let myAccountAPI = MyAccountServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        var closureCalled = false
        let signingKeys = SigningKeysModel(proofOfPossession: nil, userVerification: SigningKeysModel.UserVerificationKey.null)
        let enrollingFactor = EnrollingFactor(proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                              userVerificationKeyTag: "userVerificationKeyTag",
                                              methodType: .push, apsEnvironment: .development,
                                              pushToken: "pushToken",
                                              supportUserVerification: true,
                                              isFipsCompliant: nil,
                                              keys: signingKeys,
                                              transactionTypes: TransactionType(rawValue: 3))
        myAccountAPI.updateAuthenticatorRequest(orgHost: mockURL,
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

    func testUpdateAuthenticatorRequest_Failure() throws {
        // Validate response with 401 code
        var httpResult = HTTPURLResult(request: URLRequest(url: mockURL),
                                       response: HTTPURLResponse(url: mockURL, statusCode: 401, httpVersion: nil, headerFields: nil)!,
                                       data: GoldenData.resourceNotFoundError())
        var httpClient = MockHTTPClient(result: httpResult)
        var myAccountAPI = MyAccountServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
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
        myAccountAPI.updateAuthenticatorRequest(orgHost: mockURL,
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
        myAccountAPI = MyAccountServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        closureCalled = false
        myAccountAPI.updateAuthenticatorRequest(orgHost: mockURL,
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
                                       data: MyAccountTestData.authenticatorDataNoMethods())
        httpClient = MockHTTPClient(result: httpResult)
        myAccountAPI = MyAccountServerAPI(client: httpClient, crypto: crypto, logger: OktaLoggerMock())
        closureCalled = false
        myAccountAPI.updateAuthenticatorRequest(orgHost: mockURL,
                                                enrollmentId: "enrollmentId",
                                                metadata: metadata,
                                                deviceModel: deviceSignals,
                                                appSignals: nil,
                                                enrollingFactors: [enrollingFactor],
                                                token: .accessToken("accessToken")) { result in
            switch result {
            case .failure(let error):
                XCTAssertEqual(error.errorCode, -6)
                XCTAssertEqual(error.errorDescription, "The data couldn’t be read because it is missing.")
            case .success(_):
                XCTFail("Unexpected success")
            }
            closureCalled = true
        }

        XCTAssertTrue(closureCalled)
    }
}
