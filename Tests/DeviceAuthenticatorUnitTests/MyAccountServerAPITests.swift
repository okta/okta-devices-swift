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
}
