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

class UpdatePushTokenFlowTests: XCTestCase {

    private let expectationTimeout: TimeInterval = 1.0

    private let mockURL = URL(string: "https://example.okta.com")!
    private let authToken = AuthToken.bearer("testAuthToken")

    private var enrollmentHelper: EnrollmentTestHelper!
    private var httpResponses: [HTTPURLResponse]!
    private var dataResponses: [Data]!

    override func setUpWithError() throws {
        enrollmentHelper = EnrollmentTestHelper(applicationName: "FuncTests",
                                                applicationVersion: "1.0.0",
                                                applicationGroupId: ExampleAppConstants.appGroupId,
                                                orgHost: "someorg.okta.com",
                                                clientId: "oidcClientId",
                                                deviceToken: "abcde12345",
                                                authToken: authToken)

        httpResponses = [HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                         HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                         HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!]
        dataResponses = [GoldenData.orgData(),
                         GoldenData.authenticatorMetaData(),
                         GoldenData.authenticatorData()]
    }
    
    override func tearDownWithError() throws {
        enrollmentHelper = nil
        httpResponses = nil
        dataResponses = nil
    }

    func testUpdatePushTokenFlow_Success() throws {

        let updateTokenSuccessExpectation = expectation(description: "Update push token should complete")
        httpResponses.append(HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        dataResponses.append(GoldenData.authenticatorData())
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        do {
            try enrollmentHelper.enroll(mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(let enrollment):
                    let newDeviceTokenData = "12345abcde".data(using: .utf8)!
                    enrollment.updateDeviceToken(newDeviceTokenData, authenticationToken: self.authToken) { error in
                        XCTAssertNil(error)
                        updateTokenSuccessExpectation.fulfill()
                    }
                case .failure(let error):
                    XCTFail("Unexpected error - \(error.errorDescription ?? "")")
                }
            }
            wait(for: [updateTokenSuccessExpectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func testUpdatePushTokenFlow_ServerReturns401() throws {

        let updateTokenServer401Expectation = expectation(description: "Update push token should failed")
        httpResponses.append(HTTPURLResponse(url: mockURL, statusCode: 401, httpVersion: nil, headerFields: nil)!)
        dataResponses.append(Data())
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        do {
            try enrollmentHelper.enroll(mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(let enrollment):
                    let newDeviceTokenData = "12345abcde".data(using: .utf8)!
                    enrollment.updateDeviceToken(newDeviceTokenData, authenticationToken: self.authToken) { error in
                        if case .serverAPIError(let result, _) = error {
                            XCTAssertEqual(result.response?.statusCode, 401)
                        } else {
                            XCTFail()
                        }
                        updateTokenServer401Expectation.fulfill()
                    }
                case .failure(let error):
                    XCTFail("Unexpected error - \(error.errorDescription ?? "")")
                }
            }
            wait(for: [updateTokenServer401Expectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
}