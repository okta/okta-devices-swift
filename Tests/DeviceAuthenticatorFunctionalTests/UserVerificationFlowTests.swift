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

class UserVerificationFlowTests: FunctionalTestsBase {

    private let expectationTimeout: TimeInterval = 1.0
    private let authToken = AuthToken.bearer("testAuthToken")

    private var enrollmentHelper: EnrollmentTestHelper!
    private var httpResponses: [HTTPURLResponse]!
    private var dataResponses: [Data]!

    override func setUpWithError() throws {
        try super.setUpWithError()
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
                         MyAccountTestData.policyResponse(),
                         MyAccountTestData.enrollmentResponse()]
    }

    func testEnableUserVerification_Success() throws {

        let enableSuccessExpectation = expectation(description: "Enable user verification should complete")
        httpResponses.append(HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        dataResponses.append(MyAccountTestData.enrollmentResponse())
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        enrollmentHelper.enrollmentParams.enableCIBATransactions(enable: true)
        do {
            try enrollmentHelper.enroll(userVerification: false, mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(let enrollment):
                    enrollment.setUserVerification(authenticationToken: self.authToken, enable: true, completion: { error in
                        XCTAssertNil(error)
                        XCTAssertNotNil(enrollment)
                        XCTAssertTrue(enrollment.userVerificationEnabled)
                        XCTAssertTrue(enrollment.isCIBAEnabled)
                        enableSuccessExpectation.fulfill()
                    })
                case .failure(let error):
                    XCTFail("Unexpected error - \(error.errorDescription ?? "")")
                }
            }
            wait(for: [enableSuccessExpectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testDisableUserVerification_Success() throws {

        let disableSuccessExpectation = expectation(description: "Disable user verification should complete")
        httpResponses.append(HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        dataResponses.append(MyAccountTestData.enrollmentResponse())
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        do {
            try enrollmentHelper.enroll(userVerification: true, mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(let enrollment):
                    enrollment.setUserVerification(authenticationToken: self.authToken, enable: false, completion: { error in
                        XCTAssertNil(error)
                        XCTAssertNotNil(enrollment)
                        XCTAssertFalse(enrollment.userVerificationEnabled)
                        disableSuccessExpectation.fulfill()
                    })
                case .failure(let error):
                    XCTFail("Unexpected error - \(error.errorDescription ?? "")")
                }
            }
            wait(for: [disableSuccessExpectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testEnableUserVerification_ServerReturns401() throws {

        let enableServer401Expectation = expectation(description: "Enable user verification should fail")
        httpResponses.append(HTTPURLResponse(url: mockURL, statusCode: 401, httpVersion: nil, headerFields: nil)!)
        dataResponses.append(Data())
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        do {
            try enrollmentHelper.enroll(userVerification: false, mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(let enrollment):
                    enrollment.setUserVerification(authenticationToken: self.authToken, enable: true, completion: { error in
                        if case .serverAPIError(let result, _) = error {
                            XCTAssertEqual(result.response?.statusCode, 401)
                        } else {
                            XCTFail()
                        }
                        enableServer401Expectation.fulfill()
                    })
                case .failure(let error):
                    XCTFail("Unexpected error - \(error.errorDescription ?? "")")
                }
            }
            wait(for: [enableServer401Expectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testDisableUserVerification_ServerReturns401() throws {

        let disableServer401Expectation = expectation(description: "Diable user verification should fail")
        httpResponses.append(HTTPURLResponse(url: mockURL, statusCode: 401, httpVersion: nil, headerFields: nil)!)
        dataResponses.append(Data())
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        do {
            try enrollmentHelper.enroll(userVerification: true, mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(let enrollment):
                    enrollment.setUserVerification(authenticationToken: self.authToken, enable: false, completion: { error in
                        if case .serverAPIError(let result, _) = error {
                            XCTAssertEqual(result.response?.statusCode, 401)
                        } else {
                            XCTFail()
                        }
                        disableServer401Expectation.fulfill()
                    })
                case .failure(let error):
                    XCTFail("Unexpected error - \(error.errorDescription ?? "")")
                }
            }
            wait(for: [disableServer401Expectation], timeout: expectationTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
}
