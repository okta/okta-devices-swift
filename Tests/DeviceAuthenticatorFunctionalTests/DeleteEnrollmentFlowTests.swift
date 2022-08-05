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
// swiftlint:disable force_unwrapping
import XCTest
@testable import DeviceAuthenticator

class DeleteEnrollmentFlowTests: XCTestCase {

    private let expectaionTimeout: TimeInterval = 1.0
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

    func testDeleteEnrollment_Success() throws {

        let deleteSuccessExpectation = expectation(description: "Delete enrollment should be complete")
        httpResponses.append(HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        dataResponses.append(Data())
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        do {
            try enrollmentHelper.enroll(userVerification: false, mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(let enrollment):
                    self.enrollmentHelper.deviceAuthenticator.delete(enrollment: enrollment,
                                                                     authenticationToken: self.authToken) { error in
                        XCTAssertNil(error)
                        deleteSuccessExpectation.fulfill()
                    }
                case .failure(let error):
                    XCTFail("Unexpected error - \(error.errorDescription ?? "")")
                }
            }
            wait(for: [deleteSuccessExpectation], timeout: expectaionTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testDeleteEnrollment_ServerReturns401() throws {

        let deleteServer401Expectation = expectation(description: "Delete enrollment should fail")
        httpResponses.append(HTTPURLResponse(url: mockURL, statusCode: 401, httpVersion: nil, headerFields: nil)!)
        dataResponses.append(Data())
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        do {
            try enrollmentHelper.enroll(userVerification: false, mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(let enrollment):
                    self.enrollmentHelper.deviceAuthenticator.delete(enrollment: enrollment,
                                                                     authenticationToken: self.authToken) { error in
                        if case .serverAPIError(let result, _) = error {
                            XCTAssertEqual(result.response?.statusCode, 401)
                        } else {
                            XCTFail()
                        }
                        deleteServer401Expectation.fulfill()
                    }
                case .failure(let error):
                    XCTFail("Unexpected error - \(error.errorDescription ?? "")")
                }
            }
            wait(for: [deleteServer401Expectation], timeout: expectaionTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testDeleteEnrollmentLocally_Success() throws {

        let deleteLocallySuccessExpectation = expectation(description: "Delete enrollment from device should be completed")
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        do {
            try enrollmentHelper.enroll(userVerification: false, mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(let enrollment):
                    do {
                        try enrollment.deleteFromDevice()
                    } catch {
                        XCTFail(error.localizedDescription)
                    }
                case .failure(let error):
                    XCTFail("Unexpected error - \(error.errorDescription ?? "")")
                }
                deleteLocallySuccessExpectation.fulfill()
            }
            wait(for: [deleteLocallySuccessExpectation], timeout: expectaionTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testDeleteEnrollmentLocally_Fail() throws {

        let deleteLocallyFailExpectation = expectation(description: "Delete enrollment from device should completed")
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray: dataResponses)
        do {
            try enrollmentHelper.enroll(userVerification: false, mockHTTPClient: mockHTTPClient) { result in
                switch result {
                case .success(let enrollment):
                    do {
                        EnrollmentTestHelper.removeDBFiles()
                        XCTAssertNoThrow { try enrollment.deleteFromDevice() }
                    }
                case .failure(let error):
                    XCTFail("Unexpected error - \(error.errorDescription ?? "")")
                }
                deleteLocallyFailExpectation.fulfill()
            }
            wait(for: [deleteLocallyFailExpectation], timeout: expectaionTimeout)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
}
