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

class EnrollmentFlowTests: FunctionalTestsBase {

    private var httpResponses: [HTTPURLResponse]!

    override func setUpWithError() throws {
        try super.setUpWithError()
        httpResponses = [HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                         HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                         HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!]

    }

    func testEnrollFlow_WithExpectedResponses_ReturnsEnrolledAuthenticator() {

        let enrollmentExpectation = expectation(description: "Enrollment should complete")

        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses,
                                                            dataArray: [GoldenData.orgData(),
                                                                        MyAccountTestData.policyResponse(),
                                                                        MyAccountTestData.enrollmentResponse()])
        let oktaRestAPI = MyAccountServerAPI(client: mockHTTPClient,
                                             crypto: OktaCryptoManager(keychainGroupId: ExampleAppConstants.appGroupId,
                                                                       logger: OktaLoggerMock()),
                                             logger: OktaLoggerMock())

        let deviceAuthenticator: DeviceAuthenticatorProtocol
        do {
            deviceAuthenticator = try DeviceAuthenticatorBuilder(applicationConfig: appConfig).create()
            (deviceAuthenticator as? DeviceAuthenticator)?.impl.restAPI = oktaRestAPI

            deviceAuthenticator.enroll(authenticationToken: AuthToken.bearer("cdeb3858fabc"), authenticatorConfig: deviceAuthenticatorConfig, enrollmentParameters: enrollmentParams) { result in
                switch result {
                case .success(let authenticator):
                    XCTAssertEqual("aen1jisLwwTG7qRrH0g4", authenticator.enrollmentId)
                    XCTAssertEqual("00otiyyDFtNCyFbnC0g4", authenticator.organization.id)
                    XCTAssertEqual("00utmecoNjNd0lrWp0g4", authenticator.user.id)
                    XCTAssertEqual("test@okta.com", authenticator.user.name)
                    XCTAssertFalse(authenticator.userVerificationEnabled)
                    XCTAssertFalse(deviceAuthenticator.allEnrollments().isEmpty)
                case .failure(_):
                    XCTFail("Error enrolling authenticator")
                }
                enrollmentExpectation.fulfill()
            }
            wait(for: [enrollmentExpectation], timeout: 3.0)
        } catch {
            XCTFail("Should init Authenticator")
        }
    }

    func testMultipleEnrollmentsOnTheSameOrg() throws {

        let deviceAuthenticator = try DeviceAuthenticatorBuilder(applicationConfig: appConfig).create()
        XCTAssertTrue(deviceAuthenticator.allEnrollments().isEmpty)

        var enrollmentExpectation = expectation(description: "Enrollment should complete")

        var mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses,
                                                            dataArray: [GoldenData.orgData(),
                                                                        MyAccountTestData.policyResponse(),
                                                                        MyAccountTestData.enrollmentResponse()])
        mockHTTPClient.requestWithDataBodyHook = { url, method, urlParameters, httpBody, header, timeout in
            mockHTTPClient.requestWithDataBodyHook = nil
            guard let httpBody = httpBody,
                  let requestModel = try? JSONDecoder().decode(MyAccountAPI.AuthenticatorRequestModel.self, from: httpBody) else {
                XCTFail("Missing or invalid body in http query")
                return mockHTTPClient.request(url, method: method, urlParameters: urlParameters, httpBody: httpBody, timeout: timeout)
            }
            XCTAssertTrue(url.absoluteString.contains("idp/myaccount/app-authenticator"))
            XCTAssertEqual(method, .post)
            XCTAssertNotNil(requestModel.device)
            XCTAssertNil(requestModel.device?.id)
            XCTAssertNotNil(requestModel.device?.authenticatorAppKey)
            
            return mockHTTPClient.request(url, method: method, urlParameters: urlParameters, httpBody: httpBody, timeout: timeout)
        }

        var oktaRestAPI = MyAccountServerAPI(client: mockHTTPClient,
                                             crypto: OktaCryptoManager(keychainGroupId: ExampleAppConstants.appGroupId,
                                                                       logger: OktaLoggerMock()),
                                             logger: OktaLoggerMock())

        (deviceAuthenticator as? DeviceAuthenticator)?.impl.restAPI = oktaRestAPI

        deviceAuthenticator.enroll(authenticationToken: AuthToken.bearer("cdeb3858fabc"), authenticatorConfig: deviceAuthenticatorConfig, enrollmentParameters: enrollmentParams) { result in
            switch result {
            case .success(let authenticator):
                XCTAssertEqual("aen1jisLwwTG7qRrH0g4", authenticator.enrollmentId)
                XCTAssertEqual("00otiyyDFtNCyFbnC0g4", authenticator.organization.id)
                XCTAssertEqual("00utmecoNjNd0lrWp0g4", authenticator.user.id)
                XCTAssertEqual("test@okta.com", authenticator.user.name)
                XCTAssertFalse(authenticator.userVerificationEnabled)
                XCTAssertFalse(deviceAuthenticator.allEnrollments().isEmpty)
            case .failure(_):
                XCTFail("Error enrolling authenticator")
            }
            enrollmentExpectation.fulfill()
        }
        wait(for: [enrollmentExpectation], timeout: 3.0)

        var responseData = MyAccountTestData.enrollmentResponse()
        var responseJSON = try JSONSerialization.jsonObject(with: responseData) as! [String: Any]
        responseJSON["id"] = "authenticator2"
        responseData = try JSONSerialization.data(withJSONObject: responseJSON)
        mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses,
                                                            dataArray: [GoldenData.orgData(),
                                                                        MyAccountTestData.policyResponse(),
                                                                        responseData])
        mockHTTPClient.requestWithDataBodyHook = { url, method, urlParameters, httpBody, header, timeout in
            mockHTTPClient.requestWithDataBodyHook = nil
            guard let httpBody = httpBody,
                  let requestModel = try? JSONDecoder().decode(MyAccountAPI.AuthenticatorRequestModel.self, from: httpBody) else {
                XCTFail("Missing or invalid body in http query")
                return mockHTTPClient.request(url, method: method, urlParameters: urlParameters, httpBody: httpBody, timeout: timeout)
            }
            XCTAssertTrue(url.absoluteString.contains("idp/myaccount/app-authenticator"))
            XCTAssertEqual(method, .post)
            XCTAssertNotNil(requestModel.device?.id)
            let deviceDictionary =  responseJSON["device"] as! [String: Any]
            XCTAssertEqual(requestModel.device?.id, deviceDictionary["id"] as? String)
            XCTAssertNotNil(requestModel.device?.authenticatorAppKey)

            return mockHTTPClient.request(url, method: method, urlParameters: urlParameters, httpBody: httpBody, timeout: timeout)
        }
        oktaRestAPI = MyAccountServerAPI(client: mockHTTPClient,
                                             crypto: OktaCryptoManager(keychainGroupId: ExampleAppConstants.appGroupId,
                                                                       logger: OktaLoggerMock()),
                                             logger: OktaLoggerMock())
        (deviceAuthenticator as? DeviceAuthenticator)?.impl.restAPI = oktaRestAPI
        
        enrollmentExpectation = expectation(description: "Enrollment should complete")
        deviceAuthenticator.enroll(authenticationToken: AuthToken.bearer("cdeb3858fabc"), authenticatorConfig: deviceAuthenticatorConfig, enrollmentParameters: enrollmentParams) { result in
            switch result {
            case .success(let authenticator):
                XCTAssertEqual(responseJSON["id"] as! String, authenticator.enrollmentId)
                XCTAssertEqual("00otiyyDFtNCyFbnC0g4", authenticator.organization.id)
                XCTAssertEqual("00utmecoNjNd0lrWp0g4", authenticator.user.id)
                XCTAssertEqual("test@okta.com", authenticator.user.name)
                XCTAssertFalse(authenticator.userVerificationEnabled)
                XCTAssertFalse(deviceAuthenticator.allEnrollments().isEmpty)
            case .failure(_):
                XCTFail("Error enrolling authenticator")
            }
            enrollmentExpectation.fulfill()
        }
        wait(for: [enrollmentExpectation], timeout: 3.0)

        let enrollmentsCount = deviceAuthenticator.allEnrollments().count
        XCTAssertEqual(enrollmentsCount, 2)
        let devicesCount = try (deviceAuthenticator as? DeviceAuthenticator)?.impl.storageManager.allDeviceEnrollmentsOrgIds().count
        XCTAssertEqual(devicesCount, 1)
    }

    func testEnrollFlow_WithIncompleteOrgData_ReturnsNilAuthenticator() {

        let enrollmentExpectation = expectation(description: "Enrollment should complete")

        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses,
                                                            dataArray: [GoldenData.orgDataIncomplete(),
                                                                        MyAccountTestData.policyResponse(),
                                                                        MyAccountTestData.enrollmentResponse()])
        let oktaRestAPI = MyAccountServerAPI(client: mockHTTPClient,
                                             crypto: OktaCryptoManager(keychainGroupId: ExampleAppConstants.appGroupId,
                                                                       logger: OktaLoggerMock()),
                                             logger: OktaLoggerMock())

        let deviceAuthenticator: DeviceAuthenticatorProtocol
        do {
            deviceAuthenticator = try DeviceAuthenticatorBuilder(applicationConfig: appConfig).create()
            (deviceAuthenticator as? DeviceAuthenticator)?.impl.restAPI = oktaRestAPI

            deviceAuthenticator.enroll(authenticationToken: AuthToken.bearer("cdeb3858fabc"), authenticatorConfig: deviceAuthenticatorConfig, enrollmentParameters: enrollmentParams) { result in
                switch result {
                case .success(_):
                    XCTFail("Unexpected result")
                case .failure(let error):
                    XCTAssertEqual("Failed to fetch organization data", error.localizedDescription)
                }
                enrollmentExpectation.fulfill()
            }
            wait(for: [enrollmentExpectation], timeout: 3.0)
        } catch {
            XCTFail("Should init Authenticator")
        }
    }

    func testEnrollFlow_WithInactiveMetadata_ReturnsNilAuthenticator() {

        let enrollmentExpectation = expectation(description: "Enrollment should complete")

        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray:
                                                                [GoldenData.orgData(),
                                                                 MyAccountTestData.emptyPolicyArrayResponse(),
                                                                 MyAccountTestData.enrollmentResponse()])
        let oktaRestAPI = MyAccountServerAPI(client: mockHTTPClient,
                                             crypto: OktaCryptoManager(keychainGroupId: ExampleAppConstants.appGroupId,
                                                                       logger: OktaLoggerMock()),
                                             logger: OktaLoggerMock())

        let deviceAuthenticator: DeviceAuthenticatorProtocol
        do {
            deviceAuthenticator = try DeviceAuthenticatorBuilder(applicationConfig: appConfig).create()
            (deviceAuthenticator as? DeviceAuthenticator)?.impl.restAPI = oktaRestAPI

            deviceAuthenticator.enroll(authenticationToken: AuthToken.bearer("cdeb3858fabc"), authenticatorConfig: deviceAuthenticatorConfig, enrollmentParameters: enrollmentParams) { result in
                switch result {
                case .success(_):
                    XCTFail("Unexpected result")
                case .failure(let error):
                    XCTAssertEqual("Authenticator policy not found", error.localizedDescription)
                }
                enrollmentExpectation.fulfill()
            }
            wait(for: [enrollmentExpectation], timeout: 3.0)
        } catch {
            XCTFail("Should init Authenticator")
        }

    }
}
