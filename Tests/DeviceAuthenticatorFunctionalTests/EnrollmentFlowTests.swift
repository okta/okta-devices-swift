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
        let devicesCount = try (deviceAuthenticator as? DeviceAuthenticator)?.impl.storageManager!.allDeviceEnrollmentsOrgIds().count
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

    func testEnrollmentWithKnownDevice_ValidateRetryOnInvalidToken() throws {

        let deviceAuthenticator = try DeviceAuthenticatorBuilder(applicationConfig: appConfig).create()
        XCTAssertTrue(deviceAuthenticator.allEnrollments().isEmpty)

        let enrollmentExpectation = expectation(description: "Enrollment should complete")

        httpResponses = [HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                         HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                         HTTPURLResponse(url: mockURL, statusCode: 401, httpVersion: nil, headerFields: nil)!]
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses,
                                                            dataArray: [GoldenData.orgData(),
                                                                        MyAccountTestData.policyResponse(),
                                                                        GoldenData.invalidTokenError()])

        var numberOfEnrollRequests = 0
        mockHTTPClient.requestWithDataBodyHook = { url, method, urlParameters, httpBody, header, timeout in
            mockHTTPClient.requestWithDataBodyHook = nil
            numberOfEnrollRequests = numberOfEnrollRequests + 1
            guard let httpBody = httpBody,
                  let requestModel = try? JSONDecoder().decode(MyAccountAPI.AuthenticatorRequestModel.self, from: httpBody) else {
                XCTFail("Missing or invalid body in http query")
                return mockHTTPClient.request(url, method: method, urlParameters: urlParameters, httpBody: httpBody, timeout: timeout)
            }
            XCTAssertTrue(url.absoluteString.contains("idp/myaccount/app-authenticator"))
            XCTAssertEqual(method, .post)
            XCTAssertNotNil(requestModel.device)
            XCTAssertNotNil(requestModel.device?.id)
            XCTAssertNotNil(requestModel.device?.clientInstanceId)
            XCTAssertNotNil(requestModel.device?.deviceAttestation)
            XCTAssertNil(requestModel.device?.clientInstanceKey)
            XCTAssertNotNil(requestModel.device?.authenticatorAppKey)

            let requestToReturn = mockHTTPClient.request(url, method: method, urlParameters: urlParameters, httpBody: httpBody, timeout: timeout)
            if numberOfEnrollRequests == 1 {
                mockHTTPClient.requestWithDataBodyHook = { url, method, urlParameters, httpBody, header, timeout in
                    mockHTTPClient.requestWithDataBodyHook = nil
                    numberOfEnrollRequests = numberOfEnrollRequests + 1
                    guard let httpBody = httpBody,
                          let requestModel = try? JSONDecoder().decode(MyAccountAPI.AuthenticatorRequestModel.self, from: httpBody) else {
                        XCTFail("Missing or invalid body in http query")
                        return mockHTTPClient.request(url, method: method, urlParameters: urlParameters, httpBody: httpBody, timeout: timeout)
                    }
                    XCTAssertTrue(url.absoluteString.contains("idp/myaccount/app-authenticator"))
                    XCTAssertEqual(method, .post)
                    XCTAssertNotNil(requestModel.device)
                    XCTAssertNil(requestModel.device?.id)
                    XCTAssertNil(requestModel.device?.clientInstanceId)
                    XCTAssertNil(requestModel.device?.deviceAttestation)
                    XCTAssertNotNil(requestModel.device?.clientInstanceKey)
                    XCTAssertNotNil(requestModel.device?.authenticatorAppKey)

                    return mockHTTPClient.request(url, method: method, urlParameters: urlParameters, httpBody: httpBody, timeout: timeout)
                }
                mockHTTPClient.counter = mockHTTPClient.counter - 1
                mockHTTPClient.resultArray?.removeLast()
                mockHTTPClient.resultArray?.append(HTTPURLResult(
                    request: URLRequest(url: URL(string: "com.okta.example")!),
                    response: HTTPURLResponse(url: self.mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                    data: MyAccountTestData.enrollmentResponse()))
            }

            return requestToReturn
        }

        let oktaRestAPI = MyAccountServerAPI(client: mockHTTPClient,
                                             crypto: OktaCryptoManager(keychainGroupId: ExampleAppConstants.appGroupId,
                                                                       logger: OktaLoggerMock()),
                                             logger: OktaLoggerMock())

        (deviceAuthenticator as? DeviceAuthenticator)?.impl.restAPI = oktaRestAPI
        let deviceEnrollment = OktaDeviceEnrollment(id: "id",
                                                    orgId: "00otiyyDFtNCyFbnC0g4",
                                                    clientInstanceId: "clientInstanceId",
                                                    clientInstanceKeyTag: "clientInstanceKeyTag")
        XCTAssertNoThrow(try (deviceAuthenticator as? DeviceAuthenticator)?.impl.storageManager!.storeDeviceEnrollment(deviceEnrollment, for: "00otiyyDFtNCyFbnC0g4"))
        let oldDeviceEnrollment = try? (deviceAuthenticator as? DeviceAuthenticator)?.impl.storageManager!.deviceEnrollmentByOrgId("00otiyyDFtNCyFbnC0g4")
        XCTAssertNotNil(oldDeviceEnrollment)
        XCTAssertNotNil(oldDeviceEnrollment?.clientInstanceKeyTag)
        _ = try (deviceAuthenticator as? DeviceAuthenticator)?.impl.cryptoManager.generate(keyPairWith: .ES256,
                                                                                           with: oldDeviceEnrollment?.clientInstanceKeyTag ?? "",
                                                                                           useSecureEnclave: false,
                                                                                           useBiometrics: false,
                                                                                           isAccessibleOnOtherDevice: false,
                                                                                           biometricSettings: nil)

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

        let newDeviceEnrollment = try? (deviceAuthenticator as? DeviceAuthenticator)?.impl.storageManager!.deviceEnrollmentByOrgId("00otiyyDFtNCyFbnC0g4")
        XCTAssertNotNil(newDeviceEnrollment)
        XCTAssertNotNil(newDeviceEnrollment?.clientInstanceKeyTag)
        XCTAssertNotEqual(newDeviceEnrollment?.clientInstanceKeyTag, oldDeviceEnrollment?.clientInstanceKeyTag)
        XCTAssertNotEqual(newDeviceEnrollment?.clientInstanceId, oldDeviceEnrollment?.clientInstanceId)
        XCTAssertNotEqual(newDeviceEnrollment?.id, oldDeviceEnrollment?.id)
        XCTAssertEqual(numberOfEnrollRequests, 2)
        _ = (deviceAuthenticator as? DeviceAuthenticator)?.impl.cryptoManager.delete(keyPairWith: oldDeviceEnrollment?.clientInstanceKeyTag ?? "")
    }

    func testEnrollmentWithKnownDevice_ValidateRetryOnDeletedDevice() throws {

        let deviceAuthenticator = try DeviceAuthenticatorBuilder(applicationConfig: appConfig).create()
        XCTAssertTrue(deviceAuthenticator.allEnrollments().isEmpty)

        let enrollmentExpectation = expectation(description: "Enrollment should complete")

        httpResponses = [HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                         HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                         HTTPURLResponse(url: mockURL, statusCode: 401, httpVersion: nil, headerFields: nil)!]
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses,
                                                            dataArray: [GoldenData.orgData(),
                                                                        MyAccountTestData.policyResponse(),
                                                                        GoldenData.deletedDeviceError()])

        var numberOfEnrollRequests = 0
        mockHTTPClient.requestWithDataBodyHook = { url, method, urlParameters, httpBody, header, timeout in
            mockHTTPClient.requestWithDataBodyHook = nil
            numberOfEnrollRequests = numberOfEnrollRequests + 1
            guard let httpBody = httpBody,
                  let requestModel = try? JSONDecoder().decode(MyAccountAPI.AuthenticatorRequestModel.self, from: httpBody) else {
                XCTFail("Missing or invalid body in http query")
                return mockHTTPClient.request(url, method: method, urlParameters: urlParameters, httpBody: httpBody, timeout: timeout)
            }
            XCTAssertTrue(url.absoluteString.contains("idp/myaccount/app-authenticator"))
            XCTAssertEqual(method, .post)
            XCTAssertNotNil(requestModel.device)
            XCTAssertNotNil(requestModel.device?.id)
            XCTAssertNotNil(requestModel.device?.clientInstanceId)
            XCTAssertNotNil(requestModel.device?.deviceAttestation)
            XCTAssertNil(requestModel.device?.clientInstanceKey)
            XCTAssertNotNil(requestModel.device?.authenticatorAppKey)

            let requestToReturn = mockHTTPClient.request(url, method: method, urlParameters: urlParameters, httpBody: httpBody, timeout: timeout)
            if numberOfEnrollRequests == 1 {
                mockHTTPClient.requestWithDataBodyHook = { url, method, urlParameters, httpBody, header, timeout in
                    mockHTTPClient.requestWithDataBodyHook = nil
                    numberOfEnrollRequests = numberOfEnrollRequests + 1
                    guard let httpBody = httpBody,
                          let requestModel = try? JSONDecoder().decode(MyAccountAPI.AuthenticatorRequestModel.self, from: httpBody) else {
                        XCTFail("Missing or invalid body in http query")
                        return mockHTTPClient.request(url, method: method, urlParameters: urlParameters, httpBody: httpBody, timeout: timeout)
                    }
                    XCTAssertTrue(url.absoluteString.contains("idp/myaccount/app-authenticator"))
                    XCTAssertEqual(method, .post)
                    XCTAssertNotNil(requestModel.device)
                    XCTAssertNil(requestModel.device?.id)
                    XCTAssertNil(requestModel.device?.clientInstanceId)
                    XCTAssertNil(requestModel.device?.deviceAttestation)
                    XCTAssertNotNil(requestModel.device?.clientInstanceKey)
                    XCTAssertNotNil(requestModel.device?.authenticatorAppKey)

                    return mockHTTPClient.request(url, method: method, urlParameters: urlParameters, httpBody: httpBody, timeout: timeout)
                }
                mockHTTPClient.counter = mockHTTPClient.counter - 1
                mockHTTPClient.resultArray?.removeLast()
                mockHTTPClient.resultArray?.append(HTTPURLResult(
                    request: URLRequest(url: URL(string: "com.okta.example")!),
                    response: HTTPURLResponse(url: self.mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                    data: MyAccountTestData.enrollmentResponse()))
            }

            return requestToReturn
        }

        let oktaRestAPI = MyAccountServerAPI(client: mockHTTPClient,
                                             crypto: OktaCryptoManager(keychainGroupId: ExampleAppConstants.appGroupId,
                                                                       logger: OktaLoggerMock()),
                                             logger: OktaLoggerMock())

        (deviceAuthenticator as? DeviceAuthenticator)?.impl.restAPI = oktaRestAPI
        let deviceEnrollment = OktaDeviceEnrollment(id: "id",
                                                    orgId: "00otiyyDFtNCyFbnC0g4",
                                                    clientInstanceId: "clientInstanceId",
                                                    clientInstanceKeyTag: "clientInstanceKeyTag")
        XCTAssertNoThrow(try (deviceAuthenticator as? DeviceAuthenticator)?.impl.storageManager!.storeDeviceEnrollment(deviceEnrollment, for: "00otiyyDFtNCyFbnC0g4"))
        let oldDeviceEnrollment = try? (deviceAuthenticator as? DeviceAuthenticator)?.impl.storageManager!.deviceEnrollmentByOrgId("00otiyyDFtNCyFbnC0g4")
        XCTAssertNotNil(oldDeviceEnrollment)
        XCTAssertNotNil(oldDeviceEnrollment?.clientInstanceKeyTag)
        _ = try (deviceAuthenticator as? DeviceAuthenticator)?.impl.cryptoManager.generate(keyPairWith: .ES256,
                                                                                           with: oldDeviceEnrollment?.clientInstanceKeyTag ?? "",
                                                                                           useSecureEnclave: false,
                                                                                           useBiometrics: false,
                                                                                           isAccessibleOnOtherDevice: false,
                                                                                           biometricSettings: nil)

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

        let newDeviceEnrollment = try? (deviceAuthenticator as? DeviceAuthenticator)?.impl.storageManager.deviceEnrollmentByOrgId("00otiyyDFtNCyFbnC0g4")
        XCTAssertNotNil(newDeviceEnrollment)
        XCTAssertNotNil(newDeviceEnrollment?.clientInstanceKeyTag)
        XCTAssertNotEqual(newDeviceEnrollment?.clientInstanceKeyTag, oldDeviceEnrollment?.clientInstanceKeyTag)
        XCTAssertNotEqual(newDeviceEnrollment?.clientInstanceId, oldDeviceEnrollment?.clientInstanceId)
        XCTAssertNotEqual(newDeviceEnrollment?.id, oldDeviceEnrollment?.id)
        XCTAssertEqual(numberOfEnrollRequests, 2)
        _ = (deviceAuthenticator as? DeviceAuthenticator)?.impl.cryptoManager.delete(keyPairWith: oldDeviceEnrollment?.clientInstanceKeyTag ?? "")
    }

    func testEnrollmentWithKnownDevice_ValidateDeviceIsRecreated() throws {

        let deviceAuthenticator = try DeviceAuthenticatorBuilder(applicationConfig: appConfig).create()
        XCTAssertTrue(deviceAuthenticator.allEnrollments().isEmpty)

        let enrollmentExpectation = expectation(description: "Enrollment should complete")

        httpResponses = [HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                         HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                         HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!]
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses,
                                                            dataArray: [GoldenData.orgData(),
                                                                        MyAccountTestData.policyResponse(),
                                                                        MyAccountTestData.enrollmentResponse()])

        var numberOfEnrollRequests = 0
        mockHTTPClient.requestWithDataBodyHook = { url, method, urlParameters, httpBody, header, timeout in
            mockHTTPClient.requestWithDataBodyHook = nil
            numberOfEnrollRequests = numberOfEnrollRequests + 1
            guard let httpBody = httpBody,
                  let requestModel = try? JSONDecoder().decode(MyAccountAPI.AuthenticatorRequestModel.self, from: httpBody) else {
                XCTFail("Missing or invalid body in http query")
                return mockHTTPClient.request(url, method: method, urlParameters: urlParameters, httpBody: httpBody, timeout: timeout)
            }
            XCTAssertTrue(url.absoluteString.contains("idp/myaccount/app-authenticator"))
            XCTAssertEqual(method, .post)
            XCTAssertNotNil(requestModel.device)
            XCTAssertNil(requestModel.device?.id)
            XCTAssertNil(requestModel.device?.clientInstanceId)
            XCTAssertNil(requestModel.device?.deviceAttestation)
            XCTAssertNotNil(requestModel.device?.clientInstanceKey)
            XCTAssertNotNil(requestModel.device?.authenticatorAppKey)

            let requestToReturn = mockHTTPClient.request(url, method: method, urlParameters: urlParameters, httpBody: httpBody, timeout: timeout)

            return requestToReturn
        }

        let oktaRestAPI = MyAccountServerAPI(client: mockHTTPClient,
                                             crypto: OktaCryptoManager(keychainGroupId: ExampleAppConstants.appGroupId,
                                                                       logger: OktaLoggerMock()),
                                             logger: OktaLoggerMock())

        (deviceAuthenticator as? DeviceAuthenticator)?.impl.restAPI = oktaRestAPI
        let deviceEnrollment = OktaDeviceEnrollment(id: "id",
                                                    orgId: "00otiyyDFtNCyFbnC0g4",
                                                    clientInstanceId: "clientInstanceId",
                                                    clientInstanceKeyTag: "clientInstanceKeyTag")
        XCTAssertNoThrow(try (deviceAuthenticator as? DeviceAuthenticator)?.impl.storageManager.storeDeviceEnrollment(deviceEnrollment, for: "00otiyyDFtNCyFbnC0g4"))
        let oldDeviceEnrollment = try? (deviceAuthenticator as? DeviceAuthenticator)?.impl.storageManager.deviceEnrollmentByOrgId("00otiyyDFtNCyFbnC0g4")
        XCTAssertNotNil(oldDeviceEnrollment)
        XCTAssertNotNil(oldDeviceEnrollment?.clientInstanceKeyTag)

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

        let newDeviceEnrollment = try? (deviceAuthenticator as? DeviceAuthenticator)?.impl.storageManager!.deviceEnrollmentByOrgId("00otiyyDFtNCyFbnC0g4")
        XCTAssertNotNil(newDeviceEnrollment)
        XCTAssertNotNil(newDeviceEnrollment?.clientInstanceKeyTag)
        XCTAssertNotEqual(newDeviceEnrollment?.clientInstanceKeyTag, oldDeviceEnrollment?.clientInstanceKeyTag)
        XCTAssertNotEqual(newDeviceEnrollment?.clientInstanceId, oldDeviceEnrollment?.clientInstanceId)
        XCTAssertNotEqual(newDeviceEnrollment?.id, oldDeviceEnrollment?.id)
        XCTAssertEqual(numberOfEnrollRequests, 1)
    }
}
