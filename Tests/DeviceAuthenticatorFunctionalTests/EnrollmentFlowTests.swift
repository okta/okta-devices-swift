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

class EnrollmentFlowTests: XCTestCase {

    private var appConfig: ApplicationConfig!
    private let mockURL = URL(string: "https://example.okta.com")!
    private var deviceAuthenticatorConfig: DeviceAuthenticatorConfig!
    private var enrollmentParams: EnrollmentParameters!
    private var httpResponses: [HTTPURLResponse]!

    override func setUpWithError() throws {
        appConfig = ApplicationConfig(applicationName: "funcTests", applicationVersion: "1.0.0", applicationGroupId: ExampleAppConstants.appGroupId)
        deviceAuthenticatorConfig = DeviceAuthenticatorConfig(orgURL: URL(string: "tenant.okta.com")!, oidcClientId: "oidcClientId")
        enrollmentParams = EnrollmentParameters(deviceToken: DeviceToken.tokenData("abcde12345".data(using: .utf8)!))
        httpResponses = [HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                         HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                         HTTPURLResponse(url: mockURL, statusCode: 200, httpVersion: nil, headerFields: nil)!]
    }

    override func tearDownWithError() throws {
        appConfig = nil
        deviceAuthenticatorConfig = nil
        enrollmentParams = nil
    }

    func testEnrollFlow_WithExpectedResponses_ReturnsEnrolledAuthenticator() {

        let enrollmentExpectation = expectation(description: "Enrollment should complete")

        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray:
                                                                [GoldenData.orgData(),
                                                                 GoldenData.authenticatorMetaData(),
                                                                 GoldenData.authenticatorData()])
        let oktaRestAPI = LegacyServerAPI(client: mockHTTPClient, logger: OktaLoggerMock())

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

    func testEnrollFlow_WithIncompleteOrgData_ReturnsNilAuthenticator() {

        let enrollmentExpectation = expectation(description: "Enrollment should complete")

        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: httpResponses, dataArray:
                                                                [GoldenData.orgDataIncomplete(),
                                                                 GoldenData.authenticatorMetaData(),
                                                                 GoldenData.authenticatorData()])
        let oktaRestAPI = LegacyServerAPI(client: mockHTTPClient, logger: OktaLoggerMock())

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
                                                                 GoldenData.authenticatorMetaDataInactive(),
                                                                 GoldenData.authenticatorData()])
        let oktaRestAPI = LegacyServerAPI(client: mockHTTPClient, logger: OktaLoggerMock())

        let deviceAuthenticator: DeviceAuthenticatorProtocol
        do {
            deviceAuthenticator = try DeviceAuthenticatorBuilder(applicationConfig: appConfig).create()
            (deviceAuthenticator as? DeviceAuthenticator)?.impl.restAPI = oktaRestAPI

            deviceAuthenticator.enroll(authenticationToken: AuthToken.bearer("cdeb3858fabc"), authenticatorConfig: deviceAuthenticatorConfig, enrollmentParameters: enrollmentParams) { result in
                switch result {
                case .success(_):
                    XCTFail("Unexpected result")
                case .failure(let error):
                    XCTAssertEqual("Server replied with empty active authenticators array", error.localizedDescription)
                }
                enrollmentExpectation.fulfill()
            }
            wait(for: [enrollmentExpectation], timeout: 3.0)
        } catch {
            XCTFail("Should init Authenticator")
        }

    }
}
