/*
* Copyright (c) 2019, Okta, Inc. and/or its affiliates. All rights reserved.
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

class DeviceAuthenticatorTests: XCTestCase {
    var secureStorageMock: OktaSecureStorageMock!
    let entitiesGenerator = OktaStorageEntitiesGenerator()
    
    override func setUp() {
        super.setUp()
        UNUserNotificationCenter.current().setNotificationCategories([])
    }

    func testDeviceSDKInitialize() {
        var applicationConfig = ApplicationConfig(applicationName: "Test App",
                                                  applicationVersion: "1.0.0",
                                                  applicationGroupId: ExampleAppConstants.appGroupId)
        applicationConfig.pushSettings.approveActionTitle = "Approve"
        applicationConfig.pushSettings.denyActionTitle = "Deny"
        applicationConfig.pushSettings.userVerificationActionTitle = "Review"
        var deviceAuthenticator: DeviceAuthenticator! = nil
        do {
            deviceAuthenticator = try TestUtils.createDeviceAuthenticator(appConfig: applicationConfig)
        } catch {
            XCTFail("Unexpected initialize failure")
        }
        XCTAssertNotNil(deviceAuthenticator.impl)
        XCTAssertTrue(deviceAuthenticator.impl.storageManager is OktaStorageManager)

        let categoryExpectation = expectation(description: "expectation should complete")
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) {
            UNUserNotificationCenter.current().getNotificationCategories { categories in
                XCTAssertEqual(categories.count, 2)
                categories.forEach { category in
                    if category.identifier == InternalConstants.PushNotificationConstants.regularPushCategoryIdentifier {
                        XCTAssert(category.actions.count == 2)
                        category.actions.forEach { action in
                            if action.identifier == InternalConstants.PushNotificationConstants.approveActionIdentifier {
                                XCTAssertEqual(action.title, applicationConfig.pushSettings.approveActionTitle)
                            } else if action.identifier == InternalConstants.PushNotificationConstants.denyActionIdentifier {
                                XCTAssertEqual(action.title, applicationConfig.pushSettings.denyActionTitle)
                            } else {
                                XCTFail("Unkown push action")
                            }
                        }
                    } else if category.identifier == InternalConstants.PushNotificationConstants.userVerificationPushCategoryIdentifier {
                        XCTAssert(category.actions.count == 1)
                        XCTAssertEqual(category.identifier, InternalConstants.PushNotificationConstants.userVerificationPushCategoryIdentifier)
                        XCTAssertEqual(category.actions.first?.title, applicationConfig.pushSettings.userVerificationActionTitle)
                    } else {
                        XCTFail("Unkown push category")
                    }
                }
                categoryExpectation.fulfill()
            }
        }

        wait(for: [categoryExpectation], timeout: 1)

        let loggerClient = OktaLoggerMock()
        do {
            deviceAuthenticator = try DeviceAuthenticatorBuilder(applicationConfig: applicationConfig)
                                    .addLogger(loggerClient)
                                    .create() as? DeviceAuthenticator
        } catch {
            XCTFail("Unexpected initialize failure")
        }
        XCTAssert(deviceAuthenticator.impl.logger === loggerClient)

        do {
            applicationConfig = ApplicationConfig(applicationName: "Test App",
                                                      applicationVersion: "1.0.0",
                                                      applicationGroupId: ExampleAppConstants.bundleId)
            deviceAuthenticator = try DeviceAuthenticatorBuilder(applicationConfig: applicationConfig)
                                    .create() as? DeviceAuthenticator
            XCTFail("Call should fail")
        } catch {
            let oktaError = error as? DeviceAuthenticatorError
            XCTAssertNotNil(oktaError)
            XCTAssertEqual(oktaError?.errorCode,
                           DeviceAuthenticatorError.storageError(StorageError.missingAppGroupEntitlement).errorCode)
        }
    }
}
