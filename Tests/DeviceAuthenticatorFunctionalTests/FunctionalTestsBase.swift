/*
* Copyright (c) 2023, Okta, Inc. and/or its affiliates. All rights reserved.
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

class FunctionalTestsBase: XCTestCase {
    var appConfig: ApplicationConfig!
    let mockURL = URL(string: "https://example.okta.com")!
    var deviceAuthenticatorConfig: DeviceAuthenticatorConfig!
    var enrollmentParams: EnrollmentParameters!

    lazy var sqlDirectoryURL: URL! = {
        return FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: ExampleAppConstants.appGroupId)?.appendingPathComponent(DeviceAuthenticatorConstants.defaultStorageRelativeDirectoryPath)
    }()

    override func setUpWithError() throws {
        appConfig = ApplicationConfig(applicationName: "funcTests", applicationVersion: "1.0.0", applicationGroupId: ExampleAppConstants.appGroupId)
        deviceAuthenticatorConfig = DeviceAuthenticatorConfig(orgURL: URL(string: "tenant.okta.com")!, oidcClientId: "oidcClientId")
        enrollmentParams = EnrollmentParameters(deviceToken: DeviceToken.tokenData("abcde12345".data(using: .utf8)!))

        try? FileManager.default.removeItem(at: sqlDirectoryURL)
    }

    override func tearDownWithError() throws {
        appConfig = nil
        deviceAuthenticatorConfig = nil
        enrollmentParams = nil
    }
}
