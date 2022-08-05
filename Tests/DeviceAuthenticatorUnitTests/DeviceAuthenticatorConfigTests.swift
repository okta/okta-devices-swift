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
import DeviceAuthenticator

class DeviceAuthenticatorConfigTests: XCTestCase {
    func testCreation() throws {
        var deviceAuthenticator = DeviceAuthenticatorConfig(orgURL: URL(string: "https://tenant.okta.com")!, oidcClientId: "oidcClientId")
        XCTAssertEqual(deviceAuthenticator.oidcClientId, "oidcClientId")
        XCTAssertEqual(deviceAuthenticator.orgURL.absoluteString, "https://tenant.okta.com")

        deviceAuthenticator = DeviceAuthenticatorConfig(orgURL: URL(string: "tenant.okta.com")!, oidcClientId: "")
        XCTAssertEqual(deviceAuthenticator.orgURL.absoluteString, "https://tenant.okta.com")

        deviceAuthenticator = DeviceAuthenticatorConfig(orgURL: URL(string: "tenant.okta.com/path/endpoint")!, oidcClientId: "")
        XCTAssertEqual(deviceAuthenticator.orgURL.absoluteString, "https://tenant.okta.com")

        deviceAuthenticator = DeviceAuthenticatorConfig(orgURL: URL(string: "tenant.okta.subdomain.com")!, oidcClientId: "")
        XCTAssertEqual(deviceAuthenticator.orgURL.absoluteString, "https://tenant.okta.subdomain.com")

        deviceAuthenticator = DeviceAuthenticatorConfig(orgURL: URL(string: "tenant.okta.subdomain.com/path/endpoint")!, oidcClientId: "")
        XCTAssertEqual(deviceAuthenticator.orgURL.absoluteString, "https://tenant.okta.subdomain.com")
    }
}
