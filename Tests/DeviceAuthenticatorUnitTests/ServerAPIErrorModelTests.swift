/*
* Copyright (c) 2020, Okta, Inc. and/or its affiliates. All rights reserved.
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

class ServerAPIErrorModelTests: XCTestCase {

    func testDecoding() {
        let errorModel = try? JSONDecoder().decode(ServerAPIErrorModel.self, from: GoldenData.resourceNotFoundError())
        XCTAssertNotNil(errorModel)
        XCTAssertEqual(errorModel?.errorCode?.rawValue, "E0000154")
        XCTAssertEqual(errorModel?.errorId, "oaeYckeiQ8aQ124WltauaZB_Q")
        XCTAssertEqual(errorModel?.errorLink, "E0000154")
        XCTAssertEqual(errorModel?.errorSummary, "Not found: Resource not found: guo1vdb2WbcR7DXuJ0w5 (GenericUDObject)")
    }

    func testDecodingWithVerificationErrorFormat() {
        let errorModel = try? JSONDecoder().decode(ServerAPIErrorModel.self, from: GoldenData.verificationFlowErrorFormat())
        XCTAssertNotNil(errorModel)
        XCTAssertEqual(errorModel?.status, "REJECT")
    }
}
