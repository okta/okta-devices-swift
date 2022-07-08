/*
* Copyright (c) 2021, Okta-Present, Inc. and/or its affiliates. All rights reserved.
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

class OktaVersionTypeTests: XCTestCase {

    func testVersionsRelyOnRawValueNotDeclarationOrder() {
        enum AVersions: Int, _OktaVersionType {
            static var unknownVersion = AVersions.unknown
            case unknown = -9999
            case firstVersion = 1
            case secondVersion = 2
            case thirdVersion = 3
            case fourthVersion = 4
            case fifthVersion = 5
        }

        enum BVersions: Int, _OktaVersionType {
            static var unknownVersion = BVersions.unknown
            case unknown = -9999
            case secondVersion = 2
            case fourthVersion = 4
            case firstVersion = 1
            case thirdVersion = 3
            case fifthVersion = 5
        }
        var aCurrentVersion = AVersions.firstVersion
        var bCurrentVersion = BVersions.firstVersion
        for _ in 1...5 {
            XCTAssertEqual(aCurrentVersion.rawValue, bCurrentVersion.rawValue)
            aCurrentVersion = aCurrentVersion.nextVersion()
            bCurrentVersion = bCurrentVersion.nextVersion()
        }
    }

}
