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

class FactorDataPushTests: XCTestCase {

    var oktaFactor: OktaFactorMetadataPush!

    override func setUp() {
        oktaFactor = OktaFactorMetadataPush(id: "id",
                                            proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                            userVerificationKeyTag: "userVerificationKeyTag",
                                            transactionTypes: .login)
    }

    func testCreationWithUserVerificationKey() {
        XCTAssertEqual(oktaFactor.id, "id")
        XCTAssertEqual(oktaFactor.proofOfPossessionKeyTag, "proofOfPossessionKeyTag")
        XCTAssertEqual(oktaFactor.userVerificationKeyTag, "userVerificationKeyTag")
    }

    func testCreationWithNoUserVerificationKey() {
        oktaFactor.userVerificationKeyTag = nil
        XCTAssertEqual(oktaFactor.id, "id")
        XCTAssertEqual(oktaFactor.proofOfPossessionKeyTag, "proofOfPossessionKeyTag")
        XCTAssertNil(oktaFactor.userVerificationKeyTag)
    }
    
    func testCreationWithTransactionTypes() {
        XCTAssertEqual(oktaFactor.transactionTypes, .login)
    }

    func testSerialization_WithUVKey() {
        let data = try? JSONEncoder().encode(oktaFactor)
        XCTAssertNotNil(data)
        let pushFactorToTest = try? JSONDecoder().decode(OktaFactorMetadataPush.self, from: data!)
        XCTAssertNotNil(pushFactorToTest)
        XCTAssertEqual(pushFactorToTest?.id, "id")
        XCTAssertEqual(pushFactorToTest?.proofOfPossessionKeyTag, "proofOfPossessionKeyTag")
        XCTAssertEqual(pushFactorToTest?.userVerificationKeyTag, "userVerificationKeyTag")
        XCTAssertEqual(pushFactorToTest?.type, .push)
    }

    func testSerialization_WithoutUVKey() {
        oktaFactor.userVerificationKeyTag = nil
        let data = try? JSONEncoder().encode(oktaFactor)
        XCTAssertNotNil(data)
        let pushFactorToTest = try? JSONDecoder().decode(OktaFactorMetadataPush.self, from: data!)
        XCTAssertNotNil(pushFactorToTest)
        XCTAssertEqual(pushFactorToTest?.id, "id")
        XCTAssertEqual(pushFactorToTest?.proofOfPossessionKeyTag, "proofOfPossessionKeyTag")
        XCTAssertNil(pushFactorToTest?.userVerificationKeyTag)
        XCTAssertEqual(pushFactorToTest?.type, .push)
    }
    
    func testSerialization_withLoginTransactionTypes() {
        let data = try? JSONEncoder().encode(oktaFactor)
        XCTAssertNotNil(data)
        let pushFactorToTest = try? JSONDecoder().decode(OktaFactorMetadataPush.self, from: data!)
        XCTAssertNotNil(pushFactorToTest)
        XCTAssertEqual(pushFactorToTest?.transactionTypes, .login)
    }
    
    func testSerialization_withLoginAndCibaTransactionTypes() {
        oktaFactor.transactionTypes = [.login, .ciba]
        let data = try? JSONEncoder().encode(oktaFactor)
        XCTAssertNotNil(data)
        let pushFactorToTest = try? JSONDecoder().decode(OktaFactorMetadataPush.self, from: data!)
        XCTAssertNotNil(pushFactorToTest)
        XCTAssertEqual(pushFactorToTest?.transactionTypes, [.login, .ciba])
        XCTAssertTrue(pushFactorToTest?.transactionTypes?.supportsCIBA ?? false)
    }
    
    func testSerialization_withoutTransactionTypes_loginByDefault() {
        oktaFactor.transactionTypes = nil
        let data = try? JSONEncoder().encode(oktaFactor)
        XCTAssertNotNil(data)
        let pushFactorToTest = try? JSONDecoder().decode(OktaFactorMetadataPush.self, from: data!)
        XCTAssertNotNil(pushFactorToTest)
        XCTAssertEqual(pushFactorToTest?.transactionTypes, .login)
    }
    
}
