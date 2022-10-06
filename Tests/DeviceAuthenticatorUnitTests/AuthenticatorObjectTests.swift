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
@testable import DeviceAuthenticator

class AuthenticatorObjectTests: XCTestCase {

    func testMetaDataDecoding() {
        let decoder = JSONDecoder()
        let metaDataArray = try! decoder.decode([AuthenticatorMetaDataModel].self, from: GoldenData.authenticatorMetaData())
        XCTAssertTrue(!metaDataArray.isEmpty)
        let metaData = metaDataArray[0]
        XCTAssertEqual(metaData.id, "autuowpr5VjVjQPU30g3")
        XCTAssertEqual(metaData.key, "okta_verify")
        XCTAssertEqual(metaData.type, "APP")
        XCTAssertEqual(metaData._embedded.methods.count, 3)
        XCTAssertEqual(metaData.settings?.oauthClientId, "someOAuth2ClientId")
        metaData._embedded.methods.forEach({ authenticatorType in
            if authenticatorType.type == .totp {
                XCTAssertEqual(authenticatorType.status, "INACTIVE")
                XCTAssertNotNil(authenticatorType.settings)
                XCTAssertEqual(authenticatorType.settings?.timeIntervalInSeconds, 10)
                XCTAssertEqual(authenticatorType.settings?.passCodeLength, 6)
                XCTAssertEqual(authenticatorType.settings?.algorithm, AuthenticatorMetaDataModel.Method.Settings.TOTPAlgorithms.HMACSHA1)
                XCTAssertEqual(authenticatorType.settings?.encoding, AuthenticatorMetaDataModel.Method.Settings.TOTPSecretEncoding.Base32)
            } else if authenticatorType.type == .push {
                XCTAssertEqual(authenticatorType.status, "ACTIVE")
                XCTAssertEqual(authenticatorType.settings?.transactionTypes, [TransactionTypesModel.login, TransactionTypesModel.ciba])
            } else if authenticatorType.type == .signedNonce {
                XCTAssertEqual(authenticatorType.status, "INACTIVE")
                XCTAssertEqual(authenticatorType.settings?.keyProtection, .ANY)
                XCTAssertNotNil(authenticatorType.settings?.algorithms)
                if let algorithms = authenticatorType.settings?.algorithms {
                    XCTAssertTrue(algorithms.contains(.ES256))
                    XCTAssertTrue(algorithms.contains(.RS256))
                }
            } else {
                XCTFail("Unexpected authenticator type \(authenticatorType.type.rawValue)")
            }
        })
    }

    func testEnrolledAuthenticatorDecoding() {
        let decoder = JSONDecoder()
        let authenticator = try! decoder.decode(EnrolledAuthenticatorModel.self, from: GoldenData.authenticatorData())
        XCTAssertEqual(authenticator.id, "aen1jisLwwTG7qRrH0g4")
        XCTAssertEqual(authenticator.authenticatorId, "autuowpr5VjVjQPU30g3")
        XCTAssertEqual(authenticator.key, "okta_verify")
        XCTAssertEqual(authenticator.type, "APP")
        XCTAssertEqual(authenticator.createdDate, "Tue Dec 03 18:39:46 UTC 2019")
        XCTAssertEqual(authenticator.lastUpdated, "Tue Dec 03 18:39:46 UTC 2019")
        XCTAssertNotNil(authenticator.device)
        XCTAssertEqual(authenticator.device.id, "guotmkiKzYBTnhnC40g4")
        XCTAssertEqual(authenticator.device.profile?.displayName, "Test Device")
        XCTAssertEqual(authenticator.device.profile?.platform, .iOS)
        XCTAssertEqual(authenticator.device.profile?.manufacturer, "APPLE")
        XCTAssertEqual(authenticator.device.profile?.model, "iPhone X")
        XCTAssertEqual(authenticator.device.profile?.osVersion, "10")
        XCTAssertEqual(authenticator.device.profile?.serialNumber, "2fc4b5912826ad1")
        XCTAssertEqual(authenticator.device.profile?.udid, "2b6f0cc904d137be2e1730235f5664094b831186")
        XCTAssertEqual(authenticator.device.clientInstanceId, "cli1zEPrHHW0w4i0ALF0")
        XCTAssertEqual(authenticator.user.id, "00utmecoNjNd0lrWp0g4")
        XCTAssertEqual(authenticator.user.username, "test@okta.com")
        XCTAssertEqual(authenticator.methods?.count, 1)
        XCTAssertEqual(authenticator.methods![0].id, "opftmklWEf1vDZvr10g4")
        XCTAssertEqual(authenticator.methods![0].type, .push)
        XCTAssertEqual(authenticator.methods![0].status, "ACTIVE")
    }

    func testMetaDataUserVerificationDecoding_Preferred() {
        let preferredUVData = GoldenData.authenticatorMetaData()

        do {
            let metadata = try JSONDecoder().decode([AuthenticatorMetaDataModel].self, from: preferredUVData).first
            XCTAssertEqual(metadata?.settings?.userVerification, .preferred)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testMetaDataUserVerificationDecoding_Required() {
        guard let preferredUVString = String(data: GoldenData.authenticatorMetaData(), encoding: .utf8),
              let requiredUVData = preferredUVString.replacingOccurrences(
                of: "\"userVerification\" : \"preferred\"",
                with: "\"userVerification\" : \"required\""
              ).data(using: .utf8) else {

            XCTFail()
            return
        }

        do {
            let metadata = try JSONDecoder().decode([AuthenticatorMetaDataModel].self, from: requiredUVData).first
            XCTAssertEqual(metadata?.settings?.userVerification, .required)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testMetaDataUserVerificationDecoding_Unknown() {
        guard let preferredUVString = String(data: GoldenData.authenticatorMetaData(), encoding: .utf8),
              let requiredUVData = preferredUVString.replacingOccurrences(
                of: "\"userVerification\" : \"preferred\"",
                with: "\"userVerification\" : \"some_unknown_value\""
              ).data(using: .utf8) else {

            XCTFail()
            return
        }

        do {
            let metadata = try JSONDecoder().decode([AuthenticatorMetaDataModel].self, from: requiredUVData).first
            XCTAssertEqual(metadata?.settings?.userVerification, .unknown("some_unknown_value"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testMetaDataUserVerificationDecoding_NoValue() {
        let noUVInfoData = GoldenData.authenticatorMetaDataWithEmptyEnrollLink()

        do {
            let metadata = try JSONDecoder().decode([AuthenticatorMetaDataModel].self, from: noUVInfoData).first
            XCTAssertNil(metadata?.settings?.userVerification)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
}
