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

class AuthenticatorPolicyTests: XCTestCase {

    func testUserVerificationSetting() {
        let createMetadataWithSettings: (AuthenticatorSettingsModel?) -> AuthenticatorMetaDataModel = { settings in
            return AuthenticatorMetaDataModel(id: "id",
                                              key: "key",
                                              type: "type",
                                              status: .active,
                                              name: nil,
                                              settings: settings,
                                              _links: AuthenticatorMetaDataModel.Links(enroll: nil, logos: nil),
                                              _embedded: AuthenticatorMetaDataModel.Embedded(methods: []))
        }

        var policy = AuthenticatorPolicy(metadata: createMetadataWithSettings(nil))
        XCTAssertEqual(policy.userVerificationSetting, .preferred)

        policy = AuthenticatorPolicy(metadata: createMetadataWithSettings(
            AuthenticatorSettingsModel(appInstanceId: nil, userVerification: nil, userVerificationMethods: nil, oauthClientId: nil)
        ))
        XCTAssertEqual(policy.userVerificationSetting, .preferred)
        XCTAssertEqual(policy._userVerificationMethods, nil)

        var userVerificationMethods: [AuthenticatorSettingsModel.UserVerificationMethodSetting] = []
        policy = AuthenticatorPolicy(metadata: createMetadataWithSettings(
            AuthenticatorSettingsModel(appInstanceId: nil, userVerification: .preferred, userVerificationMethods: userVerificationMethods, oauthClientId: nil)
        ))
        XCTAssertEqual(policy.userVerificationSetting, .preferred)
        XCTAssertEqual(policy._userVerificationMethods, userVerificationMethods)

        userVerificationMethods = [.presence, .pin, .biometrics]
        policy = AuthenticatorPolicy(metadata: createMetadataWithSettings(
            AuthenticatorSettingsModel(appInstanceId: nil, userVerification: .required , userVerificationMethods: userVerificationMethods, oauthClientId: nil)
        ))
        XCTAssertEqual(policy.userVerificationSetting, .required)
        XCTAssertEqual(policy._userVerificationMethods, userVerificationMethods)

        userVerificationMethods = [.unknown("")]
        policy = AuthenticatorPolicy(metadata: createMetadataWithSettings(
            AuthenticatorSettingsModel(appInstanceId: nil, userVerification: .unknown(""), userVerificationMethods: userVerificationMethods, oauthClientId: nil)
        ))
        XCTAssertEqual(policy.userVerificationSetting, .unknown(""))
        XCTAssertEqual(policy._userVerificationMethods, userVerificationMethods)
    }

    func testHasMethodOfType() {
        let createMetadataWithMethods: ([MethodResponseModel]) -> AuthenticatorMetaDataModel = { methods in
            return AuthenticatorMetaDataModel(id: "id",
                                              key: "key",
                                              type: "type",
                                              status: .active,
                                              name: nil,
                                              settings: nil,
                                              _links: AuthenticatorMetaDataModel.Links(enroll: nil, logos: nil),
                                              _embedded: AuthenticatorMetaDataModel.Embedded(methods: methods))
        }

        var policy = AuthenticatorPolicy(metadata: createMetadataWithMethods([]))
        XCTAssertFalse(policy.hasMethod(ofType: .push))
        XCTAssertFalse(policy.hasMethod(ofType: .totp))
        XCTAssertFalse(policy.hasMethod(ofType: .signedNonce))

        policy = AuthenticatorPolicy(metadata: createMetadataWithMethods([
            MethodResponseModel(type: .push, status: "ok", settings: nil),
        ]))
        XCTAssertTrue(policy.hasMethod(ofType: .push))
        XCTAssertFalse(policy.hasMethod(ofType: .totp))
        XCTAssertFalse(policy.hasMethod(ofType: .signedNonce))

        policy = AuthenticatorPolicy(metadata: createMetadataWithMethods([
            MethodResponseModel(type: .totp, status: "ok", settings: nil),
        ]))
        XCTAssertFalse(policy.hasMethod(ofType: .push))
        XCTAssertTrue(policy.hasMethod(ofType: .totp))
        XCTAssertFalse(policy.hasMethod(ofType: .signedNonce))

        policy = AuthenticatorPolicy(metadata: createMetadataWithMethods([
            MethodResponseModel(type: .signedNonce, status: "ok", settings: nil),
        ]))
        XCTAssertFalse(policy.hasMethod(ofType: .push))
        XCTAssertFalse(policy.hasMethod(ofType: .totp))
        XCTAssertTrue(policy.hasMethod(ofType: .signedNonce))

        policy = AuthenticatorPolicy(metadata: createMetadataWithMethods([
            MethodResponseModel(type: .push, status: "ok", settings: nil),
            MethodResponseModel(type: .totp, status: "ok", settings: nil),
            MethodResponseModel(type: .signedNonce, status: "ok", settings: nil),
        ]))
        XCTAssertTrue(policy.hasMethod(ofType: .push))
        XCTAssertTrue(policy.hasMethod(ofType: .totp))
        XCTAssertTrue(policy.hasMethod(ofType: .signedNonce))
    }

    func testHasActiveMethodOfType() {
        let createMetadataWithMethods: ([MethodResponseModel]) -> AuthenticatorMetaDataModel = { methods in
            return AuthenticatorMetaDataModel(id: "id",
                                              key: "key",
                                              type: "type",
                                              status: .active,
                                              name: nil,
                                              settings: nil,
                                              _links: AuthenticatorMetaDataModel.Links(enroll: nil, logos: nil),
                                              _embedded: AuthenticatorMetaDataModel.Embedded(methods: methods))
        }

        var policy = AuthenticatorPolicy(metadata: createMetadataWithMethods([]))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .push))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .totp))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .signedNonce))

        policy = AuthenticatorPolicy(metadata: createMetadataWithMethods([
            MethodResponseModel(type: .push, status: "ACTIVE", settings: nil),
        ]))
        XCTAssertTrue(policy.hasActiveMethod(ofType: .push))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .totp))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .signedNonce))

        policy = AuthenticatorPolicy(metadata: createMetadataWithMethods([
            MethodResponseModel(type: .push, status: "INACTIVE", settings: nil),
        ]))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .push))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .totp))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .signedNonce))

        policy = AuthenticatorPolicy(metadata: createMetadataWithMethods([
            MethodResponseModel(type: .totp, status: "ACTIVE", settings: nil),
        ]))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .push))
        XCTAssertTrue(policy.hasActiveMethod(ofType: .totp))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .signedNonce))

        policy = AuthenticatorPolicy(metadata: createMetadataWithMethods([
            MethodResponseModel(type: .totp, status: "INACTIVE", settings: nil),
        ]))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .push))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .totp))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .signedNonce))

        policy = AuthenticatorPolicy(metadata: createMetadataWithMethods([
            MethodResponseModel(type: .signedNonce, status: "ACTIVE", settings: nil),
        ]))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .push))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .totp))
        XCTAssertTrue(policy.hasActiveMethod(ofType: .signedNonce))

        policy = AuthenticatorPolicy(metadata: createMetadataWithMethods([
            MethodResponseModel(type: .signedNonce, status: "INACTIVE", settings: nil),
        ]))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .push))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .totp))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .signedNonce))

        policy = AuthenticatorPolicy(metadata: createMetadataWithMethods([
            MethodResponseModel(type: .push, status: "ACTIVE", settings: nil),
            MethodResponseModel(type: .totp, status: "ACTIVE", settings: nil),
            MethodResponseModel(type: .signedNonce, status: "ACTIVE", settings: nil),
        ]))
        XCTAssertTrue(policy.hasActiveMethod(ofType: .push))
        XCTAssertTrue(policy.hasActiveMethod(ofType: .totp))
        XCTAssertTrue(policy.hasActiveMethod(ofType: .signedNonce))

        policy = AuthenticatorPolicy(metadata: createMetadataWithMethods([
            MethodResponseModel(type: .push, status: "INACTIVE", settings: nil),
            MethodResponseModel(type: .totp, status: "INACTIVE", settings: nil),
            MethodResponseModel(type: .signedNonce, status: "INACTIVE", settings: nil),
        ]))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .push))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .totp))
        XCTAssertFalse(policy.hasActiveMethod(ofType: .signedNonce))
    }
}
