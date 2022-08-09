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
// swiftlint:disable force_cast
import Foundation
@testable import DeviceAuthenticator

class TestUtils {

    class func createAuthenticatorEnrollment(orgHost: URL,
                                             orgId: String,
                                             enrollmentId: String,
                                             cryptoManager: OktaCryptoManager,
                                             userId: String = "user_id",
                                             userName: String = "user_name",
                                             userVerificationKeyTag: String? = "userVerificationKeyTag",
                                             enrollPush: Bool = true,
                                             createdDate: String = "2020-09-08T19:03:30.166Z",
                                             storageManager: PersistentStorageProtocol? = nil) -> AuthenticatorEnrollmentMock {
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [],
                                                            dataArray: [])
        let restAPIMock = RestAPIMock(client: mockHTTPClient, logger: OktaLoggerMock())
        var storage: PersistentStorageProtocol!
        if let storageManager = storageManager {
            storage = storageManager
        } else {
            storage = StorageMock()
        }

        _ = try? cryptoManager.generate(keyPairWith: .ES256, with: "proofOfPossessionKeyTag", useSecureEnclave: false, useBiometrics: false)
        var factors = [OktaFactor]()
        if enrollPush {
            let pushFactorMetadata = OktaFactorMetadataPush(id: "push_id",
                                                    proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                                    userVerificationKeyTag: userVerificationKeyTag)
            let pushFactor = VerificationMethodFactory.pushFactorFromMetadata(pushFactorMetadata,
                                                                              cryptoManager: cryptoManager,
                                                                              restAPIClient: restAPIMock,
                                                                              logger: OktaLoggerMock())
            factors.append(pushFactor)
        }

        let appConfig = ApplicationConfig(applicationName: "AppName",
                                          applicationVersion: "1.0.0",
                                          applicationGroupId: ExampleAppConstants.appGroupId)
        let authenticatorEnrollment = AuthenticatorEnrollmentMock(organization: Organization(id: orgId, url: orgHost),
                                                                  user: User(id: userId, name: userName),
                                                                  enrollmentId: enrollmentId,
                                                                  deviceId: "id",
                                                                  serverError: nil,
                                                                  creationDate: Date(),
                                                                  enrolledFactors: factors,
                                                                  cryptoManager: cryptoManager,
                                                                  restAPIClient: restAPIMock,
                                                                  storageManager: storage,
                                                                  applicationConfig: appConfig,
                                                                  logger: OktaLoggerMock())

        return authenticatorEnrollment
    }

    class func getValidEDRConfigs(path: String?) -> [[String: String]] {
        return [["name": "name_1", "description": "description_1", "location": path ?? "path", "type": "file", "format": "JWT"], ["name": "name_2", "description": "description_2", "location": "location_2", "type": "file", "format": "format_2"], ["name": "name_3", "description": "description_3", "location": "location_3", "type": "type_3", "format": "format_3"]]
    }

    class func getInvalidEDRConfigs() -> [[String: String]] {
        return [["name": "name_1", "location": "location_1", "type": "type_1", "format": "format_1"], ["name": "name_2", "description": "description", "location": "location_2", "type": "type_2"]]
    }

    class func testIntegrations() -> [_IntegrationData] {
        let integrationSignal = _PluginSignalData(name: "name", configuration: _DeviceChallengeTokenConfiguration(type: "type", format: "format"), signal: "signal", timeCollected: 200)
        return [_IntegrationData.signal(integrationSignal)]
    }

    class func testEnrollmentDescription() -> String {
        return """

        {
          "_embedded" : {
            "methods" : [
              {
                "type" : "push",
                "status" : "ACTIVE"
              }
            ]
          },
          "id" : "id",
          "key" : "okta_verify",
          "settings" : {
            "userVerification" : "required"
          },
          "type" : "type",
          "_links" : {

          }
        }
        {
          "status" : "status",
          "lastUpdated" : "2020-09-08T19:03:30.166Z",
          "createdDate" : "2020-09-08T19:03:30.166Z",
          "id" : "enrollmentId",
          "device" : {
            "status" : "",
            "id" : "deviceId",
            "createdDate" : "2020-09-08T19:03:30.166Z",
            "clientInstanceId" : "clientInstanceId",
            "lastUpdated" : "2020-09-08T19:03:30.166Z"
          },
          "key" : "okta_verify",
          "type" : "type",
          "authenticatorId" : "authenticatorId",
          "user" : {
            "id" : "userId"
          }
        }
        """
    }

    class func createAuthenticatorMetadataModel(id: String = "id",
                                                userVerification: AuthenticatorMetaDataModel.Settings.UserVerificationSetting = .preferred,
                                                methods: [AuthenticatorMethod] = [.push, .signedNonce]) -> AuthenticatorMetaDataModel {
        let settings = AuthenticatorMetaDataModel.Settings(appInstanceId: nil,
                                                           userVerification: userVerification,
                                                           oauthClientId: nil)

        var embeddedMethods = [AuthenticatorMetaDataModel.Method]()
        for method in methods {
            embeddedMethods.append(AuthenticatorMetaDataModel.Method(type: method, status: "ACTIVE", settings: nil))
        }
        return AuthenticatorMetaDataModel(id: id,
                                          key: "okta_verify",
                                          type: "type",
                                          status: .active,
                                          name: nil,
                                          settings: settings,
                                          _links: AuthenticatorMetaDataModel.Links(enroll: nil, logos: nil),
                                          _embedded: AuthenticatorMetaDataModel.Embedded(methods: embeddedMethods))
    }

    class func createDeviceAuthenticator(appConfig: ApplicationConfig? = nil) throws -> DeviceAuthenticator {
        let applicationConfig = appConfig ?? ApplicationConfig(applicationName: "Test App",
                                                               applicationVersion: "1.0.0",
                                                               applicationGroupId: ExampleAppConstants.appGroupId)
        return try DeviceAuthenticatorBuilder(applicationConfig: applicationConfig).create() as! DeviceAuthenticator
    }
}
