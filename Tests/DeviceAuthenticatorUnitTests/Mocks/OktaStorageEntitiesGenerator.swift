/*
* Copyright (c) 2021, Okta, Inc. and/or its affiliates. All rights reserved.
* The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
*
* You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*
* See the License for the specific language governing permissions and limitations under the License.
*/

import Foundation
@testable import DeviceAuthenticator

class OktaStorageEntitiesGenerator {

    func createDeviceEnrollment(id: String = UUID().uuidString,
                                orgId: String = UUID().uuidString,
                                clientInstanceId: String = UUID().uuidString,
                                clientInstanceKeyTag: String = UUID().uuidString) -> OktaDeviceEnrollment {
        return OktaDeviceEnrollment(id: id,
                                    orgId: orgId,
                                    clientInstanceId: clientInstanceId,
                                    clientInstanceKeyTag: clientInstanceKeyTag)
    }

    func createPolicy(id: String = "id",
                      userVerification: AuthenticatorMetaDataModel.Settings.UserVerificationSetting = .preferred,
                      methods: [AuthenticatorMethod] = [.push]) -> AuthenticatorPolicy {
        let metadata = TestUtils.createAuthenticatorMetadataModel(id: id,
                                                                  userVerification: userVerification,
                                                                  methods: methods)
        return AuthenticatorPolicy(metadata: metadata)
    }

    func createPushFactor(userVerification: Bool = true) -> OktaFactorMetadataPush {
        return OktaFactorMetadataPush(id: UUID().uuidString,
                                      proofOfPossessionKeyTag: UUID().uuidString,
                                      userVerificationKeyTag: userVerification ? UUID().uuidString : nil)
    }

    func createAuthenticator(orgHost: String = "test.host",
                             orgId: String = "testOrgId",
                             serverError: ServerErrorCode? = nil,
                             enrollmentId: String = UUID().uuidString,
                             userId: String = UUID().uuidString,
                             createdDate: String? = nil,
                             enrolledFactors: [OktaFactor] = [],
                             methodTypes: [AuthenticatorMethod] = [],
                             cryptoManager: OktaSharedCryptoProtocol = CryptoManagerMock(accessGroupId: ExampleAppConstants.appGroupId, logger: OktaLoggerMock()),
                             storageManager: PersistentStorageProtocol? = nil) -> AuthenticatorEnrollment {
        let mockHTTPClient = MockMultipleRequestsHTTPClient(responseArray: [],
                                                            dataArray: [])
        let restAPIMock = RestAPIMock(client: mockHTTPClient, logger: OktaLoggerMock())
        var factors = [OktaFactor]()
        if !enrolledFactors.isEmpty {
            factors = enrolledFactors
        }

        if methodTypes.contains(.push) {
            let pushMetadata = OktaFactorMetadataPush(id: "push_id",
                                                      proofOfPossessionKeyTag: "proofOfPossessionKeyTag",
                                                      userVerificationKeyTag: nil,
                                                      links: OktaFactorMetadataPush.Links(pendingLink: "pendingLink"))
            let pushFactor = OktaFactorPush(factorData: pushMetadata,
                                            cryptoManager: cryptoManager,
                                            restAPIClient: restAPIMock,
                                            logger: OktaLoggerMock())
            factors.append(pushFactor)
        }

        var storage: PersistentStorageProtocol!
        if let storageManager = storageManager {
            storage = storageManager
        } else {
            storage = StorageMock()
        }

        let config = ApplicationConfig(applicationName: "Test App",
                                       applicationVersion: "1.0.0",
                                       applicationGroupId: ExampleAppConstants.appGroupId)
        let enrollment = AuthenticatorEnrollmentMock(organization: Organization(id: orgId, url: URL(string: orgHost)!),
                                                     user: User(id: userId, name: "test_user"),
                                                     enrollmentId: enrollmentId,
                                                     deviceId: "deviceId",
                                                     serverError: serverError,
                                                     creationDate: DateFormatter.oktaDateFormatter().date(from: createdDate ?? "") ?? Date(),
                                                     enrolledFactors: factors,
                                                     cryptoManager: cryptoManager,
                                                     restAPIClient: restAPIMock,
                                                     storageManager: storage,
                                                     applicationConfig: config,
                                                     logger: OktaLoggerMock())

        return enrollment
    }
}
