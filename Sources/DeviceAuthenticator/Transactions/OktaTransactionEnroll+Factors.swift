/*
* Copyright (c) 2019-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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

extension OktaTransactionEnroll {

    func createEnrolledPushFactor(from factorModels: [EnrollingFactor],
                                  and enrolledModel: EnrolledAuthenticatorModel.AuthenticatorMethods) -> OktaFactorMetadata? {
        guard let factorModel = factorModels.first(where: { $0.methodType == .push }),
              let proofOfPossessionKeyTag = factorModel.proofOfPossessionKeyTag else {
            return nil
        }

        let links = enrolledModel.links ?? EnrolledAuthenticatorModel.AuthenticatorMethods.Links(pending: nil)
        let factor = OktaFactorMetadataPush(id: enrolledModel.id,
                                            proofOfPossessionKeyTag: proofOfPossessionKeyTag,
                                            userVerificationKeyTag: factorModel.userVerificationKeyTag,
                                            links: OktaFactorMetadataPush.Links(pendingLink: links.pending?.href))
        return factor
    }

    func createEnrollingFactorModel(with popKeyTag: String?,
                                    uvKeyTag: String?,
                                    methodType: AuthenticatorMethod,
                                    pushToken: String?) throws -> EnrollingFactor {
        // Note: for update operation we need to rebuild the whole Factor object
        var proofOfPossessionJWK: [String: _OktaCodableArbitaryType]? = nil
        let proofOfPossessionKeyTag: String
        var userVerificationKeyTag: String!
        if let tag = popKeyTag {
            proofOfPossessionKeyTag = tag
            proofOfPossessionJWK = try registerKey(with: .ES256, keyTag: proofOfPossessionKeyTag, reuseKey: true)
        } else {
            // register new key
            proofOfPossessionKeyTag = UUID().uuidString
            proofOfPossessionJWK = try registerKey(with: .ES256, keyTag: proofOfPossessionKeyTag)
        }

        var userVerificationEncodableValue: UserVerificationEncodableValue?
        if let tag = uvKeyTag {
            // Existing key tag found. Check key health to decide if it can be re-used.
            if cryptoManager.isPrivateKeyAvailable(tag) {
                userVerificationKeyTag = tag
                let userVerificationJWK = try registerKey(with: .ES256,
                                                          keyTag: userVerificationKeyTag,
                                                          reuseKey: true,
                                                          useBiometrics: true,
                                                          biometricSettings: enrollmentContext.biometricSettings)
                userVerificationEncodableValue = UserVerificationEncodableValue.keyValue(userVerificationJWK)
            }
        }

        if let enrollUserVerificationKey = enrollmentContext.enrollBiometricKey {
            if enrollUserVerificationKey {
                if userVerificationKeyTag == nil {
                    // register new key
                    userVerificationKeyTag = UUID().uuidString
                    let userVerificationJWK = try registerKey(with: .ES256,
                                                              keyTag: userVerificationKeyTag,
                                                              useBiometrics: true,
                                                              biometricSettings: enrollmentContext.biometricSettings)
                    userVerificationEncodableValue = UserVerificationEncodableValue.keyValue(userVerificationJWK)
                }
            } else {
                userVerificationKeyTag = nil
                userVerificationEncodableValue = UserVerificationEncodableValue.null
            }
        }

        var signingKeys: SigningKeysModel? = nil
        if proofOfPossessionJWK != nil || userVerificationEncodableValue != nil {
            signingKeys = SigningKeysModel(proofOfPossession: proofOfPossessionJWK,
                                           userVerification: userVerificationEncodableValue)
        }

        let apsEnvironment = applicationConfig.pushSettings.apsEnvironment == .production ? APSEnvironment.production : APSEnvironment.development
        let enrollingFactor = EnrollingFactor(proofOfPossessionKeyTag: proofOfPossessionKeyTag,
                                              userVerificationKeyTag: userVerificationKeyTag,
                                              methodType: methodType,
                                              apsEnvironment: methodType == .push ? apsEnvironment : nil,
                                              pushToken: pushToken,
                                              supportUserVerification: nil,
                                              isFipsCompliant: nil,
                                              keys: signingKeys)

        return enrollingFactor
    }

    func factorTypeFromAuthenticatorMethod(_ method: AuthenticatorMethod) -> AuthenticationMethodType {
        switch method {
        case .signedNonce:
            return .signedNonce
        case .push:
            return .push
        case .totp:
            return .totp
        case .unknown(_):
            return .unknown
        }
    }
}
