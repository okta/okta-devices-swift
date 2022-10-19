/*
* Copyright (c) 2021-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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

class AuthenticatorPolicy: Codable, AuthenticatorPolicyProtocol {
    var userVerificationSetting: UserVerificationPolicySetting {
        guard let _userVerification = _userVerification else {
            return .preferred
        }

        switch _userVerification {
        case .preferred:
            return .preferred
        case .required:
            return .required
        case .unknown(let description):
            return .unknown(description)
        }
    }

    func hasMethod(ofType type: AuthenticationMethodType) -> Bool {
        return methods.contains(AuthenticatorMethod.convertFrom(method: type))
    }

    func hasActiveMethod(ofType type: AuthenticationMethodType) -> Bool {
        return metadata._embedded.methods.first(where: { $0.type == AuthenticatorMethod.convertFrom(method: type) && $0.status == "ACTIVE" }) != nil
    }

    /// - Description: Authenticator metadata
    let metadata: AuthenticatorMetaDataModel

    required init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        metadata = try values.decode(AuthenticatorMetaDataModel.self, forKey: .metadata)
        if let deserializedMethods = try? values.decode([AuthenticatorMethod].self, forKey: .methods) {
            methods = deserializedMethods
        } else {
            methods = metadata._embedded.methods.compactMap({ $0.type })
        }
        if let deserializedUserVerification = try? values.decode(AuthenticatorSettingsModel.UserVerificationSetting.self, forKey: ._userVerification) {
            _userVerification = deserializedUserVerification
        } else {
            _userVerification = metadata.settings?.userVerification
        }
    }

    init(metadata: AuthenticatorMetaDataModel,
         userVerification: AuthenticatorSettingsModel.UserVerificationSetting? = nil,
         methods: [AuthenticatorMethod]? = nil) {
        self.metadata = metadata
        self._userVerification = userVerification ?? metadata.settings?.userVerification
        self.methods = methods ?? metadata._embedded.methods.compactMap({ $0.type })
    }

    let methods: [AuthenticatorMethod]

    private let _userVerification: AuthenticatorSettingsModel.UserVerificationSetting?

    enum CodingKeys: String, CodingKey {
        case metadata
        case _userVerification
        case methods
    }
}

extension AuthenticatorMethod {
    static func convertFrom(method: AuthenticationMethodType) -> Self {
        switch method {
        case .push:
            return .push
        case .signedNonce:
            return .signedNonce
        case .totp:
            return .totp
        case .unknown:
            return .unknown("")
        }
    }
}
