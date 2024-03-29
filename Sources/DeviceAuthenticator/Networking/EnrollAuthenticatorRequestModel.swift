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

import Foundation

struct EnrollAuthenticatorRequestModel: Encodable {
    let authenticatorId: String
    let key: String
    let device: DeviceSignalsModel?
    let appSignals: [String: _OktaCodableArbitaryType]?
    let methods: [AuthenticatorMethods]

    struct AuthenticatorMethods: Encodable {
        let type: AuthenticatorMethod
        let pushToken: String? // For Push factor
        let apsEnvironment: APSEnvironment?
        let supportUserVerification: Bool? // For TOTP factor
        let isFipsCompliant: Bool? // For TOTP
        let keys: SigningKeysModel?
        let capabilities: CapabilitiesModel?
    }
}
