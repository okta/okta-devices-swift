/*
* Copyright (c) 2022-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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

///  Each account may have multiple associated factors for authentication
enum AuthenticationMethodType: Int, Codable {
    ///  Time-based one time password factor
    case totp
    ///  Push Notification factor
    case push
    ///  Possession factor for use on this device
    case signedNonce
    ///  Factor type not yet known to this verison of the SDK
    case unknown

    func toString() -> String {
        switch self {
        case .totp: return "TOTP"
        case .push: return "Push"
        case .signedNonce: return "SignedNonce"
        case .unknown: return "Unknown"
        }
    }
}
