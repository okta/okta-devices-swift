/*
* Copyright (c) 2022, Okta, Inc. and/or its affiliates. All rights reserved.
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

/// Set of settings associated with the authenticator object
public struct DeviceAuthenticatorConfig {
    /// Organization URL, for example atko.okta.com
    public let orgURL: URL
    /// Authenticator key, for example "custom_app"
    public let authenticatorKey: String
    /// OIDC application id linked to authenticator
    public let oidcClientId: String

    public init(orgURL: URL, oidcClientId: String) {
        let scheme = "https://"
        var preprocessURL = orgURL
        if preprocessURL.scheme == nil {
            preprocessURL = URL(string: scheme + preprocessURL.absoluteString) ?? orgURL
            self.orgURL = URL(string: scheme + preprocessURL.hostString) ?? orgURL
        } else {
            self.orgURL = URL(string: scheme + preprocessURL.hostString) ?? orgURL
        }
        self.oidcClientId = oidcClientId
        self.authenticatorKey = InternalConstants.customAuthenticatorKey
    }
}
