/*
* Copyright (c) 2023, Okta, Inc. and/or its affiliates. All rights reserved.
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

/// Access token response from the IDP
public struct Oauth2Credential: Codable {
    /// The access token string as issued by the IDP
    public let access_token: String
    /// The type of token, typycally "Bearer"
    public let token_type: String
    /// The duration of time the access token is granted for
    public let expires_in: String?
    /// Optional refresh token, used for obtaining another access token
    public let refresh_token: String?
    /// Optional scope granted by the IDP
    public let scope: String?
}
