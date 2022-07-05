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

import Foundation

public enum _UserMediationType: String {
    /// User Mediation and user verification should not be challenged
    case none = "NONE"
    /// Client should read it as User Mediation as discouraged for POP key
    case optional = "OPTIONAL"
    /// User Mediation needs to be challenged
    case required = "REQUIRED"
    /// Unknown value detected
    case unknown

    public init(rawValue: String) {
        switch rawValue {
        case "NONE":
            self = .none
        case "OPTIONAL":
            self = .optional
        case "REQUIRED":
            self = .required
        default:
            self = .unknown
        }
    }
}
