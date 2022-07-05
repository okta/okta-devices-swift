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

/// Represents iOS push device token
public enum DeviceToken {
    /// Device token value is not available yet
    case empty
    /// Device token data from AppDelegate
    case tokenData(Data)
    /// String representation of device token. Note that each byte from data stream should be converted to hex string. Example of device token in String format: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    case tokenString(String)

    var rawValue: String {
        switch self {
        case .empty:
            return ""
        case .tokenData(let value):
            return value.hexString()
        case .tokenString(let value):
            return value
        }
    }
}
