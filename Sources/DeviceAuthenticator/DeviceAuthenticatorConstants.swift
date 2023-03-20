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

/// SDK constants
public struct DeviceAuthenticatorConstants {
    /// DeviceAuthenticator SDK version
    public static let version = "1.0.0"
    /// DeviceAuthenticator SDK name
    public static let name = "DeviceAuthenticator"
    /// Location of shared SQLite database
    public static let defaultStorageRelativeDirectoryPath = "Library/DeviceSDK/SQLite"
    /// Filename of SQLite database
    public static let defaultStorageName = "db"
}
