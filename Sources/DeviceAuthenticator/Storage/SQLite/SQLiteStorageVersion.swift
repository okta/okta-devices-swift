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

enum SQLiteStorageVersion: Int, OktaVersionType {
    case unknown = -1
    case v1 = 1

    static var unknownVersion: SQLiteStorageVersion { return .unknown }

    static var latestVersion: Self {
        let allCases = Self.allCases.sorted()
        return allCases.last ?? .unknown
    }

    func schema() -> String {
        switch self {
        case .unknown:
            return ""
        case .v1:
            return sqliteBaseSchema
        /*
        Example of schema migration to v2
        case .v2:
            return SQLiteStorageVersion.v1.schema() + sqliteSchemaMigration_v2
        */
        }
    }
}