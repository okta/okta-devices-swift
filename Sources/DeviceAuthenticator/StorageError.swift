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

/// Errors that may occur in the process of storage operations
public enum StorageError: Error {
    /// Thrown when SDK fails to read object from storage
    case itemNotFound
    /// Thrown when SDK detects that access group setting is invalid
    case missingAppGroupEntitlement
    /// Thrown when SDK fails to migrate data to a new version of storage schema
    case storageMigrationError(String)
    /// Thrown when SDK fails to perform operations on sqlite database
    case sqliteError(String)
    /// Thrown for cases that can't be mapped to specific error domains
    case generalStorageError(String)
}

public extension StorageError {

    var errorDescription: String {
        switch self {
        case .itemNotFound:
            return "Item not found"
        case .missingAppGroupEntitlement:
            return "Missing or incorrect app group entitlement"
        case .storageMigrationError(let description):
            return description
        case .sqliteError(let description):
            return description
        case .generalStorageError(let description):
            return description
        }
    }
}

extension StorageError: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        switch (lhs, rhs) {
            case (.itemNotFound, .itemNotFound):
                return true
            case (let .storageMigrationError(description1), let .storageMigrationError(description2)):
                return description1 == description2
            case (let .sqliteError(description1), let .sqliteError(description2)):
                return description1 == description2
            case (let .generalStorageError(description1), let .generalStorageError(description2)):
                return description1 == description2
            default:
                return false
        }
    }
}
