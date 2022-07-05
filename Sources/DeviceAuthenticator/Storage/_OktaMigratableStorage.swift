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

/// Abstraction for migratable, versioned models / persistent storages.
public protocol _OktaMigratableStorage {
    /// A type that represents storage Version
    associatedtype Version: _OktaVersionType

    /// Data Representation version from disk
    var lastKnownVersion: Version { get }

    /// Current code business-logic expected storage version to deal with
    static var targetVersion: Version { get }

    /// This method gets called  before migration routine gets executed.
    /// If function throws an error, migration will not start.
    /// - Parameter startVersion: Starting version to be migrated to after migration routine is finished.
    /// - Parameter endVersion: Version to be migrated after migration routine is finished.
    func willStartIncrementalStorageMigrationSequence(startVersion: Version, endVersion: Version) throws

    /// This method gets called  during migration routine is executing. Upon`return` from this method it is expected that `OktaMigratableStorage` becomes upgraded to `nextVersion`. For cascade migration (v.1 -> v.5) this method gets called multiple times, each time `nextVersion` is going to be: `v.2`, `v.3`, `v.4`, `v.5`
    /// - Parameter nextVersion: Guaranteed to be +1 from the curent version, as well as +1 from the last `nextVersion`.
    func performIncrementalStorageMigration(_ nextVersion: Version) throws

    /// This method gets called  after migration routine is finished.
    /// - Parameter startVersion: Starting version to be migrated to after migration routine is finished.
    /// - Parameter endVersion: Version to be migrated after migration routine is finished.
    func didFinishStorageIncrementalMigrationSequence(startVersion: Version, endVersion: Version)
}
