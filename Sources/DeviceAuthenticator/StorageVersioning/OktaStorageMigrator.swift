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
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif

class OktaStorageMigrator {

    let logger: OktaLoggerProtocol

    public init(logger: OktaLoggerProtocol) {
        self.logger = logger
    }

    func isMigrationToTargetVersionNeeded<T>(migratableStorage: T, type: T.Type) throws -> Bool where T: OktaMigratableStorage {
        let storageLastKnownVersion = migratableStorage.lastKnownVersion
        let storageTargetVersion = type.targetVersion

        guard storageTargetVersion >= storageLastKnownVersion else {
            let error = DeviceAuthenticatorError.storageError(.storageMigrationError("Storage is not backward compatible! Current version: \(storageTargetVersion), last known version: \(storageLastKnownVersion) for \(type)"))
            logger.error(eventName: "Migration Error", message: "\(error)")
            throw error
        }

        guard storageTargetVersion != storageLastKnownVersion else {
            logger.info(eventName: "Migration", message: "No storage migration needed. Current version: \(storageTargetVersion), last known version: \(storageLastKnownVersion) for \(type)")
            return false
        }

        let unknownVersion = type.Version.unknownVersion
        guard storageTargetVersion != unknownVersion else {
            let error = DeviceAuthenticatorError.storageError(.storageMigrationError("Current storage version can't be \(unknownVersion). Specify the current storage version for \(type)"))
            logger.error(eventName: "Migration Error", message: "\(error)")
            throw error
        }
        return true
    }

    /// Starts migration from `migratableStorage`'s `lastKnownVersion` to `targetVersion`
    /// Breaks down a migration routine into a subsequence of smaller migrations, so that
    /// Ensures that `lastKnownVersion` and `targetVersion` are not `.unknown`, not equal and `targetVersion` > `lastKnownVersion`
    func migrateToTargetVersion<T>(migratableStorage: T, type: T.Type) throws where T: OktaMigratableStorage {
        let storageLastKnownVersion = migratableStorage.lastKnownVersion
        guard storageLastKnownVersion != .unknownVersion else {
            throw DeviceAuthenticatorError.storageError(.storageMigrationError("Current storage version can't be unknown"))
        }
        let storageTargetVersion = type.targetVersion
        guard try isMigrationToTargetVersionNeeded(migratableStorage: migratableStorage, type: type) else {
            migratableStorage.didFinishStorageIncrementalMigrationSequence(startVersion: storageLastKnownVersion, endVersion: storageTargetVersion)
            return
        }

        // Perform migration from the last known version to the current version declared by versionable storage, one-by-one in "cascade" fashion
        do {
            try migratableStorage.willStartIncrementalStorageMigrationSequence(startVersion: storageLastKnownVersion, endVersion: storageTargetVersion)
            for version in storageLastKnownVersion.nextVersion()...storageTargetVersion {
                try migratableStorage.performIncrementalStorageMigration(version)
            }
        } catch {
            logger.error(eventName: "Migration Error", message: "\(error)")
            throw error
        }
        migratableStorage.didFinishStorageIncrementalMigrationSequence(startVersion: storageLastKnownVersion, endVersion: storageTargetVersion)
    }

}

