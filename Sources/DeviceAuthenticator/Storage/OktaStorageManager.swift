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
import OktaJWT
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif

protocol PersistentStorageProtocol: OktaEnrollmentStorageProtocol, OktaDeviceEnrollmentStorageProtocol, AuthenticatorPolicyStorageProtocol { }

struct OktaStorageBackupMetadata: OktaStorageBackup {
    let storages: [OktaRestorableStorage]
    let backups: [OktaStorageBackup]
}

/// Main storage entry point, handles multiple read / write destinations
class OktaStorageManager: PersistentStorageProtocol {
    let storage: PersistentStorageProtocol
    let logger: OktaLoggerProtocol
    var storageMigrator: OktaStorageMigrator

    init(restApiClient: ServerAPIProtocol,
         applicationConfig: ApplicationConfig,
         logger: OktaLoggerProtocol) throws {
        do {
            // Use keychain API for checking validity of application group id
            _ = try OktaSecureStorage().getData(key: "dummy_key",
                                                biometricPrompt: nil,
                                                accessGroup: applicationConfig.applicationInfo.keychainGroupId)
        } catch {
            let nsError = error as NSError
            if nsError.code == errSecMissingEntitlement {
                logger.error(eventName: "Invalid app groupd id entitlement provided", message: "Failed to create keychain storage error: \(nsError)")
                throw DeviceAuthenticatorError.storageError(StorageError.missingAppGroupEntitlement)
            }
        }

        self.storage = try Self.storage(restAPIClient: restApiClient,
                                        applicationConfig: applicationConfig,
                                        logger: logger)

        self.storageMigrator = OktaStorageMigrator(logger: logger)
        self.logger = logger
    }

    func hasPendingUnderlyingStorageMigration() -> Bool {
        if let sqliteStorage = storage as? OktaSharedSQLite,
           let isMigrationToTargetVersionNeeded = try? storageMigrator.isMigrationToTargetVersionNeeded(migratableStorage: sqliteStorage,
                                                                                                        type: OktaSharedSQLite.self) {
            return isMigrationToTargetVersionNeeded
        } else {
            return false
        }
    }

    func performStorageMigrationToTargetVersion() throws {
        if let sqliteStorage = storage as? OktaSharedSQLite {
            try storageMigrator.migrateToTargetVersion(migratableStorage: sqliteStorage, type: OktaSharedSQLite.self)
        }
    }

    static func storage(restAPIClient: ServerAPIProtocol,
                        applicationConfig: ApplicationConfig,
                        logger: OktaLoggerProtocol) throws -> PersistentStorageProtocol {
        let cryptoManager = OktaCryptoManager(keychainGroupId: applicationConfig.applicationInfo.keychainGroupId, logger: logger)
        let path = DeviceAuthenticatorConstants.defaultStorageRelativeDirectoryPath
        let fileName = DeviceAuthenticatorConstants.defaultStorageName
        let sqliteEncryptionManager = OktaSQLiteEncryptionManager(cryptoManager: cryptoManager,
                                                                  keychainGroupId: applicationConfig.applicationInfo.keychainGroupId)
        let sqliteStorage = try OktaSQLitePersistentStorage.sqlitePersistentStorage(schemaVersion: Self.targetVersion,
                                                                                    storageRelativePath: "\(path)/\(fileName)",
                                                                                    applicationGroupId: applicationConfig.applicationInfo.applicationGroupId,
                                                                                    sqliteFileEncryptionKey: nil,
                                                                                    logger: logger)
        let sqliteStorageManager = OktaSharedSQLite(sqlitePersistentStorage: sqliteStorage,
                                                    cryptoManager: cryptoManager,
                                                    restAPIClient: restAPIClient,
                                                    sqliteColumnEncryptionManager: sqliteEncryptionManager,
                                                    applicationConfig: applicationConfig,
                                                    logger: logger)

        return sqliteStorageManager
    }

    // MARK: Versioning and Migraiton
    public static let targetVersion = SQLiteStorageVersion.v1
}

extension OktaStorageManager: OktaEnrollmentStorageProtocol {

    public func storeEnrollment(_ enrollment: AuthenticatorEnrollmentProtocol) throws {
        try storage.storeEnrollment(enrollment)
    }

    public func deleteEnrollment(_ enrollment: AuthenticatorEnrollmentProtocol) throws {
        try storage.deleteEnrollment(enrollment)
    }

    public func deleteAllEnrollments() throws {
        try storage.deleteAllEnrollments()
    }

    public func allEnrollments() -> [AuthenticatorEnrollmentProtocol] {
        return storage.allEnrollments()
    }

    public func enrollmentById(enrollmentId: String) -> AuthenticatorEnrollmentProtocol? {
        return storage.enrollmentById(enrollmentId: enrollmentId)
    }

    public func enrollmentsByOrgId(_ orgId: String) -> [AuthenticatorEnrollmentProtocol] {
        return storage.enrollmentsByOrgId(orgId)
    }

    var enrollmentsCount: Int? {
        return storage.enrollmentsCount
    }
}

extension OktaStorageManager: OktaDeviceEnrollmentStorageProtocol {

    public func allDeviceEnrollmentsOrgIds() throws -> [String] {
        return try storage.allDeviceEnrollmentsOrgIds()
    }

    public func storeDeviceEnrollment(_ deviceEnrollment: OktaDeviceEnrollment, for orgId: String) throws {
        try storage.storeDeviceEnrollment(deviceEnrollment, for: orgId)
    }

    public func deviceEnrollmentByOrgId(_ orgId: String) throws -> OktaDeviceEnrollment {
        return try storage.deviceEnrollmentByOrgId(orgId)
    }

    public func deleteDeviceEnrollmentForOrgId(_ orgId: String) throws {
        try storage.deleteDeviceEnrollmentForOrgId(orgId)
    }
}

extension OktaStorageManager: AuthenticatorPolicyStorageProtocol {

    public func allAuthenticatorPoliciesOrgIds() throws -> [String] {
        return try storage.allAuthenticatorPoliciesOrgIds()
    }

    public func storeAuthenticatorPolicy(_ authenticationPolicy: AuthenticatorPolicyProtocol, orgId: String) throws {
        try storage.storeAuthenticatorPolicy(authenticationPolicy, orgId: orgId)
    }

    public func authenticatorPolicyForOrgId(_ orgId: String) throws -> AuthenticatorPolicyProtocol {
        return try storage.authenticatorPolicyForOrgId(orgId)
    }

    public func deleteAuthenticatorPolicyForOrgId(_ orgId: String) throws {
        try storage.deleteAuthenticatorPolicyForOrgId(orgId)
    }
}
