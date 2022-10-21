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
import OktaLogger
import GRDB

///  Implements object-level storage in SQLite
class OktaSharedSQLite: OktaSharedSQLiteProtocol {
    struct Constants {
        static let storageVersionKey = "DeviceSDK_SQLiteStorageVersion"
    }

    var sqlitePersistentStorage: OktaSQLitePersistentStorageProtocol
    let sqliteColumnEncryptionManager: OktaSQLiteColumnEncryptionManagerProtocol
    let restAPIClient: ServerAPIProtocol
    let cryptoManager: OktaSharedCryptoProtocol
    let applicationConfig: ApplicationConfig
    let logger: OktaLoggerProtocol

    init(sqlitePersistentStorage: OktaSQLitePersistentStorageProtocol,
         cryptoManager: OktaSharedCryptoProtocol,
         restAPIClient: ServerAPIProtocol,
         sqliteColumnEncryptionManager: OktaSQLiteColumnEncryptionManagerProtocol,
         applicationConfig: ApplicationConfig,
         logger: OktaLoggerProtocol) {
        self.sqlitePersistentStorage = sqlitePersistentStorage
        self.restAPIClient = restAPIClient
        self.cryptoManager = cryptoManager
        self.sqliteColumnEncryptionManager = sqliteColumnEncryptionManager
        self.applicationConfig = applicationConfig
        self.logger = logger
    }

    // MARK: Versioning and Migraiton
    public static let targetVersion = DeviceSDKStorageVersion.v2
    public var lastKnownVersion: Version {
        if !sqlitePersistentStorage.sqliteFileExist() {
            // if there is no SQLite stored yet, return Self.targetVersion right away to avoid
            // triggering of sqlite file creation in a lazy manner, before the actual SQLite db use
            return Self.targetVersion
        }
        var sqlUserVersion: Int?
        do {
            try sqlitePersistentStorage.sqlitePool?.read { db in
                sqlUserVersion = try Int.fetchOne(db, sql: "PRAGMA user_version")
            }
        } catch {
            logger.error(eventName: "Can't read SQLite db version", message: "Error: \(error)")
        }
        if let versionNumber = sqlUserVersion, let version = DeviceSDKStorageVersion(rawValue: versionNumber) {
            return version
        }
        return .unknown
    }

    func enrollmentStatementWriteArguments(_ enrollment: AuthenticatorEnrollmentProtocol) throws -> StatementArguments {
        guard let enrollment = enrollment as? AuthenticatorEnrollment else {
            throw DeviceAuthenticatorError.storageError(StorageError.generalStorageError("Invalid enrollment object type"))
        }
        var encryptedUsername: Data? = nil
        if let userName = enrollment.user.name {
            do {
                encryptedUsername = try sqliteColumnEncryptionManager.encryptedColumnUTF8Data(from: userName)
            } catch {
                logger.error(eventName: "SQL encryption error", message: "Failed to encrypt Username: \(error)")
            }
        }
        let writeArguments = StatementArguments([
            Column.enrollmentId: enrollment.enrollmentId,
            Column.orgId: enrollment.organization.id,
            Column.serverErrorCode: enrollment.serverError?.rawValue,
            Column.orgUrl: enrollment.organization.url.absoluteString,
            Column.userId: enrollment.user.id,
            Column.username: encryptedUsername,
            Column.deviceId: enrollment.deviceId,
            Column.updatedTimestamp: Date(),
            Column.createdTimestamp: enrollment.creationDate
        ])
        return writeArguments
    }

    func storeEnrollment(_ enrollment: AuthenticatorEnrollmentProtocol, oldEnrollment: AuthenticatorEnrollmentProtocol?, writeArguments: StatementArguments, db: Database) throws {
        guard let enrollment = enrollment as? AuthenticatorEnrollment else {
            throw DeviceAuthenticatorError.storageError(StorageError.generalStorageError("Invalid enrollment object type"))
        }

        do {
            // Remove EnrolledMethods for an old enrollmentId in case if previous Enrollment is already stored
            // An old Enrollment itself will be replaced by `REPLACE INTO` SQL statement below
            if let enrollmentDuplicate = oldEnrollment {
                try db.execute(
                    sql: "DELETE from EnrolledMethod WHERE enrollmentId = ? AND orgId = ?",
                    arguments: [enrollmentDuplicate.enrollmentId, enrollmentDuplicate.organization.id])
            }
            try db.execute(sql: "INSERT INTO Enrollment (enrollmentId, orgId, serverErrorCode, orgUrl, userId, username, deviceId, createdTimestamp, updatedTimestamp) VALUES (:enrollmentId, :orgId, :serverErrorCode, :orgUrl, :userId, :username, :deviceId, :createdTimestamp, :updatedTimestamp) ON CONFLICT(enrollmentId,orgId) DO UPDATE SET enrollmentId = :enrollmentId, orgId = :orgId, serverErrorCode = :serverErrorCode, orgUrl = :orgUrl, userId = :userId, username = :username, deviceId = :deviceId, updatedTimestamp = :updatedTimestamp", arguments: writeArguments)

            // Enrolled factors

            let factors: [OktaFactorMetadata] = buildFactorsMetadata(enrollment: enrollment)

            for factor in factors {
                let writeArguments = try factorStatementArgs(enrollmentId: enrollment.enrollmentId,
                                                             orgId: enrollment.organization.id,
                                                             factorData: factor,
                                                             creationDate: enrollment.creationDate)
                try db.execute(sql: "INSERT INTO EnrolledMethod (id, enrollmentId, orgId, type, proofOfPossessionKeyTag, userVerificationKeyTag, links, passCodeLength, timeIntervalSec, algorithm, sharedSecret, transactionTypes, createdTimestamp, updatedTimestamp) VALUES (:id, :enrollmentId, :enrollmentOrgId, :type, :proofOfPossessionKeyTag, :userVerificationKeyTag, :links, :passCodeLength, :timeIntervalSec, :algorithm, :sharedSecret, :transactionTypes, :createdTimestamp, :updatedTimestamp) ON CONFLICT(id,enrollmentId,orgId) DO UPDATE SET id = :id, enrollmentId = :enrollmentId, orgId = :enrollmentOrgId, type = :type, proofOfPossessionKeyTag = :proofOfPossessionKeyTag, userVerificationKeyTag = :userVerificationKeyTag, links = :links, passCodeLength = :passCodeLength, timeIntervalSec = :timeIntervalSec, algorithm = :algorithm, sharedSecret = :sharedSecret, transactionTypes = :transactionTypes, updatedTimestamp = :updatedTimestamp", arguments: writeArguments)
            }
        } catch {
            throw DeviceAuthenticatorError.storageError(StorageError.sqliteError(error.localizedDescription))
        }
    }

    func buildFactorsMetadata(enrollment: AuthenticatorEnrollment) -> [OktaFactorMetadata] {
        var factors: [OktaFactorMetadata] = []
        if let push = enrollment.pushFactor {
            factors.append(push.factorData)
        }

        return factors
    }

    func storeEnrollment(_ enrollment: AuthenticatorEnrollmentProtocol) throws {
        let writeArguments = try enrollmentStatementWriteArguments(enrollment)
        let enrollmentDuplicate = enrollmentByOrgId(enrollment.organization.id, userId: enrollment.user.id)
        do {
            try pool?.write({ db in
                try storeEnrollment(enrollment, oldEnrollment: enrollmentDuplicate, writeArguments: writeArguments, db: db)
            })
        } catch {
            throw DeviceAuthenticatorError.storageError(StorageError.sqliteError(error.localizedDescription))
        }
    }

    func deleteEnrollment(_ enrollment: AuthenticatorEnrollmentProtocol) throws {
        do {
            try pool?.write({ db in
                try db.execute(
                    sql: "DELETE from Enrollment WHERE enrollmentId = ? AND orgId = ?",
                    arguments: [enrollment.enrollmentId, enrollment.organization.id])

                try db.execute(
                    sql: "DELETE from EnrolledMethod WHERE enrollmentId = ? AND orgId = ?",
                    arguments: [enrollment.enrollmentId, enrollment.organization.id])
            })
        } catch {
            throw DeviceAuthenticatorError.storageError(StorageError.sqliteError(error.localizedDescription))
        }

        if enrollmentsByOrgId(enrollment.organization.id).isEmpty {
            // We just deleted the last enrollment for this org, clean up org-wide objects
            try? deleteDeviceEnrollmentForOrgId(enrollment.organization.id)
            try? deleteAuthenticatorPolicyForOrgId(enrollment.organization.id)
        }
    }

    func deleteAllEnrollments() throws {
        do {
            try pool?.write({ db in
                try db.execute(
                    sql: "DELETE from Enrollment")

                try db.execute(
                    sql: "DELETE from EnrolledMethod")

                try db.execute(
                    sql: "DELETE from AuthenticatorPolicy")

                try db.execute(
                    sql: "DELETE from DeviceEnrollment")
            })
        } catch {
            throw DeviceAuthenticatorError.storageError(StorageError.sqliteError(error.localizedDescription))
        }
    }

    func allEnrollments() -> [AuthenticatorEnrollmentProtocol] {
        var enrollments = [AuthenticatorEnrollmentProtocol]()
        do {
            try pool?.read({ db in
                let rows = try Row.fetchAll(db, sql: "SELECT * from Enrollment")
                for row in rows {
                    if let enrollment = enrollment(from: row, db: db) {
                        enrollments.append(enrollment)
                    }
                }
            })
        } catch {
            logger.error(eventName: "Error while getting all authenticators from SQLite", message: "Error: \(error)")
        }
        return enrollments
    }

    var enrollmentsCount: Int? {
        var count: Int?
        do {
            try pool?.read({ db in
                count = try Int.fetchOne(db, sql: "SELECT COUNT(*) from Enrollment")
            })
        } catch {
            logger.error(eventName: "Error while getting authenticators count from SQLite", message: "Error: \(error)")
        }
        return count
    }

    func enrollment(from row: Row, db: Database) -> AuthenticatorEnrollmentProtocol? {
        guard let enrollmentId = row.enrollmentId,
              let orgId = row.orgId,
              let orgUrlString = row.orgUrl,
              let orgUrl = URL(string: orgUrlString),
              let userId = row.userId,
              let deviceId = row.deviceId,
              let creationDate = row.created else {
            return nil
        }

        var factors = [OktaFactor]()
        if let factorRows = try? Row.fetchAll(db,
                                              sql: "SELECT * from EnrolledMethod where enrollmentId = ?", arguments: [enrollmentId]) {
            for factorRow in factorRows {
                if let factor = decodeFactorDataFromRow(factorRow) {
                    factors.append(factor)
                }
            }
        }
        var serverErrorCode: ServerErrorCode? = nil
        if let serverErrorCodeRaw = row.serverErrorCode {
            serverErrorCode = ServerErrorCode(raw: serverErrorCodeRaw)
        }
        var decryptedUsername: String? = nil
        if let encryptedUsername = row.username {
            do {
                decryptedUsername = try sqliteColumnEncryptionManager.decryptedColumnString(from: encryptedUsername)
            } catch {
                logger.error(eventName: "SQL decryption error", message: "Failed to decrypt Username: \(error)")
            }
        }

        return AuthenticatorEnrollment(organization: Organization(id: orgId, url: orgUrl),
                                       user: User(id: userId, name: decryptedUsername),
                                       enrollmentId: enrollmentId,
                                       deviceId: deviceId,
                                       serverError: serverErrorCode,
                                       creationDate: creationDate,
                                       enrolledFactors: factors,
                                       cryptoManager: cryptoManager,
                                       restAPIClient: restAPIClient,
                                       storageManager: self,
                                       applicationConfig: applicationConfig,
                                       logger: logger)
    }

    func enrollmentById(enrollmentId: String) -> AuthenticatorEnrollmentProtocol? {
        var result: AuthenticatorEnrollmentProtocol?
        do {
            try pool?.read { db in
                let rows = try Row.fetchAll(db, sql: "SELECT * from Enrollment where enrollmentId = ?", arguments: [enrollmentId])
                for row in rows {
                    if let enrollment = enrollment(from: row, db: db) {
                        result = enrollment
                        break
                    }
                }
            }
        } catch {
            logger.error(eventName: "Error while getting authenticator from SQLite", message: "Authenticator by enrollment ID: \(enrollmentId). Error: \(error)")
        }
        if result == nil {
            logger.warning(eventName: "Can't find authenticator", message: "Storage Manager can't find authenticator by enrollment ID: \(enrollmentId)")
        } else {
            logger.info(eventName: "Found authenticator", message: "Found authenticator with enrollment ID: \(enrollmentId)")
        }
        return result
    }

    // MARK: Enrollment groupings

    func enrollmentsByOrgId(_ orgId: String) -> [AuthenticatorEnrollmentProtocol] {
        var result = [AuthenticatorEnrollmentProtocol]()
        do {
            try pool?.read({ db in
                let rows = try Row.fetchAll(db, sql: "SELECT * from Enrollment where orgId = ?", arguments: [orgId])
                for row in rows {
                    if let enrollment = enrollment(from: row, db: db) {
                        result.append(enrollment)
                    }
                }
            })
        } catch {
            logger.error(eventName: "Error while getting authenticator from SQLite", message: "Authenticators by Org ID: \(orgId). Error: \(error)")
        }
        if result.isEmpty {
            logger.warning(eventName: "Can't find authenticators", message: "Storage Manager can't find authenticators by Org ID: \(orgId)")
        } else {
            logger.info(eventName: "Found authenticators", message: "Found \(result.count) authenticator(s): \(result) by Org ID: \(orgId)")
        }
        return result
    }

    func enrollmentByOrgId(_ orgId: String, userId: String) -> AuthenticatorEnrollmentProtocol? {
        var result: AuthenticatorEnrollmentProtocol? = nil
        do {
            try pool?.read { db in
                if let row = try Row.fetchOne(db, sql: "SELECT * from Enrollment where orgId = ? and userId = ?", arguments: [orgId, userId]) {
                    result = enrollment(from: row, db: db)
                }
            }
        } catch {
            logger.error(eventName: "Error while getting authenticator from SQLite", message: "Authenticator by Org ID: \(orgId) & User ID: \(userId). Error: \(error)")
        }
        if result == nil {
            logger.warning(eventName: "Can't find authenticator", message: "Storage Manager can't find authenticator by Org ID: \(orgId) & User ID: \(userId)")
        } else {
            logger.info(eventName: "Found authenticator", message: "Authenticator: \(String(describing: result)) by Org ID: \(orgId) & User ID: \(userId)")
        }

        return result
    }

    // MARK: DeviceEnrollment

    func allDeviceEnrollmentsOrgIds() throws -> [String] {
        var deviceEnrollmentOrgIds = [String]()
        do {
            try pool?.read { db in
                deviceEnrollmentOrgIds = try String.fetchAll(db, sql: "SELECT orgId FROM DeviceEnrollment")
            }
        } catch {
            let resultError = DeviceAuthenticatorError.storageError(.sqliteError(error.localizedDescription))
            logger.error(eventName: "Failed to retrieve all DeviceEnrollments orgIds from SQLite", message: "Error: \(resultError)")
            throw resultError
        }
        return deviceEnrollmentOrgIds
    }

    func deviceEnrollmentStatementWriteArguments(_ deviceEnrollment: OktaDeviceEnrollment, for orgId: String) -> StatementArguments {
        let currentDate = Date()
        let writeArguments = StatementArguments([
            Column.deviceId: deviceEnrollment.id,
            Column.orgId: orgId,
            Column.clientInstanceId: deviceEnrollment.clientInstanceId,
            Column.clientInstanceKeyTag: deviceEnrollment.clientInstanceKeyTag,
            Column.updatedTimestamp: currentDate,
            Column.createdTimestamp: currentDate
        ])
        return writeArguments
    }

    func storeDeviceEnrollment(writeArguments: StatementArguments, db: Database) throws {
        do {
            try db.execute(sql: "INSERT INTO DeviceEnrollment (deviceId, orgId, clientInstanceId, clientInstanceKeyTag, createdTimestamp, updatedTimestamp) VALUES (:deviceId, :orgId, :clientInstanceId, :clientInstanceKeyTag, :createdTimestamp, :updatedTimestamp) ON CONFLICT(deviceId,orgId) DO UPDATE SET deviceId = :deviceId, orgId = :orgId, clientInstanceId = :clientInstanceId, clientInstanceKeyTag = :clientInstanceKeyTag, updatedTimestamp = :updatedTimestamp ", arguments: writeArguments)
        } catch {
            throw DeviceAuthenticatorError.storageError(StorageError.sqliteError(error.localizedDescription))
        }
    }

    func storeDeviceEnrollment(_ deviceEnrollment: OktaDeviceEnrollment, for orgId: String) throws {
        let writeArguments = deviceEnrollmentStatementWriteArguments(deviceEnrollment, for: orgId)
        do {
            try pool?.write { db in
                try storeDeviceEnrollment(writeArguments: writeArguments, db: db)
            }
        } catch {
            throw DeviceAuthenticatorError.storageError(StorageError.sqliteError(error.localizedDescription))
        }
    }

    func deviceEnrollmentByOrgId(_ orgId: String) throws -> OktaDeviceEnrollment {
        var deviceEnrollmentRow: Row?
        do {
            try pool?.read { db in
                deviceEnrollmentRow = try Row.fetchOne(db,
                                                       sql: "SELECT * FROM DeviceEnrollment WHERE orgId = :orgId",
                                                       arguments: ["orgId": orgId])
            }
        } catch {
            throw DeviceAuthenticatorError.storageError(StorageError.sqliteError(error.localizedDescription))
        }

        guard let row = deviceEnrollmentRow else {
            throw DeviceAuthenticatorError.storageError(.sqliteError("SQLite can't fetch OktaDeviceEnrollment by orgId = \(orgId)"))
        }

        guard let deviceId = row.deviceId,
              let clientInstanceId = row.clientInstanceId,
              let clientInstanceKeyTag = row.clientInstanceKeyTag else {
            throw DeviceAuthenticatorError.storageError(.sqliteError("DeviceEnrollment for OrgId = \(orgId) missing required field(s)"))
        }

        return OktaDeviceEnrollment(id: deviceId,
                                    orgId: orgId,
                                    clientInstanceId: clientInstanceId,
                                    clientInstanceKeyTag: clientInstanceKeyTag)
    }

    func deleteDeviceEnrollmentForOrgId(_ orgId: String) throws {
        do {
            try pool?.write { db in
                try db.execute(sql: "DELETE FROM DeviceEnrollment WHERE orgId = :orgId",
                               arguments: ["orgId": orgId])
            }
        } catch {
            throw DeviceAuthenticatorError.storageError(StorageError.sqliteError(error.localizedDescription))
        }
    }

    // MARK: AuthenticatorPolicy

    func allAuthenticatorPoliciesOrgIds() throws -> [String] {
        var authenticatorPoliciesOrgIds = [String]()
        do {
            try pool?.read { db in
                authenticatorPoliciesOrgIds = try String.fetchAll(db, sql: "SELECT orgId FROM AuthenticatorPolicy")
            }
        } catch {
            let resultError = DeviceAuthenticatorError.storageError(.sqliteError(error.localizedDescription))
            logger.error(eventName: "Failed to retrieve all AuthenticatorPolicies orgIds from SQLite", message: "Error: \(resultError)")
            throw resultError
        }
        return authenticatorPoliciesOrgIds
    }

    func authenticatorPolicyStatementWriteArguments(_ authenticatorPolicy: AuthenticatorPolicyProtocol, orgId: String) throws -> StatementArguments {
        guard let authenticatorPolicy = authenticatorPolicy as? AuthenticatorPolicy else {
            throw DeviceAuthenticatorError.internalError("Failed to downcast policy to AuthenticatorPolicy")
        }
        // List active methods as a string (e.g. "totp, push")
        let activeMethodsStr = stringFromAuthenticatorMethods(authenticatorPolicy.methods)
        // UserVerificationSetting as Integer
        let userVerification = authenticatorPolicy.userVerificationSetting.rawValue
        // Policy metadata
        let data = try JSONEncoder().encode(authenticatorPolicy.metadata)
        let currentDate = Date()

        let writeArguments = StatementArguments([
            Column.policyId: authenticatorPolicy.metadata.id,
            Column.orgId: orgId,
            Column.activeMethods: activeMethodsStr,
            Column.userVerification: userVerification,
            Column.metadata: data,
            Column.updatedTimestamp: currentDate,
            Column.createdTimestamp: currentDate
        ])
        return writeArguments
    }

    func storeAuthenticatorPolicy(writeArguments: StatementArguments, db: Database) throws {
        do {
            try db.execute(sql: "INSERT INTO AuthenticatorPolicy (policyId, orgId, activeMethods, userVerification, metadata, createdTimestamp, updatedTimestamp) VALUES (:policyId, :orgId, :activeMethods, :userVerification, :metadata, :createdTimestamp, :updatedTimestamp) ON CONFLICT(policyId,orgId) DO UPDATE SET policyId = :policyId, orgId = :orgId, activeMethods = :activeMethods, userVerification = :userVerification, metadata = :metadata, updatedTimestamp = :updatedTimestamp", arguments: writeArguments)
        } catch {
            throw DeviceAuthenticatorError.storageError(StorageError.sqliteError(error.localizedDescription))
        }
    }

    func storeAuthenticatorPolicy(_ authenticatorPolicy: AuthenticatorPolicyProtocol, orgId: String) throws {
        let writeArguments = try authenticatorPolicyStatementWriteArguments(authenticatorPolicy, orgId: orgId)
        do {
            try pool?.write({ db in
                try storeAuthenticatorPolicy(writeArguments: writeArguments, db: db)
            })
        } catch {
            throw DeviceAuthenticatorError.storageError(StorageError.sqliteError(error.localizedDescription))
        }
    }

    func authenticatorPolicyForOrgId(_ orgId: String) throws -> AuthenticatorPolicyProtocol {
        var policy: AuthenticatorPolicy?
        do {
            try pool?.read({ db in
                if let row = try Row.fetchOne(db,
                                               sql: "SELECT * from AuthenticatorPolicy WHERE orgId = ?",
                                               arguments: [orgId]),
                   let data = row.metadata {
                    let decoder = JSONDecoder()
                    let metadata = try decoder.decode(AuthenticatorMetaDataModel.self, from: data)
                    let userVerification = row.userVerificationSetting
                    let methods = row.activeMethods
                    policy = AuthenticatorPolicy(metadata: metadata,
                                                 userVerification: userVerification,
                                                 methods: methods)
                }
            })
        } catch {
            logger.error(eventName: "Failed to retrieve all AuthenticatorPolicy by orgId from SQLite", message: "OrgId: \(orgId). Error: \(error)")
        }

        guard let authPolicy = policy else {
            throw DeviceAuthenticatorError.storageError(.itemNotFound)
        }
        return authPolicy
    }

    func deleteAuthenticatorPolicyForOrgId(_ orgId: String) throws {
        do {
            try pool?.write({ db in
                try db.execute(sql: "DELETE FROM AuthenticatorPolicy WHERE orgId = :orgId",
                               arguments: [Column.orgId: orgId])
            })
        } catch {
            throw DeviceAuthenticatorError.storageError(StorageError.sqliteError(error.localizedDescription))
        }
    }

    private func stringFromAuthenticatorMethods(_ methods: [AuthenticatorMethod]) -> String {
        return methods.compactMap({ $0.rawValue }).joined(separator: ",")
    }

    private var pool: DatabasePool? {
        return sqlitePersistentStorage.sqlitePool
    }

    func factorStatementArgs(enrollmentId: String,
                             orgId: String,
                             factorData: OktaFactorMetadata,
                             creationDate: Date) throws -> StatementArguments {

        // Initialize full data set with default values
        var args = StatementArguments([Column.id: factorData.id,
                                       Column.enrollmentId: enrollmentId,
                                       Column.enrollmentOrgId: orgId,
                                       Column.type: factorData.type.rawValue,
                                       Column.createdTimestamp: creationDate,
                                       Column.updatedTimestamp: Date(),
                                       Column.proofOfPossessionKeyTag: nil,
                                       Column.userVerificationKeyTag: nil,
                                       Column.links: nil,
                                       Column.passCodeLength: nil,
                                       Column.timeIntervalSec: nil,
                                       Column.algorithm: nil,
                                       Column.sharedSecret: nil,
                                       Column.transactionTypes: nil
        ])

        if let push = factorData as? OktaFactorMetadataPush {
            args = args &+ [Column.proofOfPossessionKeyTag: push.proofOfPossessionKeyTag]
            args = args &+ [Column.userVerificationKeyTag: push.userVerificationKeyTag]
            if let links = push.pushLinks {
                args = args &+ [Column.links: try? JSONEncoder().encode(links)]
            } else {
                args = args &+ [Column.links: nil]
            }
            if let transactionTypes = push.transactionTypes {
                args = args &+ [Column.transactionTypes: transactionTypes.rawValue]
            } else {
                args = args &+ [Column.transactionTypes: TransactionType.login.rawValue]
            }
        }

        return args
    }

    func decodeFactorDataFromRow(_ row: Row) -> OktaFactor? {
        guard let type = row.factorType, let id = row.id else {
            return nil
        }

        switch AuthenticationMethodType(rawValue: type) {
        case .push:
            guard let proofOfPossessionKeyTag = row.proofOfPossessionKeyTag else {
                return nil
            }
            var links: OktaFactorMetadataPush.Links?
            if let linksData = row.links {
                links = try? JSONDecoder().decode(OktaFactorMetadataPush.Links.self, from: linksData)
            }
            var transactionType: TransactionType
            if let transactionTypes = row.transactionTypes {
                transactionType = TransactionType(rawValue: transactionTypes)
            } else {
                transactionType = .login
            }
            let pushFactorMetadata = OktaFactorMetadataPush(id: id,
                                                            proofOfPossessionKeyTag: proofOfPossessionKeyTag,
                                                            userVerificationKeyTag: row.userVerificationKeyTag,
                                                            links: links,
                                                            transactionTypes: transactionType)
            return VerificationMethodFactory.pushFactorFromMetadata(pushFactorMetadata,
                                                                    cryptoManager: cryptoManager,
                                                                    restAPIClient: restAPIClient,
                                                                    logger: logger)
        default:
            logger.error(eventName: "Could not decode factor metadata from SQLite", message: "Failed to decode factor of type \(type)")
        }
        return nil
    }
}

extension OktaSharedSQLite: OktaMigratableStorage {
    typealias Version = DeviceSDKStorageVersion

    func willStartIncrementalStorageMigrationSequence(startVersion: Version, endVersion: Version) throws {
        logger.info(eventName: "Starting Storage Migration", message: "Start version: \(startVersion), end version: \(endVersion)")
    }

    func performIncrementalStorageMigration(_ nextVersion: Version) throws {
        //  "nextVersion" is guaranteed to be +1 from the "current" version
        //  By the end of this function execution, it is expected storage is migrated to "nextVersion"
        //  Upon every mid-version migration update DB's user_version, like:
        //  try db.execute(literal: "PRAGMA user_version = \(nextVersion.rawValue)")
        // TODO: Do each version migration within a single SQLite Transaction to make it auto Rolled-back in case of error
        switch nextVersion {
        case .v2:
            // Do nothing since SQLite has been introduced at v2 only, so no v1
            break
        default:
            break
        }
    }

    func didFinishStorageIncrementalMigrationSequence(startVersion: Version, endVersion: Version) {
        let logMessage = "Start version: \(startVersion), end version: \(endVersion)"
        logger.info(eventName: "Success for DeviceSDK Storage Migration", message: logMessage)
    }
}
