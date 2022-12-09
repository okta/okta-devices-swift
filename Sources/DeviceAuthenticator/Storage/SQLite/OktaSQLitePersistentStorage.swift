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
import GRDB
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif

class OktaSQLitePersistentStorage: OktaSQLitePersistentStorageProtocol {
    let schemaVersion: DeviceSDKStorageVersion
    let fileManager: FileManager
    let logger: OktaLoggerProtocol
    let sqliteURL: URL
    let sqliteConnectionBuilder: OktaSQLiteConnectionBuilderProtocol
    let sqliteFileEncryptionKey: Data?

    lazy var sqlitePool: DatabasePool? = {
        do {
            let hasDBStored = sqliteFileExist()
            if !hasDBStored {
                try fileManager.createDirectory(at: sqliteURL.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: nil)
            }
            let sharedSqlitePool = try openSQLitePool()
            if !hasDBStored {
                try initSQLiteFiles()
            }
            return sharedSqlitePool
        } catch {
            logger.error(eventName: "Error on sqlitePool initialization", message: "Error: \(error)")
        }
        return nil
    }()

    static func sqlitePersistentStorage(schemaVersion: DeviceSDKStorageVersion,
                                        storageRelativePath: String,
                                        applicationGroupId: String,
                                        fileManager: FileManager = FileManager.default,
                                        sqliteFileEncryptionKey: Data?,
                                        logger: OktaLoggerProtocol) throws -> OktaSQLitePersistentStorage {
        // Do SQLite OktaSQLitePersistentStorage caching to specific sqlite file since
        // only one connection per sql file is allowed within a single process
        guard let url = fileManager.containerURL(forSecurityApplicationGroupIdentifier: applicationGroupId)?.appendingPathComponent(storageRelativePath) else {
            throw DeviceAuthenticatorError.internalError("Can't find shared sqlite location for app group id: \(applicationGroupId), relative path: \(storageRelativePath)")
        }
        if let cachedStorage = Self.urlToSQLitePersistentStorageCache[url],
            cachedStorage.sqliteFileExist() {
            return cachedStorage
        } else {
            let result = OktaSQLitePersistentStorage(at: url, schemaVersion: schemaVersion, fileManager: fileManager, sqliteFileEncryptionKey: sqliteFileEncryptionKey, logger: logger)
            self.urlToSQLitePersistentStorageCache[url] = result
            return result
        }
    }

    static var urlToSQLitePersistentStorageCache = [URL: OktaSQLitePersistentStorage]()

    init(at sqliteURL: URL,
         schemaVersion: DeviceSDKStorageVersion,
         fileManager: FileManager = FileManager.default,
         connectionBuilder: OktaSQLiteConnectionBuilderProtocol = OktaSQLiteConnectionBuilder(),
         sqliteFileEncryptionKey: Data?,
         logger: OktaLoggerProtocol) {
        self.sqliteURL = sqliteURL
        self.schemaVersion = schemaVersion
        self.fileManager = fileManager
        self.sqliteConnectionBuilder = connectionBuilder
        self.sqliteFileEncryptionKey = sqliteFileEncryptionKey
        self.logger = logger
    }

    private func openSQLitePool() throws -> DatabasePool? {
        logger.info(eventName: "SQLiteConnectionOpen", message: "Attempt to open SQLite connection at \(sqliteURL)")
        let coordinator = NSFileCoordinator(filePresenter: nil)
        var coordinatorError: NSError?
        var dbPool: DatabasePool? = nil
        var dbError: Error?
        let coordinationBlock: (URL) -> Void = { [weak self] url in
            do {
                if let encryptionkey = self?.sqliteFileEncryptionKey {
                    dbPool = try self?.sqliteConnectionBuilder.encryptedDatabasePool(at: url, sqliteFileEncryptionKey: encryptionkey)
                } else {
                    dbPool = try self?.sqliteConnectionBuilder.databasePool(at: url)
                }
            } catch {
                dbError = error
            }
        }
        coordinator.coordinate(writingItemAt: sqliteURL, options: .forMerging, error: &coordinatorError, byAccessor: coordinationBlock)
        if let error = dbError ?? coordinatorError {
            throw DeviceAuthenticatorError.storageError(.sqliteError(error.localizedDescription))
        }

        return dbPool
    }

    func sqliteFileExist() -> Bool {
        return fileManager.fileExists(atPath: sqliteURL.path)
    }

    fileprivate func initSQLiteFiles() throws {
        let hasDBStored = sqliteFileExist()
        guard hasDBStored, let sqlitePool = self.sqlitePool else {
            throw DeviceAuthenticatorError.internalError("Can't open SQLite connection")
        }

        try sqlitePool.write { db in
            try db.execute(sql: schemaVersion.sqliteSchema())
            try db.execute(sql: "PRAGMA user_version=\(schemaVersion.rawValue)")
        }
    }

}
