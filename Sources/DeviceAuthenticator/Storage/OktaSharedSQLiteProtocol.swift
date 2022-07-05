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
import OktaLogger

/// Represents physical .sqlite persistent storage file on disk
protocol OktaSQLitePersistentStorageProtocol {

    var sqlitePool: DatabasePool? { get set }
    var sqliteURL: URL { get }
    var fileManager: FileManager { get }
    var logger: OktaLoggerProtocol { get }

    /// Having this assigned should cause SQLite file be encrypted/decrypted by a key specified here
    /// Assigning to `nil`  means no file-level encryption will be applied, and DB will be stored in a readable way on disk
    var sqliteFileEncryptionKey: Data? { get }

    func sqliteFileExist() -> Bool
}

/// Business-logic oriented sqlite storage manager
protocol OktaSharedSQLiteProtocol: PersistentStorageProtocol {

    var sqlitePersistentStorage: OktaSQLitePersistentStorageProtocol { get }
}
