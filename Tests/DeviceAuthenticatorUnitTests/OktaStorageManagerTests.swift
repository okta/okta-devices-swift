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
import XCTest
@testable import DeviceAuthenticator

class OktaStorageManagerTests: XCTestCase {

#if os(iOS)
    func testStorageManager() throws {

        let applicationConfig = ApplicationConfig(applicationName: "",
                                                  applicationVersion: "",
                                                  applicationGroupId: ExampleAppConstants.appGroupId)
        let storageManager = try OktaStorageManager(restApiClient: RestAPIMock(client: HTTPClient(logger: OktaLoggerMock(), userAgent: ""),
                                                                               logger: OktaLoggerMock()),
                                                    applicationConfig: applicationConfig, logger: OktaLoggerMock())
        let storageMigratorMock = OktaStorageMigratorMock(logger: OktaLoggerMock())
        storageManager.storageMigrator = storageMigratorMock

        XCTAssertTrue(storageManager.hasPendingUnderlyingStorageMigration())
        XCTAssertTrue(storageMigratorMock.isMigrationToTargetVersionNeededCalled)

        try storageManager.performStorageMigrationToTargetVersion()
        XCTAssertTrue(storageMigratorMock.migrateToTargetVersionCalled)
    }
#endif
}

class OktaStorageMigratorMock: OktaStorageMigrator {
    var isMigrationToTargetVersionNeededCalled = false
    var migrateToTargetVersionCalled = false

    override func isMigrationToTargetVersionNeeded<T>(migratableStorage: T, type: T.Type) throws -> Bool where T: OktaMigratableStorage {
        isMigrationToTargetVersionNeededCalled = true
        return true
    }

    override func migrateToTargetVersion<T>(migratableStorage: T, type: T.Type) throws where T: OktaMigratableStorage {
        migrateToTargetVersionCalled = true
    }
}
