/*
* Copyright (c) 2021, Okta-Present, Inc. and/or its affiliates. All rights reserved.
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
import OktaLogger
@testable import DeviceAuthenticator

class OktaStorageMigratorTests: XCTestCase {

    var testMigratableStorage = TestMigratableStorage()
    
    override func tearDown() {
        testMigratableStorage.lastKnownVersion = .unknown
        TestMigratableStorage.targetVersion = .unknown
        testMigratableStorage.needsFailMigrationAtVersion = nil
        testMigratableStorage.willStartMigrationCallback = nil
        testMigratableStorage.didFinishMigrationCallback = nil
        testMigratableStorage.performIncrementalMigration = nil
    }

    func testMigrateAllVersionsSuccess() {
        // GIVEN:
        // last persisted storage of v.1
        // while current storage has v.5
        //
        // WHEN:
        // Migrator performs storage migration from v.1 -> v.5
        //
        // THEN:
        // - Cascade migration v.1 -> v.2 -> v.3 -> v.4 -> v.5 happens
        verifyAllVersionsMigrationSuccess(lastKnownVersion: .firstVersion, currentVersion: .fifthVersion)
    }
    
    func testMigrateSingleVersionsSuccess() {
        // GIVEN:
        // last persisted storage of v.4
        // while current storage has v.5
        //
        // WHEN:
        // Migrator performs storage migration from v.4 -> v.5
        //
        // THEN:
        // - Cascade migration of a single v.4 -> v.5 upgrade happens
        verifyAllVersionsMigrationSuccess(lastKnownVersion: .fourthVersion, currentVersion: .fifthVersion)
    }
    
    // MARK: - Utils
    
    func verifyAllVersionsMigrationSuccess(lastKnownVersion: TestStorageVersion, currentVersion: TestStorageVersion) {
        testMigratableStorage.lastKnownVersion = lastKnownVersion
        TestMigratableStorage.targetVersion = currentVersion
        
        let willStartMigrationExpectation =  expectation(description: "willStartPersistanceIncrementalMigrationSequence has been called")
        let didFinishMigrationExpectation =  expectation(description: "didFinishPersistanceIncrementalMigrationSequence has been called")
        
        var actualMigratedVersions = [TestStorageVersion]()
        
        let fistUpgradeVersion = lastKnownVersion.nextVersion()
        let finishUpgradeVersion = currentVersion
        
        // for a simple single version bump (v.4 -> v.5) expectedMigratedVersions will contain only migration to v.5 call
        // for a cascade migration (v.1 -> v.5) expectedMigratedVersions will contain every version for which migration gets perfromed (v.2, v.3, v.4, v.5)
        let expectedMigratedVersions: [TestStorageVersion] = Array(fistUpgradeVersion...finishUpgradeVersion)
        
        testMigratableStorage.willStartMigrationCallback = { startVersion, endVersion in
            willStartMigrationExpectation.fulfill()
            XCTAssertEqual(lastKnownVersion, startVersion)
            XCTAssertEqual(currentVersion, endVersion)
        }
        testMigratableStorage.performIncrementalMigration = { nextVersion in
            actualMigratedVersions.append(nextVersion)
        }
        testMigratableStorage.didFinishMigrationCallback = { startVersion, endVersion in
            didFinishMigrationExpectation.fulfill()
            XCTAssertEqual(lastKnownVersion, startVersion)
            XCTAssertEqual(currentVersion, endVersion)
        }
        
        let storageMigrator = OktaStorageMigrator(logger: OktaLogger())
        XCTAssertNoThrow(try storageMigrator.migrateToTargetVersion(migratableStorage: testMigratableStorage, type: TestMigratableStorage.self))
        
        XCTAssertEqual(expectedMigratedVersions, actualMigratedVersions)
        wait(for: [willStartMigrationExpectation, didFinishMigrationExpectation], timeout: 1.0)
    }

}
