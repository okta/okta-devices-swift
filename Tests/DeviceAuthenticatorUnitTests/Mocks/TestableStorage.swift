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
@testable import DeviceAuthenticator

enum TestStorageVersion: Int, _OktaVersionType {
    case unknown = -9999
    case firstVersion = 1
    case secondVersion = 2
    case thirdVersion = 3
    case fourthVersion = 4
    case fifthVersion = 5
    
    static var unknownVersion: TestStorageVersion { return .unknown }
}

class TestMigratableStorage : _OktaMigratableStorage {
    typealias Version = TestStorageVersion

    var lastKnownVersion: TestStorageVersion = .unknown
    static var targetVersion: TestStorageVersion = .unknown

    var needsFailMigrationAtVersion: TestStorageVersion? = nil
    var willStartMigrationCallback: ((TestStorageVersion, TestStorageVersion) -> Void)? = nil
    var didFinishMigrationCallback: ((TestStorageVersion, TestStorageVersion) -> Void)? = nil
    var performIncrementalMigration: ((TestStorageVersion) -> Void)? = nil
    
    func willStartIncrementalStorageMigrationSequence(startVersion: TestStorageVersion, endVersion: TestStorageVersion) throws {
        willStartMigrationCallback?(startVersion, endVersion)
    }
    
    func performIncrementalStorageMigration(_ nextVersion: TestStorageVersion) throws {
        performIncrementalMigration?(nextVersion)
    }
    
    func didFinishStorageIncrementalMigrationSequence(startVersion: TestStorageVersion, endVersion: TestStorageVersion) {
        didFinishMigrationCallback?(startVersion, endVersion)
    }
}
