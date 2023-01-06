/*
* Copyright (c) 2022-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif
import GRDB
@testable import DeviceAuthenticator

class OktaSharedSQLiteTests: XCTestCase {

    let testGroupId = ExampleAppConstants.appGroupId
    let relativeSQLitePath = "DeviceSDK/SQLite"
    let sqliteFileBasename = "TestEmptySQLite"
    let fileManager = FileManager.default
    let entitiesGenerator = OktaStorageEntitiesGenerator()

    lazy var sqlDirectoryURL: URL! = {
        return fileManager.containerURL(forSecurityApplicationGroupIdentifier: testGroupId)?.appendingPathComponent(relativeSQLitePath)
    }()

    override func setUp() {
        super.setUp()

        // Clean SQLite-related files before test run
        try? fileManager.removeItem(at: sqlDirectoryURL)
    }

    func testCreatesEmptySQLiteOnFirstLaunch() throws {
        try createsEmptySQLiteOnFirstLaunch(prefersSecureEnclaveUsage: false)
    }

    private func createsEmptySQLiteOnFirstLaunch(prefersSecureEnclaveUsage: Bool) throws {
        // GIVEN:
        // No SQLite stored at shared group directory
        let urlToCheck = sqlDirectoryURL?.appendingPathComponent(sqliteFileBasename)
        XCTAssertNotNil(urlToCheck)
        XCTAssertFalse(fileManager.fileExists(atPath: urlToCheck!.relativePath))

        // WHEN:
        // OktaSQLitePersistentStorage gets created
        let sqliteStorage = try createStorage(prefersSecureEnclaveUsage: prefersSecureEnclaveUsage)

        // THEN:
        // 1. SQLite connection is established
        // 2. SQLite exists on disk
        XCTAssertNotNil(sqliteStorage.sqlitePool)
        XCTAssertTrue(fileManager.fileExists(atPath: urlToCheck!.relativePath))
    }

    func testSQLFilesNotOverriten() throws {
        try sqlFilesNotOverriten(fullDatabaseEncryption: false)
    }

    func sqlFilesNotOverriten(fullDatabaseEncryption: Bool) throws {
        // GIVEN:
        // Unencrypted SQLite files are already present
        let sqlFileNames = ["\(sqliteFileBasename)-wal", "\(sqliteFileBasename)-shm", sqliteFileBasename]
        let testBundle = Bundle(for: OktaSharedSQLiteTests.self)
        let preFilledFileUrls = sqlFileNames.compactMap { testBundle.url(forResource: $0, withExtension: "") }
        XCTAssertEqual(preFilledFileUrls.count, 3)
        let destinationUrls = sqlFileNames.compactMap { sqlDirectoryURL.appendingPathComponent($0) }
        XCTAssertEqual(destinationUrls.count, 3)
        XCTAssertNoThrow(try fileManager.createDirectory(at: sqlDirectoryURL, withIntermediateDirectories: true, attributes: nil))
        for (i, element) in preFilledFileUrls.enumerated() {
            try fileManager.copyItem(at: element, to: destinationUrls[i])
        }
        let fileTimestampsBeforeStorageInit = try destinationUrls.map {
            return try fileManager.attributesOfItem(atPath: $0.path)[.creationDate] as? Date
        }

        // WHEN:
        // OktaSQLitePersistentStorage gets created no existing files are overriten
        let sqliteStorage = try createStorage(prefersSecureEnclaveUsage: false)

        // THEN:
        // 1.
        //   - for encrypted SQLite case no SQLite connection is established
        //   - for unencrypted SQLite case SQLite connection is established
        // 2. No existing files are overriten
        if fullDatabaseEncryption {
            XCTAssertNil(sqliteStorage.sqlitePool)
        } else {
            XCTAssertNotNil(sqliteStorage.sqlitePool)
        }
        let fileTimestampsAfterStorageInit = try destinationUrls.map {
            return try fileManager.attributesOfItem(atPath: $0.path)[.creationDate] as? Date
        }
        XCTAssertEqual(fileTimestampsBeforeStorageInit, fileTimestampsAfterStorageInit)
    }

    // MARK: Enrollments

    func testStoreRetrieveEnrollment() throws {
        let _ = try storeRetrieveEnrollment(fullDatabaseEncryption: false, prefersSecureEnclaveUsage: false)
    }

    func storeRetrieveEnrollment(fullDatabaseEncryption: Bool, prefersSecureEnclaveUsage: Bool) throws -> AuthenticatorEnrollment {
        let sqlite = try createSqlite(fullDatabaseEncryption: fullDatabaseEncryption, prefersSecureEnclaveUsage: prefersSecureEnclaveUsage)
        let enrollment = entitiesGenerator.createAuthenticator(methodTypes: [AuthenticatorMethod.signedNonce, AuthenticatorMethod.push, AuthenticatorMethod.totp], transactionTypes: [.login, .ciba])
        let push = enrollment.pushFactor
        try? sqlite.storeEnrollment(enrollment)

        guard let retrieved = sqlite.allEnrollments().first as? AuthenticatorEnrollment else {
            XCTFail()
            throw NSError(domain: "TestError", code: -1, userInfo: nil)
        }
        XCTAssertEqual(retrieved.enrollmentId, enrollment.enrollmentId)
        XCTAssertEqual(retrieved.orgHost, enrollment.orgHost)
        XCTAssertEqual(retrieved.userId, enrollment.userId)
        XCTAssertEqual(retrieved.userName, enrollment.userName)
        XCTAssertEqual(retrieved.orgId, enrollment.orgId)
        XCTAssertEqual(retrieved.deviceId, enrollment.deviceId)
        
        XCTAssertTrue(retrieved.isCIBAEnabled)

        // Spot check key factor values for expected key values
        XCTAssertEqual(retrieved.pushFactor?.factorData.proofOfPossessionKeyTag, enrollment.pushFactor?.factorData.proofOfPossessionKeyTag)
        XCTAssertEqual(retrieved.pushFactor?.factorData.userVerificationKeyTag, enrollment.pushFactor?.factorData.userVerificationKeyTag)
        XCTAssertEqual(retrieved.pushFactor?.factorData.proofOfPossessionKeyTag, enrollment.pushFactor?.factorData.proofOfPossessionKeyTag)
        XCTAssertNotEqual(retrieved.pushFactor?.factorData.proofOfPossessionKeyTag, enrollment.pushFactor?.factorData.userVerificationKeyTag)

        guard let retrievedPush = retrieved.pushFactor else {
            XCTFail()
            throw NSError(domain: "TestError", code: -1, userInfo: nil)
        }

        // Check serialized metadata for byte-level comparison
        let encoder = JSONEncoder()
        XCTAssertEqual(try? encoder.encode(retrievedPush.factorData), try! encoder.encode(push!.factorData))
        XCTAssertNotNil(retrievedPush.factorData.pushLinks?.pendingLink)
        XCTAssertEqual(retrievedPush.factorData.pushLinks?.pendingLink, push!.factorData.pushLinks?.pendingLink)
        return retrieved
    }

    func testStoreRetrieveEnrollmentWithError() throws {
        try storeRetrieveEnrollmentWithError(fullDatabaseEncryption: false, prefersSecureEnclaveUsage: false)
    }
    
    func testEnrollmentsCount_MultipleItems_ReturnsCount() throws {
        let sqlite = try createSqlite(fullDatabaseEncryption: false, prefersSecureEnclaveUsage: false)
        let createdDate = "2020-09-08T19:30:30.166Z"
        let enrollmentA = entitiesGenerator.createAuthenticator(createdDate: createdDate)
        try? sqlite.storeEnrollment(enrollmentA)
        let enrollmentB = entitiesGenerator.createAuthenticator(createdDate: createdDate)
        try? sqlite.storeEnrollment(enrollmentB)
        let enrollmentC = entitiesGenerator.createAuthenticator(createdDate: createdDate)
        try? sqlite.storeEnrollment(enrollmentC)
        
        XCTAssertEqual(sqlite.enrollmentsCount, 3)
    }
    
    func testEnrollmentsCount_emptyItems_Returns0() throws {
        let sqlite = try createSqlite(fullDatabaseEncryption: false, prefersSecureEnclaveUsage: false)        
        XCTAssertEqual(sqlite.enrollmentsCount, 0)
    }

    func storeRetrieveEnrollmentWithError(fullDatabaseEncryption: Bool, prefersSecureEnclaveUsage: Bool) throws {
        let sqlite = try createSqlite(fullDatabaseEncryption: fullDatabaseEncryption, prefersSecureEnclaveUsage: prefersSecureEnclaveUsage)
        let errorCodes: [ServerErrorCode?] = [
            nil,
            .userSuspended,
            .deviceSuspended,
            .enrollmentSuspended,
            .userDeleted,
            .enrollmentNotFound,
            .phishingAttemptDetected,
            .resourceNotFound,
            .enrollmentDeleted,
            .deviceDeleted,
            .biometricKeyEnrollmentComplianceError
        ]
        let states: [EnrollmentState] = [
            .active,
            .suspended,
            .suspended,
            .suspended,
            .deleted,
            .deleted,
            .active,
            .active,
            .reset,
            .reset,
            .active
        ]
        XCTAssertEqual(errorCodes.count, states.count)
        (0..<errorCodes.count).forEach { index in
            let state = states[index]
            let errorCode = errorCodes[index]
            let enrollment = entitiesGenerator.createAuthenticator(orgId: "orgId-\(index)",
                                                                   serverError: errorCode,
                                                                   methodTypes: [AuthenticatorMethod.signedNonce, AuthenticatorMethod.push, AuthenticatorMethod.totp])
            try? sqlite.storeEnrollment(enrollment)

            guard let retrieved = sqlite.enrollmentsByOrgId(enrollment.orgId).first as? AuthenticatorEnrollment else {
                XCTFail()
                return
            }
            XCTAssertEqual(retrieved.state, state)
        }
    }


    func testMultipleEnrollments() throws {
        try multipleEnrollments(fullDatabaseEncryption: false, prefersSecureEnclaveUsage: false)
    }

    func multipleEnrollments(fullDatabaseEncryption: Bool, prefersSecureEnclaveUsage: Bool) throws {
        let sqlite = try createSqlite(fullDatabaseEncryption: fullDatabaseEncryption, prefersSecureEnclaveUsage: prefersSecureEnclaveUsage)
        let createdDate = "2020-09-08T19:30:30.166Z"
        let enrollmentA = entitiesGenerator.createAuthenticator(createdDate: createdDate)
        try? sqlite.storeEnrollment(enrollmentA)
        let enrollmentB = entitiesGenerator.createAuthenticator(createdDate: createdDate)
        try? sqlite.storeEnrollment(enrollmentB)

        let retrieved = sqlite.allEnrollments()
        XCTAssertEqual(retrieved.count, 2)

        guard let retrievedA = retrieved.first as? AuthenticatorEnrollment,
              let retrievedB = retrieved.last as? AuthenticatorEnrollment else {
            XCTFail()
            return
        }

        XCTAssertEqual(retrievedA.enrollmentId, enrollmentA.enrollmentId)
        XCTAssertEqual(retrievedA.orgHost, enrollmentA.orgHost)
        XCTAssertEqual(retrievedA.userId, enrollmentA.userId)
        XCTAssertEqual(retrievedA.userName, enrollmentA.userName)
        XCTAssertEqual(retrievedA.orgId, enrollmentA.orgId)
        XCTAssertEqual(retrievedA.deviceId, enrollmentA.deviceId)
        XCTAssertEqual(retrievedA.creationDate.timeIntervalSinceReferenceDate, enrollmentA.creationDate.timeIntervalSinceReferenceDate, accuracy: 0.001)

        XCTAssertEqual(retrievedB.enrollmentId, enrollmentB.enrollmentId)
        XCTAssertEqual(retrievedB.orgHost, enrollmentB.orgHost)
        XCTAssertEqual(retrievedB.userId, enrollmentB.userId)
        XCTAssertEqual(retrievedB.userName, enrollmentB.userName)
        XCTAssertEqual(retrievedB.orgId, enrollmentB.orgId)
        XCTAssertEqual(retrievedB.deviceId, enrollmentB.deviceId)
        XCTAssertEqual(retrievedB.creationDate.timeIntervalSinceReferenceDate, enrollmentB.creationDate.timeIntervalSinceReferenceDate, accuracy: 0.001)
    }

    func testOverwriteEnrollment() throws {
        try overwriteEnrollment(fullDatabaseEncryption: false, prefersSecureEnclaveUsage: false)
    }

    func overwriteEnrollment(fullDatabaseEncryption: Bool, prefersSecureEnclaveUsage: Bool) throws {
        let sqlite = try createSqlite(fullDatabaseEncryption: fullDatabaseEncryption, prefersSecureEnclaveUsage: prefersSecureEnclaveUsage)
        let push = entitiesGenerator.createPushFactor()
        let pushFactor = OktaFactorPush(factorData: push,
                                        cryptoManager: sqlite.cryptoManager,
                                        restAPIClient: sqlite.restAPIClient,
                                        logger: sqlite.logger)
        let enrollmentA = entitiesGenerator.createAuthenticator(orgId: "myOrgId",
                                                                enrollmentId: "id-1",
                                                                userId: "user1@hello.world",
                                                                enrolledFactors: [pushFactor])

        try? sqlite.storeEnrollment(enrollmentA)
        let enrollmentB = entitiesGenerator.createAuthenticator(orgId: "myOrgId",
                                                                enrollmentId: "id-1",
                                                                userId: "user1@hello.world",
                                                                enrolledFactors: [pushFactor])
        try? sqlite.storeEnrollment(enrollmentB)

        let retrieved = sqlite.allEnrollments()
        XCTAssertEqual(retrieved.count, 1)

        guard let retrievedB = retrieved.first as? AuthenticatorEnrollment else {
            XCTFail()
            return
        }

        // enrollmentB should have overwritten enrollmentA since (orgId + userId) fields are considered to be unique id for orgs across all the cells
        XCTAssertEqual(retrievedB.enrollmentId, enrollmentB.enrollmentId)
        XCTAssertEqual(retrievedB.userId, enrollmentA.userId)
        XCTAssertNotNil(retrievedB.pushFactor)
    }

    func testDeleteLastEnrollment() throws {
        try deleteLastEnrollment(fullDatabaseEncryption: false, prefersSecureEnclaveUsage: false)
    }

    func deleteLastEnrollment(fullDatabaseEncryption: Bool, prefersSecureEnclaveUsage: Bool) throws {
        // GIVEN:
        // - two AuthenticatorEnrollments for the same org
        // - single DeviceEnrollment for the same org stored
        // - single AuthenticatorPolicy for the same org stored
        let sqlite = try createSqlite(fullDatabaseEncryption: fullDatabaseEncryption, prefersSecureEnclaveUsage: prefersSecureEnclaveUsage)
        let orgId = "test-org-id"
        let methodTypes: [AuthenticatorMethod] = [.totp, .push, .signedNonce]
        let enrollment = entitiesGenerator.createAuthenticator(orgId: orgId,
                                                               enrollmentId: "enrollment-id",
                                                               userId: "user@hello.world",
                                                               methodTypes: methodTypes)
        let enrollment2 = entitiesGenerator.createAuthenticator(orgId: orgId,
                                                                enrollmentId: "enrollment-id2",
                                                                userId: "user2@hello.world")
        XCTAssertNoThrow(try sqlite.storeEnrollment(enrollment))
        XCTAssertNoThrow(try sqlite.storeEnrollment(enrollment2))
        let deviceEnrollment = entitiesGenerator.createDeviceEnrollment(id: "device-enrollment-id",
                                                                        orgId: orgId)
        XCTAssertNoThrow(try sqlite.storeDeviceEnrollment(deviceEnrollment, for: orgId))
        let policy = entitiesGenerator.createPolicy(id: "policy-id",
                                                    methods: methodTypes)
        XCTAssertNoThrow(try sqlite.storeAuthenticatorPolicy(policy, orgId: orgId))
        var storedEnrollments = sqlite.allEnrollments()
        XCTAssertEqual(storedEnrollments.count, 2)
        XCTAssertNoThrow(try sqlite.deviceEnrollmentByOrgId(orgId))
        XCTAssertNoThrow(try sqlite.authenticatorPolicyForOrgId(orgId))

        // WHEN1:
        // - one of AuthenticatorEnrollment get's deleted
        XCTAssertNoThrow(try sqlite.deleteEnrollment(enrollment))

        // THEN1:
        // - verify second AuthenticatorEnrollment is still stored
        // - verify DeviceEnrollment and AuthenticatorPolicy are still stored
        storedEnrollments = sqlite.allEnrollments()
        XCTAssertEqual(storedEnrollments.count, 1)
        XCTAssertNoThrow(try sqlite.deviceEnrollmentByOrgId(orgId))
        XCTAssertNoThrow(try sqlite.authenticatorPolicyForOrgId(orgId))

        // WHEN2:
        // - second (the last) org's AuthenticatorEnrollment get's deleted
        XCTAssertNoThrow(try sqlite.deleteEnrollment(enrollment2))

        // THEN2:
        // - verify no AuthenticatorEnrollments are stored
        // - verify no DeviceEnrollment and AuthenticatorPolicy are stored
        let retrieved = sqlite.allEnrollments()
        XCTAssertEqual(retrieved.count, 0)
        XCTAssertThrowsError(try sqlite.deviceEnrollmentByOrgId(orgId))
        XCTAssertThrowsError(try sqlite.authenticatorPolicyForOrgId(orgId))
    }

    func testFindEnrollmentById() throws {
        let sqlite = try createSqlite(fullDatabaseEncryption: false, prefersSecureEnclaveUsage: false)
        let push = entitiesGenerator.createPushFactor()
        let pushFactor = OktaFactorPush(factorData: push,
                                        cryptoManager: sqlite.cryptoManager,
                                        restAPIClient: sqlite.restAPIClient,
                                        logger: sqlite.logger)
        let enrollment = entitiesGenerator.createAuthenticator(orgId: "myOrgId",
                                                               enrollmentId: "id-1",
                                                               userId: "user1@hello.world",
                                                               enrolledFactors: [pushFactor])

        try? sqlite.storeEnrollment(enrollment)

        let retrievedEnrollment = sqlite.enrollmentById(enrollmentId: enrollment.enrollmentId)
        XCTAssertNotNil(retrievedEnrollment)

        guard let retrievedAuthenticatorEnrollment = retrievedEnrollment as? AuthenticatorEnrollment else {
            XCTFail()
            return
        }

        XCTAssertEqual(retrievedAuthenticatorEnrollment.enrollmentId, enrollment.enrollmentId)
        XCTAssertNotNil(retrievedAuthenticatorEnrollment.pushFactor)
    }

    // MARK: DeviceEnrollment

    ///  Store and retrieve a single randomized device enrollment
    func testStoreRetrieveDeviceEnrollment() throws {
        try storeRetrieveDeviceEnrollment(fullDatabaseEncryption: false, prefersSecureEnclaveUsage: false)
    }

    func storeRetrieveDeviceEnrollment(fullDatabaseEncryption: Bool, prefersSecureEnclaveUsage: Bool) throws {
        let sqlite = try createSqlite(fullDatabaseEncryption: fullDatabaseEncryption, prefersSecureEnclaveUsage: prefersSecureEnclaveUsage)
        let deviceEnrollment = entitiesGenerator.createDeviceEnrollment()
        XCTAssertNoThrow(try sqlite.storeDeviceEnrollment(deviceEnrollment, for: deviceEnrollment.orgId!))

        let retrieved = try? sqlite.deviceEnrollmentByOrgId(deviceEnrollment.orgId!)
        XCTAssertEqual(retrieved?.id, deviceEnrollment.id)
        XCTAssertEqual(retrieved?.orgId, deviceEnrollment.orgId)
        XCTAssertEqual(retrieved?.clientInstanceId, deviceEnrollment.clientInstanceId)
        XCTAssertEqual(retrieved?.clientInstanceKeyTag, deviceEnrollment.clientInstanceKeyTag)

        XCTAssertNoThrow(try sqlite.storeDeviceEnrollment(deviceEnrollment, for: deviceEnrollment.orgId!))

        let encoder = JSONEncoder()
        let inputData = try? encoder.encode(deviceEnrollment)
        let outputData = try? encoder.encode(retrieved)
        XCTAssertNotNil(outputData)
        XCTAssertEqual(inputData, outputData)

        let retrievedAll = try? sqlite.allDeviceEnrollmentsOrgIds()
        XCTAssertEqual(retrievedAll?.count, 1)
        XCTAssertEqual(retrievedAll?.first, deviceEnrollment.orgId)
    }

    ///  Store two device enrollments with the same data for different orgs, should be retrieved intact
    func testMultipleDeviceEnrollmentsMultipleOrgs() throws {
        try multipleDeviceEnrollmentsMultipleOrgs(fullDatabaseEncryption: false, prefersSecureEnclaveUsage: false)
    }

    func multipleDeviceEnrollmentsMultipleOrgs(fullDatabaseEncryption: Bool, prefersSecureEnclaveUsage: Bool) throws {
        let sqlite = try createSqlite(fullDatabaseEncryption: fullDatabaseEncryption, prefersSecureEnclaveUsage: prefersSecureEnclaveUsage)
        let firstEnrollment = entitiesGenerator.createDeviceEnrollment()
        let secondEnrollment = OktaDeviceEnrollment(id: firstEnrollment.id,
                                                    orgId: UUID().uuidString,
                                                    clientInstanceId: firstEnrollment.clientInstanceId,
                                                    clientInstanceKeyTag: firstEnrollment.clientInstanceKeyTag)
        XCTAssertNoThrow(try sqlite.storeDeviceEnrollment(firstEnrollment, for: firstEnrollment.orgId!))
        XCTAssertNoThrow(try sqlite.storeDeviceEnrollment(secondEnrollment, for: secondEnrollment.orgId!))

        let retrievedFirst = try? sqlite.deviceEnrollmentByOrgId(firstEnrollment.orgId!)
        XCTAssertEqual(retrievedFirst?.id, firstEnrollment.id)
        let retrievedSecond = try? sqlite.deviceEnrollmentByOrgId(secondEnrollment.orgId!)
        XCTAssertEqual(retrievedSecond?.id, secondEnrollment.id)
        XCTAssertEqual(retrievedFirst?.id, retrievedSecond?.id)
        XCTAssertNotEqual(retrievedFirst?.orgId, retrievedSecond?.orgId)

        let retrievedAll = try? sqlite.allDeviceEnrollmentsOrgIds()
        XCTAssertNotNil(retrievedAll)
        XCTAssertEqual(retrievedAll!.count, 2)
        XCTAssertTrue(retrievedAll!.contains(firstEnrollment.orgId!))
        XCTAssertTrue(retrievedAll!.contains(secondEnrollment.orgId!))
    }

    ///  Write two different device enrollments to the same org + deviceId, should be overwritten
    func testOverwriteDeviceEnrollmentForSameOrgDevice() throws {
        try overwriteDeviceEnrollmentForSameOrgDevice(fullDatabaseEncryption: false, prefersSecureEnclaveUsage: false)
    }

    func overwriteDeviceEnrollmentForSameOrgDevice(fullDatabaseEncryption: Bool, prefersSecureEnclaveUsage: Bool) throws {
        let sqlite = try createSqlite(fullDatabaseEncryption: fullDatabaseEncryption, prefersSecureEnclaveUsage: prefersSecureEnclaveUsage)
        let firstEnrollment = entitiesGenerator.createDeviceEnrollment()
        let orgId = firstEnrollment.orgId!
        XCTAssertNoThrow(try sqlite.storeDeviceEnrollment(firstEnrollment, for: orgId))

        let secondEnrollment = OktaDeviceEnrollment(id: firstEnrollment.id,
                                                    orgId: orgId,
                                                    clientInstanceId: UUID().uuidString,
                                                    clientInstanceKeyTag: UUID().uuidString)

        XCTAssertNoThrow(try sqlite.storeDeviceEnrollment(secondEnrollment, for: orgId))
        let retrieved = try? sqlite.deviceEnrollmentByOrgId(orgId)

        XCTAssertEqual(retrieved?.id, secondEnrollment.id)
        XCTAssertEqual(retrieved?.orgId, secondEnrollment.orgId)
        XCTAssertEqual(retrieved?.clientInstanceId, secondEnrollment.clientInstanceId)
        XCTAssertEqual(retrieved?.clientInstanceKeyTag, secondEnrollment.clientInstanceKeyTag)
        
        let deviceEnrollments = try? sqlite.allDeviceEnrollmentsOrgIds()
        XCTAssertEqual(deviceEnrollments?.count, 1)
    }

    ///  Store and delete a device enrollment successfully
    func testDeleteDeviceEnrollment() throws {
        try deleteDeviceEnrollment(fullDatabaseEncryption: false, prefersSecureEnclaveUsage: false)
    }

    func deleteDeviceEnrollment(fullDatabaseEncryption: Bool, prefersSecureEnclaveUsage: Bool) throws {
        let sqlite = try createSqlite(fullDatabaseEncryption: fullDatabaseEncryption, prefersSecureEnclaveUsage: prefersSecureEnclaveUsage)
        let enrollment = entitiesGenerator.createDeviceEnrollment()
        let orgId = enrollment.orgId!
        XCTAssertThrowsError(try sqlite.deviceEnrollmentByOrgId(orgId))
        XCTAssertNoThrow(try sqlite.storeDeviceEnrollment(enrollment, for: orgId))
        XCTAssertNoThrow(try sqlite.deleteDeviceEnrollmentForOrgId(orgId))
        let retrieved = try? sqlite.deviceEnrollmentByOrgId(orgId)
        XCTAssertNil(retrieved)
    }

    // MARK: AuthenticatorPolicy

    func testStoreRetrieveAuthenticatorPolicy() throws {
        try storeRetrieveAuthenticatorPolicy(fullDatabaseEncryption: false, prefersSecureEnclaveUsage: false)
    }

    func storeRetrieveAuthenticatorPolicy(fullDatabaseEncryption: Bool, prefersSecureEnclaveUsage: Bool) throws {
        let sqlite = try createSqlite(fullDatabaseEncryption: fullDatabaseEncryption, prefersSecureEnclaveUsage: prefersSecureEnclaveUsage)
        let policy = entitiesGenerator.createPolicy()
        let orgId = UUID().uuidString
        try? sqlite.storeAuthenticatorPolicy(policy, orgId: orgId)

        let retrieved = try? sqlite.authenticatorPolicyForOrgId(orgId) as? AuthenticatorPolicy
        XCTAssertEqual(retrieved?.userVerificationSetting, policy.userVerificationSetting)
        XCTAssertEqual(retrieved?.hasMethod(ofType: .totp), false)
        XCTAssertEqual(retrieved?.hasMethod(ofType: .push), true)
    }

    ///  Write two AuthenticatorPolicy objects to the same org
    func testOverwriteAuthenticatorPolicy() throws {
        try overwriteAuthenticatorPolicy(fullDatabaseEncryption: false, prefersSecureEnclaveUsage: false)
    }

    func overwriteAuthenticatorPolicy(fullDatabaseEncryption: Bool, prefersSecureEnclaveUsage: Bool) throws {
        let sqlite = try createSqlite(fullDatabaseEncryption: fullDatabaseEncryption, prefersSecureEnclaveUsage: prefersSecureEnclaveUsage)
        let policyA = entitiesGenerator.createPolicy()
        let orgId = UUID().uuidString
        try? sqlite.storeAuthenticatorPolicy(policyA, orgId: orgId)

        // Overwrite the policy for this org with another policy, same authenticator
        let policyB = entitiesGenerator.createPolicy(id: policyA.metadata.id, userVerification: .required, methods: [.totp, .signedNonce])
        try? sqlite.storeAuthenticatorPolicy(policyB, orgId: orgId)

        let retrieved = try? sqlite.authenticatorPolicyForOrgId(orgId) as? AuthenticatorPolicy
        XCTAssertEqual(retrieved?.userVerificationSetting, policyB.userVerificationSetting)
        XCTAssertEqual(retrieved?.hasMethod(ofType: .totp), true)
        XCTAssertEqual(retrieved?.hasMethod(ofType: .signedNonce), true)
        XCTAssertEqual(retrieved?.hasMethod(ofType: .push), false)
    }

    ///  Set two policy objecst on different orgs, they should both be retrievable and not overwrite
    func testMultiplePoliciesDifferentOrgs() throws {
        try multiplePoliciesDifferentOrgs(fullDatabaseEncryption: false, prefersSecureEnclaveUsage: false)
    }

    func multiplePoliciesDifferentOrgs(fullDatabaseEncryption: Bool, prefersSecureEnclaveUsage: Bool) throws {
        let sqlite = try createSqlite(fullDatabaseEncryption: fullDatabaseEncryption, prefersSecureEnclaveUsage: prefersSecureEnclaveUsage)
        let policyA = entitiesGenerator.createPolicy()
        let orgIdA = UUID().uuidString
        try? sqlite.storeAuthenticatorPolicy(policyA, orgId: orgIdA)

        // Overwrite the policy for this org with another policy
        let orgIdB = UUID().uuidString
        let policyB = entitiesGenerator.createPolicy(id: "different", userVerification: .required, methods: [.totp])
        try? sqlite.storeAuthenticatorPolicy(policyB, orgId: orgIdB)

        var retrieved = try? sqlite.authenticatorPolicyForOrgId(orgIdA) as? AuthenticatorPolicy
        XCTAssertEqual(retrieved?.userVerificationSetting, .preferred)
        XCTAssertEqual(retrieved?.hasMethod(ofType: .push), true)

        retrieved = try? sqlite.authenticatorPolicyForOrgId(orgIdB) as? AuthenticatorPolicy
        XCTAssertEqual(retrieved?.userVerificationSetting, .required)
        XCTAssertEqual(retrieved?.hasMethod(ofType: .push), false)
    }

    ///  Store then delete an authenticator policy for a given org id
    func testDeleteAuthenticatorPolicy() throws {
        try deleteAuthenticatorPolicy(fullDatabaseEncryption: false, prefersSecureEnclaveUsage: false)
    }

    func deleteAuthenticatorPolicy(fullDatabaseEncryption: Bool, prefersSecureEnclaveUsage: Bool) throws {
        let sqlite = try createSqlite(fullDatabaseEncryption: fullDatabaseEncryption, prefersSecureEnclaveUsage: prefersSecureEnclaveUsage)
        let policy = entitiesGenerator.createPolicy()
        let orgId = UUID().uuidString
        XCTAssertNoThrow(try sqlite.storeAuthenticatorPolicy(policy, orgId: orgId))
        XCTAssertNoThrow(try sqlite.deleteAuthenticatorPolicyForOrgId(orgId))

        let retrieved = try? sqlite.authenticatorPolicyForOrgId(orgId)
        XCTAssertNil(retrieved)
    }

    // MARK: Encryption
    func testMandatorySQLiteColumsEncrypted() throws {
        // GIVEN:
        // Populated SQLite DB with only Column-level encryption enabled
        let enrollment = try storeRetrieveEnrollment(fullDatabaseEncryption: false, prefersSecureEnclaveUsage: false)

        // WHEN:
        // Raw SQLite file get's accessed
        let sqliteDestinationUrl = sqlDirectoryURL.appendingPathComponent(sqliteFileBasename+"-wal")
        let text = try String(contentsOf: sqliteDestinationUrl, encoding: .ascii)

        // THEN:
        // - other SQLite columns are stored in unencrypted way. Verify it by accessing random columns
        XCTAssertFalse(text.contains(enrollment.userName!))

        XCTAssertTrue(text.contains(enrollment.enrollmentId))
        XCTAssertTrue(text.contains(enrollment.orgHost.path))
        XCTAssertTrue(text.contains(enrollment.userId))
        XCTAssertTrue(text.contains(enrollment.orgId))
        XCTAssertTrue(text.contains(enrollment.deviceId))
    }

    // MARK: Private Helpers

    private func createStorage(prefersSecureEnclaveUsage: Bool) throws -> OktaSQLitePersistentStorage {
        guard let url = fileManager.containerURL(forSecurityApplicationGroupIdentifier: testGroupId)?.appendingPathComponent("\(relativeSQLitePath)/\(sqliteFileBasename)") else {
            throw NSError(domain: "TestError", code: -1, userInfo: nil)
        }

        return OktaSQLitePersistentStorage(at: url,
                                           schemaVersion: SQLiteSchema().version,
                                           fileManager: fileManager,
                                           sqliteFileEncryptionKey: nil,
                                           logger: OktaLogger())
    }

    private func createSqlite(fullDatabaseEncryption: Bool, prefersSecureEnclaveUsage: Bool) throws -> OktaSharedSQLite {
        let logger = OktaLogger()
        let storage = try createStorage(prefersSecureEnclaveUsage: prefersSecureEnclaveUsage)
        #if os(iOS)
        let crypto = OktaCryptoManager(keychainGroupId: testGroupId, logger: logger)
        #else
        let crypto = CryptoManagerMock(keychainGroupId: testGroupId, logger: logger)
        #endif
        let restAPI = RestAPIMock(client: MockHTTPClient(), logger: logger)
        let config = ApplicationConfig(applicationName: "Test App",
                                       applicationVersion: "1.0.0",
                                       applicationGroupId: ExampleAppConstants.appGroupId)
        return OktaSharedSQLite(sqlitePersistentStorage: storage,
                                cryptoManager: crypto,
                                restAPIClient: restAPI,
                                sqliteColumnEncryptionManager: OktaSQLiteEncryptionManager(cryptoManager: crypto, keychainGroupId: crypto.keychainGroupId),
                                applicationConfig: config,
                                logger: logger)
    }
}
