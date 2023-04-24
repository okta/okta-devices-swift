/*
* Copyright (c) 2021-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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

// swiftlint:disable file_types_order

extension OktaSharedSQLite {

    struct Column {

        // Enrollments

        static let enrollmentId = "enrollmentId"
        static let orgId = "orgId"
        static let serverErrorCode = "serverErrorCode"
        static let orgUrl = "orgUrl"
        static let userId = "userId"
        static let username = "username"
        static let deviceId = "deviceId"
        static let createdTimestamp = "createdTimestamp"
        static let updatedTimestamp = "updatedTimestamp"

        // EnrollmentMethods

        static let type = "type"
        static let metadata = "metadata"
        static let sharedSecret = "sharedSecret"

        static let id = "id"
        static let enrollmentOrgId = "enrollmentOrgId"

        static let proofOfPossessionKeyTag = "proofOfPossessionKeyTag"
        static let userVerificationKeyTag = "userVerificationKeyTag"
        static let userVerificationBioOrPinKeyTag = "userVerificationBioOrPinKeyTag"
        static let links = "links"
        static let passCodeLength = "passCodeLength"
        static let timeIntervalSec = "timeIntervalSec"
        static let algorithm = "algorithm"
        static let transactionTypes = "transactionTypes"

        // AuthenticatorPolicy
        static let policyId = "policyId"
        static let userVerification = "userVerification"
        static let activeMethods = "activeMethods"

        // DeviceEnrollments
        static let clientInstanceId = "clientInstanceId"
        static let clientInstanceKeyTag = "clientInstanceKeyTag"
    }
}

///  Type-safe accessors for values in sql tables
extension GRDB.Row {

    // MARK: Enrollments

    var id: String? {
        return self[OktaSharedSQLite.Column.id]
    }

    var orgId: String? {
        return self[OktaSharedSQLite.Column.orgId]
    }

    var orgUrl: String? {
        return self[OktaSharedSQLite.Column.orgUrl]
    }

    var userId: String? {
        return self[OktaSharedSQLite.Column.userId]
    }

    /// Encrypted column
    var username: Data? {
        return self[OktaSharedSQLite.Column.username]
    }

    var deviceId: String? {
        return self[OktaSharedSQLite.Column.deviceId]
    }

    var serverErrorCode: String? {
        return self[OktaSharedSQLite.Column.serverErrorCode]
    }

    var created: Date? {
        return self[OktaSharedSQLite.Column.createdTimestamp]
    }

    var updated: Date? {
        return self[OktaSharedSQLite.Column.updatedTimestamp]
    }

    var factorType: Int? {
        return self[OktaSharedSQLite.Column.type]
    }

    var proofOfPossessionKeyTag: String? {
        return self[OktaSharedSQLite.Column.proofOfPossessionKeyTag]
    }

    var userVerificationKeyTag: String? {
        return self[OktaSharedSQLite.Column.userVerificationKeyTag]
    }

    var userVerificationBioOrPinKeyTag: String? {
        return self[OktaSharedSQLite.Column.userVerificationBioOrPinKeyTag]
    }

    var metadata: Data? {
        return self[OktaSharedSQLite.Column.metadata]
    }

    var totpSecret: Data? {
        return self[OktaSharedSQLite.Column.sharedSecret]
    }

    var transactionTypes: Int? {
        return self[OktaSharedSQLite.Column.transactionTypes]
    }

    var links: Data? {
        return self[OktaSharedSQLite.Column.links]
    }

    var passcodeLength: Int? {
        return self[OktaSharedSQLite.Column.passCodeLength]
    }

    var timeIntervalInSeconds: Int? {
        return self[OktaSharedSQLite.Column.timeIntervalSec]
    }

    var algorithm: Int? {
        return self[OktaSharedSQLite.Column.algorithm]
    }

    var enrollmentId: String? {
        return self[OktaSharedSQLite.Column.enrollmentId]
    }

    var enrollmentOrgId: String? {
        return self[OktaSharedSQLite.Column.enrollmentOrgId]
    }

    var clientInstanceId: String? {
        return self[OktaSharedSQLite.Column.clientInstanceId]
    }

    var clientInstanceKeyTag: String? {
        return self[OktaSharedSQLite.Column.clientInstanceKeyTag]
    }

    var userVerificationSetting: AuthenticatorSettingsModel.UserVerificationSetting? {
        guard let value: String = self[OktaSharedSQLite.Column.userVerification] else {
            return nil
        }

        return AuthenticatorSettingsModel.UserVerificationSetting(raw: value)
    }

    var activeMethods: [AuthenticatorMethod]? {
        guard let methodsStr: String = self[OktaSharedSQLite.Column.activeMethods] else {
            return []
        }
        return convertAuthenticatorMethodString(methodsStr)
    }

    private func convertAuthenticatorMethodString(_ methodString: String?) -> [AuthenticatorMethod]? {
        methodString?.components(separatedBy: ",").compactMap({ AuthenticatorMethod(raw: $0) })
    }
}
