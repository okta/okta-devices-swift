/*
* Copyright (c) 2019, Okta, Inc. and/or its affiliates. All rights reserved.
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
@testable import DeviceAuthenticator

class StorageMock: PersistentStorageProtocol {

    typealias storeEnrollmentType = (AuthenticatorEnrollmentProtocol) throws -> Void
    typealias enrollmentByIdType = (String) -> AuthenticatorEnrollmentProtocol?
    typealias deviceEnrollmentByOrgIdType = (String) throws -> OktaDeviceEnrollment

    var enrollments: [String: AuthenticatorEnrollmentProtocol] = [: ]
    var deviceEnrollments: [String: OktaDeviceEnrollment] = [: ]
    var policies: [String: AuthenticatorPolicyProtocol] = [: ]
    public var memoryCacheEnabled: Bool = true
    var enrollmentsByURLClosure: ((URL) -> [AuthenticatorEnrollmentProtocol])?
    var enrollmentsByOrgIdClosure: ((String) -> [AuthenticatorEnrollmentProtocol])?
    var storeEnrollmentHook: storeEnrollmentType?
    var enrollmentByIdHook: enrollmentByIdType?
    var deviceEnrollmentByOrgIdHook: deviceEnrollmentByOrgIdType?

    func enrollmentById(enrollmentId: String) -> AuthenticatorEnrollmentProtocol? {
        if let enrollmentByIdHook = enrollmentByIdHook {
            return enrollmentByIdHook(enrollmentId)
        } else {
            return enrollments.first { $1.enrollmentId == enrollmentId }.map({ $1 })
        }
    }

    func enrollmentsByOrgId(_ orgId: String) -> [AuthenticatorEnrollmentProtocol] {
        if let enrollmentsByOrgId = enrollmentsByOrgIdClosure {
            return enrollmentsByOrgId(orgId)
        } else {
            return enrollments.first { $1.organization.id == orgId }.map({ [$1] }) ?? []
        }
    }

    func deviceEnrollmentByOrgId(_ orgId: String) throws -> OktaDeviceEnrollment {
        if let deviceEnrollmentByOrgIdHook = deviceEnrollmentByOrgIdHook {
            return try deviceEnrollmentByOrgIdHook(orgId)
        } else {
            guard let device = deviceEnrollments.first(where: { $0.key == orgId }).map({ $1 }) else {
                throw DeviceAuthenticatorError.storageError(StorageError.itemNotFound)
            }

            return device
        }
    }

    func allDeviceEnrollmentsOrgIds() throws -> [String] {
        return []
    }

    func storeEnrollment(_ enrollment: AuthenticatorEnrollmentProtocol) throws {
        if let storeEnrollmentHook = storeEnrollmentHook {
            try storeEnrollmentHook(enrollment)
        } else {
            enrollments[enrollment.enrollmentId] = enrollment
        }
    }

    func deleteEnrollment(_ enrollment: AuthenticatorEnrollmentProtocol) throws {
        enrollments.removeValue(forKey: enrollment.enrollmentId)
    }

    func deleteAllEnrollments() throws {
        enrollments.removeAll()
    }

    func allEnrollments() -> [AuthenticatorEnrollmentProtocol] {
        return enrollments.values.map({ $0 })
    }

    func storeDeviceEnrollment(_ deviceEnrollment: OktaDeviceEnrollment, for orgId: String) throws {
        deviceEnrollments[orgId] = deviceEnrollment
    }

    func deleteDeviceEnrollmentForOrgId(_ orgId: String) throws {
        deviceEnrollments.removeValue(forKey: orgId)
    }

    func allAuthenticatorPoliciesOrgIds() -> [String] {
        return policies.keys.map({ $0 })
    }

    func storeAuthenticatorPolicy(_ authenticationPolicy: AuthenticatorPolicyProtocol, orgId: String) throws {
        policies[orgId] = authenticationPolicy
    }

    func authenticatorPolicyForOrgId(_ orgId: String) throws -> AuthenticatorPolicyProtocol {
        guard let policy = policies.first(where: { $0.key == orgId }).map({ $1 }) else {
            throw DeviceAuthenticatorError.storageError(StorageError.itemNotFound)
        }

        return policy
    }

    func deleteAuthenticatorPolicyForOrgId(_ orgId: String) throws {
        policies.removeValue(forKey: orgId)
    }
}
