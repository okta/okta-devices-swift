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

protocol OktaEnrollmentStorageProtocol {
    func storeEnrollment(_ enrollment: AuthenticatorEnrollmentProtocol) throws
    func deleteEnrollment(_ enrollment: AuthenticatorEnrollmentProtocol) throws
    func deleteAllEnrollments() throws
    func allEnrollments() -> [AuthenticatorEnrollmentProtocol]
    func enrollmentById(enrollmentId: String) -> AuthenticatorEnrollmentProtocol?
    func enrollmentsByOrgId(_ orgId: String) -> [AuthenticatorEnrollmentProtocol]
    func storeServerErrorCode(_ errorCode: ServerErrorCode?, enrollment: AuthenticatorEnrollmentProtocol) throws

    var enrollmentsCount: Int? { get }
}
