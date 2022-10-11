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

///  Representation of enrollment (authenticator account) object
public protocol AuthenticatorEnrollmentProtocol {
    /// Authenticator enrollment id
    var enrollmentId: String { get }

    /// Organization information
    var organization: Organization { get }

    /// Enrolled user information
    var user: User { get }

    /// Returns true if enrollment has additional capabilities to authenticate user via biometrics or pin
    var userVerificationEnabled: Bool { get }

    ///  Enables or disables user verification capabilities for the enrollment. If the enrollment already has it set then this operation will replace the existing user verification key.
    ///  - Parameters:
    ///   - authenticationToken: Authentication token, e.g. Bearer token
    ///   - enable: Boolean flag to enable/disable user verification
    ///   - completion: Closure called when the process has completed
    func setUserVerification(authenticationToken: AuthToken, enable: Bool, completion: @escaping (DeviceAuthenticatorError?) -> Void)

    /// Returns true if enrollment has support for CIBA Transactions. If false, this authenticator won't receive CIBA challenges from server.
    var isCIBAEnabled: Bool { get }

    /// Enables or disables support for CIBA Transactions for the enrollment. By disabling it, the authenticator won't receive CIBA challenges from server.
    func enableCIBATransactions(authenticationToken: AuthToken, enable: Bool, completion: @escaping (DeviceAuthenticatorError?) -> Void)


    ///  Update the push token associated with all enrollments on this device
    /// - Parameters:
    ///   - token: APNS token to be updated, will be performed for all enrollments on this device
    ///   - authenticationToken: Authentication token, e.g. Bearer token
    ///   - completion: Closure called upon completion of token update for all enrollments
    func updateDeviceToken(_ token: Data,
                           authenticationToken: AuthToken,
                           completion: @escaping (DeviceAuthenticatorError?) -> Void)

    ///  Fetch any unresolved push challenges associated with enrollments on this device
    ///  - Parameters:
    ///   - authenticationToken: Authentication token, e.g. Bearer token
    ///   - allowedClockSkewInSeconds: The amount of clock skew in seconds to tolerate when verifying
    ///   - completion: Closure called when the retrieval process has completed
    ///  - Discussion: This method is useful for user-driven activity indicating they would like to remediate a challenge. Examples: User clicks a refresh button, foregrounds the app.
    func retrievePushChallenges(authenticationToken: AuthToken,
                                allowedClockSkewInSeconds: Int,
                                completion: @escaping (Result<[PushChallengeProtocol], DeviceAuthenticatorError>) -> Void)

    ///  Delete the enrollment from this device's local storage
    ///  - Discussion: Deleting enrollments without notifying the server will cause the user to be potentially locked out. Use [DeviceAuthenticatorProtocol.delete] instead
    func deleteFromDevice() throws
}

public extension AuthenticatorEnrollmentProtocol {
    func retrievePushChallenges(authenticationToken: AuthToken,
                                allowedClockSkewInSeconds: Int = 300,
                                completion: @escaping (Result<[PushChallengeProtocol], DeviceAuthenticatorError>) -> Void) {
        retrievePushChallenges(authenticationToken: authenticationToken,
                               allowedClockSkewInSeconds: allowedClockSkewInSeconds,
                               completion: completion)
    }
}
