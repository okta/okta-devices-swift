/*
* Copyright (c) 2019-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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
import UserNotifications

/// Defines the list of supported operations by instance that conforms to below protocol
public protocol DeviceAuthenticatorProtocol {
    /// Downloads authenticator policy.
    /// - Parameters:
    ///   - authenticationToken: Authentication token, for example access token
    ///   - authenticatorConfig: Authenticator level config, oidc client id, url and etc.
    ///   - completion: Closure that returns downloaded policy or error
    func downloadPolicy(authenticationToken: AuthToken,
                        authenticatorConfig: DeviceAuthenticatorConfig,
                        completion: @escaping (Result<AuthenticatorPolicyProtocol, DeviceAuthenticatorError>) -> Void)

    ///  Convenience enrollment method enumerating the relevant parameters for push
    /// - Parameters:
    ///   - authenticationToken: Authentication token, for example access token
    ///   - authenticatorConfig: Authenticator level config, oidc client id, url and etc.
    ///   - enrollmentParameters: Set of enrollment settings, device token, user verification and etc.
    ///   - completion: Closure that returns enrolled authenticator or error
    func enroll(authenticationToken: AuthToken,
                authenticatorConfig: DeviceAuthenticatorConfig,
                enrollmentParameters: EnrollmentParameters,
                completion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void)

    /// Returns a list of all enrollments currently managed by the device SDK
    func allEnrollments() -> [AuthenticatorEnrollmentProtocol]

    ///  Deletes an enrollment on server and on device. Requires a network call in order to delete the server-side components.
    /// - Parameters:
    ///   - enrollment: Enrollment to delete
    ///   - authenticationToken: Authentication token for server API call, for example access token
    /// - Discussion: If deleting the enrollment on the server side fails, the transaction will be rolled back and an error supplied in the completion handler (e.g. no network connectivity)
    func delete(enrollment: AuthenticatorEnrollmentProtocol,
                authenticationToken: AuthToken,
                completion: @escaping (DeviceAuthenticatorError?) -> Void)

    ///  Given a push notification content received by your app, attempt to parse it as an Okta push.
    ///  - Parameters:
    ///   - notification: Push notification recieved by application
    ///   - allowedClockSkewInSeconds: The amount of clock skew in seconds to tolerate when verifying
    ///  Discussion: In the case of a non-okta notification, this function will throw an OktaError.pushNotRecognized object.
    func parsePushNotification(_ notification: UNNotification, allowedClockSkewInSeconds: UInt) throws -> PushChallengeProtocol

    /// Given a push notification response received by your app, attempt to parse it as an Okta push.
    ///  - Parameters:
    ///   - response: Response object from actionable notification
    ///   - allowedClockSkewInSeconds: The amount of clock skew in seconds to tolerate when verifying
    ///  Discussion: In the case of a non-okta notification, this function will throw an OktaError.pushNotRecognized object.
    func parsePushNotificationResponse(_ response: UNNotificationResponse, allowedClockSkewInSeconds: UInt) throws -> PushChallengeProtocol
}

public extension DeviceAuthenticatorProtocol {
    func parsePushNotification(_ notification: UNNotification, allowedClockSkewInSeconds: UInt = 300) throws -> PushChallengeProtocol {
        try parsePushNotification(notification, allowedClockSkewInSeconds: allowedClockSkewInSeconds)
    }

    func parsePushNotificationResponse(_ response: UNNotificationResponse, allowedClockSkewInSeconds: UInt = 300) throws -> PushChallengeProtocol {
        try parsePushNotificationResponse(response, allowedClockSkewInSeconds: allowedClockSkewInSeconds)
    }
}
