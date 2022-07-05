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

import Foundation

/// Base challenge protocol with set of data that every challenge contains
public protocol ChallengeProtocol {
    /// Org url that originated the challenge
    var originURL: URL? { get }
    /// Time of the sign-in attempt
    var transactionTime: Date { get }
    ///  App whose login resulted in the challenge request (e.g. "Salesforce.com")
    var appInstanceName: String? { get }

    /// Resolve a challenge to complete the transaction with the user's accept or reject response
    /// - Parameters:
    ///   - onRemediation: Handle additional steps required to before completion (e.g. present biometrics)
    ///   - onCompletion: Closure called upon completion. If an error is returned, the challenge was not resolved.
    func resolve(onRemediation: @escaping (RemediationStep) -> Void,
                 onCompletion: @escaping (DeviceAuthenticatorError?) -> Void)
}
