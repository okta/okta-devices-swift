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

import Foundation

/// User's response/consent to the push challenge
public enum PushChallengeUserResponse {
    /// User has not yet responded to this challenge (all challenges start in this state)
    case userNotResponded
    /// User responded affirmatively to the push challenge UX
    case userApproved
    /// User explicitly denied the push challenge UX
    case userDenied
}

/// Represents parsed push challenge
public protocol PushChallengeProtocol: ChallengeProtocol {
    ///  Localized location of the client sign-in attempt (e.g. "San Francisco, CA, USA")
    var clientLocation: String? { get }
    ///  OS of the client sign-in attempt (e.g. "macOS")
    var clientOS: String? { get }
    ///  What is the user's response to this challenge?
    var userResponse: PushChallengeUserResponse { get set }
}
