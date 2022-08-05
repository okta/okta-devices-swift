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
import DeviceAuthenticator

protocol UserConsentViewModelProtocol {
    var titleString: String { get }
    var clientLocationString: String { get }
    var clientOSString: String { get }
    var urlString: String { get }
    var dateString: String { get }
    var timeString: String { get }
    var onRemediationComplete: () -> Void { get set }

    func didTapApproveChallenge()
    func didTapDenyChallenge()
}

struct UserConsentViewModel: UserConsentViewModelProtocol {

    private let remediationStep: RemediationStepUserConsent

    var onRemediationComplete: () -> Void = {}

    init(remediationStep: RemediationStepUserConsent) {
        self.remediationStep = remediationStep
    }

    var titleString: String = "Did You Just Try to Sign In?"

    private var pushChallenge: PushChallengeProtocol? {
        return remediationStep.challenge as? PushChallengeProtocol
    }

    var clientLocationString: String {
        "\(pushChallenge?.clientLocation ?? "Unknown location")"
    }
    var clientOSString: String {
        "\(pushChallenge?.clientOS ?? "Unknown")"
    }
    var urlString: String {
        "\(pushChallenge?.originURL?.absoluteString ?? "Unknown")"
    }
    var dateString: String {
        guard let transactionTime = pushChallenge?.transactionTime else {
            return "Unknown"
        }
        let locale = Locale(identifier: "en_US_POSIX")
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.locale = locale
        let dateString = formatter.string(from: transactionTime)
        return "\(dateString)"
    }
    var timeString: String {
        guard let transactionTime = pushChallenge?.transactionTime else {
            return "Unknown"
        }
        let locale = Locale(identifier: "en_US_POSIX")
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        formatter.locale = locale
        let timeString = formatter.string(from: transactionTime)
        return "\(timeString)"
    }

    func didTapApproveChallenge() {
        remediationStep.provide(.approved)
        onRemediationComplete()
    }

    func didTapDenyChallenge() {
        remediationStep.provide(.denied)
        onRemediationComplete()
    }
}
