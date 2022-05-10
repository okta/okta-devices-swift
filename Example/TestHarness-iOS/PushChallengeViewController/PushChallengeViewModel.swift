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
import UIKit
import OktaDeviceSDK

protocol PushChallengeViewModelProtocol {
    
    var view: UserConsentViewProtocol? { set get }
    
    var titleString: String { get }
    var clientLocationString: String { get }
    var clientOSString: String { get }
    var urlString: String { get }
    var dateString: String { get }
    var timeString: String { get }
    
    func start()
    func approveChallenge()
    func denyChallenge()
}

typealias PushChallengeCompletion = (() -> Void)

class PushChallengeViewModel: PushChallengeViewModelProtocol {

    var titleString: String = "Did You Just Try to Sign In?"

    private var pushChallenge: PushChallengeProtocol? {
        return remediationStep.challenge as? PushChallengeProtocol
    }
    
    var clientLocationString: String {
        "Client Location: \(pushChallenge?.clientLocation ?? "Unknown location")"
    }
    var clientOSString: String {
        "Client OS: \(pushChallenge?.clientOS ?? "Unknown")"
    }
    var urlString: String {
        "Original URL: \(pushChallenge?.originURL?.absoluteString ?? "Unknown")"
    }
    var dateString: String {
        guard let transactionTime = pushChallenge?.transactionTime else {
            return "Date: Unknown"
        }
        let locale = Locale(identifier: "en_US_POSIX")
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.locale = locale
        let dateString = formatter.string(from: transactionTime)
        return "Date: \(dateString)"
    }
    var timeString: String {
        guard let transactionTime = pushChallenge?.transactionTime else {
            return "Time: Unknown"
        }
        let locale = Locale(identifier: "en_US_POSIX")
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        formatter.locale = locale
        let timeString = formatter.string(from: transactionTime)
        return "Time: \(timeString)"
    }
    
    weak var view: UserConsentViewProtocol?

    private let logger: LoggerManagerProtocol?
    private let remediationStep: RemediationStepUserConsent
    private let completion: PushChallengeCompletion
    
    init(remediationStep: RemediationStepUserConsent,
         logger: LoggerManagerProtocol? = LoggerManager.shared,
         completion: @escaping PushChallengeCompletion)
    {
        self.remediationStep = remediationStep
        self.logger = logger
        self.completion = completion
    }

    func start() {
        view?.updateData()
    }
    
    func approveChallenge() {
        remediationStep.provide(.approved)
        completion()
    }
    
    func denyChallenge() {
        remediationStep.provide(.denied)
        completion()
    }
}
