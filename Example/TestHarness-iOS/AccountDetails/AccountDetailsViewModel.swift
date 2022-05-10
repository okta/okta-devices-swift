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

import OktaOidc
import Foundation
import OktaDeviceSDK

protocol AccountDetailsViewModelProtocol {
    var listTitle: String { get }
    var profileInfo: [(key: String, value: String)] { get }
    var isEnableUserVerification: Bool { get }

    func start()
    func showActions(from sourceButton: UIBarButtonItem)
    func retrievePendingPushChallenges()
    func setUserVerification(enable: Bool)
}

class AccountDetailsViewModel: AccountDetailsViewModelProtocol {
    weak var view: AccountDetailsViewProtocol?

    let listTitle = "Account Details"
    var isEnableUserVerification: Bool { enrollment.userVerificationEnabled }
    private(set) var profileInfo = [(key: String, value: String)]()

    private let oidcStateManager: OktaOidcStateManager?
    private var actions: [ActionSheetActionViewModel] = []
    private let logger: LoggerManagerProtocol?
    private let enrollment: AuthenticatorEnrollmentProtocol
    private let enrollmentDeleted: (AuthenticatorEnrollmentProtocol) -> Void
    private let authenticator: DeviceAuthenticatorProtocol
    private let accessTokenManager: AccessTokenManagerProtocol

    init(enrollment: AuthenticatorEnrollmentProtocol,
         oidcStateManager: OktaOidcStateManager?,
         authenticator: DeviceAuthenticatorProtocol,
         enrollmentDeleted: @escaping (AuthenticatorEnrollmentProtocol) -> Void,
         logger: LoggerManagerProtocol? = LoggerManager.shared,
         accessTokenManager: AccessTokenManagerProtocol)
    {
        self.oidcStateManager = oidcStateManager
        self.logger = logger
        self.enrollment = enrollment
        self.enrollmentDeleted = enrollmentDeleted
        self.authenticator = authenticator
        self.accessTokenManager = accessTokenManager

        let updatePushTokenAction = ActionSheetActionViewModel(title: "Update Push Token") { [weak self] in self?.startPushTokenUpdate() }
        let retrievePendingChallengeAction = ActionSheetActionViewModel(title: "Retrieve Pending Challenge") { [weak self] in
            self?.retrievePendingChallenge()
        }
        let deleteAccountAction = ActionSheetActionViewModel(title: "Delete Account", style: .destructive) { [weak self] in self?.confirmDeleteAccount()
        }
        let revokeAccessToken = ActionSheetActionViewModel(title: "Revoke access token") { [weak self] in
            self?.confirmRevokeAccessToken()
        }
        let cancelAction = ActionSheetActionViewModel(title: "Cancel", style: .cancel)
        actions = [updatePushTokenAction, retrievePendingChallengeAction, revokeAccessToken, deleteAccountAction, cancelAction]
    }

    func start() {
        logger?.info(event: .accountDetails("Getting account details"))
        profileInfo = enrollment.asDictionary.compactMapValues { $0 as? String }.reduce(into: []) { $0.append((key: $1.key, value: $1.value)) }
        view?.updateData()
    }

    func showActions(from sourceButton: UIBarButtonItem) {
        view?.presentActionSheet(actions, title: nil, sourceButton: sourceButton)
    }
    
    func retrievePendingPushChallenges() {
        retrievePendingChallenge()
    }

    func setUserVerification(enable: Bool) {
        view?.showActivityIndicator()
        logger?.info(event: .accountDetails("Start updating user verification key with value: \(enable)"))
        getAccessToken { [weak self] accessToken, error in
            guard let self = self else {
                return
            }
            guard let accessToken = accessToken else {
                self.view?.hideActivityIndicator()
                self.logger?.error(event: .accountDetails("Access token can not be nil"))
                return
            }
            let authToken = AuthToken.bearer(accessToken)
            self.enrollment.setUserVerification(authenticationToken: authToken, enable: enable) { [weak self] error in
                executeOnMainThread {
                    self?.view?.hideActivityIndicator()
                    if let error = error {
                        self?.logger?.error(event: .accountDetails(error.localizedDescription))
                        self?.view?.presentError(title: "Error", message: error.localizedDescription)
                        return
                    }
                    self?.logger?.info(event: .accountDetails("Success updating user verification key with value: \(enable)"))
                    self?.view?.updateData()
                }
            }
        }
    }

    private func updatePushToken(with token: String) {
        let token = token.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: " ", with: "")
        guard !token.isEmpty else { return }
        guard let tokenData = token.data(using: .utf8) else {
            logger?.warning(event: .updatePushToken("User entered push token is invalid"))
            view?.presentError(title: "Error", message: "Push token is invalid")
            return
        }
        view?.showActivityIndicator()
        logger?.info(event: .updatePushToken("Start updating push token"))
        getAccessToken { [weak self] accessToken, error in
            guard let self = self else {
                return
            }
            guard let accessToken = accessToken else {
                self.view?.hideActivityIndicator()
                self.logger?.error(event: .accountDetails("Access token can not be nil"))
                return
            }
            let enrollmentId = self.enrollment.enrollmentId
            self.enrollment.updateDeviceToken(tokenData, authenticationToken: AuthToken.bearer(accessToken)) { [weak self] error in
                if let error = error {
                    self?.logger?.error(event: .pushTokenUpdate("Error: \(error.additionalDescription)); enrollment: \(enrollmentId)"))
                } else {
                    self?.logger?.info(event: .pushTokenUpdate("OktaAuthenticator.sdk push token update finished"))
                }
                executeOnMainThread {
                    self?.view?.hideActivityIndicator()
                    self?.displayLogs()
                }
            }
        }
    }

    private func displayLogs() {
        guard let logger = self.logger, let view = self.view else {
            return
        }
        LogSnapshot.show(from: logger, in: view)
    }

    private func startPushTokenUpdate() {
        view?.getSingleLineText(title: "Enter New Push Token", message: nil, placeholder: "Push Token") { [weak self] in
            self?.logger?.info(event: .updatePushToken("User entered push token: \($0)"))
            self?.updatePushToken(with: $0)
        }
    }

    private func retrievePendingChallenge() {
        view?.showActivityIndicator()
        logger?.info(event: .accountDetails("Retrieve pending challenges"))
        getAccessToken { [weak self] accessToken, error in
            guard let self = self else {
                return
            }
            guard let accessToken = accessToken else {
                self.view?.hideActivityIndicator()
                self.logger?.error(event: .accountDetails("Access token can not be nil"))
                return
            }
            self.enrollment.retrievePushChallenges(authenticationToken: AuthToken.bearer(accessToken)) { result in
                DispatchQueue.main.async {
                    self.view?.hideActivityIndicator()
                    switch result {
                    case .success(let pushChallenges):
                        if pushChallenges.count == 0 {
                            self.logger?.info(event: .pendingChallenge("Server responded with 0 pending challenges"))
                            self.view?.presentError(title: "Success", message: "Server responded with 0 pending challenges")
                        }
                        self.logger?.info(event: .pendingChallenge("Retrieve pending challenge was successful"))
                        self.resolvePushChallenges(pushChallenges)
                    case .failure(let error):
                        self.logger?.error(event: .pendingChallenge("Retrieve pending challenge failed with error - \(error.additionalDescription)"))
                        self.displayLogs()
                    }
                }
            }
        }
    }

    private func confirmDeleteAccount() {
        view?.confirmAction(
            title: "Are you sure?",
            message: "After deleting enrollment your enrollment will be deleted.", yesActionStyle: .destructive
        ) { [weak self] in
            self?.deleteAccount()
        }
    }

    private func deleteAccount() {
        view?.showActivityIndicator()
        logger?.info(event: .deleteAccount("Deleting enrollment \(enrollment.enrollmentId)"))
        getAccessToken { [weak self] accessToken, error in
            guard let self = self else {
                return
            }
            guard let accessToken = accessToken else {
                self.view?.hideActivityIndicator()
                self.logger?.error(event: .accountDetails("Access token can not be nil"))
                return
            }
            let authToken = AuthToken.bearer(accessToken)
            self.authenticator.delete(enrollment: self.enrollment, authenticationToken: authToken) { [weak self] error in
                executeOnMainThread {
                    guard let self = self else {
                        return
                    }
                    self.view?.hideActivityIndicator()
                    if let error = error {
                        self.processDeletingEnrollmentError(error)
                    } else {
                        self.view?.pop(completion: {
                            self.enrollmentDeleted(self.enrollment)
                        })
                    }
                }
            }
        }
    }
    
    private func confirmRevokeAccessToken() {
        view?.confirmAction(
            title: "Are you sure?",
            message: "You will not be able to manage your account", yesActionStyle: .destructive
        ) { [weak self] in
            self?.revokeAccessToken()
        }
    }
    
    private func revokeAccessToken() {
        view?.showActivityIndicator()
        logger?.info(event: .accountDetails("Revoke access token for enrollment: \(enrollment.enrollmentId)"))
        getAccessToken {[weak self] accessToken, error in
            guard let self = self else {
                return
            }
            guard let accessToken = accessToken else {
                self.view?.hideActivityIndicator()
                self.logger?.error(event: .accountDetails("Access token can not be nil"))
                return
            }
            self.oidcStateManager?.revoke(accessToken, callback: { [weak self] success, error in
                guard let self = self else {
                    return
                }
                executeOnMainThread {
                    self.view?.hideActivityIndicator()
                    if success {
                        self.displayLogs()
                    } else {
                        if let error = error {
                            self.processRevokeAccessTokenError(error)
                        } else {
                            self.processRevokeAccessTokenUnknownError()
                        }
                    }
                }
            })
        }
    }
    
    private func processRevokeAccessTokenUnknownError() {
        let unknownErrorString = "Unknown error revoke access token for enrollment: \(self.enrollment.enrollmentId)"
        self.logger?.error(event: .accountDetails(unknownErrorString))
        self.view?.presentError(title: "Error", message: unknownErrorString)
    }
    
    private func processRevokeAccessTokenError(_ error: Error) {
        self.logger?.error(event: .accountDetails("Error revoke access token for enrollment: \(self.enrollment.enrollmentId): \(error.localizedDescription)"))
        self.view?.presentError(title: "Error", message: error.localizedDescription)
    }
    
    private func processDeletingEnrollmentError(_ error: DeviceAuthenticatorError) {
        self.logger?.error(event: .deleteAccount("Error deleting enrollment \(self.enrollment.enrollmentId): \(error.additionalDescription)"))
        self.view?.presentError(title: "Error", message: error.additionalDescription)
    }
    
    private func resolvePushChallenges(_ pushChallenges: [PushChallengeProtocol]) {
        pushChallenges.forEach {
            self.resolvePushChallenge($0)
        }
    }
    
    private func resolvePushChallenge(_ pushChallenge: PushChallengeProtocol) {
        guard let navigationController = (self.view as? UIViewController)?.navigationController else {
            return
        }
        pushChallenge.resolve { step in
            DispatchQueue.main.async {
                let remediationEventsHandler = RemediationEventsHandler(navigationController: navigationController)
                remediationEventsHandler.handle(step)
            }
        } onCompletion: { [weak self] error in
            DispatchQueue.main.async {
                if let error = error {
                    self?.view?.presentError(title: "Error", message: error.localizedDescription)
                    self?.logger?.error(event: .accountDetails("Can not resolve push challenge: \(error.localizedDescription)"))
                } else {
                    self?.logger?.error(event: .accountDetails("Success resolve push challenge"))
                }
            }
        }
    }

    private func getAccessToken(completion: @escaping (String?, AccessTokenManagerError?) -> ()) {
        logger?.info(event: .accountDetails("Start get access token"))
        accessTokenManager.loadAccessToken(for: enrollment.enrollmentId) { [weak self] result in
            switch result {
            case .success(let accessToken):
                self?.logger?.info(event: .accountDetails("Load access token successfully"))
                completion(accessToken, nil)
                
            case .failure(let error):
                let errorString = "Load access token with error: \(error.errorDescription)"
                self?.logger?.error(event: .accountDetails(errorString))
                self?.view?.presentError(title: "Access token error", message: errorString)
                completion(nil, error)
            }
        }
    }
}
