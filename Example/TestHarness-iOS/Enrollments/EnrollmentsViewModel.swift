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
import OktaDeviceSDK

struct EnrollmentData {
    let oidcConfig: OktaOidcConfig
    let oidcStateManager: OktaOidcStateManager?
}

protocol EnrollmentsViewModelProtocol {
    var listTitle: String { get }

    var hasEnrolledAuthenticators: Bool { get }

    var enrollmentsCount: Int { get }
    var enrolledAuthenticators: [AuthenticatorEnrollmentProtocol] { get }

    func start()
    func startEnrollment(on viewController: UIViewController)
    func showAccountDetails(for enrollment: AuthenticatorEnrollmentProtocol)
    func showActions(from sourceButton: UIBarButtonItem)
    func delete(enrollment: AuthenticatorEnrollmentProtocol)
}

class EnrollmentsViewModel: EnrollmentsViewModelProtocol, MailServiceDelegate {

    weak var view: EnrollmentsViewProtocol?

    let listTitle = "Enrolled authenticators"

    var enrollmentsCount: Int { enrolledAuthenticators.count }
    private(set) var enrolledAuthenticators: [AuthenticatorEnrollmentProtocol] = [] {
        didSet {
            view?.updateData()
            view?.updateUI()
        }
    }

    var hasEnrolledAuthenticators: Bool { enrollmentsCount != 0 }

    private let pushTokenUpdater: () -> Void
    private let logger: LoggerManagerProtocol?
    private var actions: [ActionSheetActionViewModel] = []
    private let mailService: MailServiceProtocol
    private let userDefaults: UserDefaults
    private let fileManager: FileManager
    private let oktaFileManager: OktaFilesManagerProtocol
    private let deviceAuthenticator: DeviceAuthenticatorProtocol
    private let accessTokenManager: AccessTokenManagerProtocol

    init(pushTokenUpdater: @escaping () -> Void = { UIApplication.shared.registerForRemoteNotifications() },
         logger: LoggerManagerProtocol? = LoggerManager.shared,
         mailService: MailServiceProtocol = MailService(),
         userDefaults: UserDefaults = .standard,
         fileManager: FileManager = .default,
         oktaFileManager: OktaFilesManagerProtocol = OktaFilesManager.shared,
         deviceAuthenticator: DeviceAuthenticatorProtocol,
         accessTokenManager: AccessTokenManagerProtocol)
    {
        self.pushTokenUpdater = pushTokenUpdater
        self.logger = logger
        self.mailService = mailService
        self.userDefaults = userDefaults
        self.fileManager = fileManager
        self.oktaFileManager = oktaFileManager
        self.deviceAuthenticator = deviceAuthenticator
        self.accessTokenManager = accessTokenManager

        mailService.delegate = self

        enrolledAuthenticators = deviceAuthenticator.allEnrollments()
        refreshAccessTokens(enrollments: enrolledAuthenticators)

        let sendLogsToEmailAction = ActionSheetActionViewModel(title: "Send Logs to Email") { [weak self] in self?.sendLogs() }
        let sendSqliteToEmailAction = ActionSheetActionViewModel(title: "Send Sqlite DB to Email") { [weak self] in self?.sendSqliteDb() }
        let clearLogsAction = ActionSheetActionViewModel(title: "Clear Logs", style: .destructive) { [weak self] in self?.confirmClearLogs() }
        let cancelAction = ActionSheetActionViewModel(title: "Cancel", style: .cancel)
        actions = [sendLogsToEmailAction, sendSqliteToEmailAction, clearLogsAction, cancelAction]
    }

    func showActions(from sourceButton: UIBarButtonItem) {
        view?.presentActionSheet(actions, title: nil, sourceButton: sourceButton)
    }

    func showAccountDetails(for enrollment: AuthenticatorEnrollmentProtocol) {
        let viewController = AccountDetailsViewController.loadFromStoryboard()
        let oidcStateManager = OktaOidcStateManager.readFromSecureStorage(by: enrollment.enrollmentId)
        let viewModel = AccountDetailsViewModel(enrollment: enrollment, oidcStateManager: oidcStateManager, authenticator: deviceAuthenticator, enrollmentDeleted: enrollmentDeleted, accessTokenManager: accessTokenManager)
        viewController.viewModel = viewModel
        viewModel.view = viewController
        view?.showAccountDetails(viewController)
    }

    private func enrollmentDeleted(_ enrollment: AuthenticatorEnrollmentProtocol) {
        logger?.info(event: .deleteAccount("Clean up after enrollment deletion"))
        if let stateManager = OktaOidcStateManager.readFromSecureStorage(by: enrollment.enrollmentId) {
            do {
                try stateManager.removeFromSecureStorage()
            } catch {
                logger?.error(event: .deleteAccount(error.localizedDescription))
            }
        }

        var enrollments = enrolledAuthenticators
        if let index = enrollments.firstIndex(where: { $0.enrollmentId == enrollment.enrollmentId }) {
            enrollments.remove(at: index)
        }
        enrolledAuthenticators = enrollments
        view?.updateData()
        view?.updateUI()
        displayLogs()
    }

    func start() {
        view?.updateData()
        view?.updateUI()
    }

    func startEnrollment(on viewController: UIViewController) {
        logger?.info(event: .enrollment("Start enrollment"))

        let vc = OidcConfigViewController.loadFromStoryboard()
        let viewModel = OidcConfigViewModel(logger: logger) { [weak self] config, isEnableUserVerification in
            self?.enroll(with: config, userVerification: isEnableUserVerification, on: viewController)
        }
        vc.viewModel = viewModel
        viewModel.view = vc
        view?.push(vc)
    }

    private func enroll(with config: OktaOidcConfig, userVerification: Bool, on viewController: UIViewController) {
        logger?.info(event: .enrollment("Start OIDC flow"))

        guard let oidc = try? OktaOidc(configuration: config) else {
            logger?.error(event: .enrollment("Failed to instantiate OktaOidc with the config provided!"))
            view?.presentError(title: "Error", message: "Failed to instantiate OktaOidc with the config provided!")
            return
        }
        view?.showActivityIndicator()
        logger?.info(event: .enrollment("Start signInWithBrowser"))
        oidc.signInWithBrowser(from: viewController) { [weak self] stateManager, error in
            self?.view?.hideActivityIndicator()
            if let error = error {
                if error.localizedDescription.contains("org.openid.appauth.general error -3") {
                    self?.logger?.info(event: .enrollment("User cancelled oidc sign in"))
                    return
                }

                self?.logger?.error(event: .enrollment("Error signing in with broser: \(error.localizedDescription)"))
                self?.view?.presentError(title: "Error", message: error.localizedDescription)
                return
            }

            guard let stateManager = stateManager else {
                self?.logger?.error(event: .enrollment("Unknown error: stateManager could not be nil"))
                self?.view?.presentError(title: "Error", message: "stateManager could not be nil")
                return
            }

            guard let accessToken = stateManager.accessToken else {
                self?.logger?.error(event: .enrollment("Unknown error: Access token could not be nil"))
                self?.view?.presentError(title: "Error", message: "Access token could not be nil")
                return
            }
            
            guard let issuerURL = URL(string: oidc.configuration.issuer) else {
                self?.logger?.error(event: .enrollment("Unknown error: Issuer URL could not be nil"))
                self?.view?.presentError(title: "Error", message: "Issuer URL could not be nil")
                return
            }

            var deviceToken = DeviceToken.empty
            if let pushToken = UserDefaults.deviceToken() {
                deviceToken = .tokenData(pushToken)
            } else {
                self?.logger?.warning(event: .enrollment("Unknown error: Device push token is nil"))
            }
 
            var enrollmentParameters = EnrollmentParameters(deviceToken: deviceToken)
            enrollmentParameters.enableUserVerification(enable: userVerification)
            let deviceAuthenticatorConfig = DeviceAuthenticatorConfig(orgURL: issuerURL, oidcClientId: oidc.configuration.clientId)
            self?.view?.showActivityIndicator()
            self?.logger?.info(event: .enrollment("Getting access token success. Start authenticator enrollment"))
            self?.deviceAuthenticator.enroll(authenticationToken: AuthToken.bearer(accessToken),
                                             authenticatorConfig: deviceAuthenticatorConfig,
                                             enrollmentParameters: enrollmentParameters) { result in
                DispatchQueue.main.async {
                    self?.view?.hideActivityIndicator()
                    switch result {
                    case .success(let enrollment):
                        self?.save(enrollment, stateManager: stateManager)
                        self?.pushTokenUpdater()
                        self?.logger?.info(event: .enrollment("Authenticator successfully enrolled: \(enrollment.enrollmentId)"))
                    case .failure(let error):
                        self?.logger?.error(event: .enrollment("Error enrolling authenticator: \(error.localizedDescription)"))
                        self?.view?.presentError(title: "Error", message: error.localizedDescription)
                    }
                }
            }
        }
    }

    func delete(enrollment: AuthenticatorEnrollmentProtocol) {
        let title = "Are you sure?"
        let message = "Your enrollment will be deleted locally."
        view?.confirmAction(title: title, message: message, yesActionStyle: .destructive) { [weak self] in
            self?.localDelete(enrollment)
        }
    }

    private func localDelete(_ enrollment: AuthenticatorEnrollmentProtocol) {
        logger?.info(event: .deleteAccount("Locally deleting enrollment \(enrollment.enrollmentId)"))
        do {
            try enrollment.deleteFromDevice()
            if let stateManager = OktaOidcStateManager.readFromSecureStorage(by: enrollment.enrollmentId) {
                try stateManager.removeFromSecureStorage()
            }
            logger?.info(event: .deleteAccount("Success locally delete enrollment \(enrollment.enrollmentId)"))
        }
        catch {
            logger?.error(event: .deleteAccount("Error locally deleting enrollment \(enrollment.enrollmentId): \(error.localizedDescription)"))
        }
        enrolledAuthenticators = deviceAuthenticator.allEnrollments()
        displayLogs()
    }

    private func confirmClearLogs() {
        view?.confirmAction(title: "Are you sure?", message: "This can not be undone", yesActionStyle: .destructive) { [weak self] in self?.clearLogs() }
    }

    private func clearLogs() {
        logger?.clear()
    }

    private func sendLogs() {
        logger?.currentLogData { [weak self] data in
            var joined = Data()
            data.forEach { joined.append($0) }
            let attachment = MailAttachment(data: joined, fileName: "logs.txt", mimeType: "text/plain")
            self?.mailService.sendMail(subject: "TestHarness-iOS Logs", body: nil, isHtml: true, recepients: [], attachments: [attachment])
        }
    }

    private func sendSqliteDb() {
        let applicationGroupId = GlobalConstants.appGroupId
        let path = DeviceAuthenticatorConstants.defaultStorageRelativeDirectoryPath

        guard let url = fileManager.containerURL(forSecurityApplicationGroupIdentifier: applicationGroupId)?.appendingPathComponent(path) else {
            return
        }
        oktaFileManager.getFiles(from: url) { [weak self] result in
            switch result {
            case .failure(let error):
                self?.logger?.error(event: .sendingSqliteFiles(error.localizedDescription))
                self?.view?.presentError(title: "Error", message: error.localizedDescription)

            case .success(let files):
                let attachments = files.map { MailAttachment(data: $0.attachment, fileName: $0.fileName, mimeType: "application/vnd.sqlite3") }
                self?.mailService.sendMail(subject: "TestHarness-iOS Sqlite files", body: nil, isHtml: true, recepients: [], attachments: attachments)
            }
        }
    }

    private func displayLogs() {
        guard let logger = logger, let view = view else {
            return
        }
        LogSnapshot.show(from: logger, in: view)
    }

    // MARK: MailServiceDelegate
    func mailServicePresent(_ viewController: UIViewController) {
        view?.present(viewController)
    }

    func mailServiceError(_ error: MailServiceError) {
        switch error {
        case .canNotSendMail:
            view?.presentError(title: "Error", message: "No Email Account. If you want to send email pls add your email account in device Settings -> Mail -> Contacts.")
        case .other(let message):
            view?.presentError(title: "Error", message: message)
        }
    }

    private func refreshAccessTokens(enrollments: [AuthenticatorEnrollmentProtocol]) {
        accessTokenManager.refreshAllAccessTokens()
    }

    private func save(_ enrollment: AuthenticatorEnrollmentProtocol, stateManager: OktaOidcStateManager) {
        let enrollmentId = enrollment.enrollmentId
        do {
            try stateManager.writeToSecureStorage(by: enrollmentId)
            logger?.info(event: .accountDetails("Auth state save successfully"))
        } catch {
            logger?.error(event: .accountDetails("Auth state save with error: \(error)"))
        }
        if let index = enrolledAuthenticators.firstIndex(where: { $0.enrollmentId == enrollment.enrollmentId }) {        enrolledAuthenticators.remove(at: index)
        }
        enrolledAuthenticators.append(enrollment)
    }
}
