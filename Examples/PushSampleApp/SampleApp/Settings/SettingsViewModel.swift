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
import OktaDeviceSDK
import OktaLogger

protocol SettingsViewModelProtocol {
    func setup(cell: SettingsCell, with row: Int)
    var numberOfRows: Int { get }
    var title: String { get }
    var view: SettingsViewUpdatable? { get }
}

class SettingsViewModel: SettingsViewModelProtocol {
    
    private let authenticator: DeviceAuthenticatorProtocol
    private let webAuthenticator: OktaWebAuthProtocol
    private let logger: OktaLogger?
    var title: String = "Security Settings"
    weak var view: SettingsViewUpdatable?
    private var cellModels: [SettingsCellProtocol] = []
    
    init(deviceauthenticator: DeviceAuthenticatorProtocol,
         webAuthenticator: OktaWebAuthProtocol,
         settingsView: SettingsViewUpdatable,
         logger: OktaLogger? = nil) {
        self.authenticator = deviceauthenticator
        self.webAuthenticator = webAuthenticator
        self.view = settingsView
        self.logger = logger
        setupCellModels()
        //Here you would fetch your backend's Authenticator Policy. This to decide if User Verification is required or preferred so you would update your UX accordingly.
        //fetchPolicy()
    }
    
    private var userVerificationCellModel: UserVerificationCellModel? {
        // Check if an enrollment exists on device.
        guard let authenticator = authenticator.allEnrollments().first else { return nil }
        
        return UserVerificationCellModel(isEnabled: authenticator.userVerificationEnabled, didToggleSwitch: { [weak self] isOn in
            self?.toggleUserVerification(enable: isOn)
        })
    }
    
    private var enrollmentCellModel: PushSettingsCellModel {
        let isEnrolled = !authenticator.allEnrollments().isEmpty
        return PushSettingsCellModel(isEnabled: isEnrolled, didToggleSwitch: { [weak self] isOn in
            guard isOn else {
                self?.beginEnrollmentDeletion()
                return
            }
            self?.beginEnrollment()
        })
    }
    
    private var deviceAuthenticatorConfig: DeviceAuthenticatorConfig? {
        guard let url = webAuthenticator.baseURL else {
            logger?.error(eventName: EnrollmentError.authConfigErrorTitle, message: EnrollmentError.baseUrlError.description)
            view?.showAlert(alertTitle: EnrollmentError.authConfigErrorTitle, alertText: EnrollmentError.baseUrlError.description)
            return nil
        }
        guard let clientId = webAuthenticator.clientId else {
            logger?.error(eventName: EnrollmentError.authConfigErrorTitle, message: EnrollmentError.clientIdError.description)
            view?.showAlert(alertTitle: EnrollmentError.authConfigErrorTitle, alertText: EnrollmentError.clientIdError.description)
            return nil
        }
        return DeviceAuthenticatorConfig(orgURL: url, oidcClientId: clientId)
    }
    
    var numberOfRows: Int {
        return cellModels.count
    }
    
    func setup(cell: SettingsCell, with row: Int) {
        cell.setup(cellModel: cellModels[row])
    }
    
    private func setupCellModels() {
        let cells: [SettingsCellProtocol?] = [
            EmailSettingsCellModel(),
            enrollmentCellModel,
            userVerificationCellModel
        ]
        cellModels = cells.compactMap({ $0 })
    }

    /*
    Here you would fetch your backend's Authenticator Policy. This to decide if User Verification is required or preferred so you would update your UX accordingly
     
    private func fetchPolicy() {
        let authToken = AuthToken.bearer(accessToken)
        guard let deviceAuthenticatorConfig = self.deviceAuthenticatorConfig else { return }
        self.authenticator.downloadPolicy(authenticationToken: authToken, authenticatorConfig: deviceAuthenticatorConfig) { [weak self] result in }
        }
    }
    */

    private func getAccessToken(completion: @escaping (String) -> Void) {
        // Fetching a valid access token. WebAuthenticator will try to refresh it if expired.
        webAuthenticator.getAccessToken { [weak self] result in
            switch result {
            case .success(let token):
                completion(token.accessToken)
            case .failure(let error):
                self?.logger?.error(eventName: LoggerEvent.account.rawValue, message: error.localizedDescription)
                self?.view?.showAlert(alertTitle: "Error", alertText: EnrollmentError.accessTokenError.description)
                self?.view?.updateView(shouldShowSpinner: false)
            }
        }
    }
    
    private func beginEnrollment() {
        getAccessToken { token in
            self.enrolldDeviceAuthenticator(with: token)
        }
    }
    
    private func enrolldDeviceAuthenticator(with accessToken: String) {
        
        let authToken = AuthToken.bearer(accessToken)

        guard let deviceAuthenticatorConfig = deviceAuthenticatorConfig else { return }

        var deviceToken = DeviceToken.empty
        if let pushToken = UserDefaults.deviceToken() {
            deviceToken = .tokenData(pushToken)
        } else {
            logger?.warning(eventName: LoggerEvent.enrollment.rawValue, message: "Device token is nil")
        }
        let enrollmentParams = EnrollmentParameters(deviceToken: deviceToken)
        
        view?.updateView(shouldShowSpinner: true)

        authenticator.enroll(authenticationToken: authToken,
                             authenticatorConfig: deviceAuthenticatorConfig,
                             enrollmentParameters: enrollmentParams) { [weak self] result in
            
            switch result {
            case .success(let authenticator):
                self?.logger?.info(eventName: LoggerEvent.enrollment.rawValue, message: "Success enrolling this device, enrollment ID - \(authenticator.enrollmentId)")
                self?.view?.showAlert(alertTitle: "Enrolled Successfully", alertText: "You can now use this app as push authenticator")
            case .failure(let error):
                self?.logger?.error(eventName: EnrollmentError.deviceAuthenticatorError(error).description, message: error.localizedDescription)
                self?.view?.showAlert(alertTitle: EnrollmentError.errorTitle, alertText: error.localizedDescription)
            }
            self?.setupCellModels()
            self?.view?.updateView(shouldShowSpinner: false)
        }
    }
    
    private func beginEnrollmentDeletion() {
        // Selecting the first enrollment object of the authenticators associated to this device since this sample app only shows enrollment of a single authenticator.
        guard let enrollment = authenticator.allEnrollments().first else {
            view?.showAlert(alertTitle: EnrollmentDeleteError.errorTitle, alertText: EnrollmentDeleteError.noEnrollmentDeleteError.description)
            logger?.error(eventName: LoggerEvent.enrollmentDelete.rawValue, message: EnrollmentDeleteError.noEnrollmentDeleteError.description)
            return
        }
        getAccessToken { token in
            self.deleteEnrollment(enrollment: enrollment, accessToken: token)
        }
    }
    
    private func deleteEnrollment(enrollment: AuthenticatorEnrollmentProtocol, accessToken: String) {
        let authToken = AuthToken.bearer(accessToken)
        view?.updateView(shouldShowSpinner: true)
        authenticator.delete(enrollment: enrollment, authenticationToken: authToken) { [weak self] error in
            if let error = error {
                self?.view?.showAlert(alertTitle: EnrollmentDeleteError.errorTitle, alertText: error.localizedDescription)
                self?.logger?.error(eventName: LoggerEvent.enrollmentDelete.rawValue, message: error.localizedDescription)
            } else {
                self?.view?.showAlert(alertTitle: "Deletion Successfully", alertText: "Success removing this device as a push authenticator")
            }
            self?.setupCellModels()
            self?.view?.updateView(shouldShowSpinner: false)
        }
    }
    
    private func toggleUserVerification(enable: Bool) {
        guard let authenticator = authenticator.allEnrollments().first else {
            return
        }
        view?.updateView(shouldShowSpinner: true)
        getAccessToken { accessToken in
            let authToken = AuthToken.bearer(accessToken)
            authenticator.setUserVerification(authenticationToken: authToken, enable: enable) { [weak self] error in
                if let error = error {
                    self?.view?.showAlert(alertTitle: "Error updating User Verification", alertText: error.localizedDescription)
                    self?.logger?.error(eventName: LoggerEvent.userVerification.rawValue, message: error.localizedDescription)
                } else {
                    self?.view?.showAlert(alertTitle: "Success updating User Verification", alertText: "")
                }
                self?.setupCellModels()
                self?.view?.updateView(shouldShowSpinner: false)
            }
        }
    }
}

enum EnrollmentError: Error {
    case accessTokenError, baseUrlError, clientIdError, deviceAuthenticatorError(DeviceAuthenticatorError?)

    var description: String {
        switch self {
        case .accessTokenError:
            return "Error getting access token"
        case .baseUrlError:
            return "Base url should not be nil"
        case .clientIdError:
            return "ClientId should not be nil"
        case .deviceAuthenticatorError(let error):
            return "DeviceAuthenticator error \(error)"
        }
    }
    
    static let errorTitle = "Failed to enroll"
    static let authConfigErrorTitle = "Error creating config"
}

enum EnrollmentDeleteError: Error {
    case noEnrollmentDeleteError, accessTokenError, deviceAuthenticatorError(DeviceAuthenticatorError?)

    var description: String {
        switch self {
        case .noEnrollmentDeleteError:
            return "No enrollment to delete"
        case .accessTokenError:
            return "Error getting access token"
        case .deviceAuthenticatorError(let error):
            return "DeviceAuthenticator error \(error)"
        }
    }
    static let errorTitle = "Failed to delete"
}
