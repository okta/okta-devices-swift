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
    var didEnroll: (String, String) -> Void { get set }
}

class SettingsViewModel: SettingsViewModelProtocol {
    
    private let authenticator: DeviceAuthenticatorProtocol
    private let webAuthenticator: OktaWebAuthProtocol
    private let logger: OktaLogger?
    var title: String = "Security Settings"
    var didEnroll: (String, String) -> Void = { _, _ in }
    
    private lazy var cellModels: [SettingsCellProtocol] = {
        let isEnrolled = !self.authenticator.allEnrollments().isEmpty
        return [
            EmailSettingsCellModel(),
            PushSettingsCellModel(isEnabled: isEnrolled, didToggleSwitch: { isOn in
                guard isOn else {
                    // TODO: Handle enrollment deletion
                    return
                }
                self.beginEnrollment()
            })]
    }()
    
    init(deviceauthenticator: DeviceAuthenticatorProtocol,
         webAuthenticator: OktaWebAuthProtocol,
         logger: OktaLogger? = nil) {
        self.authenticator = deviceauthenticator
        self.webAuthenticator = webAuthenticator
        self.logger = logger
    }
    
    var numberOfRows: Int {
        return cellModels.count
    }
    
    func setup(cell: SettingsCell, with row: Int) {
        cell.setup(cellModel: cellModels[row])
    }
    
    private func beginEnrollment() {
        // Fetching a valid access token to pass to enrollment. WebAuthenticator will try to refresh it if expired.
        webAuthenticator.getAccessToken { [weak self] result in
            switch result {
            case .success(_):
                self?.enroll()
            case .failure(let error):
                self?.logger?.error(eventName: LoggerEvent.account.rawValue, message: error.localizedDescription)
            }
        }
    }
    
    private func enroll() {
        guard let accessToken = webAuthenticator.accessToken else {
            logger?.error(eventName: LoggerEvent.enrollment.rawValue, message: EnrollmentError.accessTokenError.description)
            didEnroll(EnrollmentError.errorTitle, EnrollmentError.accessTokenError.description)
            return
        }
        let authToken = AuthToken.bearer(accessToken)

        guard let url = webAuthenticator.baseURL else {
            logger?.error(eventName: LoggerEvent.enrollment.rawValue, message: EnrollmentError.baseUrlError.description)
            didEnroll(EnrollmentError.errorTitle, EnrollmentError.baseUrlError.description)
            return
        }
        guard let clientId = webAuthenticator.clientId else {
            logger?.error(eventName: LoggerEvent.enrollment.rawValue, message: EnrollmentError.clientIdError.description)
            didEnroll(EnrollmentError.errorTitle, EnrollmentError.clientIdError.description)
            return
        }

        let deviceAuthenticatorConfig = DeviceAuthenticatorConfig(orgURL: url, oidcClientId: clientId)

        var deviceToken = DeviceToken.empty
        if let pushToken = UserDefaults.deviceToken() {
            deviceToken = .tokenData(pushToken)
        } else {
            logger?.warning(eventName: LoggerEvent.enrollment.rawValue, message: "Device token is nil")
        }
        let enrollmentParams = EnrollmentParameters(deviceToken: deviceToken)

        authenticator.enroll(authenticationToken: authToken,
                             authenticatorConfig: deviceAuthenticatorConfig,
                             enrollmentParameters: enrollmentParams) { [weak self] result in
            
            switch result {
            case .success(let authenticator):
                self?.logger?.info(eventName: LoggerEvent.enrollment.rawValue, message: "Success enrolling this device, enrollment ID - \(authenticator.enrollmentId)")
                self?.didEnroll("Enrolled Successfully", "You can now use this app as push authenticator")
            case .failure(let error):
                self?.logger?.error(eventName: EnrollmentError.deviceAuthenticatorError(error).description, message: error.localizedDescription)
                self?.didEnroll(EnrollmentError.errorTitle, error.localizedDescription)
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
}
