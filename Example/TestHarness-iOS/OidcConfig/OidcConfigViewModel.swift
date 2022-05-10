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
import OktaLogger

protocol OidcConfigViewModelProtocol {
    var doneButtonTitle: String { get }
    var issuer: String? { get }
    var clientId: String? { get }
    var redirectUri: String? { get }
    var logoutRedirectUri: String? { get }

    func start()
    func prepareConfig(clientId: String, issuer: String, redirectUri: String, logoutRedirectUri: String)
}

class OidcConfigViewModel: OidcConfigViewModelProtocol {
    struct Constants {
        struct Keys  {
            static let issuer = "issuer"
            static let clientId = "clientId"
            static let redirectUri = "redirectUri"
            static let logoutRedirectUri = "logoutRedirectUri"
        }
    }

    let doneButtonTitle = "Enroll"

    weak var view: OidcConfigViewProtocol?

    var issuer: String? { dict[Constants.Keys.issuer] }
    var clientId: String? { dict[Constants.Keys.clientId] }
    var redirectUri: String? { dict[Constants.Keys.redirectUri] }
    var logoutRedirectUri: String? { dict[Constants.Keys.logoutRedirectUri] }
    
    private var dict = [String: String]()
    private let userDefaults: UserDefaults
    private let completion: (OktaOidcConfig, Bool) -> Void
    private let plistName: String
    private let bundle: Bundle
    private let logger: LoggerManagerProtocol?

    init(
        plistName: String = OktaOidcConfig.defaultPlistName,
        userDefaults: UserDefaults = .standard,
        bundle: Bundle = .main,
        logger: LoggerManagerProtocol?,
        completion: @escaping (OktaOidcConfig, Bool) -> Void)
    {
        self.completion = completion
        self.userDefaults = userDefaults
        self.plistName = plistName
        self.bundle = bundle
        self.logger = logger
    }

    func start() {
        readPlist()
        if let issuer = userDefaults.string(forKey: Constants.Keys.issuer) {
            dict[Constants.Keys.issuer] = issuer
        }
        if let clientId = userDefaults.string(forKey: Constants.Keys.clientId) {
            dict[Constants.Keys.clientId] = clientId
        }
        if let redirectUri = userDefaults.string(forKey: Constants.Keys.redirectUri) {
            dict[Constants.Keys.redirectUri] = redirectUri
        }
        if let logoutRedirectUri = userDefaults.string(forKey: Constants.Keys.logoutRedirectUri) {
            dict[Constants.Keys.logoutRedirectUri] = logoutRedirectUri
        }
        view?.updateData()
    }

    func prepareConfig(clientId: String, issuer: String, redirectUri: String, logoutRedirectUri: String) {
        let clientId = clientId.trimmingCharacters(in: .whitespacesAndNewlines)
        let issuer = issuer.trimmingCharacters(in: .whitespacesAndNewlines)
        let redirectUri = redirectUri.trimmingCharacters(in: .whitespacesAndNewlines)
        let logoutRedirectUri = logoutRedirectUri.trimmingCharacters(in: .whitespacesAndNewlines)

        dict[Constants.Keys.issuer] = issuer
        dict[Constants.Keys.clientId] = clientId
        dict[Constants.Keys.redirectUri] = redirectUri
        dict[Constants.Keys.logoutRedirectUri] = redirectUri

        userDefaults.setValue(issuer, forKey: Constants.Keys.issuer)
        userDefaults.setValue(clientId, forKey: Constants.Keys.clientId)
        userDefaults.setValue(redirectUri, forKey: Constants.Keys.redirectUri)
        userDefaults.setValue(logoutRedirectUri, forKey: Constants.Keys.logoutRedirectUri)

        logger?.info(event: .enrollment("Try to prepare oidc config; clientId: \(clientId); issuer: \(issuer)"))
        let config: OktaOidcConfig
        do {
            config = try OktaOidcConfig(with: dict)
            askEnableUserVerificationKey { [weak self] isEnable in
                self?.view?.pop {
                    self?.completion(config, isEnable)
                }
            }
        } catch {
            logger?.info(event: .enrollment("Error preparing oidc config: \(error.localizedDescription)"))
            view?.presentError(title: "Error", message: error.localizedDescription)
        }
    }

    private func readPlist() {
        let plistPath = bundle.path(forResource: plistName, ofType: "plist") ?? ""
        let url = URL(fileURLWithPath: plistPath)
        if let data = try? Data(contentsOf: url), let dict = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: String] {
            self.dict = dict
        }
    }
    
    private func askEnableUserVerificationKey(_ completion: @escaping ((Bool) -> ())) {
        let yesAction = ActionSheetActionViewModel(title: "Yes") {
            completion(true)
        }
        let noAction = ActionSheetActionViewModel(title: "No", style: .cancel) {
            completion(false)
        }
        view?.presentAlert([yesAction, noAction], title: "User verification key", message: "Do you want to enroll user verification key")
    }
}
