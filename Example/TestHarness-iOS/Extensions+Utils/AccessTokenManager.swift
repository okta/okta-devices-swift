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
import OktaOidc
import OktaDeviceSDK

typealias AccessTokenCompletion = ((Result<String, AccessTokenManagerError>) -> ())

protocol AccessTokenManagerProtocol {

    func loadAccessToken(for enrollmentId: String, completion: @escaping AccessTokenCompletion)
    func refreshAccessToken(for enrollmentId: String, completion: @escaping AccessTokenCompletion)
    func refreshAllAccessTokens()
}

enum AccessTokenManagerError: Error {
    case missingAuthState(_ enrollmentId: String)
    case couldNotUpdateAccessToken(_ enrollmentId: String)
    case renewError(_ enrollmentId: String, _ error: Error)

    var errorDescription: String {
        switch self {
        case .missingAuthState(let enrollmentId):
            return "Auth state is missing for enrollmentId: \(enrollmentId)"
        case .couldNotUpdateAccessToken(let enrollmentId):
            return "Access token is nil after renew for enrollmentId: \(enrollmentId)"
        case .renewError(let enrollmentId, let error):
            return "Renew access token for enrollmentId: \(enrollmentId) failed: \(error.localizedDescription)"
        }
    }
}

class AccessTokenManager: AccessTokenManagerProtocol {

    private let logger: LoggerManagerProtocol?
    private let deviceAuthenticator: DeviceAuthenticatorProtocol
    
    init(deviceAuthenticator: DeviceAuthenticatorProtocol,
         logger: LoggerManagerProtocol? = LoggerManager.shared) {
        self.logger = logger
        self.deviceAuthenticator = deviceAuthenticator
    }

    func loadAccessToken(for enrollmentId: String, completion: @escaping AccessTokenCompletion) {
        guard let oidcStateManager = OktaOidcStateManager.readFromSecureStorage(by: enrollmentId) else {
            completion(.failure(.missingAuthState(enrollmentId)))
            return
        }
        if let accessToken = oidcStateManager.accessToken {
            completion(.success(accessToken))
            return
        }
        oidcStateManager.renew { [weak self] oidcStateManager, error in
            executeOnMainThread {
                if let oidcStateManager = oidcStateManager, let accessToken = oidcStateManager.accessToken {
                    self?.writeToSecureStorage(oidcStateManager: oidcStateManager, by: enrollmentId)
                    completion(.success(accessToken))
                } else if let error = error {
                    let accessTokenManagerError = AccessTokenManagerError.renewError(enrollmentId, error)
                    self?.logger?.error(event: .accountDetails(accessTokenManagerError.errorDescription))
                    completion(.failure(accessTokenManagerError))
                } else {
                    let accessTokenManagerError = AccessTokenManagerError.couldNotUpdateAccessToken(enrollmentId)
                    self?.logger?.error(event: .accountDetails(accessTokenManagerError.errorDescription))
                    completion(.failure(accessTokenManagerError))
                }
            }
        }
    }

    func refreshAccessToken(for enrollmentId: String, completion: @escaping AccessTokenCompletion) {
        guard let oidcStateManager = OktaOidcStateManager.readFromSecureStorage(by: enrollmentId) else {
            completion(.failure(.missingAuthState(enrollmentId)))
            return
        }
        refreshAccessToken(oidcStateManager: oidcStateManager, enrollmentId: enrollmentId, completion: completion)
    }

    func refreshAllAccessTokens() {
        let enrollmentIds = deviceAuthenticator.allEnrollments().map { $0.enrollmentId }
        enrollmentIds.forEach { enrollmentId in
            refreshAccessToken(for: enrollmentId) { [weak self] result in
                switch result {
                case .success(_):
                    let logString = "Access token udpated successfully for enrollmentId: \(enrollmentId)"
                    self?.logger?.info(event: .accountDetails(logString))
                case .failure(let error):
                    self?.logger?.error(event: .accountDetails(error.errorDescription))
                }
            }
        }
    }

    private func writeToSecureStorage(oidcStateManager: OktaOidcStateManager, by enrollmentId: String) {
        do {
            try oidcStateManager.writeToSecureStorage(by: enrollmentId)
            logger?.info(event: .accountDetails("Save enrollment config successfully"))
        } catch {
            logger?.error(event: .accountDetails("Save enrollment config with error: \(error)"))
        }
    }

    private func refreshAccessToken(oidcStateManager: OktaOidcStateManager, enrollmentId: String, completion: @escaping AccessTokenCompletion) {
        oidcStateManager.renew { [weak self] oidcStateManager, error in
            executeOnMainThread {
                if let oidcStateManager = oidcStateManager, let accessToken = oidcStateManager.accessToken {
                    self?.writeToSecureStorage(oidcStateManager: oidcStateManager, by: enrollmentId)
                    completion(.success(accessToken))
                } else if let error = error {
                    let accessTokenManagerError = AccessTokenManagerError.renewError(enrollmentId, error)
                    self?.logger?.error(event: .accountDetails(accessTokenManagerError.errorDescription))
                    completion(.failure(accessTokenManagerError))
                } else {
                    let accessTokenManagerError = AccessTokenManagerError.couldNotUpdateAccessToken(enrollmentId)
                    self?.logger?.error(event: .accountDetails(accessTokenManagerError.errorDescription))
                    completion(.failure(accessTokenManagerError))
                }
            }
        }
    }
}
