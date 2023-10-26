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
import WebAuthenticationUI

// Wrapper protocol for Okta WebAuthentication object
protocol OktaWebAuthProtocol {
    func signIn(from: WebAuthentication.WindowAnchor?,
                options: [WebAuthentication.Option]?,
                completion: @escaping (Result<AuthFoundation.Token, WebAuthenticationError>) -> Void)
    func signOut(from window: WebAuthentication.WindowAnchor?, completion: @escaping (Result<Void, WebAuthenticationError>) -> Void)
    func getAccessToken(completion: @escaping (Result<Token, OAuth2Error>) -> Void)

    var isSignedIn: Bool { get }
    var accessToken: String? { get }
    var baseURL: URL? { get }
    var clientId: String? { get }
    var userName: String? { get }
    var email: String? { get }
}

extension WebAuthentication: OktaWebAuthProtocol {
    var isSignedIn: Bool {
        guard let _ = Credential.default?.token.accessToken else { return false }
        return true
    }

    var accessToken: String? {
        Credential.default?.token.accessToken
    }

    var baseURL: URL? {
        Credential.default?.oauth2.baseURL
    }

    var clientId: String? {
        Credential.default?.oauth2.configuration.clientId
    }

    var userName: String? {
        Credential.default?.token.idToken?.name
    }

    var email: String? {
        Credential.default?.token.idToken?.email
    }

    func signOut(from window: WebAuthentication.WindowAnchor?, completion: @escaping (Result<Void, WebAuthenticationError>) -> Void) {
        signOut(from: window, credential: Credential.default) { result in
            self.clearCredential()
            switch result {
            case .success():
                completion(Result.success(()))
            case .failure(let error):
                completion(Result.failure(error))
            }
        }
    }

    func clearCredential() {
        try? Credential.default?.remove()
    }

    func getAccessToken(completion: @escaping (Result<Token, OAuth2Error>) -> Void) {
        Credential.default?.refreshIfNeeded(completion: { result in
            switch result {
            case .success():
                if let token = Credential.default?.token {
                    completion(Result.success(token))
                } else {
                    completion(Result.failure(OAuth2Error.missingToken(type: .accessToken)))
                }
            case .failure(let error):
                completion(Result.failure(error))
            }
        })
    }
}
