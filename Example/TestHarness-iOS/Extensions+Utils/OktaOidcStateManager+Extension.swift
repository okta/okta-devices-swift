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

extension OktaOidcStateManager {

    func writeToSecureStorage(by enrollmentId: String) throws {
        let authStateData: Data
        if #available(iOS 11, OSX 10.14, *) {
            authStateData = try NSKeyedArchiver.archivedData(withRootObject: self, requiringSecureCoding: false)
        } else {
            authStateData = NSKeyedArchiver.archivedData(withRootObject: self)
        }
        try OktaOidcKeychain.set(
            key: enrollmentId,
            data: authStateData,
            accessibility: self.accessibility
        )
    }
    
    func removeFromSecureStorage(by enrollmentId: String) throws {
        try OktaOidcKeychain.remove(key: enrollmentId)
    }

    class func readFromSecureStorage(by enrollmentId: String) -> OktaOidcStateManager? {
        guard let encodedAuthState: Data = try? OktaOidcKeychain.get(key: enrollmentId) else {
            return nil
        }
        let state: OktaOidcStateManager?
        if #available(iOS 11, OSX 10.14, *) {
            state = (try? NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(encodedAuthState)) as? OktaOidcStateManager
        } else {
            state = NSKeyedUnarchiver.unarchiveObject(with: encodedAuthState) as? OktaOidcStateManager
        }
        return state
    }
    
    
}
