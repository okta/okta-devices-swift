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

extension Bundle {

    /**
     Return the team identifier from the keychain entitlements (e.g. "B7F62B65BN")
     */
    static var teamIdentifier: String? = {
        var queryLoad: [String: AnyObject] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "bundleSeedID" as AnyObject,
            kSecAttrService as String: "" as AnyObject,
            kSecReturnAttributes as String: kCFBooleanTrue
        ]

        if #available(macOS 10.15, iOS 13.0, *) {
            queryLoad[kSecUseDataProtectionKeychain as String] = kCFBooleanTrue
        }

        var result: AnyObject?
        var status = withUnsafeMutablePointer(to: &result) {
            SecItemCopyMatching(queryLoad as CFDictionary, UnsafeMutablePointer($0))
        }

        if status == errSecItemNotFound {
            status = withUnsafeMutablePointer(to: &result) {
                SecItemAdd(queryLoad as CFDictionary, UnsafeMutablePointer($0))
            }
        }

        // Returned access group should be of the form <team_id>.<bundle_identifier>
        if status == noErr {
            status = SecItemDelete(queryLoad as CFDictionary)
            if let resultDict = result as? [String: Any], let accessGroup = resultDict[kSecAttrAccessGroup as String] as? String {
                let components = accessGroup.components(separatedBy: ".")
                return components.first
            } else {
                return nil
            }
        } else {
            print("Error getting TeamID via Keychain")
            return nil
        }
    }()

    ///  Return the version of the bundle (e.g. "1.2.3")
    func versionString() -> String {
        return infoDictionary?["CFBundleShortVersionString"] as? String ?? ""
    }

    ///  Return the display name of this bundle (e.g. "Okta Verify")
    func applicationName() -> String {
        return infoDictionary?["CFBundleDisplayName"] as? String ?? ""
    }
}
