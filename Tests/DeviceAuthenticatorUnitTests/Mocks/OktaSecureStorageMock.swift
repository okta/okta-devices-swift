/*
* Copyright (c) 2019, Okta, Inc. and/or its affiliates. All rights reserved.
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
@testable import DeviceAuthenticator

class OktaSecureStorageMock: OktaSecureStorage {

    // set this flag to false if you want to simulate raising of excpetion or return
    var storeSuccessCase = true
    var readSuccessCase = true
    var deleteSuccessCase = true
    var keysValues = [String: Data]()

    typealias getDataHookType = (String, String?, String?) throws -> Data
    var getDataHook: getDataHookType?

    override public func set(data: Data, forKey key: String, behindBiometrics: Bool, accessGroup: String) throws {
        if storeSuccessCase {
            keysValues[key] = data
        } else {
            throw NSError(domain: "secure storage", code: Int(errSecDuplicateItem), userInfo: nil)
        }
    }

    override public func set(data: Data,
                             forKey key: String,
                             behindBiometrics: Bool,
                             accessGroup: String?,
                             accessibility: CFString?) throws {
        if storeSuccessCase {
            keysValues[key] = data
        } else {
            throw NSError(domain: "secure storage", code: Int(errSecDuplicateItem), userInfo: nil)
        }
    }

    override public func getData(key: String, biometricPrompt prompt: String? = nil, accessGroup: String? = nil) throws -> Data {
        if let getDataHook = getDataHook {
            return try getDataHook(key, prompt, accessGroup)
        }

        if readSuccessCase {
            guard let data = keysValues[key] else {
                throw NSError(domain: "secure storage", code: Int(errSecItemNotFound), userInfo: nil)
            }
            return data
        } else {
            throw NSError(domain: "secure storage", code: Int(errSecItemNotFound), userInfo: nil)
        }
    }

    override public func delete(key: String) throws {
        try delete(key: key, accessGroup: nil)
    }

    override public func delete(key: String, accessGroup: String? = nil) throws {
        if deleteSuccessCase {
            keysValues.removeValue(forKey: key)
        } else {
            throw NSError(domain: "secure storage", code: Int(errSecInvalidItemRef), userInfo: nil)
        }
    }
    
    override func getStoredKeys(biometricPrompt prompt: String? = nil, accessGroup: String? = nil) throws -> [String] {
        if readSuccessCase {
            return Array(keysValues.keys)
        } else {
            throw NSError(domain: "secure storage", code: Int(errSecItemNotFound), userInfo: nil)
        }
    }
}
