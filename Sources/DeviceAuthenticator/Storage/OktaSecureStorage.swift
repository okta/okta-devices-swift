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
import LocalAuthentication

public protocol OktaSecureStorageProtocol {
    func getData(key: String, biometricPrompt prompt: String?, accessGroup: String?) throws -> Data
    func set(data: Data,
             forKey key: String,
             behindBiometrics: Bool,
             accessGroup: String?,
             accessibility: CFString?) throws
}

class OktaSecureStorage: OktaSecureStorageProtocol {

    static let keychainErrorDomain = "com.okta.securestorage"

    let applicationPassword: String?

    public init(applicationPassword password: String? = nil) {
        applicationPassword = password
    }

    func set(_ string: String, forKey key: String) throws {

        try set(string, forKey: key, behindBiometrics: false)
    }

    func set(_ string: String, forKey key: String, behindBiometrics: Bool) throws {

        try set(string, forKey: key, behindBiometrics: behindBiometrics, accessGroup: nil, accessibility: nil)
    }

    func set(_ string: String,
                        forKey key: String,
                        behindBiometrics: Bool,
                        accessibility: CFString) throws {

        try set(string, forKey: key, behindBiometrics: behindBiometrics, accessGroup: nil, accessibility: accessibility)
    }

    func set(_ string: String,
                        forKey key: String,
                        behindBiometrics: Bool,
                        accessGroup: String) throws {

        try set(string, forKey: key, behindBiometrics: behindBiometrics, accessGroup: accessGroup, accessibility: nil)
    }

    func set(_ string: String,
                        forKey key: String,
                        behindBiometrics: Bool,
                        accessGroup: String?,
                        accessibility: CFString?) throws {

        guard let bytesStream = string.data(using: .utf8) else {
            throw NSError(domain: OktaSecureStorage.keychainErrorDomain, code: Int(errSecParam), userInfo: nil)
        }

        try set(data: bytesStream, forKey: key, behindBiometrics: behindBiometrics, accessGroup: accessGroup, accessibility: accessibility)
    }

    func set(data: Data, forKey key: String) throws {

        try set(data: data, forKey: key, behindBiometrics: false)
    }

    func set(data: Data, forKey key: String, behindBiometrics: Bool) throws {

        try set(data: data, forKey: key, behindBiometrics: behindBiometrics, accessGroup: nil, accessibility: nil)
    }

    func set(data: Data,
                        forKey key: String,
                        behindBiometrics: Bool,
                        accessibility: CFString) throws {

        try set(data: data, forKey: key, behindBiometrics: false, accessGroup: nil, accessibility: accessibility)
    }

    func set(data: Data,
                        forKey key: String,
                        behindBiometrics: Bool,
                        accessGroup: String) throws {

        try set(data: data, forKey: key, behindBiometrics: behindBiometrics, accessGroup: accessGroup, accessibility: nil)
    }

    func set(data: Data,
                        forKey key: String,
                        behindBiometrics: Bool,
                        accessGroup: String?,
                        accessibility: CFString?) throws {

        var query = baseQuery()
        query[kSecValueData as String] = data
        query[kSecAttrAccount as String] = key
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        var applicationPasswordSet = false
        if let _ = applicationPassword {
            applicationPasswordSet = true
        }

        if behindBiometrics || applicationPasswordSet {

            var biometryAndPasscodeFlags = SecAccessControlCreateFlags()
            if behindBiometrics {
                if #available(iOS 11.3, *) {
                    biometryAndPasscodeFlags.insert(SecAccessControlCreateFlags.biometryCurrentSet)
                } else {
                    biometryAndPasscodeFlags.insert(SecAccessControlCreateFlags.touchIDCurrentSet)
                }
                biometryAndPasscodeFlags.insert(SecAccessControlCreateFlags.or)
                biometryAndPasscodeFlags.insert(SecAccessControlCreateFlags.devicePasscode)
            }

            var applicationPasswordFlag = SecAccessControlCreateFlags()
            if applicationPasswordSet {
                applicationPasswordFlag.insert(SecAccessControlCreateFlags.applicationPassword)
                let laContext = LAContext()
                guard let passwordData = applicationPassword?.data(using: .utf8) else {
                    throw NSError(domain: OktaSecureStorage.keychainErrorDomain, code: Int(errSecParam), userInfo: nil)
                }
                laContext.setCredential(passwordData, type: LACredentialType.applicationPassword)
                query[kSecUseAuthenticationContext as String] = laContext
            }

            var cfError: Unmanaged<CFError>?
            let secAccessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                   accessibility ?? kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                                   [biometryAndPasscodeFlags,
                                                                    applicationPasswordFlag],
                                                                   &cfError)

            if let error: Error = cfError?.takeRetainedValue() {
                throw error
            }

            query[kSecAttrAccessControl as String] = secAccessControl

        } else {
            query[kSecAttrAccessible as String] = accessibility ?? kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }

        var errorCode = SecItemAdd(query as CFDictionary, nil)
        if errorCode == noErr {
            return
        } else if errorCode == errSecDuplicateItem {
            let searchQuery = findQuery(for: key, accessGroup: accessGroup)
            query.removeValue(forKey: kSecClass as String)
            query.removeValue(forKey: kSecAttrService as String)
            if #available(macOS 10.15, iOS 13.0, *) {
                query.removeValue(forKey: kSecUseDataProtectionKeychain as String)
            }
            errorCode = SecItemUpdate(searchQuery as CFDictionary, query as CFDictionary)
            if errorCode != noErr {
                throw NSError(domain: OktaSecureStorage.keychainErrorDomain, code: Int(errorCode), userInfo: nil)
            }
        } else {
            throw NSError(domain: OktaSecureStorage.keychainErrorDomain, code: Int(errorCode), userInfo: nil)
        }
    }

    func get(key: String, biometricPrompt prompt: String? = nil) throws -> String {

        return try get(key: key, biometricPrompt: prompt, accessGroup: nil)
    }

    func get(key: String, biometricPrompt prompt: String? = nil, accessGroup: String? = nil) throws -> String {

        let data = try getData(key: key, biometricPrompt: prompt, accessGroup: accessGroup)
        guard let string = String(data: data, encoding: .utf8) else {
            throw NSError(domain: OktaSecureStorage.keychainErrorDomain, code: Int(errSecInvalidData), userInfo: nil)
        }

        return string
    }

    func getData(key: String, biometricPrompt prompt: String? = nil, accessGroup: String? = nil) throws -> Data {

        var query = findQuery(for: key, accessGroup: accessGroup)
        query[kSecReturnData as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        if let prompt = prompt {
            query[kSecUseOperationPrompt as String] = prompt
        }

        if let password = applicationPassword {
            let laContext = LAContext()
            laContext.setCredential(password.data(using: .utf8), type: .applicationPassword)
            query[kSecUseAuthenticationContext as String] = laContext
        }

        var ref: AnyObject? = nil

        let errorCode = SecItemCopyMatching(query as CFDictionary, &ref)
        guard errorCode == noErr, let data = ref as? Data else {
            throw NSError(domain: OktaSecureStorage.keychainErrorDomain, code: Int(errorCode), userInfo: nil)
        }

        return data
    }

    func getStoredKeys(biometricPrompt prompt: String? = nil, accessGroup: String? = nil) throws -> [String] {
        var query = findQuery(accessGroup: accessGroup)
        query[kSecReturnAttributes as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        if let prompt = prompt {
            query[kSecUseOperationPrompt as String] = prompt
        }

        if let password = applicationPassword {
            let laContext = LAContext()
            laContext.setCredential(password.data(using: .utf8), type: LACredentialType.applicationPassword)
            query[kSecUseAuthenticationContext as String] = laContext
        }

        var ref: AnyObject? = nil
        let errorCode = SecItemCopyMatching(query as CFDictionary, &ref)
        guard errorCode == noErr,
            let results = ref as? [[AnyHashable: Any]]
        else {
            throw NSError(domain: OktaSecureStorage.keychainErrorDomain, code: Int(errorCode), userInfo: nil)
        }
        let keys = results
            .compactMap { $0[kSecAttrAccount] as? String }

        return keys
    }

    func delete(key: String) throws {

        try delete(key: key, accessGroup: nil)
    }

    func delete(key: String, accessGroup: String? = nil) throws {

        let query = findQuery(for: key, accessGroup: accessGroup)
        let errorCode = SecItemDelete(query as CFDictionary)
        if errorCode != noErr && errorCode != errSecItemNotFound {
            throw NSError(domain: OktaSecureStorage.keychainErrorDomain, code: Int(errorCode), userInfo: nil)
        }
    }

    func clear() throws {

        let query = baseQuery()
        let errorCode = SecItemDelete(query as CFDictionary)
        if errorCode != noErr && errorCode != errSecItemNotFound {
            throw NSError(domain: OktaSecureStorage.keychainErrorDomain, code: Int(errorCode), userInfo: nil)
        }
    }

    func isTouchIDSupported() -> Bool {

        let laContext = LAContext()
        var touchIdSupported = false
        if #available(iOS 11.0, *) {
            let touchIdEnrolled = laContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            touchIdSupported = laContext.biometryType == .touchID && touchIdEnrolled
        } else {
            touchIdSupported = laContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        }
        return touchIdSupported
    }

    func isFaceIDSupported() -> Bool {

        let  laContext = LAContext()
        let biometricsEnrolled = laContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        var faceIdSupported = false
        if #available(iOS 11.0, macOS 10.15, *) {
            faceIdSupported = laContext.biometryType == .faceID
        }
        return biometricsEnrolled && faceIdSupported
    }

    func bundleSeedId() throws -> String {

        var query = baseQuery()
        query[kSecAttrAccount as String] = "bundleSeedID"
        query[kSecReturnAttributes as String] = kCFBooleanTrue

        var ref: AnyObject? = nil

        var errorCode = SecItemCopyMatching(query as CFDictionary, &ref)
        if errorCode == errSecItemNotFound {
            errorCode = SecItemAdd(query as CFDictionary, &ref)
            guard errorCode == noErr else {
                throw NSError(domain: OktaSecureStorage.keychainErrorDomain, code: Int(errorCode), userInfo: nil)
            }
        }

        guard let returnedDictionary = ref as? Dictionary<String, Any> else {
            throw NSError(domain: OktaSecureStorage.keychainErrorDomain, code: Int(errSecDecode), userInfo: nil)
        }

        guard let accessGroup = returnedDictionary[kSecAttrAccessGroup as String] as? String else {
           throw NSError(domain: OktaSecureStorage.keychainErrorDomain, code: Int(errSecDecode), userInfo: nil)
        }

        let components = accessGroup.components(separatedBy: ".")

        guard let teamId = components.first else {
            throw NSError(domain: OktaSecureStorage.keychainErrorDomain, code: Int(errSecDecode), userInfo: nil)
        }

        return teamId
    }

    //MARK: Private

    private func baseQuery() -> Dictionary<String, Any> {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword as String,
            kSecAttrService as String: "OktaSecureStorage"]
        if #available(macOS 10.15, iOS 13.0, *) {
            query[kSecUseDataProtectionKeychain as String] = kCFBooleanTrue
        }
        return query
    }

    private func findQuery(for key: String? = nil, accessGroup: String? = nil) -> Dictionary<String, Any> {
        var query = baseQuery()
        if let key = key {
            query[kSecAttrAccount as String] = key
        }
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        return query
    }
}
