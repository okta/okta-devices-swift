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

class SecKeyHelperMock: SecKeyHelper {

    typealias generateKeyPairType = (CFDictionary, UnsafeMutablePointer<SecKey?>?, UnsafeMutablePointer<SecKey?>?) -> OSStatus
    typealias generateRandomKeyType = (CFDictionary, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> SecKey?
    typealias getKeyType = (CFDictionary, UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus
    typealias deleteKeyType = (CFDictionary) -> OSStatus

    var generateKeyPairHook: generateKeyPairType?
    var generateRandomKeyHook: generateRandomKeyType?
    var getKeyHook: getKeyType?
    var deleteKeyHook: deleteKeyType?

    var generateKeyPairExpectaion = 0 as OSStatus
    var generateKeyPairSpyParameters = [:] as CFDictionary
    var generateKeyPairPublicKeySpyParameter: UnsafeMutablePointer<SecKey?>?
    var generateKeyPairPrivateKeySpyParmeter: UnsafeMutablePointer<SecKey?>?
    var generateKeyPairErrorSpyParameter: UnsafeMutablePointer<Unmanaged<CFError>?>?

    var deleteCallCount = 0
    var deleteKeyExpectations = [] as [OSStatus]
    var deleteSpyQueryParams = [] as [CFDictionary]

    var keyExpectation: SecKey?
    var getKeyExpectation = 0 as OSStatus
    var getKeySpyParameters = [:] as CFDictionary
    var getKeyRefExpectation: CFTypeRef?

    var createSignatureExpectation: CFData?
    var createSignatureError: CFError?
    var createSignatureKeySpyParmeter: SecKey?
    var createSignatureAlgorithmParemeter = .ecdsaSignatureDigestX962SHA256 as SecKeyAlgorithm
    var createSignatureDataToSignParameter: CFData = Data() as CFData

    var verifySignatureExpection = false

    override public init() {
        let ec256ValidPrivateKeyBase64 = "BIBwuQyPfBPU+fyXiU+i0FOqEAHtm3U5aER8gIWVnyJvw9YfSa7ylqLNpdeyTie4zUFP9UU4FXLByqcaGFR1q05at441RDVAq1aewlvnE9pKcZmCiiayoO37AxpdRYcTmA=="
        keyExpectation = OktaKeyGeneratorHelper.getValidSecKeyES256(ec256ValidPrivateKeyBase64, isPublic: false)
        getKeyRefExpectation = keyExpectation as CFTypeRef
    }

    override public func generateKeyPair(_ parameters: CFDictionary, _ publicKey: UnsafeMutablePointer<SecKey?>?, _ privateKey: UnsafeMutablePointer<SecKey?>?) -> OSStatus {

        if let generateKeyPairHook = generateKeyPairHook {
            return generateKeyPairHook(parameters, publicKey, privateKey)
        }

        var parameterCopy = [NSObject: NSObject]().merging(parameters as! Dictionary) { $1 }
#if targetEnvironment(simulator)
        parameterCopy[kSecAttrTokenID] = nil
#endif
        let ec256ValidPrivateKeyBase64 = "BIBwuQyPfBPU+fyXiU+i0FOqEAHtm3U5aER8gIWVnyJvw9YfSa7ylqLNpdeyTie4zUFP9UU4FXLByqcaGFR1q05at441RDVAq1aewlvnE9pKcZmCiiayoO37AxpdRYcTmA=="
        let secKey: SecKey = OktaKeyGeneratorHelper.getValidSecKeyES256(ec256ValidPrivateKeyBase64, isPublic: false)!
        publicKey?.initialize(to: SecKeyCopyPublicKey(secKey))
        privateKey?.initialize(to: secKey)
        self.generateKeyPairSpyParameters = parameters
        self.generateKeyPairPublicKeySpyParameter = publicKey
        self.generateKeyPairPrivateKeySpyParmeter = privateKey
        return getKeyExpectation
    }

    override public func generateRandomKey(_ parameters: CFDictionary, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> SecKey? {
        if let generateRandomKeyHook = generateRandomKeyHook {
            return generateRandomKeyHook(parameters, error)
        }

        self.generateKeyPairSpyParameters = parameters
        self.generateKeyPairErrorSpyParameter = error
        return keyExpectation
    }

    override public func deleteKey(_ query: CFDictionary) -> OSStatus {
        if let deleteKeyHook = deleteKeyHook {
            return deleteKeyHook(query)
        }

        defer {
            deleteCallCount = deleteCallCount + 1
        }

        if deleteCallCount < deleteKeyExpectations.count {
            deleteSpyQueryParams.append(query)
            return deleteKeyExpectations[deleteCallCount]
        }
        return 0
    }

    override public func getKey(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
        if let getKeyHook = getKeyHook {
            return getKeyHook(query, result)
        }

        self.getKeySpyParameters = query
        result?.pointee = getKeyRefExpectation as CFTypeRef
        return getKeyExpectation
    }

    override public func createSignature(_ key: SecKey, _ algorithm: SecKeyAlgorithm, _ dataToSign: CFData, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFData? {
        createSignatureKeySpyParmeter = key
        createSignatureAlgorithmParemeter = algorithm
        createSignatureDataToSignParameter = dataToSign
        if let err = createSignatureError {
            error?.pointee = Unmanaged<CFError>.passRetained(err)
        }
        return createSignatureExpectation
    }

    override public func verifySignature(_ key: SecKey, _ algorithm: SecKeyAlgorithm, _ signedData: CFData, _ signature: CFData, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> Bool {
        return verifySignatureExpection
    }

    public func verifyGenerateKeyPairExpectation(_ parameters: CFDictionary) -> Bool {
        return NSDictionary(dictionary: generateKeyPairSpyParameters).isEqual(to: parameters as? [String: Any] ?? [:])
    }

    public func verifyDeleteExpectation(_ parameters: [CFDictionary]) -> Bool {
        return NSArray(array: deleteSpyQueryParams).isEqual(to: parameters)
    }

    public func verifyGet(_ parameters: CFDictionary) -> Bool {
        return NSDictionary(dictionary: getKeySpyParameters).isEqual(to: parameters as? [String: Any] ?? [:])
    }

    public func verifyCreateSignature(algorithm: SecKeyAlgorithm, dataToSign: CFData) -> Bool {
        return algorithm == createSignatureAlgorithmParemeter
        && (dataToSign as NSData as Data) == (createSignatureDataToSignParameter as NSData as Data)
    }
}
