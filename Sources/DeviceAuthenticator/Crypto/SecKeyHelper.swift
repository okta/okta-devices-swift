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

class SecKeyHelper {
    func generateKeyPair(_ parameters: CFDictionary,
                         _ publicKey: UnsafeMutablePointer<SecKey?>?,
                         _ privateKey: UnsafeMutablePointer<SecKey?>?) -> OSStatus {
        return SecKeyGeneratePair(parameters, publicKey, privateKey)
    }

    func generateRandomKey(_ parameters: CFDictionary,
                           _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> SecKey? {
        return SecKeyCreateRandomKey(parameters, error)
    }

    func deleteKey(_ query: CFDictionary) -> OSStatus {
        return SecItemDelete(query)
    }

    func getKey(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
        return SecItemCopyMatching(query, result)
    }

    func createSignature(_ key: SecKey, _ algorithm: SecKeyAlgorithm, _ dataToSign: CFData, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFData? {
        return SecKeyCreateSignature(key, algorithm, dataToSign, error)
    }

    func verifySignature(_ key: SecKey, _ algorithm: SecKeyAlgorithm, _ signedData: CFData, _ signature: CFData, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> Bool {
        return SecKeyVerifySignature(key, algorithm, signedData, signature, error)
    }

}
