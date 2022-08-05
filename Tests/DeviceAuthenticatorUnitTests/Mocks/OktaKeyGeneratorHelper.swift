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

class OktaKeyGeneratorHelper {
    class func getValidSecKeyES256(_ base64Key: String, isPublic: Bool) -> SecKey? {
        guard let data = Data(base64Encoded: base64Key) else {
            return nil
        }
        let keyDict: [NSObject: NSObject] = [
                kSecAttrKeyType: kSecAttrKeyTypeEC,
                kSecAttrKeyClass: isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits: NSNumber(value: 256),
                kSecReturnPersistentRef: true as NSObject]
        return SecKeyCreateWithData(data as CFData, keyDict as CFDictionary, nil)
    }
}
