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

extension Data {
    init?(hexString: String) {
        let dataLength = hexString.count / 2
        var data = Data(capacity: dataLength)
        var intervalStart = hexString.startIndex
        while let intervalEnd = hexString.index(intervalStart, offsetBy: 2, limitedBy: hexString.endIndex) {
            let hexNumber = hexString[intervalStart..<intervalEnd]
            guard let number = UInt8(hexNumber, radix: 16) else { return nil }
            data.append(contentsOf: [number])
            intervalStart = intervalEnd
        }
        self = data
    }

    var hexString: String {
        let hexString = map { String(format: "%02.2hhx", $0) }.joined()
        return hexString
    }
}
