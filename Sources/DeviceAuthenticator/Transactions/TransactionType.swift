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

public struct TransactionType: OptionSet {

    public let rawValue: Int

    public init(rawValue: Int) {
        self.rawValue = rawValue
    }

    ///  Type for Login transactions
    public static let login = TransactionType(rawValue: 1 << 0)

    ///  Type for Transactional MFA (CIBA) transactions
    public static let ciba = TransactionType(rawValue: 1 << 1)

    public var supportsCIBA: Bool {
        return self.contains(.ciba)
    }
}
