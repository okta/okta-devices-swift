/*
* Copyright (c) 2021, Okta, Inc. and/or its affiliates. All rights reserved.
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

/// - Description: Abstraction for version representation. Versions are represented by Integers. To maintain SemVer specification compliance, use `enum` with SemVer-compatible cases, while having underlying `Int` as a `rawType`. Supports Swift Ranges syntax. Versions order is determined by RawType value, not versions declaration order.
public protocol _OktaVersionType: CaseIterable, Strideable, RawRepresentable where RawValue == Int, Stride == Int, AllCases.Index == Int {

    /// - Description: Represents unidentifiable or non-existing version. Example: calling `.nextVersion()` on the most recent version is expected to return `unknownVersion` value
    static var unknownVersion: Self { get }

    /// - Description: Descendent for a given version
    func nextVersion() -> Self
}

/// - Description: default `Strideable` methods implementation for Swift Ranges support, as well as `nextVersion()` default implemetation.
public extension _OktaVersionType {
    static func < (a: Self, b: Self) -> Bool {
        return a.rawValue < b.rawValue
    }

    func advanced(by n: Int) -> Self {
        return Self(rawValue: self.rawValue + n) ?? Self.unknownVersion
    }

    func distance(to other: Self) -> Int {
        return other.rawValue - self.rawValue
    }

    /// - Returns: Next version from `Self.allCases` array or `Self.unknownVersion` if next version does not exist
    func nextVersion() -> Self {
        guard self != Self.unknownVersion else {
            return Self.unknownVersion
        }

        let allCases = Self.allCases.sorted()
        guard let currentVersionIndex = allCases.firstIndex(of: self) else {
            return Self.unknownVersion
        }

        let nextVersionIndex = currentVersionIndex + 1
        guard nextVersionIndex < allCases.count else {
            return Self.unknownVersion
        }
        return allCases[nextVersionIndex]
    }
}
