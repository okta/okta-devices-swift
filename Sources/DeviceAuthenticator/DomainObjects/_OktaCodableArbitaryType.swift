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

public enum _OktaCodableArbitaryType: Codable, Equatable {
     case int(Int)
     case bool(Bool)
     case string(String)
     case array([_OktaCodableArbitaryType])
     case dictionary([String: _OktaCodableArbitaryType])

     public init(from decoder: Decoder) throws {
         let container = try decoder.singleValueContainer()
         do {
             self = .int(try container.decode(Int.self))
         } catch DecodingError.typeMismatch {
             do {
                 self = .string(try container.decode(String.self))
             } catch DecodingError.typeMismatch {
                 do {
                     self = .array(try container.decode([_OktaCodableArbitaryType].self))
                 } catch DecodingError.typeMismatch {
                    do {
                        self = .dictionary(try container.decode([String: _OktaCodableArbitaryType].self))
                    } catch DecodingError.typeMismatch {
                        self = .bool(try container.decode(Bool.self))
                    }
                 }
             }
         }
     }

     public func encode(to encoder: Encoder) throws {
         var container = encoder.singleValueContainer()
         switch self {
         case .int(let int): try container.encode(int)
         case .string(let string): try container.encode(string)
         case .array(let list): try container.encode(list)
         case .dictionary(let dictionary): try container.encode(dictionary)
         case .bool(let bool): try container.encode(bool)
         }
     }

     public static func == (_ lhs: _OktaCodableArbitaryType, _ rhs: _OktaCodableArbitaryType) -> Bool {
         switch (lhs, rhs) {
         case (.int(let int1), .int(let int2)): return int1 == int2
         case (.string(let string1), .string(let string2)): return string1 == string2
         case (.array(let list1), .array(let list2)): return list1 == list2
         case (.dictionary(let dict1), .dictionary(let dict2)): return dict1 == dict2
         case (.bool(let bool1), .bool(let bool2)): return bool1 == bool2
         default: return false
         }
     }
}
