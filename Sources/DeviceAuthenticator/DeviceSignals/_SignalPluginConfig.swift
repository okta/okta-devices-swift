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

// This structure is needed to decode manifest JSONs. This will be translated into SignalPluginConfig
struct IntegrationsConfig: Codable {
    let name: String
    let description: String
    let type: String
    let location: String
    let format: String
}

// Represents single plugin configuration read in from manifest file stored on client machine
public struct _SignalPluginConfig: Codable {
    let name: String
    let description: String
    let type: String
    // contents of typeData change depending on type value
    let typeData: [String: String]

    public init(name: String, description: String, type: String, typeData: [String: String]) {
        self.name = name
        self.description = description
        self.type = type
        self.typeData = typeData
    }
}

