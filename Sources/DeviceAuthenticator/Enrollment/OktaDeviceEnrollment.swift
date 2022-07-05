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

class OktaDeviceEnrollment: Codable {
    let id: String

    /// Deprecated and always will contain `nil` in case of new enrollments or SQLite-backed storage. To identify the org, refer `orgId` instead
    @available(*, deprecated, message: "orgURL is deprecated and always will contain `nil` in case of new enrollments or SQLite-backed storage. To identify the org, refer `orgId` instead")
    let orgURL: URL?
    let orgId: String?
    let clientInstanceId: String
    let clientInstanceKeyTag: String

    init(id: String,
         orgURL: URL? = nil,
         orgId: String,
         clientInstanceId: String,
         clientInstanceKeyTag: String) {
        self.id = id
        self.orgURL = orgURL
        self.orgId = orgId
        self.clientInstanceId = clientInstanceId
        self.clientInstanceKeyTag = clientInstanceKeyTag
    }
}
