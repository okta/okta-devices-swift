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

extension UserDefaults {
    
    private static let DeviceTokenKey = "DeviceTokenKey"
    private static let ConfigsKey = "OidcConfigs"

    static func clearDeviceToken() {
        UserDefaults.standard.removeObject(forKey: DeviceTokenKey)
    }
    
    static func save(deviceToken: Data) {
        UserDefaults.standard.set(deviceToken, forKey: DeviceTokenKey)
    }
    
    static func deviceToken() -> Data? {
        return UserDefaults.standard.data(forKey: DeviceTokenKey)
    }

    static func saveEnrollmentConfig(by enrollmentId: String, config: [String: String]) {
        var configs = enrollmentConfigs() ?? [:]
        configs[enrollmentId] = config
        UserDefaults.standard.set(configs, forKey: ConfigsKey)
    }

    static func enrollmentConfigs() -> [String: [String: String]]? {
        return UserDefaults.standard.dictionary(forKey: ConfigsKey) as? [String: [String: String]]
    }

    static func deleteEnrollmentConfig(by enrollmentId: String) {
        var configs = enrollmentConfigs() ?? [:]
        configs.removeValue(forKey: enrollmentId)
        UserDefaults.standard.set(configs, forKey: ConfigsKey)
    }
}
