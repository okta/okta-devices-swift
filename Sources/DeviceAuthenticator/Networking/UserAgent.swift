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
#if os(iOS)
import UIKit
#endif

protocol UserAgentProtocol {
    /**
     Create the Okta-Standard device user agent string:
     <application_bundle_id>/<app_version> <sdk_name>/<sdk_version> <os>/<os_version> <device_manufacturer>/<device_model>
     Example:
     "B7F62B65BN.com.okta.example/1.2.3 DeviceAuthenticator/0.0.1 iOS/13.4.1 Apple/iPhone11,1"
     */
    static func standardUserAgent() -> String

    /**
     Create the Okta-Standard device user agent string:
     <application_bundle_id>/<app_version> <sdk_name>/<sdk_version> <os>/<os_version> <device_manufacturer>/<device_model> <tracking_id>
     Example:
     "B7F62B65BN.com.okta.example/1.2.3 DeviceAuthenticator/0.0.1 iOS/13.4.1 Apple/iPhone11,1 23881EA9-EC60-43BF-B1E6-25F183C63715"

     - Parameters:
        - appInstanceId: Application instance ID.
     */
    static func standardUserAgent(appInstanceId: String) -> String
}

/// HTTP header "user-agent" value that SDK includes in each HTTP request
class UserAgent: NSObject, UserAgentProtocol {

    class func standardUserAgent() -> String {
        var fields = [String]()

        // App identifier/version: "B7F62B65BN.com.okta.mobile/1.0.1"
        let appBundle = Bundle.main
        let appInfo = appIdentifier(bundle: appBundle) + "/" + appBundle.versionString()
        fields.append(appInfo)

        // SDK Name/Version: "DeviceAuthenticator/0.0.1"
        fields.append(sdkInfo())

        // Platform info: "iOS/13.2.1"
        fields.append(platformInfo())

        // Device info: "Apple/iPhone12,4"
        fields.append(deviceInfo())

        return fields.joined(separator: " ")
    }

    class func standardUserAgent(appInstanceId: String) -> String {
        let userAgent = Self.standardUserAgent()
        return appInstanceId.isEmpty ? userAgent : "\(userAgent) \(appInstanceId)"
    }

    // MARK: Private

    class func appIdentifier(bundle: Bundle) -> String {
        // prefix with team ID if available
        var prefix = ""
        if let teamIdentifier = Bundle.teamIdentifier {
            prefix = teamIdentifier + "."
        }
        return prefix + (bundle.bundleIdentifier ?? "")
    }

    class func platformInfo() -> String {
#if os(iOS)
        return "iOS/\(UIDevice.current.systemVersion)"
#elseif os(OSX)
        let version = ProcessInfo.processInfo.operatingSystemVersion
        return "macOS/\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
#endif
    }

    class func deviceInfo() -> String {
        let deviceModel = BasicSignalsHelper().deviceModel
        return "Apple/\(deviceModel)"
    }

    class func sdkInfo() -> String {
        DeviceAuthenticatorConstants.name + "/" + DeviceAuthenticatorConstants.version
    }
}
