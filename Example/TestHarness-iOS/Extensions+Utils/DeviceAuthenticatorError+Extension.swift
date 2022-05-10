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
import OktaDeviceSDK

extension DeviceAuthenticatorError {
    var additionalDescription: String {
        switch self {
        case .serverAPIError(let result, _):
            let additionalInformation = additionalServerErrorInformation(result)
            return "Server call has failed." + additionalInformation
        default:
            return errorDescription ?? "Unknown error"
        }
    }

    private func additionalServerErrorInformation(_ result: HTTPURLResult) -> String {
        var additionalInformationString = ""
        if let requestURLString = result.request?.url?.absoluteString {
            additionalInformationString += " API endpoint: \(requestURLString)"
        }
        if let statusCode = result.response?.statusCode {
            additionalInformationString += " Status Code: \(statusCode)"
        }
        if let data = result.data, let resultString = String(data: data, encoding: .utf8) {
            additionalInformationString += " JSON Payload: \(resultString)"
        }
        return additionalInformationString
    }
}
