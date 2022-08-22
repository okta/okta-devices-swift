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
@testable import DeviceAuthenticator

class MockAPIResponse {

    static func response(for error: ServerErrorCode) -> MockHTTPClient {
        let url = URL(string: "test.org")!
        let json = genericResponse(with: error.rawValue)
        let data = try? JSONEncoder().encode(json)
        let response = HTTPURLResponse(url: url,
                                       statusCode: error.httpCode(),
                                       httpVersion: nil, headerFields: nil)
        return MockHTTPClient(response: response, data: data)
    }

    static func genericResponse(with code: String) -> [String: String] {
        return [
            "errorCode": code,
            "errorSummary": "Generic error summary (\(code))",
            "errorLink": code,
            "errorId": UUID().uuidString
        ]
    }

}
