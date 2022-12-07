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
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif

/// HTTP client implementation for sending HTTP requests
class HTTPClient: HTTPClientProtocol {

    var currentSession: URLSession {
        return self.urlSession
    }

    required init(urlSession: URLSession? = nil,
                  logger: OktaLoggerProtocol,
                  userAgent: String) {
        self.urlSession = urlSession ?? URLSession.shared
        self.logger = logger
        self.userAgent = userAgent
    }

    func request(
        _ url: URL,
        method: HTTPMethod = .get,
        urlParameters: [String: String] = [:],
        bodyParameters: [String: Any] = [:],
        headers: [String: String] = [:],
        timeout: TimeInterval = 0
    ) -> URLRequestProtocol {
        var httpBody: Data?
        var mutatedHeaders = headers

        if let bodyParamsData = try? JSONSerialization.data(withJSONObject: bodyParameters, options: []), !bodyParameters.isEmpty {
            if headers["Content-Type"] == nil {
                mutatedHeaders["Content-Type"] = "application/json"
            }
            httpBody = bodyParamsData
        }

        return self.request(
            url,
            method: method,
            urlParameters: urlParameters,
            httpBody: httpBody,
            headers: mutatedHeaders,
            timeout: timeout
        )
    }

    func request(
        _ url: URL,
        method: HTTPMethod = .get,
        urlParameters: [String: String] = [:],
        httpBody: Data?,
        headers: [String: String] = [:],
        timeout: TimeInterval = 0
    ) -> URLRequestProtocol {
        var request = URLRequest(url: url)
        request.httpMethod = method.toString()

        if timeout != 0 {
            request.timeoutInterval = timeout
        }

        // Override + append additional request headers
        headers.forEach { request.addValue($0.value, forHTTPHeaderField: $0.key) }
        request.addValue(self.userAgent, forHTTPHeaderField: "User-Agent")

        // Attach URL query parameters
        if var urlComponents = URLComponents(url: url, resolvingAgainstBaseURL: true), !urlParameters.isEmpty {
            urlComponents.queryItems = urlParameters.map { URLQueryItem(name: $0.key, value: $0.value) }
            if urlComponents.url != nil {
                request.url = urlComponents.url
            }
        }

        // Attach http body data
        if httpBody != nil {
            request.httpBody = httpBody
        }

        return OktaURLRequest(urlSession: self.urlSession, request: request)
    }

    // Internal properties
    let userAgent: String
    var logger: OktaLoggerProtocol
    fileprivate var urlSession: URLSession
}

