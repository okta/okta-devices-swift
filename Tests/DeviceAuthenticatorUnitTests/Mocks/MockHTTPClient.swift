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
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif
@testable import DeviceAuthenticator

class MockURLRequest: URLRequestProtocol {

    typealias responseHookType = (@escaping (HTTPURLResult) -> Void) -> Void
    typealias expectedRequestHeadersHook = (String, String) -> Void

    var responseHook: responseHookType?
    var requestHeadersHook: expectedRequestHeadersHook?
    var currentRequest: URLRequest
    var result: HTTPURLResult?

    required init(urlSession: URLSession, request: URLRequest) {
        self.currentRequest = request
        self.result = nil
    }

    init(result: HTTPURLResult, headers: [String: String]? = nil, httpBody: Data? = nil, method: HTTPMethod = .get) {
        self.currentRequest = result.request!
        self.currentRequest.allHTTPHeaderFields = headers
        self.currentRequest.httpBody = httpBody
        self.currentRequest.httpMethod = method == .get ? "GET" : "POST"
        self.result = HTTPURLResult(request: self.currentRequest, response: result.response, data: result.data, error: result.error)
    }

    func response(completion: @escaping (HTTPURLResult) -> Void) {
        if let responseHook = responseHook {
            responseHook(completion)
        } else {
            completion(self.result!)
        }
    }

    func addHeader(name: String, value: String) -> Self {
        requestHeadersHook?(name, value)
        return self
    }
}

class MockHTTPClient: HTTPClient {
    var result: HTTPURLResult?
    let mockRequest = URLRequest(url: URL(string: "com.okta.example")!)

    typealias requestHookType = (URL, HTTPMethod, [String: String], Data?, [String: String], TimeInterval) -> URLRequestProtocol

    var requestHook: requestHookType?

    required init(urlSession: URLSession?, logger: OktaLoggerProtocol, userAgent: String?) {
        super.init(urlSession: urlSession, logger: OktaLoggerMock(), userAgent: userAgent ?? "")
    }

    convenience init(result: HTTPURLResult) {
        self.init(urlSession: nil, logger: OktaLoggerMock(), userAgent: nil)
        self.result = result
    }

    convenience init(response: HTTPURLResponse? = nil, data: Data? = nil) {
        let result = HTTPURLResult(request: URLRequest(url: URL(string: "com.okta.example")!), response: response, data: data)
        self.init(result: result)
    }

    convenience init(error: Error) {
        let result = HTTPURLResult(request: URLRequest(url: URL(string: "com.okta.example")!), response: nil, data: nil, error: error)
        self.init(result: result)
    }

    override func request(
        _ url: URL,
        method: HTTPMethod = .get,
        urlParameters: [String: String] = [:],
        bodyParameters: [String: Any] = [:],
        headers: [String: String] = [:],
        timeout: TimeInterval = 0
    ) -> URLRequestProtocol {
        if let requestHook = requestHook {
            return requestHook(url, method, urlParameters, nil, headers, timeout)
        } else {
            return MockURLRequest(result: result!, headers: headers)
        }
    }

    override func request(
        _ url: URL,
        method: HTTPMethod = .get,
        urlParameters: [String: String] = [:],
        httpBody: Data?,
        headers: [String: String] = [:],
        timeout: TimeInterval = 0
    ) -> URLRequestProtocol {
        if let requestHook = requestHook {
            return requestHook(url, method, urlParameters, httpBody, headers, timeout)
        } else {
            return MockURLRequest(result: result!, headers: headers, httpBody: httpBody, method: method)
        }
    }
}
