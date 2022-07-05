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
import OktaLogger

protocol HTTPClientProtocol {

    /// Current url session
    var currentSession: URLSession { get }

    /**
     * Initializer for the HTTP client.
     *
     * - Parameters:
     *   - urlSession:      An optional `URLSession` coordinator for network requests
     *                      and handling `URLSessionDelegate` actions.
     *   - logger: pass logger instance for logging
     *   - userAgent: pass string to be set in User-Agent http header
     */
    init(urlSession: URLSession?,
         logger: OktaLoggerProtocol,
         userAgent: String)

    /**
     * Creates a custom `OktaURLRequest` object given configuration options
     *
     * - Parameters:
     *   - url:             The URL to be requested
     *   - method:          Request method for a desired network action.
     *                      Defaults to "GET".
     *   - urlParameters:   URL query parameters to send along with the request.
     *                      Defaults to `[:]`.
     *   - bodyParameters:  Payload/parameters to send along with the request.
     *                      Defaults to `[:]`.
     *   - headers:         Additional request headers. May override default headers
     *                      used by this library.
     *                      Defaults to `[:]`.
     *   - timeout:         A custom timeout, if desired.
     *                      Defaults to `0` which means to use the default configured timeout
     *
     * - Returns:           The created `OktaURLRequestProtocol`.
     */
    func request(
        _ url: URL,
        method: HTTPMethod,
        urlParameters: [String: String],
        bodyParameters: [String: Any],
        headers: [String: String],
        timeout: TimeInterval
    ) -> URLRequestProtocol

    /**
     * Creates a custom `OktaURLRequest` object given configuration options
     *
     * - Parameters:
     *   - url:             The URL to be requested
     *   - method:          Request method for a desired network action.
     *                      Defaults to "GET".
     *   - urlParameters:   URL query parameters to send along with the request.
     *                      Defaults to `[:]`.
     *   - httpBody:            Data to attach to the body of the HTTP request.
     *   - headers:         Additional request headers. May override default headers
     *                      used by this library.
     *                      Defaults to `[:]`.
     *   - timeout:         A custom timeout, if desired.
     *                      Defaults to `0` which means to use the default configured timeout
     *
     * - Returns:           The created `OktaURLRequestProtocol`.
     */
    func request(
        _ url: URL,
        method: HTTPMethod,
        urlParameters: [String: String],
        httpBody: Data?,
        headers: [String: String],
        timeout: TimeInterval
    ) -> URLRequestProtocol
}

extension HTTPClientProtocol {
    func request(
        _ url: URL,
        method: HTTPMethod = .get,
        urlParameters: [String: String] = [:],
        bodyParameters: [String: Any] = [:],
        headers: [String: String] = [:],
        timeout: TimeInterval = 0
    ) -> URLRequestProtocol {
        request(url, method: method, urlParameters: urlParameters, bodyParameters: bodyParameters, headers: headers, timeout: timeout)
    }

    func request(
        _ url: URL,
        method: HTTPMethod = .get,
        urlParameters: [String: String] = [:],
        httpBody: Data?,
        headers: [String: String] = [:],
        timeout: TimeInterval = 0
    ) -> URLRequestProtocol {
        request(url, method: method, urlParameters: urlParameters, httpBody: httpBody, headers: headers, timeout: timeout)
    }
}
