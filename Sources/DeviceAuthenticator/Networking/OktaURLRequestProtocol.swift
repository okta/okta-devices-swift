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

/// Abstract interface that represents HTTP request
@objc protocol URLRequestProtocol {
    var currentRequest: URLRequest { get }

    /**
     * Initializer for the Networking interface.
     *
     * - Parameters:
     *   - urlSession:  A `URLSession` coordinator for network requests
     *                  and handling `URLSessionDelegate` actions.
     *   - request:     An optional `URLRequest` created from the `HTTPClient.request` call
     */
    init(urlSession: URLSession, request: URLRequest)

    /**
     * Fetches the given URLRequest.
     *
     * - Parameters:
     *   - completion:  Handler to execute after the async call completes
     *
     * - Returns: Self
     */
    @objc func response(completion: @escaping (_ result: HTTPURLResult) -> Void)

    /**
     * Adds a header to the request
     *
     * - Parameters:
     *   - name:        The name of the header
     *   - token:       The value of the header
     *
     * - Returns: Self
     */
    @objc
    func addHeader(name: String, value: String) -> Self
}
