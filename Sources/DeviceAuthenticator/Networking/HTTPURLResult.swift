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

/// Class represents result from HTTP operation
public class HTTPURLResult: NSObject, NSSecureCoding {
    /// Object that represents request to server
    public let request: URLRequest?
    /// Optional server response object
    public let response: HTTPURLResponse?
    /// Optional data from server response(HTTP body)
    public let data: Data?
    /// Optional error from HTTP operation. This propery is non-nil for network related issues, for example request timed-out
    public let error: Error?

    /// NSSecureCoding protocol conformance
    public static var supportsSecureCoding = true

    public func encode(with coder: NSCoder) {
        coder.encode(request, forKey: "request")
        coder.encode(response, forKey: "response")
        coder.encode(data, forKey: "data")
        coder.encode(error, forKey: "error")
    }

    public required convenience init?(coder: NSCoder) {
        let request = coder.decodeObject(of: [NSURLRequest.self], forKey: "request") as? URLRequest
        let response = coder.decodeObject(of: [HTTPURLResponse.self], forKey: "response") as? HTTPURLResponse
        let data = coder.decodeObject(of: [NSData.self], forKey: "data") as? Data
        let error = coder.decodeObject(of: [NSError.self], forKey: "error") as? Error

        self.init(request: request, response: response, data: data, error: error)
    }

    /// Initializes a `Result` object.
    ///
    /// - Parameters:
    ///   - request:     `URLRequest` sent to the server
    ///   - response:    `HTTPURLResponse`returned by the server
    ///   - error:       Error response from the network request, response, or misc errors that occur during the API request.
    public init(request: URLRequest?, response: HTTPURLResponse?, data: Data?, error: Error? = nil) {
        self.request = request
        self.response = response
        self.data = data
        self.error = error
    }
}
