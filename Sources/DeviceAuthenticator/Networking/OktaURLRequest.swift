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

/// Class that represents HTTP request
class OktaURLRequest: URLRequestProtocol {
    var currentSession: URLSession
    var currentRequest: URLRequest

    required init(urlSession: URLSession, request: URLRequest) {
        self.currentSession = urlSession
        self.currentRequest = request
    }

    func response(completion: @escaping (_ result: HTTPURLResult) -> Void) {
        let task = self.currentSession.dataTask(with: self.currentRequest) { data, response, error in
            let httpResponse = response as? HTTPURLResponse
            completion(HTTPURLResult(request: self.currentRequest, response: httpResponse, data: data, error: error))
        }
        task.resume()
    }

    func addHeader(name: String, value: String) -> Self {
        self.currentRequest.addValue(value, forHTTPHeaderField: name)
        return self
    }
}
