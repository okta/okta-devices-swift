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
import OktaLogger
@testable import DeviceAuthenticator

class MockMultipleRequestsHTTPClient: HTTPClient {
    var resultArray: [HTTPURLResult]?
    let mockRequest = URLRequest(url: URL(string: "com.okta.example")!)
    var counter = -1

    required init(urlSession: URLSession?, logger: OktaLoggerProtocol, userAgent: String) {
        super.init(urlSession: urlSession, logger: logger, userAgent: userAgent)
    }

    convenience init(resultArray: [HTTPURLResult]) {
        self.init(urlSession: nil, logger: OktaLoggerMock(), userAgent: "")
        self.resultArray = resultArray
    }

    convenience init(responseArray: [HTTPURLResponse], dataArray: [Data]) {
        var resultArray = [HTTPURLResult]()
        for index in 0..<responseArray.count {
            resultArray.append(HTTPURLResult(
                request: URLRequest(url: URL(string: "com.okta.example")!),
                response: responseArray[index],
                data: dataArray.isEmpty ? Data() : dataArray[index]
            ))
        }
        self.init(resultArray: resultArray)
    }

    convenience init(error: Error) {
        let resultArray = [HTTPURLResult(request: URLRequest(url: URL(string: "com.okta.example")!), response: nil, data: nil, error: error)]
        self.init(resultArray: resultArray)
    }

    override func request(
        _ url: URL,
        method: HTTPMethod = .get,
        urlParameters: [String : String] = [:],
        bodyParameters: [String : Any] = [:],
        headers: [String : String] = [:],
        timeout: TimeInterval = 0
    ) -> URLRequestProtocol {
        counter += 1
        return MockURLRequest(result: resultArray![counter], headers: headers)
    }

    override func request(
        _ url: URL,
        method: HTTPMethod = .get,
        urlParameters: [String : String] = [:],
        httpBody: Data?,
        headers: [String : String] = [:],
        timeout: TimeInterval = 0
    ) -> URLRequestProtocol {
        counter += 1
        return MockURLRequest(result: resultArray![counter], headers: headers)
    }
}
