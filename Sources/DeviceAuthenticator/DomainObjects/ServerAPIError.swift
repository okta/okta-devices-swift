/*
* Copyright (c) 2020, Okta, Inc. and/or its affiliates. All rights reserved.
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

/// Structure represents error model from server HTTP responses. See also https://developer.okta.com/docs/reference/error-codes/
public struct ServerAPIErrorModel: Codable {
    /// An Okta code for this type of error
    public let errorCode: ServerErrorCode?
    /// A short description of what caused this error. Sometimes this contains dynamically-generated information about your specific error
    public let errorSummary: String?
    /// An Okta code for this type of error
    public let errorLink: String?
    /// A unique identifier for this error. This can be used by Okta Support to help with troubleshooting.
    public let errorId: String?
    /// Status of failed operation, for example REJECTED
    public let status: String?
    /// Further information about what caused this error
    public let errorCauses: [[String: String]]?
}
