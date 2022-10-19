/*
* Copyright (c) 2021-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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

/// Errors that the Okta server returns
public enum ServerErrorCode: Codable {
    /// Operation failed because enrollment no longer exists on server side
    case enrollmentDeleted
    /// Operation failed because user no longer exists on server side
    case userDeleted
    /// Operation failed because device no longer exists on server side
    case deviceDeleted
    /// Operation failed because enrollment is in suspended state on server side
    case enrollmentSuspended
    /// Operation failed because device is in suspended state on server side
    case deviceSuspended
    /// Operation failed because user is in suspended state on server side
    case userSuspended
    /// Requested resourse no longer exists on server side
    case resourceNotFound
    /// Operation failed because authenticator enrollment no longer exists on server side
    case enrollmentNotFound
    /// Enrollment request failed due to authenticator policy requires user verification capability for the enrollment
    case biometricKeyEnrollmentComplianceError
    /// Operation failed due to invalid authentication token in SDK request, e.g. token expired, incorrectly signed and etc.
    case invalidToken
    /// All other errors. Complete list of errors can be found in developer documentation https://developer.okta.com/docs/reference/error-codes/
    case unknown(String)

    // swiftlint:disable cyclomatic_complexity
    public init(raw: String) {
        switch raw {
        case "E0000154":
            self = .enrollmentDeleted
        case "E0000011":
            self = .invalidToken
        case "E0000156":
            self = .userDeleted
        case "E0000152":
            self = .deviceSuspended
        case "E0000153":
            self = .deviceDeleted
        case "E0000155":
            self = .userSuspended
        case "E0000180":
            self = .enrollmentSuspended
        case "E0000158":
            self = .biometricKeyEnrollmentComplianceError
        case "E0000007":
            self = .resourceNotFound
        case "E0000008":
            self = .enrollmentNotFound
        default:
            self = .unknown(raw)
        }
    }
    // swiftlint:enable cyclomatic_complexity

    public var isResourceDeleted: Bool {
        switch self {
        case .enrollmentDeleted,
             .userDeleted,
             .deviceDeleted,
             .enrollmentNotFound:
            return true
        default: return false
        }
    }

    public var isResourceSuspended: Bool {
        switch self {
        case .deviceSuspended,
             .userSuspended,
             .enrollmentSuspended:
            return true
        default: return false
        }
    }

    public var rawValue: String {
        switch self {
        case .enrollmentDeleted:
            return "E0000154"
        case .deviceSuspended:
            return "E0000152"
        case .deviceDeleted:
            return "E0000153"
        case .biometricKeyEnrollmentComplianceError:
            return "E0000158"
        case .userSuspended:
            return "E0000155"
        case .userDeleted:
            return "E0000156"
        case .enrollmentSuspended:
            return "E0000180"
        case .resourceNotFound:
            return "E0000007"
        case .enrollmentNotFound:
            return "E0000008"
        case .invalidToken:
            return "E0000011"
        case .unknown(let value):
            return value
        }
    }

    public func httpCode() -> Int {
        switch self {
        case .enrollmentDeleted:
            return 410
        case .deviceSuspended:
            return 403
        case .deviceDeleted:
            return 410
        case .biometricKeyEnrollmentComplianceError:
            return 400
        case .userSuspended:
            return 423
        case .userDeleted:
            return 410
        case .enrollmentSuspended:
            return 423
        case .resourceNotFound, .enrollmentNotFound:
            return 404
        default:
            return 400
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let stringValue = try container.decode(String.self)
        self.init(raw: stringValue)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.rawValue)
    }

}
