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

public let DeviceAuthenticatorErrorDomain: String = "DeviceAuthenticator.DeviceAuthenticatorError"

/// Errors that may occur in the process of enrollment and verification flows
public enum DeviceAuthenticatorError: Error {
    /// Thrown when server returns HTTP level response. Error may also contain optional `ServerAPIErrorModel` for cases when server replied with json body. See also https://developer.okta.com/docs/reference/error-codes/
    case serverAPIError(HTTPURLResult, ServerAPIErrorModel?)
    /// Thrown when SDK fails to send HTTP request to server. May indicate connectivity or network problems
    case networkError(Error)
    /// Thrown when SDK fails to perform crypto operations
    case securityError(SecurityError)
    /// Thrown when SDK fails to perform storage level operations
    case storageError(StorageError)
    /// Thrown for cases that can't be mapped to specific error domains. For example server returned malformed or unexpected data
    case genericError(String)
    /// Thrown when SDK detects some bad or unrecoverable state. Usually indicates a bug in SDK implementation
    case internalError(String)
    /// Thrown when SDK fails to find enrollment for the authentication challenge
    case accountNotFoundForChallenge(ChallengeProtocol)
    /// Thrown when SDK fails to parse provided push notification
    case pushNotRecognized
    /// Thrown when authenticator policy doesn't have any verification methods that SDK can enroll
    case noVerificationMethodsToEnroll
}

extension DeviceAuthenticatorError: CustomNSError {

    public static var errorDomain: String {
        return DeviceAuthenticatorErrorDomain
    }

    public var errorCode: Int {
        switch self {
        case .serverAPIError(_, _):
            return -1
        case .networkError(_):
            return -2
        case .securityError:
            return -3
        case .storageError(_):
            return -4
        case .genericError(_):
            return -5
        case .internalError:
            return -6
        case .accountNotFoundForChallenge(_):
            return -7
        case .pushNotRecognized:
            return -8
        case .noVerificationMethodsToEnroll:
            return -9
        }
    }

    public var errorUserInfo: [String: Any] {
        var userInfo: [String: Any] = [: ]
        switch self {
        case .serverAPIError(let result, let errorModel):
            userInfo["result"] = result
            if let errorModel = errorModel {
                userInfo["json"] = try? JSONEncoder().encode(errorModel)
            } else {
                userInfo["json"] = [: ] as [String: Any]
            }
            return userInfo
        case .storageError(error: let error):
            userInfo[NSUnderlyingErrorKey] = error
            userInfo[NSLocalizedDescriptionKey] = error.errorDescription
            return userInfo
        case .networkError(let error),
             .securityError(let error as Error):
            userInfo[NSUnderlyingErrorKey] = error
            return userInfo
        case .genericError(description: let description):
            userInfo[NSLocalizedDescriptionKey] = description
            return userInfo
        default:
            return userInfo
        }
    }
}

extension DeviceAuthenticatorError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .storageError(error: let error):
            return error.errorDescription
        case .networkError(let error):
            return error.localizedDescription
        case .securityError:
            return "Encryption operation failed"
        case .serverAPIError(_, _):
            return "Server call has failed"
        case .accountNotFoundForChallenge(_):
            return "Account not found"
        case .genericError(let errorString),
             .internalError(let errorString):
            return errorString
        case .pushNotRecognized:
            return "Unrecognized push notification"
        case .noVerificationMethodsToEnroll:
            return "Authenticator policy doesn't have any methods to enroll"
        }
    }
}

extension DeviceAuthenticatorError {
    static func oktaError(from error: Error) -> Self {
        if let oktaError = error as? DeviceAuthenticatorError {
            return oktaError
        } else if let encryptionError = error as? SecurityError {
            return DeviceAuthenticatorError.securityError(encryptionError)
        } else if let storageError = error as? StorageError {
            return DeviceAuthenticatorError.storageError(storageError)
        } else {
            return DeviceAuthenticatorError.internalError(error.localizedDescription)
        }
    }
}

extension DeviceAuthenticatorError {
    func userVerificationCancelled() -> Bool {
        if case .securityError(let encryptionErr) = self {
            if case .localAuthenticationCancelled(_) = encryptionErr {
                return true
            }
        }
        return false
    }

    func userVerificationFailed() -> Bool {
        if case .securityError(let encryptionErr) = self {
            if case .localAuthenticationFailed(_) = encryptionErr {
                return true
            }
        }
        return false
    }

    var serverErrorCode: ServerErrorCode? {
        if case .serverAPIError(_, let model) = self {
            return model?.errorCode
        }
        return nil
    }
}

extension DeviceAuthenticatorError: Equatable {
    public static func == (lhs: DeviceAuthenticatorError, rhs: DeviceAuthenticatorError) -> Bool {
        return lhs.errorCode == rhs.errorCode
    }
}
