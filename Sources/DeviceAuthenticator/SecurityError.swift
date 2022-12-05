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
import LocalAuthentication
import CryptoTokenKit

/// Errors that may occur in the process of crypto operations
public enum SecurityError: Error {
    /// Thrown when SDK fails to sign payload with private key
    case failedToSignPayload(String)
    /// Thrown when SDK fails to generate public or private crypto key
    case keyGenFailed(OSStatus, String)
    /// Thrown when SDK detect that crypto key has been invalidated by iOS (e.g. biometry changed)
    case keyCorrupted(Error)
    /// Thrown when user cancels local authentication process via local authentication dialog
    case localAuthenticationCancelled(Error)
    /// Thrown for cases that can't be mapped to specific error domains. For example SDK failed to parse web token information
    case generalEncryptionError(OSStatus, Error?, String)
    /// Thrown when SDK fails to build JWK payload
    case jwkError(String)
    /// Thrown when SDK fails to build JWT payload
    case jwtError(String)
    /// Thrown when SDK fails to encrypt/decrypt data
    case dataEncryptionDecryptionError(Error?)
}

public extension SecurityError {
    static func create(with signingError: Unmanaged<CFError>?) -> SecurityError {
        guard let signingError = signingError?.takeRetainedValue() else {
            return SecurityError.generalEncryptionError(-1, nil, "Error signing JWT with key")
        }

        let nsError: NSError = signingError as Error as NSError
        let userCancelledErrorCode = LAError.Code.userCancel.rawValue // -2
        if nsError.code == userCancelledErrorCode && nsError.domain == LAErrorDomain {
            return localAuthenticationCancelled(nsError)
        }

        let corruptedDataErrorCode = TKError.Code.corruptedData.rawValue // -3
        if nsError.code == corruptedDataErrorCode && nsError.domain == TKErrorDomain {
            return keyCorrupted(nsError)
        }

        if let laErr = signingError as? LAError {
            if laErr.code == .userCancel {
                return localAuthenticationCancelled(laErr)
            }
        }

        if let tkErr = signingError as? TKError {
            if tkErr.code == .corruptedData {
                return keyCorrupted(tkErr)
            }
        }

        return SecurityError.generalEncryptionError(-1, nsError, "Error signing JWT with key")
    }
}

extension SecurityError: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        switch (lhs, rhs) {
            case (.failedToSignPayload, .failedToSignPayload):
                return true
            case (let .keyGenFailed(code1, description1), let .keyGenFailed(code2, description2)):
                return code1 == code2 && description1 == description2
            case (let .generalEncryptionError(code1, _, description1), let .generalEncryptionError(code2, _, description2)):
                return code1 == code2 && description1 == description2
            case (let .jwkError(description1), let .jwkError(description2)):
                return description1 == description2
            case (let .jwtError(description1), let .jwtError(description2)):
                return description1 == description2
        case (let .dataEncryptionDecryptionError(error1), let .dataEncryptionDecryptionError(error2)):
            if error1 == nil && error2 == nil {
                return true
            } else if let nsError1 = error1 as? NSError,
                      let nsError2 = error2 as? NSError,
                      nsError1.code == nsError2.code {
                return true
            } else {
                return false
            }
            default:
                return false
        }
    }
}
