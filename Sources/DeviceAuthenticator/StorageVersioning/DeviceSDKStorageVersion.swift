/*
* Copyright (c) 2021, Okta, Inc. and/or its affiliates. All rights reserved.
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

enum DeviceSDKStorageVersion: Int, OktaVersionType {
    case unknown = -1

    /**
     Starting point of DevicesSDK Storage versioning
     */
    case v1 = 1

    /**
     See v2 of DevicesSDK Storage changes in _Discussion_ section below

     _User Defaults Storage:_
     * `DeviceEnrollment.orgUrl` - Deprecated. New enrollments will not contain value for this property, while legacy enrollment will.
     * `DeviceEnrollment.orgId` - added
     * `AuthenticatorPolicy.userVerificationSetting` - becomes injectable property backed by `_userVerification`, instead of being calculatable
     * `AuthenticatorPolicy.methods` - new property, injectable

     _Keychain Storage:_
     - no chancges

     _SQLite Storage:_
     - no changes, since it is introduced for the 1st time
    */
    case v2 = 2

    static var unknownVersion: DeviceSDKStorageVersion { return .unknown }
}
