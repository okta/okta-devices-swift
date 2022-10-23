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

extension OktaTransactionEnroll {
    func enrollPushFactor(serverMethod: MethodResponseModel) throws -> EnrollingFactor? {
        logger.info(eventName: self.logEventName, message: "Enrolling PUSH factor")

        let pushFactor = enrollmentToUpdate?.enrolledFactors.first(where: { $0 is OktaFactorPush }) as? OktaFactorPush
        let proofOfPossessionKeyTag = pushFactor?.proofOfPossessionKeyTag
        let userVerificationKeyTag = pushFactor?.userVerificationKeyTag
        var deviceToken: DeviceToken = enrollmentContext.pushToken
        if case DeviceToken.empty = deviceToken {
            if let deviceTokenData = readDeviceToken(enrollmentId: enrollmentToUpdate?.enrollmentId ?? "") {
                deviceToken = .tokenData(deviceTokenData)
            }
        }
        let enrollingFactor = try createEnrollingFactorModel(with: proofOfPossessionKeyTag,
                                                             uvKeyTag: userVerificationKeyTag,
                                                             methodType: .push,
                                                             pushToken: deviceToken.rawValue)
        return enrollingFactor
    }
}
