/*
* Copyright (c) 2019-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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
    func buildDeviceModelData(customDeviceSignals: DeviceSignals?) -> DeviceSignalsModel {
        let deviceModelBuilder = OktaDeviceModelBuilder(orgHost: enrollmentContext.orgHost.absoluteString,
                                                        applicationConfig: applicationConfig,
                                                        requestedSignals: [],
                                                        customSignals: customDeviceSignals,
                                                        cryptoManager: self.cryptoManager,
                                                        jwtGenerator: jwtGenerator,
                                                        jwkGenerator: jwkGenerator,
                                                        logger: logger)
        let deviceModel: DeviceSignalsModel
        if let deviceEnrollment = deviceEnrollment {
            logger.info(eventName: self.logEventName, message: "Building device model based on existing device object")
            deviceModel = deviceModelBuilder.buildForUpdateEnrollment(with: deviceEnrollment)
        } else {
            logger.info(eventName: self.logEventName, message: "Registering new device object")
            let clientInstanceKeyTag = UUID().uuidString
            deviceModel = deviceModelBuilder.buildForCreateEnrollment(with: clientInstanceKeyTag)
            self.clientInstanceKeyTag = clientInstanceKeyTag
        }

        return deviceModel
    }
}
