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
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif

/// Base class from remediation objects
public class RemediationStep {
    /// Call this function when you don't want or don't know how to handle remediation step object.  SDK will continue authentication and perform default remediation in that case
    public func defaultProcess() {
        defaultProcessClosure()
    }

    init(logger: OktaLoggerProtocol, defaultProcessClosure: @escaping () -> Void) {
        self.defaultProcessClosure = defaultProcessClosure
        self.logger = logger
    }

    let defaultProcessClosure: () -> Void
    let logger: OktaLoggerProtocol
}

