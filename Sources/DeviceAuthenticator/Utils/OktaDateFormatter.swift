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

extension DateFormatter {
    class func oktaDateFormatter() -> ISO8601DateFormatter {
        let isoFormatter = ISO8601DateFormatter();
        isoFormatter.formatOptions = [ISO8601DateFormatter.Options.withColonSeparatorInTime,
                                      ISO8601DateFormatter.Options.withFractionalSeconds,
                                      ISO8601DateFormatter.Options.withFullDate,
                                      ISO8601DateFormatter.Options.withFullTime,
                                      ISO8601DateFormatter.Options.withTimeZone]
        return isoFormatter
    }
}

