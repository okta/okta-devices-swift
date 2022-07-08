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
import UserNotifications

extension UNNotificationResponse {

    static func testNotificationResponse(with parameters: [AnyHashable: Any], testIdentifier: String) -> UNNotificationResponse {
        let notificationContent = UNMutableNotificationContent()
        notificationContent.title = "Test Title"
        notificationContent.body = "Test Body"
        notificationContent.userInfo = parameters

        let dateInfo = Calendar.current.dateComponents([.year, .month, .day, .hour, .minute, .second], from: Date())
        let trigger = UNCalendarNotificationTrigger(dateMatching: dateInfo, repeats: false)

        let notificationRequest = UNNotificationRequest(identifier: "testIdentifier", content: notificationContent, trigger: trigger)
        
        return UNNotificationResponse(coder: TestNotificationCoder(with: notificationRequest, testIdentifier: testIdentifier))!
    }
}

class TestNotificationCoder: NSCoder {

    private enum FieldKey: String {
        case date,
             request,
             sourceIdentifier,
             intentIdentifiers,
             notification,
             actionIdentifier,
             originIdentifier,
             targetConnectionEndpoint,
             targetSceneIdentifier
    }
    private let testIdentifier: String
    private let request: UNNotificationRequest
    override var allowsKeyedCoding: Bool { true }

    init(with request: UNNotificationRequest, testIdentifier: String) {
        self.request = request
        self.testIdentifier = testIdentifier
    }

    override func decodeObject(forKey key: String) -> Any? {
        let fieldKey = FieldKey(rawValue: key)
        switch fieldKey {
        case .date:
            return Date()
        case .request:
            return request
        case .sourceIdentifier, .actionIdentifier, .originIdentifier:
            return testIdentifier
        case .notification:
            return UNNotification(coder: self)
        default:
            return nil
        }
    }
}
