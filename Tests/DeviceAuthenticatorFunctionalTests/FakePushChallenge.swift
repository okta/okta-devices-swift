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
@testable import OktaJWT
@testable import DeviceAuthenticator

class FakePushChallenge {
    class func mockIDXJWT(transactionId: String = "transactionId",
                          enrollmentId: String,
                          challengeTextItems: [String]? = nil,
                          userVerification: UserVerificationChallengeRequirement = .none,
                          unusualActivities: [String]? = nil,
                          keyTypes: [String]? = nil,
                          challengeContext: [String: String] = ["clientOS": "iOS", "clientLocation": "San Francisco, USA", "transactionTime": "2090-09-08T19:03:30.166Z"],
                          verificationURI: String = "verificationUri",
                          transactionType: String = "LOGIN",
                          bindingMessage: String? = nil) -> String {
        var jwtPayload = JSONWebToken.Payload()
        var context = challengeContext
        context["transactionType"] = transactionType
        if let bindingMessage = bindingMessage {
            context["bindingMessage"] = bindingMessage
        }
        jwtPayload["challengeContext"] = context
        if let challengeTextItems = challengeTextItems,
           var challengeContext = jwtPayload["challengeContext"] as? [String: Any] {
            challengeContext["challengeTextItems"] = challengeTextItems
            jwtPayload["challengeContext"] = challengeContext
        }
        if let unusualActivities = unusualActivities,
           var challengeContext = jwtPayload["challengeContext"] as? [String: Any] {
            challengeContext["unusualActivitiesTextItems"] = unusualActivities
            jwtPayload["challengeContext"] = challengeContext
        }
        jwtPayload["orgId"] = "00otiyyDFtNCyFbnC0g4"
        jwtPayload["iss"] = "https://devicesdk.hioktane.com"
        jwtPayload["aud"] = "audience"
        jwtPayload["iat"] = Int(Date().timeIntervalSince1970)
        jwtPayload["transactionId"] = transactionId
        jwtPayload["authenticatorEnrollmentId"] = enrollmentId
        jwtPayload["verificationUri"] = verificationURI
        jwtPayload["method"] = "push"
        jwtPayload["nonce"] = "nonce"
        jwtPayload["userVerification"] = userVerification.value
        jwtPayload["exp"] = Int64(Date().timeIntervalSince1970 + 5 * 60)
        guard let jwt = try? JSONWebToken(payload: jwtPayload).rawString else {
            return ""
        }

        let parts = jwt.split(separator: ".").map(String.init)

        return "eyJhbGciOiJSUzI1NiIsInR5cCI6Im9rdGEtcHVzaGJpbmQrand0Iiwia2lkIjoiZDI2OTM4RlZyQmoxRVgxQklCS3dOeTVYanBja3J3Y2VIUTNRT3BMWjVvQSJ9" + "." + parts[1] + "." + "iy2kJytB0z_TSFMz2yXE6-tHyWFluP0oQZ1r4NFhCU2aUnYFia04ZmsjDJr4lOCqZ7F1wbqtLuYIgeKw4txxoPFDthhibnYs83en0955xWysXok9tHl7cOFRJFcH5sUpROkxUVnl1L713LO3bMZHp-0AUy0cd7jKsmrN3iOenMTkgaZb_A94bY6J5CHMkJyHVlRUognnzlZ1SE37JO3ldlxVy6QQfA3Z4eT99B-hUdGTkiM85hT8p5N8kmtRyXpG4KFDSIDAgSD0WtGgYIVklJ_m8g8Ydfniqioolq_HNqiUKx2HJsu36ozbTZE3HW6ailMkIVS4r1BKL80ROXvCyw"
    }
}

extension UserVerificationChallengeRequirement {

    var value: String {
        switch self {
        case .none:
            return "NONE"
        case .discouraged:
            return "DISCOURAGED"
        case .preferred:
            return "PREFERRED"
        case .required:
            return "REQUIRED"
        case .unknown:
            return "unknown"
        }
    }
}
