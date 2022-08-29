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
// swiftlint:disable force_unwrapping
import Foundation
@testable import DeviceAuthenticator

class EnrollmentTestHelper {

    private let authToken: AuthToken
    private var appConfig: ApplicationConfig!
    private var deviceAuthenticatorConfig: DeviceAuthenticatorConfig!
    private var enrollmentParams: EnrollmentParameters!
    private(set) var deviceAuthenticator: DeviceAuthenticatorProtocol!

    init(applicationName: String,
         applicationVersion: String,
         applicationGroupId: String,
         orgHost: String,
         clientId: String,
         deviceToken: String,
         authToken: AuthToken) {
        self.authToken = authToken
        appConfig = ApplicationConfig(applicationName: applicationName,
                                      applicationVersion: applicationVersion,
                                      applicationGroupId: applicationGroupId)
        deviceAuthenticatorConfig = DeviceAuthenticatorConfig(orgURL: URL(string: orgHost)!,
                                                              oidcClientId: clientId)
        enrollmentParams = EnrollmentParameters(deviceToken: DeviceToken.tokenString(deviceToken))
//        Self.removeDBFiles()
    }

    deinit {
        Self.removeDBFiles()
    }

    func enroll(userVerification: Bool = false,
                mockHTTPClient: HTTPClient,
                completion: @escaping (Result<AuthenticatorEnrollmentProtocol, DeviceAuthenticatorError>) -> Void) throws {

        enrollmentParams.enableUserVerification(enable: userVerification)
        let oktaRestAPI = LegacyServerAPI(client: mockHTTPClient, logger: OktaLoggerMock())
        do {
            deviceAuthenticator = try DeviceAuthenticatorBuilder(applicationConfig: appConfig).create()
            (deviceAuthenticator as? DeviceAuthenticator)?.impl.restAPI = oktaRestAPI
            deviceAuthenticator.enroll(authenticationToken: authToken,
                                       authenticatorConfig: deviceAuthenticatorConfig,
                                       enrollmentParameters: enrollmentParams,
                                       completion: completion)
        }
    }

    static func removeDBFiles() {
        let fileManager = FileManager.default
        let path = DeviceAuthenticatorConstants.defaultStorageRelativeDirectoryPath
        guard let url = fileManager.containerURL(forSecurityApplicationGroupIdentifier: ExampleAppConstants.appGroupId)?.appendingPathComponent(path) else {
            return
        }
        try? fileManager.removeItem(at: url)
    }
}
