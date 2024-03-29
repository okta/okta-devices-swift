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
import XCTest
import OktaJWT
#if SWIFT_PACKAGE
import LoggerCore
#else
import OktaLogger
#endif
@testable import DeviceAuthenticator

class OktaDeviceBindJWTTests: XCTestCase {

    func testInitDeviceBindJWTSuccess() {
        do {
            let mut = try OktaBindJWT(string: OktaJWTTestData.validDeviceChallengeRequestJWT(), validatePayload: false, logger: OktaLoggerMock())
            XCTAssertEqual(mut.nonce, "FWkfwFWkfw3jfd3jfd")
            XCTAssertEqual(mut.iss, "https://your-org.okta.com")
            XCTAssertEqual(mut.iat, 1467145094)
            XCTAssertEqual(mut.exp, 1467148694)
            XCTAssertEqual(mut.userMediation, nil)
            XCTAssertEqual(mut.userVerification, nil)
            XCTAssertEqual(mut.methodType.rawValue, "signed_nonce")
            XCTAssertEqual(mut.transactionId, "123456789")
            XCTAssertEqual(mut.verificationURL.absoluteString, "https://your-org.okta.com/idp/idx/authenticators/authenticatorId/transactions/transactionId/verify")
            XCTAssertEqual(mut.signals.count, 11)
            XCTAssertNotNil(mut.signals.first(where: { $0 == "screenLock" }))
            XCTAssertNotNil(mut.signals.first(where: { $0 == "rootPrivileges" }))
            XCTAssertNotNil(mut.signals.first(where: { $0 == "fullDiskEncryption" }))
            XCTAssertNotNil(mut.signals.first(where: { $0 == "id" }))
            XCTAssertNotNil(mut.signals.first(where: { $0 == "os" }))
            XCTAssertNotNil(mut.signals.first(where: { $0 == "osVersion" }))
            XCTAssertNotNil(mut.signals.first(where: { $0 == "manufacturer" }))
            XCTAssertNotNil(mut.signals.first(where: { $0 == "model" }))
            XCTAssertNotNil(mut.signals.first(where: { $0 == "deviceAttestation" }))
            XCTAssertNotNil(mut.signals.first(where: { $0 == "appId" }))
            XCTAssertNotNil(mut.signals.first(where: { $0 == "appManaged" }))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testInitDeviceBindJWTSuccess_PreferredUserVerification() {
        do {
            let mut = try OktaBindJWT(string: OktaJWTTestData.validDeviceChallengeRequestJWTWithUserVerificationPreferred(), validatePayload: false, logger: OktaLoggerMock())
            XCTAssertEqual(mut.userVerification, .preferred)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testUnexpectedJWTType() {
        do {
            let _ = try OktaBindJWT(string: OktaJWTTestData.unexpectedJWTType(), validatePayload: false, logger: OktaLoggerMock())
            XCTFail("Exception expected")
        } catch let error as SecurityError {
            XCTAssertEqual(error, SecurityError.jwtError("Invalid JWT structure"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testJWTPayloadWithoutOrgId() {
        do {
            let _ = try OktaBindJWT(string: OktaJWTTestData.payloadWithoutOrgId(), validatePayload: false, logger: OktaLoggerMock())
            XCTFail("Exception expected")
        } catch let error as SecurityError {
            XCTAssertEqual(error, SecurityError.jwtError("orgId claim isn't present in JWT payload"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testJWTPayloadWithoutNonce() {
        do {
            let _ = try OktaBindJWT(string: OktaJWTTestData.payloadWithoutNonce(), validatePayload: false, logger: OktaLoggerMock())
            XCTFail("Exception expected")
        } catch let error as SecurityError {
            XCTAssertEqual(error, SecurityError.jwtError("nonce claim isn't present in JWT payload"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testJWTPayloadWithoutVerificationURI() {
        do {
            let _ = try OktaBindJWT(string: OktaJWTTestData.payloadWithoutVerificationURI(), validatePayload: false, logger: OktaLoggerMock())
            XCTFail("Exception expected")
        } catch let error as SecurityError {
            XCTAssertEqual(error, SecurityError.jwtError("verificationUri claim isn't present in JWT payload"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testJWTPayloadWithoutIss() {
        do {
            let _ = try OktaBindJWT(string: OktaJWTTestData.payloadWithoutIss(), validatePayload: false, logger: OktaLoggerMock())
            XCTFail("Exception expected")
        } catch let error as SecurityError {
            XCTAssertEqual(error, SecurityError.jwtError("iss claim isn't present in JWT payload"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testJWTPayloadWithoutAud() {
        do {
            let _ = try OktaBindJWT(string: OktaJWTTestData.payloadWithoutAud(), validatePayload: false, logger: OktaLoggerMock())
            XCTFail("Exception expected")
        } catch let error as SecurityError {
            XCTAssertEqual(error, SecurityError.jwtError("aud claim isn't present in JWT payload"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testJWTPayloadWithoutIat() {
        do {
            let _ = try OktaBindJWT(string: OktaJWTTestData.payloadWithoutIat(), validatePayload: false, logger: OktaLoggerMock())
            XCTFail("Exception expected")
        } catch let error as SecurityError {
            XCTAssertEqual(error, SecurityError.jwtError("iat claim isn't present in JWT payload"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testJWTPayloadWithoutExp() {
        do {
            let _ = try OktaBindJWT(string: OktaJWTTestData.payloadWithoutExp(), validatePayload: false, logger: OktaLoggerMock())
            XCTFail("Exception expected")
        } catch let error as SecurityError {
            XCTAssertEqual(error, SecurityError.jwtError("exp claim isn't present in JWT payload"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testJWTPayloadWithoutTransactionId() {
        do {
            let _ = try OktaBindJWT(string: OktaJWTTestData.payloadWithoutTransactionId(), validatePayload: false, logger: OktaLoggerMock())
            XCTFail("Exception expected")
        } catch let error as SecurityError {
            XCTAssertEqual(error, SecurityError.jwtError("transactionId claim isn't present in JWT payload"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testDeviceChallengeResponseJWTGeneration() {
        let cryptoManager = CryptoManagerMock(keychainGroupId: ExampleAppConstants.appGroupId, logger: OktaLoggerMock())
        _ = try? cryptoManager.generate(keyPairWith: .ES256, with: "kid", useSecureEnclave: false, useBiometrics: false)
        let key = cryptoManager.get(keyOf: .privateKey, with: "kid")
        let mut = try? OktaBindJWT(string: OktaJWTTestData.validDeviceChallengeRequestJWT(), validatePayload: false, logger: OktaLoggerMock())
        XCTAssertNotNil(mut)
        do {
            let config = ApplicationConfig(applicationName: "Test App",
                                           applicationVersion: "1.0.0",
                                           applicationGroupId: ExampleAppConstants.appGroupId)
            let builder = OktaDeviceModelBuilder(orgHost: "https://tenenat.okta.com",
                                                 applicationConfig: config,
                                                 requestedSignals: ["diskEncryptionType", "screenLockType"],
                                                 customSignals: nil,
                                                 cryptoManager: cryptoManager,
                                                 logger: OktaLoggerMock())
            let deviceEnrollment = OktaDeviceEnrollment(id: "id",
                                                        orgId: "https://tenant.okta.com",
                                                        clientInstanceId: "clientInstanceId",
                                                        clientInstanceKeyTag: "clientInstanceKeyTag")
            let deviceSignals = builder.buildForVerifyTransaction(deviceEnrollmentId: deviceEnrollment.id,
                                                                  clientInstanceKey: deviceEnrollment.clientInstanceId)
            let context: [String: _OktaCodableArbitaryType] = ["userConsent": .string("NONE")]
            let encodedJWT = try mut!.generateDeviceChallengeResponseJWT(key: key!,
                                                                         enrollmentId: "authenticatorEnrollmentId",
                                                                         sub: "user_id",
                                                                         methodEnrollmentId: "factorId",
                                                                         kid: "kid",
                                                                         signals: deviceSignals,
                                                                         context: context,
                                                                         integrations: TestUtils.testIntegrations(),
                                                                         signalProviders: TestUtils.testIntegrations(),
                                                                         keyType: .proofOfPossession)
            let decodedJWT = try JSONWebToken(string: encodedJWT, typeHeader: "okta-devicebind+jwt")
            XCTAssertEqual(decodedJWT.payload["iss"] as! String, "authenticatorEnrollmentId")
            XCTAssertEqual(decodedJWT.payload["sub"] as! String, "user_id")
            XCTAssertEqual(decodedJWT.payload["tx"] as! String, mut!.transactionId)
            let deviceSignalsDictionary = decodedJWT.payload["deviceSignals"] as? [String: Any]
            XCTAssertNotNil(deviceSignalsDictionary)
            XCTAssertNotNil(deviceSignalsDictionary!["clientInstanceId"])
            XCTAssertNotNil(deviceSignalsDictionary!["screenLockType"])
            #if os(iOS)
            XCTAssertNil(deviceSignalsDictionary!["displayName"])
            XCTAssertNotNil(deviceSignalsDictionary!["diskEncryptionType"])
            #endif
            XCTAssertEqual(decodedJWT.payload["methodEnrollmentId"] as! String, "factorId")
            XCTAssertNotNil(decodedJWT.payload["nonce"])
            XCTAssertEqual(decodedJWT.payload["nonce"] as? String, "FWkfwFWkfw3jfd3jfd")
            let challengeResponseContext = decodedJWT.payload["challengeResponseContext"] as? [String: String]
            XCTAssertNotNil(challengeResponseContext)
            let userConsent = challengeResponseContext?["userConsent"]
            XCTAssertNotNil(userConsent)
            XCTAssertEqual(.string(userConsent!), context["userConsent"])
            XCTAssertEqual(decodedJWT.payload["keyType"] as? String, "proofOfPossession")
            let integrations = decodedJWT.payload["integrations"] as? [[String: Any]]
            XCTAssertEqual(integrations?.first?["name"] as! String, "name")
            let providers = decodedJWT.payload["signalProviders"] as? [[String: Any]]
            XCTAssertEqual(providers?.first?["name"] as! String, "name")
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testDeviceChallengeResponseJWTSignatureValidation() {
        let mut = try? OktaDeviceBindJWTPartialMock(string: OktaJWTTestData.validSignedDeviceChallengeRequestJWT(),
                                                    validatePayload: true,
                                                    customizableHeaders: OktaJWTTestData.validJWKCustomizeTypeHeader,
                                                    ignoreExpValidation: false,
                                                    ignoreIatValidation: false,
                                                    allowedClockSkewInSeconds: 8000000000000,
                                                    logger: OktaLoggerMock())
        XCTAssertNotNil(mut)
        XCTAssertNoThrow(try mut?.validate(with: "https://your-org.okta.com"))
        XCTAssertNotNil(mut?.optionsToValidate["iss"])
        XCTAssertNotNil(mut?.optionsToValidate["exp"])
        XCTAssertNotNil(mut?.optionsToValidate["iat"])
        XCTAssertNotNil(mut?.optionsToValidate["typ"])
    }

    func testDeviceChallengeResponseJWTInvalidSignatureValidationFails() {
        do {
            let _ = try OktaDeviceBindJWTPartialMock(string: OktaJWTTestData.validSignedDeviceChallengeRequestJWT(),
                                                     validatePayload: true,
                                                     customizableHeaders: OktaJWTTestData.invalidJWKCustomizeTypeHeader,
                                                     logger: OktaLoggerMock())
        } catch let error as SecurityError {
            XCTAssertEqual(error, SecurityError.jwtError("Invalid Key ID"))
        } catch {
            XCTFail("Unexpected error - \(error)")
        }
    }

    func testDeviceChallengeResponseJWTIssuedInFutureChallengeRequestJWT() {
        do {
            let mut = try OktaDeviceBindJWTPartialMock(string: OktaJWTTestData.validSignedDeviceChallengeRequestJWT(),
                                                       validatePayload: true,
                                                       customizableHeaders: OktaJWTTestData.validJWKCustomizeTypeHeader,
                                                       ignoreIatValidation: false,
                                                       logger: OktaLoggerMock())
            try mut.validate(with: "https://your-org.okta.com")
            XCTFail("Exception is expected")
        } catch let error as SecurityError {
            XCTAssertEqual(error, SecurityError.jwtError("The JWT was issued in the future"))
        } catch {
            XCTFail("Unexpected error - \(error)")
        }
    }

    func testDeviceChallengeResponseJWTExpiredChallengeRequestJWT() {
        do {
            let mut = try OktaDeviceBindJWTPartialMock(string: OktaJWTTestData.validSignedDeviceChallengeRequestJWT(),
                                                       validatePayload: true,
                                                       customizableHeaders: OktaJWTTestData.validJWKCustomizeTypeHeader,
                                                       ignoreExpValidation: false,
                                                       logger: OktaLoggerMock())
            try mut.validate(with: "https://your-org.okta.com")
            XCTFail("Exception is expected")
        } catch let error as SecurityError {
            XCTAssertEqual(error, SecurityError.jwtError("The JWT expired and is no longer valid"))
        } catch {
            XCTFail("Unexpected error - \(error)")
        }
    }

    func testInvalidJWTHeader() {
        do {
            let _ = try OktaBindJWT(string: OktaJWTTestData.invalidJWTHeader(), validatePayload: false, logger: OktaLoggerMock())
            XCTFail("Exception expected")
        } catch let error as SecurityError {
            XCTAssertEqual(error, SecurityError.jwtError("Invalid JWT structure"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testInvalidJWTPayload() {
        do {
            let _ = try OktaBindJWT(string: OktaJWTTestData.invalidJWTPayload(), logger: OktaLoggerMock())
            XCTFail("Exception expected")
        } catch let error as SecurityError {
            XCTAssertEqual(error, SecurityError.jwtError("Invalid JWT structure"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testInvalidJWTHeaderJSON() {
        do {
            let _ = try OktaBindJWT(string: OktaJWTTestData.invalidJWTHeaderJSON(), logger: OktaLoggerMock())
            XCTFail("Exception expected")
        } catch let error as SecurityError {
            XCTAssertEqual(error, SecurityError.jwtError("Invalid JWT structure"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testInvalidJWTPayloadJSON() {
        do {
            let _ = try OktaBindJWT(string: OktaJWTTestData.invalidJWTPayloadJSON(), logger: OktaLoggerMock())
            XCTFail("Exception expected")
        } catch let error as SecurityError {
            XCTAssertEqual(error, SecurityError.jwtError("Invalid JWT structure"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    // Verify that the payload's content can be logged via `description`
    // Should contain device signals as well as signalPlugin data
    func testPayloadDescription() {
        let amr = "face"
        let issuer = UUID().uuidString
        let audience = UUID().uuidString
        let subject = UUID().uuidString
        let nonce = UUID().uuidString
        let binding = UUID().uuidString
        let context: [String: _OktaCodableArbitaryType] = ["binding": .string(binding)]
        let signalProvider = _PluginSignalData(name: "com.okta.device.integrity", configuration: .local, signal: "{sensitiveSignal}", timeCollected: 1233456)
        let signalProviderData = _IntegrationData.signal(signalProvider)

        let integration = _PluginSignalData(name: "com.okta.test.integration", configuration: .local, signal: "{sensitiveIntegration}", timeCollected: 1233456)
        let integrationData = _IntegrationData.signal(integration)

        let signals = DeviceSignalsModel(platform: .iOS, osVersion: "1.2.3", displayName: "displayName")
        signals.displayName = "helloPIIName"
        signals.udid = "helloPIIUDID"
        signals.serialNumber = "abcdef8888PII"
        signals.deviceAttestation = ["managementHint":
                .string("{sensitiveDeviceAttestation}")]
        let payload = OktaDeviceBindJWTPayload(iss: issuer,
                                               aud: audience,
                                               sub: subject,
                                               tx: "txValue",
                                               amr: [amr],
                                               deviceSignals: signals,
                                               nonce: nonce,
                                               methodEnrollmentId: nil,
                                               keyType: nil,
                                               challengeResponseContext: context,
                                               integrations: [integrationData],
                                               signalProviders: [signalProviderData])

        let desc = payload.description
        XCTAssertTrue(desc.contains(amr))
        XCTAssertTrue(desc.contains(issuer))
        XCTAssertTrue(desc.contains(audience))
        XCTAssertTrue(desc.contains(subject))
        XCTAssertTrue(desc.contains(nonce))
        XCTAssertTrue(desc.contains("txValue"))
        XCTAssertTrue(desc.contains(binding))
        XCTAssertTrue(desc.contains("IOS"))

        // Integration should be printered, but the sensitive part redacted
        XCTAssertTrue(desc.contains(integration.name))
        XCTAssertTrue(desc.contains("\(integration.timeCollected)"))
        XCTAssertFalse(desc.contains(integration.signal))

        // SignalProvider should be present, signal part redacted
        XCTAssertTrue(desc.contains(signalProvider.name))
        XCTAssertTrue(desc.contains("\(signalProvider.timeCollected)"))
        XCTAssertFalse(desc.contains(signalProvider.signal))

        // Device Attestation should be printed, sensitive portion redacted
        XCTAssertTrue(desc.contains("deviceAttestation"))
        XCTAssertFalse(desc.contains("managementHint"))
        XCTAssertFalse(desc.contains("{sensitiveDeviceAttestation}"))

        XCTAssertFalse(desc.contains(signals.serialNumber ?? UUID().uuidString))
        XCTAssertFalse(desc.contains(signals.udid ?? UUID().uuidString))
        XCTAssertFalse(desc.contains(signals.displayName ?? UUID().uuidString))
    }
}
