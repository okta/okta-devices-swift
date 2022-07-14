# ``DeviceAuthenticator``

This library allows your app to integrate with Okta service to provide APNS push-based MFA.

## Overview

This SDK is available through [CocoaPods](http://cocoapods.org). To install it, add the following line to your Podfile:

```ruby
pod 'DeviceAuthenticator'
```

A complete integration requires your app to implement the following:

- **Creation**: Create the SDK object to work with your Okta authenticator configuration
- **Enrollment**: Register a device and optional biometrics with an account for use with push MFA.
- **Verification**: Resolve an MFA challenge step for a sign-in attempt against an enrolled account, prompting the user to approve or reject it (with optional biometrics).
- **Update**: Refresh the APNS token, remediate changed biometrics, deregister the account on the device.

## Topics

### Create device authenticator instance

```swift
let appicationConfig = ApplicationConfig(applicationName: "TestApp",
                                         applicationVersion: "1.0.0",
                                         applicationGroupId: "group.com.company.testapp")
#if DEBUG
appicationConfig.apsEnvironment = .development
#endif

let authenticator: DeviceAuthenticatorProtocol = try? DeviceAuthenticatorBuilder(applicationConfig: applicationConfig).create()
```

- ``ApplicationConfig``
- ``DeviceAuthenticatorBuilder/create()``
- ``DeviceAuthenticatorProtocol``

### Enroll push MFA

```swift
let accessToken = "eySBDC...." // https://developer.okta.com/docs/reference/api/oidc/#access-token
let apnsToken = <ab12ef7b 32b...> // from `application:didRegisterForRemoteNotificationsWithDeviceToken`
let enrollmentParameters = EnrollmentParameters(deviceToken: apnsToken, enableUserVerification: false)
let authenticatorConfig = DeviceAuthenticatorConfig(orgURL: URL(string: "atko.okta.com")!,
                                                    oidcClientId: "client_id")

authenticator.enroll(authenticationToken: AuthToken.bearer(accessToken),
                     authenticatorConfig: authenticatorConfig,
                     enrollmentParameters: enrollmentParameters) { result in
                            switch result {
                                case .success(let enrollment):
                                  print("Enrollment created: \(enrollment)")       
                                case .failure(let error):
                                  print(error.localizedDescription)
                                }                          
                          }
                           
```

- ``EnrollmentParameters``
- ``DeviceAuthenticatorConfig``
- ``DeviceAuthenticatorProtocol/enroll(authenticationToken:authenticatorConfig:enrollmentParameters:completion:)``

### Retrieve push challenges on upon demand

```swift
func retrievePushChallenges() {
    let enrollments = authenticator.allEnrollments()
    enrollments.forEach { enrollment in
        enrollment.retrievePushChallenges(authenticationToken: AuthToken.bearer("accessToken")) { result in
            switch result {
                case .success(let challenges):
                    print("Challenges retrieve: \(challenges)")      
                case .failure(let error):
                    print(error.localizedDescription)
              }
        }
    }
}

// App may choose to execute this operation upon app foreground, for example
func applicationDidBecomeActive(_ application: UIApplication) {
    retrievePushChallenges()
}
```

- ``DeviceAuthenticatorProtocol/allEnrollments()``
- ``AuthenticatorEnrollmentProtocol``

### Parse push challenge

```swift
func userNotificationCenter(_ center: UNUserNotificationCenter,
                            willPresentNotification notification: UNNotification,
                            withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
    if let pushChallenge = try? authenticator.parsePushNotification(notification) {
        // Handle the push challenge
        pushChallenge.resolve(onRemediationStep: { step in
                                 self.handle(step)
                          }) { error in
                                 if let error = error {
                                    print("Error resolving challenge: \(error)")
                               }
                          }
        }
        return
    }
    
    // handle non-okta push notification responses here
    completion([])
}
```

- ``DeviceAuthenticatorProtocol``
- ``ChallengeProtocol/resolve(onRemediation:onCompletion:)``

### Resolve push challenge

```swift
func userNotificationCenter(_ center: UNUserNotificationCenter,
                            willPresentNotification notification: UNNotification,
                            withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
    if let pushChallenge = try? authenticator.parsePushNotification(notification) {
        // Handle the push challenge
        pushChallenge.resolve(onRemediationStep: { step in
                                 self.handle(step)
                          }) { error in
                                 if let error = error {
                                    print("Error resolving challenge: \(error)")
                               }
                          }
        }
        return
    }
    
    // handle non-okta push notification responses here
    completion([])
}

func handle(_ remediationStep: RemediationStep) {
    switch remediationStep {
    case let consentStep as RemediationStepUserConsent:
        // This challenge requires user consent to be processed.
        // Show UX to allow the user to say "yes" or "no" to the sign-in attempt, then provide their response.
        consentStep.provide(.approved)
    case let verificationStep as RemediationStepUserVerification:
        // SDK would like to show the touch/face ID dialog
        // You may override the default text with your own here.
        // NOTE: iOS requires the application or extension to be foregrounded in order to show the user verification dialog
        let params = UserVerificationParameters(localizedFallbackTitle: "Biometric transaction failed. Please use pin to proceed",
                                                localizedCancelTitle: nil,
                                                localizedReason: nil)
        verificationStep.provide(params)
    case let messageStep as RemediationStepMessage:
        // There is a non-fatal error happened during challenge verification flow - for example user verification key is not available
        print(messageStep.message)
    }
}
```

- ``DeviceAuthenticatorProtocol``
- ``ChallengeProtocol/resolve(onRemediation:onCompletion:)``
- ``RemediationStepUserConsent``
- ``RemediationStepUserVerification``
- ``RemediationStepMessage``
 
