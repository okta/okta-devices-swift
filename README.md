#  Okta Authenticator SDK 

This library allows your app to integrate with Okta service to provide APNS push-based MFA.

**Table of Contents**
- [Okta Authenticator SDK](#okta-authenticator-sdk)
  - [Release status](#release-status)
  - [Need help?](#need-help)
  - [Getting started](#getting-started)
    - [CocoaPods](#cocoapods)
  - [Usage](#usage)
    - [Creation](#creation)
    - [Enrollment](#enrollment)
      - [Retrieving Existing Enrollments](#retrieving-existing-enrollments)
      - [Update Push Token](#update-push-token)
    - [Verification](#verification)
      - [App is foregrounded](#app-is-foregrounded)
      - [Retrieve challenges on upon demand](#retrieve-challenges-on-upon-demand)
      - [Resolve the challenge](#resolve-the-challenge)
  - [Known issues](#known-issues)
  - [Contributing](#contributing)
  
## Release status

This library uses semantic versioning and follows Okta's [Library Version Policy][okta-library-versioning].


| Version | Status                             |
| ------- | ---------------------------------- |
| 0.0.1   | ⚠ Beta                                   |

⚠ Beta version is currently in development and isn't ready for production use

The latest release can always be found on the [releases page][github-releases].

## Need help?
 
If you run into problems using the SDK, you can:
 
* Ask questions on the [Okta Developer Forums][devforum]
* Post [issues][github-issues] here on GitHub (for code errors)

## Getting started

### CocoaPods

This SDK is available through [CocoaPods](http://cocoapods.org). To install it, add the following line to your Podfile:

```ruby
pod 'OktaDeviceSDK'
```

## Usage

A complete integration requires your app to implement the following:

- **Creation**: Create the SDK object to work with your Okta authenticator configuration
- **Enrollment**: Register a device and optional biometrics with an account for use with push MFA.
- **Verification**: Resolve an MFA challenge step for a sign-in attempt against an enrolled account, prompting the user to approve or reject it (with optional biometrics).
- **Update**: Refresh the APNS token, remediate changed biometrics, deregister the account on the device.

### Creation
```swift
let appicationConfig = ApplicationConfig(applicationName: "TestApp",
                                         applicationVersion: "1.0.0",
                                         applicationGroupId: "group.com.company.testapp")
#if DEBUG
appicationConfig.apsEnvironment = .development
#endif

let authenticator: DeviceAuthenticatorProtocol = try? DeviceAuthenticatorBuilder(applicationConfig: applicationConfig).create()
```

See also:<br>
[ApplicationConfig](https://github.com/okta-tardis/okta-devices-swift/blob/IA_readme_update/Sources/OktaDeviceSDK/Common/ApplicationConfig.swift)<br>
[DeviceAuthenticatorBuilder](https://github.com/okta-tardis/okta-devices-swift/blob/IA_readme_update/Sources/DeviceAuthenticatorBuilder.swift)<br>

### Enrollment

Enrollment registers your app + device combination for push MFA against an account.

```swift
let accessToken = "eySBDC...." // https://developer.okta.com/docs/reference/api/oidc/#access-token
let apnsToken = <ab12ef7b 32b...> // from `application:didRegisterForRemoteNotificationsWithDeviceToken`
let enrollmentParameters = EnrollmentParameters(deviceToken: apnsToken, enableUserVerification: false)
let authenticatorConfig = AuthenticatorConfig(orgURL: URL(string: "atko.okta.com")!,
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

See also: 
[EnrollmentParameters](https://github.com/okta-tardis/okta-devices-swift/blob/IA_readme_update/Sources/OktaDeviceSDK/Common/EnrollmentParameters.swift) 
[AuthenticatorConfig](https://github.com/okta-tardis/okta-devices-swift/blob/IA_readme_update/Sources/OktaDeviceSDK/Common/DeviceAuthenticatorConfig.swift) 
[DeviceAuthenticatorProtocol.enroll](https://github.com/okta-tardis/okta-devices-swift/blob/IA_readme_update/Sources/DeviceAuthenticatorProtocol.swift#L34) 

#### Retrieving Existing Enrollments
In order to retrieve information about existing enrollments, use `allEnrollments()`.
This can be used to display attributes for a list of accounts or find a specific account in order to update or delete it.

```swift
let enrollments = authenticator.allEnrollments()
```

See also:<br>
[DeviceAuthenticatorProtocol.allEnrollments](https://github.com/okta-tardis/okta-devices-swift/blob/IA_readme_update/Sources/DeviceAuthenticatorProtocol.swift#L40)<br>

#### Update Push Token
Whenever iOS assigns or updates the push token, your app must pass the new `deviceToken` to the SDK, which will perform the update for all enrollments associated with this device.

```swift
func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
    let accessToken = "eySBDC...." // https://developer.okta.com/docs/reference/api/oidc/#access-token
    let enrollments = authenticator.allEnrollments()
    enrollments.forEach { enrollment in
        enrollment.updateDeviceToken(deviceToken, authenticationToken: AuthToken.bearer(accessToken)) { error in
            if let error = error {
                print("Error updating APNS token: \(error)")
            }
        }
    }
}
```

See also:<br>
[AuthenticatorEnrollmentProtocol.updateDeviceToken](https://github.com/okta-tardis/okta-devices-swift/blob/IA_readme_update/Sources/AuthenticatorEnrollmentProtocol.swift#L41)<br>

#### Add user verification capabilites into existing enrollment
Users may be prompted with biometric local authentication for the challenged factor; this will occur if authentication policy requires user verification.

```swift
let accessToken = "eySBDC...." // https://developer.okta.com/docs/reference/api/oidc/#access-token
let enrollments = authenticator.allEnrollments()
enrollments.forEach { enrollment in
    enrollment.setUserVerification(authenticationToken: AuthToken.bearer(accessToken), enable: true) { error in
        if let error = error {
            print("Error enabling user verification: \(error)")
        }
    }
}
```

See also:<br>
[AuthenticatorEnrollmentProtocol.setUserVerification](https://github.com/okta-tardis/okta-devices-swift/blob/IA_readme_update/Sources/AuthenticatorEnrollmentProtocol.swift#L34)<br>

#### Delete enrollment
Use the `enrollment.delete()` method to unenroll push verification. This will result in the SDK deleting enrollment from a device when a successful response is received from the Okta server.

```swift
let accessToken = "eySBDC...." // https://developer.okta.com/docs/reference/api/oidc/#access-token
let enrollments = authenticator.allEnrollments()
enrollments.forEach { enrollment in
    enrollment.delete(enrollment: enrollment, authenticationToken: AuthToken.bearer(accessToken)) { error in
        if let error = error {
            print("Error deleting enrollment: \(error)")
        }
    }
}
```

See also:<br>
[DeviceAuthenticatorProtocol.delete](https://github.com/okta-tardis/okta-devices-swift/blob/IA_readme_update/Sources/DeviceAuthenticatorProtocol.swift#L47)<br>

#### Delete enrollment from device
Use the `enrollment.deleteFromDevice()` method to delete enrollment from a device without notifying the Okta server.

```swift
let accessToken = "eySBDC...." // https://developer.okta.com/docs/reference/api/oidc/#access-token
let enrollments = authenticator.allEnrollments()
enrollments.forEach { enrollment in
    do {
        try enrollment.deleteFromDevice()
    } catch {
        print("Error deleting enrollment: \(error)")
    }
}
```

See also:<br>
[AuthenticatorEnrollmentProtocol.deleteFromDevice](https://github.com/okta-tardis/okta-devices-swift/blob/IA_readme_update/Sources/AuthenticatorEnrollmentProtocol.swift#L57)<br>

### Verification
When a user attempts to sign in to the enrolled account (e.g. via an app or a web browser), Okta's backend will create a push challenge and send this challenge to all enrolled devices via APNS using the API token uploaded to your okta console.

Given a valid APNS configuration via the Okta Admin portal, the push challenge will be delivered via `UNUserNotificationCenter` in the same way other push notifications may be delivered to your app.
#### App is foregrounded

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

See also:<br>
[DeviceAuthenticatorProtocol.parsePushNotification](https://github.com/okta-tardis/okta-devices-swift/blob/IA_readme_update/Sources/DeviceAuthenticatorProtocol.swift#L56)<br>
[ChallengeProtocol.resolve](https://github.com/okta-tardis/okta-devices-swift/blob/IA_readme_update/Sources/ChallengeProtocol.swift#L27)<br>

#### Retrieve challenges on upon demand
Though APNS messages are usually delivered quickly, they may not always be received by the user's device in a timely manner.
In addition, the user may configure your app's notification permissions in ways that can prevent them from being displayed.

In order to account for these scenarios, the SDK provides a pull-based API to acquire outstanding challenges. This allows the app to poll for challenges when it expects to receive one (e.g.  user attempted to log in with your app).

This API needs to be called for each registered enrollments -- in case of success callback will return array of outstanding challenges for the enrollment.
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

See also:<br>
[AuthenticatorEnrollmentProtocol.retrievePushChallenges](https://github.com/okta-tardis/okta-devices-swift/blob/IA_readme_update/Sources/AuthenticatorEnrollmentProtocol.swift#L51)<br>

#### Resolve the challenge
Once you have received a challenge via one of the channels above, your app should `resolve` them in order to proceed with login.
The SDK may request remediation steps in order to complete resolution, such as `RemediationStepUserConsent` (to request the user to approve/deny the challenge) or `RemediationStepUserVerification` to notify the app that a biometric verification dialog is about to be displayed.

Upon success or failure, the `completion` closure will be called with an optional `Error` object.

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

See also:<br>
[DeviceAuthenticatorProtocol.parsePushNotification](https://github.com/okta-tardis/okta-devices-swift/blob/IA_readme_update/Sources/DeviceAuthenticatorProtocol.swift#L56)<br>
[ChallengeProtocol.resolve](https://github.com/okta-tardis/okta-devices-swift/blob/IA_readme_update/Sources/ChallengeProtocol.swift#L27)<br>
[RemediationStepUserConsent](https://github.com/okta-tardis/okta-devices-swift/blob/IA_readme_update/Sources/OktaDeviceSDK/Common/Remediation/RemediationStepUserConsent.swift)<br>
[RemediationStepUserVerification](https://github.com/okta-tardis/okta-devices-swift/blob/IA_readme_update/Sources/OktaDeviceSDK/Common/Remediation/RemediationStepUserVerification.swift)<br>
[RemediationStepMessage](https://github.com/okta-tardis/okta-devices-swift/blob/IA_readme_update/Sources/OktaDeviceSDK/Common/Remediation/RemediationStepMessage.swift)<br>

## Known issues

## Contributing
 
We are happy to accept contributions and PRs! Please see the [contribution guide](CONTRIBUTING.md) to understand how to structure a contribution.

[devforum]: https://devforum.okta.com/
[lang-landing]: https://developer.okta.com/code/swift/
[github-releases]: https://github.com/okta-tardis/okta-devices-swift/releases
[Rate Limiting at Okta]: https://developer.okta.com/docs/api/getting_started/rate-limits
[okta-library-versioning]: https://developer.okta.com/code/library-versions
