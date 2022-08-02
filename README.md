#  Okta Devices SDK 

Enable your app to validate the identity of a user for an Okta authenticator that uses Apple Push Notification service (APNs).

**Table of Contents**
- [Okta Devices SDK](#okta-devices-sdk)
  - [Release status](#release-status)
  - [Need help?](#need-help)
  - [Getting started](#getting-started)
    - [Including Okta Devices SDK](#including-okta-devices-sdk)
  - [Usage](#usage)
    - [Creation](#Creation)
    - [Enrollment](#Enrollment)
      - [Retrieving existing enrollments](#retrieving-existing-enrollments)
      - [Update Push Token](#update-push-token)
      - [Add user verification capabilites into existing enrollment](#add-user-verification-capabilites-into-existing-enrollment)
      - [Delete enrollment](#delete-enrollment)
      - [Delete enrollment from device](#delete-enrollment-from-device)
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

### Including Okta Devices SDK

Okta Devices SDK is available from [CocoaPods](http://cocoapods.org). To add it to your project, add the following lines to your Podfile:

```ruby
target 'MyApplicationTarget' do
  pod 'DeviceAuthenticator'
end
```

## Usage

Okta Devices SDK supports identity verification using a custom authenticator in an Okta org. Your app interacts with that custom authenticator in three ways:
- **Enrollment**: Add a device and optional biometric data to a user's account to enable identity verification using push notifications.
- **Verification**: Verify the identity of a user by prompting them to approve or reject a sign-in attempt.
- **Update**: Update the biometric data in a user's account, refresh the APNs token to keep it active, and remove a device from a user's account.


### Creation
First create a device authenticator to interact with the Devices SDK.

```swift
let appicationConfig = ApplicationConfig(applicationName: "TestApp",
                                         applicationVersion: "1.0.0",
                                         applicationGroupId: "group.com.company.testapp")
#if DEBUG
appicationConfig.apsEnvironment = .development
#endif

let authenticator = try? DeviceAuthenticatorBuilder(applicationConfig: applicationConfig).create()
```

### Enrollment
Enroll push verification method for user's account

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

#### Retrieving existing enrollments
In order to retrieve information about existing enrollments, use `allEnrollments()`.
This can be used to display attributes for a list of accounts or find a specific account in order to update or delete it.

```swift
let enrollments = authenticator.allEnrollments()
```

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

#### Add user verification capabilites into existing enrollment
Users may be prompted with biometric local authentication for the challenged push factor; this will occur if authentication policy requires user verification.

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

#### Delete enrollment from device
Use the `enrollment.deleteFromDevice()` method to delete enrollment from a device without notifying the Okta server.
The difference between calling deleteFromDevice and delete is that deleteFromDevice does not make a server call to unenroll push verification, therefore it does not require any authorization.

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

### Verification
When a user attempts to sign in to the enrolled account (e.g. via an app or a web browser), Okta's backend will create a push challenge and send this challenge to all enrolled devices via APNs using the API token uploaded to your okta console.

Given a valid APNs configuration via the Okta Admin portal, the push challenge will be delivered via `UNUserNotificationCenter` in the same way other push notifications may be delivered to your app.

#### App is foregrounded

```swift
func userNotificationCenter(_ center: UNUserNotificationCenter,
                            willPresentNotification notification: UNNotification,
                            withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
    // Try to parse incoming push notification
    if let pushChallenge = try? authenticator.parsePushNotification(notification) {
        // This is Okta push challenge. Handle the push challenge
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

#### Retrieve challenges on upon demand
Though APNs messages are usually delivered quickly, they may not always be received by the user's device in a timely manner.
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

#### Resolve the challenge
Once you have received a challenge via one of the channels above, your app should `resolve` them in order to proceed with login.
The SDK may request remediation steps in order to complete resolution, such as `RemediationStepUserConsent` (to request the user to approve/deny the challenge)

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
    case let messageStep as RemediationStepMessage:
        // There is a non-fatal error happened during challenge verification flow - for example user verification key is not available
        print(messageStep.message)
    default:
        // Default processing for unexpected remediation step
        remediationStep.defaultProcess()
    }
}
```

See the [Push Sample App] for a complete implementation on resolving a push challenge.

## Known issues


## Contributing
 
We are happy to accept contributions and PRs! Please see the [contribution guide](CONTRIBUTING.md) to understand how to structure a contribution.

[devforum]: https://devforum.okta.com/
[lang-landing]: https://developer.okta.com/code/swift/
[github-releases]: https://github.com/okta/okta-devices-swift/releases
[github-issues]: https://github.com/okta/okta-devices-swift/issues
[Rate Limiting at Okta]: https://developer.okta.com/docs/api/getting_started/rate-limits
[okta-library-versioning]: https://developer.okta.com/code/library-versions
[Push Sample App]: https://github.com/okta/okta-devices-swift/tree/master/Examples/PushSampleApp
