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

import XCTest

class OktaJWTTestData {

    class func validDeviceChallengeRequestJWT() -> String {
        /*
         {
           "alg": "HS256",
           "typ": "okta-devicebind+jwt"
         }
         {
           "iss": "https://your-org.okta.com",
           "aud": "https://your-org.okta.com",
           "iat": 1467145094,
           "exp": 1467148694,
           "signals": [
             "screenLock",
             "rootPrivileges",
             "fullDiskEncryption",
             "id",
             "os",
             "osVersion",
             "manufacturer",
             "model",
             "deviceAttestation",
             "appId",
             "appManaged"
           ],
           "nonce": "FWkfwFWkfw3jfd3jfd",
           "transactionId": "123456789",
           "orgId": "00o1of110tVBGWFKAWGI",
           "keyTypes": ["proofOfPossession"],
           "method": "signed_nonce",
           "verificationUri": "https://your-org.okta.com/idp/idx/authenticators/authenticatorId/transactions/transactionId/verify",
           "integrations": [
              {
                 "name": "name_1"
              }
           ]
         }
         */
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJrZXlUeXBlcyI6WyJwcm9vZk9mUG9zc2Vzc2lvbiJdLCJtZXRob2QiOiJzaWduZWRfbm9uY2UiLCJ2ZXJpZmljYXRpb25VcmkiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tL2lkcC9pZHgvYXV0aGVudGljYXRvcnMvYXV0aGVudGljYXRvcklkL3RyYW5zYWN0aW9ucy90cmFuc2FjdGlvbklkL3ZlcmlmeSIsImludGVncmF0aW9ucyI6W3sibmFtZSI6Im5hbWVfMSJ9XX0.3csxmkcoUtwQVaL6mx4LCcjP0Cb7DJnRnWrL5Y9qGtY"
    }

    class func validDeviceChallengeRequestJWTWithUserVerificationKey() -> String {
        /*
         {
           "alg": "HS256",
           "typ": "okta-devicebind+jwt"
         }
         {
           "iss": "https://your-org.okta.com",
           "aud": "https://your-org.okta.com",
           "iat": 1467145094,
           "exp": 1467148694,
           "signals": [
             "screenLock",
             "rootPrivileges",
             "fullDiskEncryption",
             "id",
             "os",
             "osVersion",
             "manufacturer",
             "model",
             "deviceAttestation",
             "appId",
             "appManaged"
           ],
           "nonce": "FWkfwFWkfw3jfd3jfd",
           "transactionId": "123456789",
           "orgId": "00o1of110tVBGWFKAWGI",
           "keyType": "userVerification",
           "method": "signed_nonce",
           "verificationUri": "https://your-org.okta.com/idp/idx/authenticators/authenticatorId/transactions/transactionId/verify"
         }
         */
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJrZXlUeXBlcyI6WyJ1c2VyVmVyaWZpY2F0aW9uIl0sIm1ldGhvZCI6InNpZ25lZF9ub25jZSIsInZlcmlmaWNhdGlvblVyaSI6Imh0dHBzOi8veW91ci1vcmcub2t0YS5jb20vaWRwL2lkeC9hdXRoZW50aWNhdG9ycy9hdXRoZW50aWNhdG9ySWQvdHJhbnNhY3Rpb25zL3RyYW5zYWN0aW9uSWQvdmVyaWZ5In0.ouEW2lmMfGr8ooblri7dFFtY-LUCSwZn4rkavbTv5rU"
    }

    class func validDeviceChallengeRequestJWTWithTwoKeys() -> String {
        /*
         {
           "alg": "HS256",
           "typ": "okta-devicebind+jwt"
         }
         {
           "iss": "https://your-org.okta.com",
           "aud": "https://your-org.okta.com",
           "iat": 1467145094,
           "exp": 1467148694,
           "signals": [
             "screenLock",
             "rootPrivileges",
             "fullDiskEncryption",
             "id",
             "os",
             "osVersion",
             "manufacturer",
             "model",
             "deviceAttestation",
             "appId",
             "appManaged"
           ],
           "nonce": "FWkfwFWkfw3jfd3jfd",
           "transactionId": "123456789",
           "orgId": "00o1of110tVBGWFKAWGI",
           "keyTypes": ["userVerification","proofOfPossession"],
           "method": "signed_nonce",
           "appInstanceName": "Salesforce.com"
           "verificationUri": "https://your-org.okta.com/idp/idx/authenticators/authenticatorId/transactions/transactionId/verify"
         }
         */
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJrZXlUeXBlIjoidXNlclZlcmlmaWNhdGlvbiIsImtleVR5cGVzIjpbInVzZXJWZXJpZmljYXRpb24iLCJwcm9vZk9mUG9zc2Vzc2lvbiJdLCJtZXRob2QiOiJzaWduZWRfbm9uY2UiLCJ2ZXJpZmljYXRpb25VcmkiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tL2lkcC9pZHgvYXV0aGVudGljYXRvcnMvYXV0aGVudGljYXRvcklkL3RyYW5zYWN0aW9ucy90cmFuc2FjdGlvbklkL3ZlcmlmeSJ9.N13Pw0dQmBqjoOgYrEuehLNaU39ySrenQ-kDDsaeVeI"
    }

    class func validDeviceChallengeRequestJWTWithUnknownKey() -> String {
        /*
         {
           "alg": "HS256",
           "typ": "okta-devicebind+jwt"
         }
         {
           "iss": "https://your-org.okta.com",
           "aud": "https://your-org.okta.com",
           "iat": 1467145094,
           "exp": 1467148694,
           "signals": [
             "screenLock",
             "rootPrivileges",
             "fullDiskEncryption",
             "id",
             "os",
             "osVersion",
             "manufacturer",
             "model",
             "deviceAttestation",
             "appId",
             "appManaged"
           ],
           "nonce": "FWkfwFWkfw3jfd3jfd",
           "transactionId": "123456789",
           "orgId": "00o1of110tVBGWFKAWGI",
           "keyTypes": ["unknown"],
           "method": "signed_nonce",
           "verificationUri": "https://your-org.okta.com/idp/idx/authenticators/authenticatorId/transactions/transactionId/verify"
         }
         */
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJrZXlUeXBlcyI6WyJ1bmtub3duIl0sIm1ldGhvZCI6InNpZ25lZF9ub25jZSIsInZlcmlmaWNhdGlvblVyaSI6Imh0dHBzOi8veW91ci1vcmcub2t0YS5jb20vaWRwL2lkeC9hdXRoZW50aWNhdG9ycy9hdXRoZW50aWNhdG9ySWQvdHJhbnNhY3Rpb25zL3RyYW5zYWN0aW9uSWQvdmVyaWZ5In0.mqC-kCnOjvJ5tbawWFRENUh4CuDVb_XTXvcKGW0KxCQ"
    }

    class func validDeviceChallengeRequestJWTWithUnknownFactor() -> String {
        /*
         {
           "alg": "HS256",
           "typ": "okta-devicebind+jwt"
         }
         {
           "iss": "https://your-org.okta.com",
           "aud": "https://your-org.okta.com",
           "iat": 1467145094,
           "exp": 1467148694,
           "signals": [
             "screenLock",
             "rootPrivileges",
             "fullDiskEncryption",
             "id",
             "os",
             "osVersion",
             "manufacturer",
             "model",
             "deviceAttestation",
             "appId",
             "appManaged"
           ],
           "nonce": "FWkfwFWkfw3jfd3jfd",
           "transactionId": "123456789",
           "orgId": "00o1of110tVBGWFKAWGI",
           "keyTypes": ["userVerification"],
           "method": "unknown",
           "verificationUri": "https://your-org.okta.com/idp/idx/authenticators/authenticatorId/transactions/transactionId/verify"
         }
         */
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJrZXlUeXBlcyI6WyJ1c2VyVmVyaWZpY2F0aW9uIl0sIm1ldGhvZCI6InVua25vd24iLCJ2ZXJpZmljYXRpb25VcmkiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tL2lkcC9pZHgvYXV0aGVudGljYXRvcnMvYXV0aGVudGljYXRvcklkL3RyYW5zYWN0aW9ucy90cmFuc2FjdGlvbklkL3ZlcmlmeSJ9.X4L_eC3xbtsmNZ0yLKywsc37yv0P_rqwnWRvTbscX6o"
    }

    class func validDeviceChallengeRequestJWTWithUserMediationRequired() -> String {
        /*
         {
           "alg": "HS256",
           "typ": "okta-devicebind+jwt"
         }
         {
           "iss": "https://your-org.okta.com",
           "aud": "https://your-org.okta.com",
           "iat": 1467145094,
           "exp": 1467148694,
           "signals": [
             "screenLock",
             "rootPrivileges",
             "fullDiskEncryption",
             "id",
             "os",
             "osVersion",
             "manufacturer",
             "model",
             "deviceAttestation",
             "appId",
             "appManaged"
           ],
           "nonce": "FWkfwFWkfw3jfd3jfd",
           "transactionId": "123456789",
           "orgId": "00o1of110tVBGWFKAWGI",
           "userMediation": "REQUIRED"
           "method": "signed_nonce",
           "verificationUri": "https://your-org.okta.com/idp/idx/authenticators/authenticatorId/transactions/transactionId/verify",
           "integrations": [
              {
                 "name": "name_1"
              }
           ]
         }
         */
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJ1c2VyTWVkaWF0aW9uIjoiUkVRVUlSRUQiLCJtZXRob2QiOiJzaWduZWRfbm9uY2UiLCJ2ZXJpZmljYXRpb25VcmkiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tL2lkcC9pZHgvYXV0aGVudGljYXRvcnMvYXV0aGVudGljYXRvcklkL3RyYW5zYWN0aW9ucy90cmFuc2FjdGlvbklkL3ZlcmlmeSIsImludGVncmF0aW9ucyI6W3sibmFtZSI6Im5hbWVfMSJ9XX0.K66gTp_oUTwhl_AvttFUKAK04yx256G43jdJk3DOxBM"
    }

    class func validDeviceChallengeRequestJWTWithUserVerificationPreferred() -> String {
        /*
         {
           "alg": "HS256",
           "typ": "okta-devicebind+jwt"
         }
         {
           "iss": "https://your-org.okta.com",
           "aud": "https://your-org.okta.com",
           "iat": 1467145094,
           "exp": 1467148694,
           "signals": [
             "screenLock",
             "rootPrivileges",
             "fullDiskEncryption",
             "id",
             "os",
             "osVersion",
             "manufacturer",
             "model",
             "deviceAttestation",
             "appId",
             "appManaged"
           ],
           "nonce": "FWkfwFWkfw3jfd3jfd",
           "transactionId": "123456789",
           "orgId": "00o1of110tVBGWFKAWGI",
           "keyTypes": ["userVerification","proofOfPossession"],
           "userVerification": "PREFERRED",
           "method": "signed_nonce",
           "appInstanceName": "Salesforce.com"
           "verificationUri": "https://your-org.okta.com/idp/idx/authenticators/authenticatorId/transactions/transactionId/verify"
         }
         */
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJrZXlUeXBlIjoidXNlclZlcmlmaWNhdGlvbiIsImtleVR5cGVzIjpbInVzZXJWZXJpZmljYXRpb24iLCJwcm9vZk9mUG9zc2Vzc2lvbiJdLCJ1c2VyVmVyaWZpY2F0aW9uIjoiUFJFRkVSUkVEIiwibWV0aG9kIjoic2lnbmVkX25vbmNlIiwidmVyaWZpY2F0aW9uVXJpIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbS9pZHAvaWR4L2F1dGhlbnRpY2F0b3JzL2F1dGhlbnRpY2F0b3JJZC90cmFuc2FjdGlvbnMvdHJhbnNhY3Rpb25JZC92ZXJpZnkifQ.YE0srw-jAR89GqAFIpuqIitLHJ-gT58hQ-05rUOsEDI"
    }

    class func validDeviceChallengeRequestJWTWithUserVerificationRequired() -> String {
    /*
     {
       "alg": "HS256",
       "typ": "okta-devicebind+jwt"
     }
     {
       "iss": "https://your-org.okta.com",
       "aud": "https://your-org.okta.com",
       "iat": 1467145094,
       "exp": 1467148694,
       "signals": [
         "screenLock",
         "rootPrivileges",
         "fullDiskEncryption",
         "id",
         "os",
         "osVersion",
         "manufacturer",
         "model",
         "deviceAttestation",
         "appId",
         "appManaged"
       ],
       "nonce": "FWkfwFWkfw3jfd3jfd",
       "transactionId": "123456789",
       "orgId": "00o1of110tVBGWFKAWGI",
       "userVerification": "REQUIRED",
       "method": "signed_nonce",
       "verificationUri": "https://your-org.okta.com/idp/idx/authenticators/authenticatorId/transactions/transactionId/verify"
     }
     */
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJ1c2VyVmVyaWZpY2F0aW9uIjoiUkVRVUlSRUQiLCJtZXRob2QiOiJzaWduZWRfbm9uY2UiLCJ2ZXJpZmljYXRpb25VcmkiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tL2lkcC9pZHgvYXV0aGVudGljYXRvcnMvYXV0aGVudGljYXRvcklkL3RyYW5zYWN0aW9ucy90cmFuc2FjdGlvbklkL3ZlcmlmeSJ9.4ujSmx4vVCl3SXd-l3106rNdoBwn_DfDzTxQ_pCXroE"
}

class func validDeviceChallengeRequestJWTWithUserMediationOptional() -> String {
        /*
         {
           "alg": "HS256",
           "typ": "okta-devicebind+jwt"
         }
         {
           "iss": "https://your-org.okta.com",
           "aud": "https://your-org.okta.com",
           "iat": 1467145094,
           "exp": 1467148694,
           "signals": [
             "screenLock",
             "rootPrivileges",
             "fullDiskEncryption",
             "id",
             "os",
             "osVersion",
             "manufacturer",
             "model",
             "deviceAttestation",
             "appId",
             "appManaged"
           ],
           "nonce": "FWkfwFWkfw3jfd3jfd",
           "transactionId": "123456789",
           "orgId": "00o1of110tVBGWFKAWGI",
           "userMediation": "OPTIONAL"
           "method": "signed_nonce",
           "verificationUri": "https://your-org.okta.com/idp/idx/authenticators/authenticatorId/transactions/transactionId/verify",
           "integrations": [
              {
                 "name": "name_1"
              }
           ]
         }
         */
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJ1c2VyTWVkaWF0aW9uIjoiT1BUSU9OQUwiLCJtZXRob2QiOiJzaWduZWRfbm9uY2UiLCJ2ZXJpZmljYXRpb25VcmkiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tL2lkcC9pZHgvYXV0aGVudGljYXRvcnMvYXV0aGVudGljYXRvcklkL3RyYW5zYWN0aW9ucy90cmFuc2FjdGlvbklkL3ZlcmlmeSIsImludGVncmF0aW9ucyI6W3sibmFtZSI6Im5hbWVfMSJ9XX0.ryzsvAH1hD_qOjMgMdfwjPs186tG9fY7ctbQ28pqWog"
    }

    class func validDeviceChallengeRequestJWTWithUVDiscouraged() -> String {
            /*
             {
               "alg": "HS256",
               "typ": "okta-devicebind+jwt"
             }
             {
               "iss": "https://your-org.okta.com",
               "aud": "https://your-org.okta.com",
               "iat": 1467145094,
               "exp": 1467148694,
               "signals": [
                 "screenLock",
                 "rootPrivileges",
                 "fullDiskEncryption",
                 "id",
                 "os",
                 "osVersion",
                 "manufacturer",
                 "model",
                 "deviceAttestation",
                 "appId",
                 "appManaged"
               ],
               "nonce": "FWkfwFWkfw3jfd3jfd",
               "transactionId": "123456789",
               "orgId": "00o1of110tVBGWFKAWGI",
               "userMediation": "NONE",
               "userVerification": "DISCOURAGED",
               "method": "signed_nonce",
               "verificationUri": "https://your-org.okta.com/idp/idx/authenticators/authenticatorId/transactions/transactionId/verify",
               "integrations": [
                  {
                     "name": "name_1"
                  }
               ]
             }
             */
            return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJ1c2VyTWVkaWF0aW9uIjoiTk9ORSIsInVzZXJWZXJpZmljYXRpb24iOiJESVNDT1VSQUdFRCIsIm1ldGhvZCI6InNpZ25lZF9ub25jZSIsInZlcmlmaWNhdGlvblVyaSI6Imh0dHBzOi8veW91ci1vcmcub2t0YS5jb20vaWRwL2lkeC9hdXRoZW50aWNhdG9ycy9hdXRoZW50aWNhdG9ySWQvdHJhbnNhY3Rpb25zL3RyYW5zYWN0aW9uSWQvdmVyaWZ5IiwiaW50ZWdyYXRpb25zIjpbeyJuYW1lIjoibmFtZV8xIn1dfQ.xb-TmvNdfSkAwt1XZFiTIl-Ex-0GUeQhHFnPELP5zUM"
        }

    class func validDeviceChallengeRequestJWTWithUVRequiredAndUserMediationRequired() -> String {
        /*
         {
           "alg": "HS256",
           "typ": "okta-devicebind+jwt"
         }
         {
           "iss": "https://your-org.okta.com",
           "aud": "https://your-org.okta.com",
           "iat": 1467145094,
           "exp": 1467148694,
           "signals": [
             "screenLock",
             "rootPrivileges",
             "fullDiskEncryption",
             "id",
             "os",
             "osVersion",
             "manufacturer",
             "model",
             "deviceAttestation",
             "appId",
             "appManaged"
           ],
           "nonce": "FWkfwFWkfw3jfd3jfd",
           "transactionId": "123456789",
           "orgId": "00o1of110tVBGWFKAWGI",
           "userMediation": "REQUIRED",
           "userVerification": "REQUIRED",
           "method": "signed_nonce",
           "verificationUri": "https://your-org.okta.com/idp/idx/authenticators/authenticatorId/transactions/transactionId/verify",
           "integrations": [
              {
                 "name": "name_1"
              }
           ]
         }
         */
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJ1c2VyTWVkaWF0aW9uIjoiUkVRVUlSRUQiLCJ1c2VyVmVyaWZpY2F0aW9uIjoiUkVRVUlSRUQiLCJtZXRob2QiOiJzaWduZWRfbm9uY2UiLCJ2ZXJpZmljYXRpb25VcmkiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tL2lkcC9pZHgvYXV0aGVudGljYXRvcnMvYXV0aGVudGljYXRvcklkL3RyYW5zYWN0aW9ucy90cmFuc2FjdGlvbklkL3ZlcmlmeSIsImludGVncmF0aW9ucyI6W3sibmFtZSI6Im5hbWVfMSJ9XX0.FsZRwZqN6DA58u0SLIMha_xG-gcoNB6wOn_5_JvXr6I"
    }

    class func validDeviceChallengeRequestJWTWithUVPreferredAndUserMediationOptional() -> String {
        /*
         {
           "alg": "HS256",
           "typ": "okta-devicebind+jwt"
         }
         {
           "iss": "https://your-org.okta.com",
           "aud": "https://your-org.okta.com",
           "iat": 1467145094,
           "exp": 1467148694,
           "signals": [
             "screenLock",
             "rootPrivileges",
             "fullDiskEncryption",
             "id",
             "os",
             "osVersion",
             "manufacturer",
             "model",
             "deviceAttestation",
             "appId",
             "appManaged"
           ],
           "nonce": "FWkfwFWkfw3jfd3jfd",
           "transactionId": "123456789",
           "orgId": "00o1of110tVBGWFKAWGI",
           "userMediation": "OPTIONAL",
           "userVerification": "PREFERRED",
           "method": "signed_nonce",
           "verificationUri": "https://your-org.okta.com/idp/idx/authenticators/authenticatorId/transactions/transactionId/verify",
           "integrations": [
              {
                 "name": "name_1"
              }
           ]
         }
         */
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJ1c2VyTWVkaWF0aW9uIjoiT1BUSU9OQUwiLCJ1c2VyVmVyaWZpY2F0aW9uIjoiUFJFRkVSUkVEIiwibWV0aG9kIjoic2lnbmVkX25vbmNlIiwidmVyaWZpY2F0aW9uVXJpIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbS9pZHAvaWR4L2F1dGhlbnRpY2F0b3JzL2F1dGhlbnRpY2F0b3JJZC90cmFuc2FjdGlvbnMvdHJhbnNhY3Rpb25JZC92ZXJpZnkiLCJpbnRlZ3JhdGlvbnMiOlt7Im5hbWUiOiJuYW1lXzEifV19.rpunffAJ-BVyKYxW-02pWztLPBt6fuLfVSCpSbGy7HQ"
    }

    class func validDeviceChallengeRequestJWTForMacOS() -> String {
        return "eyJraWQiOiJOR2hMekM5d25obDdrR255bHBCdjJZd3hEdHBHOHhoTGktQ3hYWFZvRy1jIiwidHlwIjoib2t0YS1kZXZpY2ViaW5kK2p3dCIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJodHRwczovL3FhLWR0LWF1dGgxLmhpb2t0YW5lLmNvbSIsImF1ZCI6Im9rdGEuNjNjMDgxZGItMWYxMy01MDg0LTg4MmYtZTc5ZTFlNWUyZGE3IiwiZXhwIjoxNTkyOTUzMzIwLCJpYXQiOjE1OTI5NTMwMjAsImp0aSI6ImZ0dDIzT25xZ0pxVGZnbEN6YXpfUmZoQnRaYVhFaWhEMUciLCJub25jZSI6Il91ajNORi1BMnZQcnFLNUl0UlhkeHdlOVFCb0h5Q0g2IiwidHJhbnNhY3Rpb25JZCI6ImZ0dDIzT25xZ0pxVGZnbEN6YXpfUmZoQnRaYVhFaWhEMUciLCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwicGxhdGZvcm0iLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIl0sInVzZXJWZXJpZmljYXRpb25SZXF1aXJlbWVudCI6ZmFsc2UsInZlcmlmaWNhdGlvblVyaSI6Imh0dHBzOi8vcWEtZHQtYXV0aDEuaGlva3RhbmUuY29tL2F1dGhlbnRpY2F0b3JzL3Nzb19leHRlbnNpb24vdHJhbnNhY3Rpb25zL2Z0dDIzT25xZ0pxVGZnbEN6YXpfUmZoQnRaYVhFaWhEMUcvdmVyaWZ5IiwiY2FTdWJqZWN0TmFtZXMiOlsiQ049bW9iaWxlLU4wNjctSDIwMy1DQSwgREM9bW9iaWxlLCBEQz1sb2NhbCJdLCJtZG1BdHRlc3RhdGlvbklzc3VlcnMiOlt7Imlzc3VlckROIjoiTUUweEZUQVRCZ29Ka2lhSmsvSXNaQUVaRmdWc2IyTmhiREVXTUJRR0NnbVNKb21UOGl4a0FSa1dCbTF2WW1sc1pURWNNQm9HQTFVRUF4TVRiVzlpYVd4bExVNHdOamN0U0RJd015MURRUT09IiwiYWtpIjoiaHVKSlhIL1dvUmpTeEMzOG1OMm9Cdkp0MnpjPSJ9XSwia2V5VHlwZSI6InByb29mT2ZQb3NzZXNzaW9uIiwiZmFjdG9yVHlwZSI6ImNyeXB0byIsIm9yZ0lkIjoiMDBvdGl5eURGdE5DeUZibkMwZzQiLCJ2ZXIiOjB9.G00gAKeAVo9N5C_rFCzGK39USPW-EEX9xp6t7iXnT8GhpeJ95LVADLXNVgFLboPWeTuhp7_KRCUR5zvligM68-kfFN6fXW_gVtWJ6tb-qx7qLci4SDWB-3zkVe8ykZ_RNmSxzEMP2Unew-xsfkajDNheP6kE-zFW2ZbiRiRsnVAIYQ2YhdZ7WFKb6ex7W8OtoaGCtGyse8g6II5KjMki_IhmTJn1glcC9P7B5CpHLIoQDYF-TQGISMpml1bhgBwpDHfLes4arOY2IN7ItmuB8Eps3rAJELhnxL1KGtmeHmklRf5Nj5qIiKf1XzeHofPHVOSrfYLkeBEmUS2krK8Ckg"
    }
    class func validSignedDeviceChallengeRequestJWT() -> String {
        /*
         {
           "alg": "RS256",
           "typ": "okta-devicebind+jwt"
         }
         {
           "iss": "https://your-org.okta.com",
           "aud": "https://your-org.okta.com",
           "iat": 1467145094,
           "exp": 1467148694,
           "signals": ["screenLock",
                         "rootPrivileges",
                         "fullDiskEncryption",
                         "id",
                         "os",
                         "osVersion",
                         "manufacturer",
                         "model",
                         "deviceAttestation",
                         "appId",
                         "appManaged"
                     ],
             "nonce": "FWkfwFWkfw3jfd3jfd",
             "transactionId": "123456789",
             "orgId": "00o1of110tVBGWFKAWGI",
             "keyType": "proofOfPossession",
             "method": "signed_nonce",
             "verificationUri": "https://your-org.okta.com/idp/authenticators/authenticatorId/transactions/transactionId/verify"
         }
         // signed with kid: "01c094c3-459d-4c9d-9e0f-3d943004a887" below
         */

        return "eyJraWQiOiJiZWU5ZjMyYi02M2M1LTRlZTItYmJlMC01YzE3ZDdiMGQ1MDciLCJ0eXAiOiJva3RhLWRldmljZWJpbmQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJhdWQiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiaXNzIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsIm1ldGhvZCI6InNpZ25lZF9ub25jZSIsImV4cCI6MSwia2V5VHlwZSI6InByb29mT2ZQb3NzZXNzaW9uIiwiaWF0IjoxNTgwNTEzODI5NzM4LCJub25jZSI6IkZXa2Z3RldrZnczamZkM2pmZCIsInRyYW5zYWN0aW9uSWQiOiIxMjM0NTY3ODkiLCJvcmdJZCI6IjAwbzFvZjExMHRWQkdXRktBV0dJIiwidmVyaWZpY2F0aW9uVXJpIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbS9pZHAvYXV0aGVudGljYXRvcnMvYXV0aGVudGljYXRvcklkL3RyYW5zYWN0aW9ucy90cmFuc2FjdGlvbklkL3ZlcmlmeSJ9.muTpbKldS5UcdAZPz9pUJuGviiOYL8NkznbmS5Z199jYFsDWtXx2XrWPFsr-W19qNJvwvpCucf3LY1ezoL1YKtmsMtKg1EI4uok_0brOX3Asw_ibEVXryLwVA0sOtZfpwV9yAmLcDMBFOjD3C7JhS10P_65YjW7l-Xzak2Yc1qCr6gMmm4o11hsdlf7REujqBEYhEpZjizYHnQf1ic4u_CiDP_QrPFHIRHlgDZSV6DCfgitl7LG3CE9XRbIOb3dOcd4cQRxnw9KxaLDa3E1cq6LRYp7PM8TAWhCRhvQETi_iXDr1sD9pVnSy_t0MZNwlYYqB8bwsyZ8LU3Cz5kLtNw"
    }

    class func mockDeviceChallengeSignedNonceWithAppInstance() -> String {
        /*
         {
           "alg": "RS256",
           "typ": "okta-devicebind+jwt"
         }
         {
           "iss": "https://your-org.okta.com",
           "aud": "https://your-org.okta.com",
           "iat": 1467145094,
           "exp": 1467148694,
           "signals": ["screenLock",
                         "rootPrivileges",
                         "fullDiskEncryption",
                         "id",
                         "os",
                         "osVersion",
                         "manufacturer",
                         "model",
                         "deviceAttestation",
                         "appId",
                         "appManaged"
                     ],
             "nonce": "FWkfwFWkfw3jfd3jfd",
             "transactionId": "123456789",
             "orgId": "00o1of110tVBGWFKAWGI",
             "keyType": "proofOfPossession",
             "method": "signed_nonce",
             "verificationUri": "https://your-org.okta.com/idp/authenticators/authenticatorId/transactions/transactionId/verify"
         }
         // invalid signature
         */

        return "eyJraWQiOiJiZWU5ZjMyYi02M2M1LTRlZTItYmJlMC01YzE3ZDdiMGQ1MDciLCJ0eXAiOiJva3RhLWRldmljZWJpbmQrand0IiwiYWxnIjoiUlMyNTYifQ.ewogICJhdWQiOiAiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsCiAgImlzcyI6ICJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwKICAibWV0aG9kIjogInNpZ25lZF9ub25jZSIsCiAgImV4cCI6IDEsCiAgImtleVR5cGUiOiAicHJvb2ZPZlBvc3Nlc3Npb24iLAogICJpYXQiOiAxNTgwNTEzODI5NzM4LAogICJub25jZSI6ICJGV2tmd0ZXa2Z3M2pmZDNqZmQiLAogICJ0cmFuc2FjdGlvbklkIjogIjEyMzQ1Njc4OSIsCiAgIm9yZ0lkIjogIjAwbzFvZjExMHRWQkdXRktBV0dJIiwKICAidmVyaWZpY2F0aW9uVXJpIjogImh0dHBzOi8veW91ci1vcmcub2t0YS5jb20vaWRwL2F1dGhlbnRpY2F0b3JzL2F1dGhlbnRpY2F0b3JJZC90cmFuc2FjdGlvbnMvdHJhbnNhY3Rpb25JZC92ZXJpZnkiLAogICJhcHBJbnN0YW5jZU5hbWUiOiAiU2FsZXNmb3JjZS5jb20iCn0.muTpbKldS5UcdAZPz9pUJuGviiOYL8NkznbmS5Z199jYFsDWtXx2XrWPFsr-W19qNJvwvpCucf3LY1ezoL1YKtmsMtKg1EI4uok_0brOX3Asw_ibEVXryLwVA0sOtZfpwV9yAmLcDMBFOjD3C7JhS10P_65YjW7l-Xzak2Yc1qCr6gMmm4o11hsdlf7REujqBEYhEpZjizYHnQf1ic4u_CiDP_QrPFHIRHlgDZSV6DCfgitl7LG3CE9XRbIOb3dOcd4cQRxnw9KxaLDa3E1cq6LRYp7PM8TAWhCRhvQETi_iXDr1sD9pVnSy_t0MZNwlYYqB8bwsyZ8LU3Cz5kLtNw"
    }

    static var validJWKCustomizeTypeHeader = [
        "alg": "RS256",
        "e": "AQAB",
        "n": "nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa-GSYOD2QU68Mb59oSk2OB-BtOLpJofmbGEGgvmwyCI9Mw",
        "kid": "bee9f32b-63c5-4ee2-bbe0-5c17d7b0d507",
        "kty": "RSA",
        "use": "sig"
    ]

    static var invalidJWKCustomizeTypeHeader = [
        "alg": "RS256",
        "e": "AQAB",
        "n": "nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa-GSYOD2QU68Mb59oSk2OB-BtOLpJofmbGEGgvmwyCI9Mw",
        "kid": "None",
        "kty": "RSA",
        "use": "sig"
    ]

    class func invalidJWTStructure() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJrZXlUeXBlIjoicHJvb2ZPZlBvc3Nlc3Npb24iLCJmYWN0b3JUeXBlIjoiY3J5cHRvIiwidmVyaWZpY2F0aW9uVXJpIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbS9pZHAvYXV0aGVudGljYXRvcnMvYXV0aGVudGljYXRvcklkL3RyYW5zYWN0aW9ucy90cmFuc2FjdGlvbklkL3ZlcmlmeSJ9"
    }

    class func invalidJWTHeader() -> String {
        return "e.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJrZXlUeXBlIjoicHJvb2ZPZlBvc3Nlc3Npb24iLCJmYWN0b3JUeXBlIjoiY3J5cHRvIiwidmVyaWZpY2F0aW9uVXJpIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbS9pZHAvYXV0aGVudGljYXRvcnMvYXV0aGVudGljYXRvcklkL3RyYW5zYWN0aW9ucy90cmFuc2FjdGlvbklkL3ZlcmlmeSJ9.Cc5Fl_t6KSKvGyqVjumXYuqPtqvram05icvBfQTgcxg"
    }

    class func invalidJWTPayload() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.e.Cc5Fl_t6KSKvGyqVjumXYuqPtqvram05icvBfQTgcxg"
    }

    class func invalidJWTHeaderJSON() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3Qi.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJrZXlUeXBlIjoicHJvb2ZPZlBvc3Nlc3Npb24iLCJmYWN0b3JUeXBlIjoiY3J5cHRvIiwidmVyaWZpY2F0aW9uVXJpIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbS9pZHAvYXV0aGVudGljYXRvcnMvYXV0aGVudGljYXRvcklkL3RyYW5zYWN0aW9ucy90cmFuc2FjdGlvbklkL3ZlcmlmeSJ9.Cc5Fl_t6KSKvGyqVjumXYuqPtqvram05icvBfQTgcxg"
    }

    class func invalidJWTPayloadJSON() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJrZXlUeXBlIjoicHJvb2ZPZlBvc3Nlc3Npb24iLCJmYWN0b3JUeXBlIjoiY3J5cHRvIiwidmVyaWZpY2F0aW9uVXJpIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbS9pZHAvYXV0aGVudGljYXRvcnMvYXV0aGVudGljYXRvcklkL3RyYW5zYWN0aW9ucy90cmFuc2FjdGlvbklkL3ZlcmlmeS.Cc5Fl_t6KSKvGyqVjumXYuqPtqvram05icvBfQTgcxg"
    }

    class func unexpectedJWTType() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJrZXlUeXBlIjoicHJvb2ZPZlBvc3Nlc3Npb24iLCJmYWN0b3JUeXBlIjoiY3J5cHRvIiwidmVyaWZpY2F0aW9uVXJpIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbS9pZHAvYXV0aGVudGljYXRvcnMvYXV0aGVudGljYXRvcklkL3RyYW5zYWN0aW9ucy90cmFuc2FjdGlvbklkL3ZlcmlmeSJ9.siwWsRDrGQLt_5JVB67guXZiZAUbDTQFZA92i8jnmtM"
    }

    class func payloadWithoutOrgId() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsImtleVR5cGUiOiJwcm9vZk9mUG9zc2Vzc2lvbiIsImZhY3RvclR5cGUiOiJjcnlwdG8iLCJ2ZXJpZmljYXRpb25VcmkiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tL2lkcC9pZHgvYXV0aGVudGljYXRvcnMvYXV0aGVudGljYXRvcklkL3RyYW5zYWN0aW9ucy90cmFuc2FjdGlvbklkL3ZlcmlmeSJ9.OJ54ZGhiP8TPN-h7ziX7X7WtUoF6IqtImqMbaE29pZ8"
    }

    class func payloadWithoutNonce() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sInRyYW5zYWN0aW9uSWQiOiIxMjM0NTY3ODkiLCJvcmdJZCI6IjAwbzFvZjExMHRWQkdXRktBV0dJIiwia2V5VHlwZSI6InByb29mT2ZQb3NzZXNzaW9uIiwiZmFjdG9yVHlwZSI6ImNyeXB0byIsInZlcmlmaWNhdGlvblVyaSI6Imh0dHBzOi8veW91ci1vcmcub2t0YS5jb20vaWRwL2F1dGhlbnRpY2F0b3JzL2F1dGhlbnRpY2F0b3JJZC90cmFuc2FjdGlvbnMvdHJhbnNhY3Rpb25JZC92ZXJpZnkifQ.7mW2xliGBB_SiKn4BqA2TNdwSMf5_giyY3ymrYX1XZE"
    }

    class func payloadWithoutVerificationURI() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJrZXlUeXBlIjoicHJvb2ZPZlBvc3Nlc3Npb24iLCJmYWN0b3JUeXBlIjoiY3J5cHRvIn0.udKcu_kNKq4v-kblpThkViz7pDvnFKVUmkTVuWCoFuw"
    }

    class func payloadWithoutIss() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJhdWQiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiaWF0IjoxNDY3MTQ1MDk0LCJleHAiOjE0NjcxNDg2OTQsInNpZ25hbHMiOlsic2NyZWVuTG9jayIsInJvb3RQcml2aWxlZ2VzIiwiZnVsbERpc2tFbmNyeXB0aW9uIiwiaWQiLCJvcyIsIm9zVmVyc2lvbiIsIm1hbnVmYWN0dXJlciIsIm1vZGVsIiwiZGV2aWNlQXR0ZXN0YXRpb24iLCJhcHBJZCIsImFwcE1hbmFnZWQiXSwibm9uY2UiOiJGV2tmd0ZXa2Z3M2pmZDNqZmQiLCJ0cmFuc2FjdGlvbklkIjoiMTIzNDU2Nzg5Iiwib3JnSWQiOiIwMG8xb2YxMTB0VkJHV0ZLQVdHSSIsImtleVR5cGUiOiJwcm9vZk9mUG9zc2Vzc2lvbiIsImZhY3RvclR5cGUiOiJjcnlwdG8iLCJ2ZXJpZmljYXRpb25VcmkiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tL2lkcC9hdXRoZW50aWNhdG9ycy9hdXRoZW50aWNhdG9ySWQvdHJhbnNhY3Rpb25zL3RyYW5zYWN0aW9uSWQvdmVyaWZ5In0.CHqtOBwegJTW9VBO8mXNj0U3pfyReUhwsYOuxTluW_g"
    }

    class func payloadWithoutAud() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiaWF0IjoxNDY3MTQ1MDk0LCJleHAiOjE0NjcxNDg2OTQsInNpZ25hbHMiOlsic2NyZWVuTG9jayIsInJvb3RQcml2aWxlZ2VzIiwiZnVsbERpc2tFbmNyeXB0aW9uIiwiaWQiLCJvcyIsIm9zVmVyc2lvbiIsIm1hbnVmYWN0dXJlciIsIm1vZGVsIiwiZGV2aWNlQXR0ZXN0YXRpb24iLCJhcHBJZCIsImFwcE1hbmFnZWQiXSwibm9uY2UiOiJGV2tmd0ZXa2Z3M2pmZDNqZmQiLCJ0cmFuc2FjdGlvbklkIjoiMTIzNDU2Nzg5Iiwib3JnSWQiOiIwMG8xb2YxMTB0VkJHV0ZLQVdHSSIsImtleVR5cGUiOiJwcm9vZk9mUG9zc2Vzc2lvbiIsImZhY3RvclR5cGUiOiJjcnlwdG8iLCJ2ZXJpZmljYXRpb25VcmkiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tL2lkcC9hdXRoZW50aWNhdG9ycy9hdXRoZW50aWNhdG9ySWQvdHJhbnNhY3Rpb25zL3RyYW5zYWN0aW9uSWQvdmVyaWZ5In0.nFxR_rK5Vd_Jhsag1u0bCJAV8XkvZDxz7sDcS8GrvdQ"
    }

    class func payloadWithoutIat() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImV4cCI6MTQ2NzE0ODY5NCwic2lnbmFscyI6WyJzY3JlZW5Mb2NrIiwicm9vdFByaXZpbGVnZXMiLCJmdWxsRGlza0VuY3J5cHRpb24iLCJpZCIsIm9zIiwib3NWZXJzaW9uIiwibWFudWZhY3R1cmVyIiwibW9kZWwiLCJkZXZpY2VBdHRlc3RhdGlvbiIsImFwcElkIiwiYXBwTWFuYWdlZCJdLCJub25jZSI6IkZXa2Z3RldrZnczamZkM2pmZCIsInRyYW5zYWN0aW9uSWQiOiIxMjM0NTY3ODkiLCJvcmdJZCI6IjAwbzFvZjExMHRWQkdXRktBV0dJIiwia2V5VHlwZSI6InByb29mT2ZQb3NzZXNzaW9uIiwiZmFjdG9yVHlwZSI6ImNyeXB0byIsInZlcmlmaWNhdGlvblVyaSI6Imh0dHBzOi8veW91ci1vcmcub2t0YS5jb20vaWRwL2F1dGhlbnRpY2F0b3JzL2F1dGhlbnRpY2F0b3JJZC90cmFuc2FjdGlvbnMvdHJhbnNhY3Rpb25JZC92ZXJpZnkifQ.V9kejKTOzXTw4NesM4xa3reTXFhtW5SvHZgO-B09LvQ"
    }

    class func payloadWithoutExp() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwic2lnbmFscyI6WyJzY3JlZW5Mb2NrIiwicm9vdFByaXZpbGVnZXMiLCJmdWxsRGlza0VuY3J5cHRpb24iLCJpZCIsIm9zIiwib3NWZXJzaW9uIiwibWFudWZhY3R1cmVyIiwibW9kZWwiLCJkZXZpY2VBdHRlc3RhdGlvbiIsImFwcElkIiwiYXBwTWFuYWdlZCJdLCJub25jZSI6IkZXa2Z3RldrZnczamZkM2pmZCIsInRyYW5zYWN0aW9uSWQiOiIxMjM0NTY3ODkiLCJvcmdJZCI6IjAwbzFvZjExMHRWQkdXRktBV0dJIiwia2V5VHlwZSI6InByb29mT2ZQb3NzZXNzaW9uIiwiZmFjdG9yVHlwZSI6ImNyeXB0byIsInZlcmlmaWNhdGlvblVyaSI6Imh0dHBzOi8veW91ci1vcmcub2t0YS5jb20vaWRwL2F1dGhlbnRpY2F0b3JzL2F1dGhlbnRpY2F0b3JJZC90cmFuc2FjdGlvbnMvdHJhbnNhY3Rpb25JZC92ZXJpZnkifQ.iChCidSRfNgctah8JO5yv74Y0NOQT5sEiP396T33TDs"
    }

    class func payloadWithoutKeyType() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJtZXRob2QiOiJzaWduZWRfbm9uY2UiLCJ2ZXJpZmljYXRpb25VcmkiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tL2lkcC9hdXRoZW50aWNhdG9ycy9hdXRoZW50aWNhdG9ySWQvdHJhbnNhY3Rpb25zL3RyYW5zYWN0aW9uSWQvdmVyaWZ5In0.b33YeochFYrEo8HehJQYiqRyh5l2HWU4q2JXLD0t7B4"
    }

    class func payloadWithoutTransactionId() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwib3JnSWQiOiIwMG8xb2YxMTB0VkJHV0ZLQVdHSSIsImtleVR5cGUiOiJwcm9vZk9mUG9zc2Vzc2lvbiIsImZhY3RvclR5cGUiOiJjcnlwdG8iLCJ2ZXJpZmljYXRpb25VcmkiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tL2lkcC9hdXRoZW50aWNhdG9ycy9hdXRoZW50aWNhdG9ySWQvdHJhbnNhY3Rpb25zL3RyYW5zYWN0aW9uSWQvdmVyaWZ5In0.3lIxRidAzY4IrcE9SkmEiM_xfWfktVIEfoyw2FwA91Y"
    }

    class func payloadWithBadVerifyURI() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJrZXlUeXBlIjoicHJvb2ZPZlBvc3Nlc3Npb24iLCJmYWN0b3JUeXBlIjoiY3J5cHRvIiwidmVyaWZpY2F0aW9uVXJpIjoiICJ9.d0aef69DL_vXQLW-ob8wrytJ8TnCjejipUQZ6B7buhw"
    }

    class func payloadWithInvalidIssClaim() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJhdWQiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiaXNzIjoiICIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJrZXlUeXBlIjoicHJvb2ZPZlBvc3Nlc3Npb24iLCJmYWN0b3JUeXBlIjoiY3J5cHRvIiwidmVyaWZpY2F0aW9uVXJpIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbS9pZHAvYXV0aGVudGljYXRvcnMvYXV0aGVudGljYXRvcklkL3RyYW5zYWN0aW9ucy90cmFuc2FjdGlvbklkL3ZlcmlmeSJ9.Zx5KjcZg2wcLW4eziOQ3e2UOXgNjeU1dsjEK2HRW9oo"
    }

    class func payloadWithInvalidVerificationURL() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJhdWQiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiaXNzIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJrZXlUeXBlIjoicHJvb2ZPZlBvc3Nlc3Npb24iLCJmYWN0b3JUeXBlIjoiY3J5cHRvIiwidmVyaWZpY2F0aW9uVXJpIjoiICJ9.wsBNsc5mbe8TBW-AqvDrL0InaN0IB_lhgUaWGlwm6g0"
    }

    class func pushChallengeJWT() -> String {
        return "eyJraWQiOiJoM0E0amNRd3lJcDJEbXNzWktlS3hPbFlEODdwd2w4bnNDUHB3ZkxKX3VFIiwidHlwIjoib2t0YS1wdXNoYmluZCtqd3QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2N1c3RvbXB1c2gub2t0YTEuY29tIiwiYXVkIjoib2t0YS42M2MwODFkYi0xZjEzLTUwODQtODgyZi1lNzllMWU1ZTJkYTciLCJleHAiOjE2NDU3MjM3MDAsImlhdCI6MTY0NTcyMzQwMCwianRpIjoiZnRMYV9ubWo2dEV1TnNyMGRLWExIa0taMmpyTlU3UUpSUyIsIm5vbmNlIjoiWDJtOGEtVnprdUVDTFZwNXp4M3oiLCJ0cmFuc2FjdGlvbklkIjoiZnRMYV9ubWo2dEV1TnNyMGRLWExIa0taMmpyTlU3UUpSUyIsInZlcmlmaWNhdGlvblVyaSI6Imh0dHBzOi8vY3VzdG9tcHVzaC5va3RhMS5jb20vYXBpL3YxL2F1dGhuL2ZhY3RvcnMvb3BmZzBwaE12UmFPOWZDdzQwZzQvdHJhbnNhY3Rpb25zL2Z0TGFfbm1qNnRFdU5zcjBkS1hMSGtLWjJqck5VN1FKUlMvdmVyaWZ5Iiwia2V5VHlwZSI6InByb29mT2ZQb3NzZXNzaW9uIiwia2V5VHlwZXMiOlsicHJvb2ZPZlBvc3Nlc3Npb24iXSwiZmFjdG9yVHlwZSI6InB1c2giLCJhcHBJbnN0YW5jZU5hbWUiOiJUZXN0QXBwIiwib3JnSWQiOiIwMG9mbHB3TnJ5czNqVll5cjBnNCIsIm1ldGhvZCI6InB1c2giLCJraWQiOiIwMDFFOTk1Ri01OUNCLTRDRjgtQTUwMC0yMEVBQ0REMTFBNjYiLCJtZXRob2RFbnJvbGxtZW50SWQiOiJvcGZnMHBoTXZSYU85ZkN3NDBnNCIsImF1dGhlbnRpY2F0b3JFbnJvbGxtZW50SWQiOiJwZmRnMHBmeVhQVDZFOGF6ZDBnNCIsImNoYWxsZW5nZUNvbnRleHQiOnsic2hvd1VzZXJMb2NhdGlvbkluTm90aWZpY2F0aW9uIjp0cnVlLCJjbGllbnRPUyI6IlVOS05PV04iLCJjbGllbnRMb2NhdGlvbiI6IlVua25vd24gbG9jYXRpb24iLCJ0cmFuc2FjdGlvblRpbWUiOiIyMDIyLTAyLTI0VDE3OjIzOjEzLjg0NVoiLCJ0cmFuc2FjdGlvblR5cGUiOiJMT0dJTiIsInVudXN1YWxBY3Rpdml0aWVzVGV4dEl0ZW1zIjpbXSwicmlza0xldmVsIjoiTk9ORSJ9LCJ1c2VySWQiOiIwMHVmbHpwY0lMMWpKdmpaUjBnNCIsInZlciI6MH0.Ki_TIiTu4yf_ZBQ13XilfUz78jkLjGDHcpqgPceOCe1y8E8Ip3Quh1nRoYuYyeXa9Wub3nPC4xDiYuSLvEAaaQ7KO76PNThApAfXVcuvlqnKJB-4YPCnElobPANrKkODSUHuWo_lK9xNeT_d_RkF0K90ttMfSTEZyEWN3WomQsFeDt-r0tDMJNKJ43djQkYNBiwd6CJrSnKhi0fjftASSCE_VnvpjP8ivpkJgWOMId82libszxx7B4y-Cd8lRbNjgAET5fAjkP3xF8wtHeILNsMh4ftBJbGHAtM4UGa2Ll7ChmqtN4AEoQL8r39wt3Nv7XDus1a_97MSXOPUxtwVkw"
    }

    class func pushChallengeJWT_AuthorizationServerId() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2N1c3RvbXB1c2gub2t0YTEuY29tIiwiYXVkIjoib2t0YS42M2MwODFkYi0xZjEzLTUwODQtODgyZi1lNzllMWU1ZTJkYTciLCJleHAiOjE2NDU3MjM3MDAsImlhdCI6MTY0NTcyMzQwMCwianRpIjoiZnRMYV9ubWo2dEV1TnNyMGRLWExIa0taMmpyTlU3UUpSUyIsIm5vbmNlIjoiWDJtOGEtVnprdUVDTFZwNXp4M3oiLCJ0cmFuc2FjdGlvbklkIjoiZnRMYV9ubWo2dEV1TnNyMGRLWExIa0taMmpyTlU3UUpSUyIsInZlcmlmaWNhdGlvblVyaSI6Imh0dHBzOi8vY3VzdG9tcHVzaC5va3RhMS5jb20vYXBpL3YxL2F1dGhuL2ZhY3RvcnMvb3BmZzBwaE12UmFPOWZDdzQwZzQvdHJhbnNhY3Rpb25zL2Z0TGFfbm1qNnRFdU5zcjBkS1hMSGtLWjJqck5VN1FKUlMvdmVyaWZ5Iiwia2V5VHlwZSI6InByb29mT2ZQb3NzZXNzaW9uIiwia2V5VHlwZXMiOlsicHJvb2ZPZlBvc3Nlc3Npb24iXSwiZmFjdG9yVHlwZSI6InB1c2giLCJhcHBJbnN0YW5jZU5hbWUiOiJUZXN0QXBwIiwib3JnSWQiOiIwMG9mbHB3TnJ5czNqVll5cjBnNCIsIm1ldGhvZCI6InB1c2giLCJraWQiOiIwMDFFOTk1Ri01OUNCLTRDRjgtQTUwMC0yMEVBQ0REMTFBNjYiLCJtZXRob2RFbnJvbGxtZW50SWQiOiJvcGZnMHBoTXZSYU85ZkN3NDBnNCIsImF1dGhlbnRpY2F0b3JFbnJvbGxtZW50SWQiOiJwZmRnMHBmeVhQVDZFOGF6ZDBnNCIsImNoYWxsZW5nZUNvbnRleHQiOnsic2hvd1VzZXJMb2NhdGlvbkluTm90aWZpY2F0aW9uIjp0cnVlLCJjbGllbnRPUyI6IlVOS05PV04iLCJjbGllbnRMb2NhdGlvbiI6IlVua25vd24gbG9jYXRpb24iLCJ0cmFuc2FjdGlvblRpbWUiOiIyMDIyLTAyLTI0VDE3OjIzOjEzLjg0NVoiLCJ0cmFuc2FjdGlvblR5cGUiOiJMT0dJTiIsInVudXN1YWxBY3Rpdml0aWVzVGV4dEl0ZW1zIjpbXSwicmlza0xldmVsIjoiTk9ORSJ9LCJ1c2VySWQiOiIwMHVmbHpwY0lMMWpKdmpaUjBnNCIsInZlciI6MCwiYXV0aG9yaXphdGlvblNlcnZlcklkIjoiZGVmYXVsdCJ9.LRfJk4pCNo91Nh2pkCuc9ULqXRhzdj2PxDLxFgpd93o"
    }
    
    class func pushChallengeCIBAJWT() -> String {
        return "eyJraWQiOiJoM0E0amNRd3lJcDJEbXNzWktlS3hPbFlEODdwd2w4bnNDUHB3ZkxKX3VFIiwidHlwIjoib2t0YS1wdXNoYmluZCtqd3QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2N1c3RvbXB1c2gub2t0YTEuY29tIiwiYXVkIjoib2t0YS42M2MwODFkYi0xZjEzLTUwODQtODgyZi1lNzllMWU1ZTJkYTciLCJleHAiOjE2NDU3MjM3MDAsImlhdCI6MTY0NTcyMzQwMCwianRpIjoiZnRMYV9ubWo2dEV1TnNyMGRLWExIa0taMmpyTlU3UUpSUyIsIm5vbmNlIjoiWDJtOGEtVnprdUVDTFZwNXp4M3oiLCJ0cmFuc2FjdGlvbklkIjoiZnRMYV9ubWo2dEV1TnNyMGRLWExIa0taMmpyTlU3UUpSUyIsInZlcmlmaWNhdGlvblVyaSI6Imh0dHBzOi8vY3VzdG9tcHVzaC5va3RhMS5jb20vYXBpL3YxL2F1dGhuL2ZhY3RvcnMvb3BmZzBwaE12UmFPOWZDdzQwZzQvdHJhbnNhY3Rpb25zL2Z0TGFfbm1qNnRFdU5zcjBkS1hMSGtLWjJqck5VN1FKUlMvdmVyaWZ5Iiwia2V5VHlwZSI6InByb29mT2ZQb3NzZXNzaW9uIiwia2V5VHlwZXMiOlsicHJvb2ZPZlBvc3Nlc3Npb24iXSwiZmFjdG9yVHlwZSI6InB1c2giLCJhcHBJbnN0YW5jZU5hbWUiOiJUZXN0QXBwIiwib3JnSWQiOiIwMG9mbHB3TnJ5czNqVll5cjBnNCIsIm1ldGhvZCI6InB1c2giLCJraWQiOiIwMDFFOTk1Ri01OUNCLTRDRjgtQTUwMC0yMEVBQ0REMTFBNjYiLCJtZXRob2RFbnJvbGxtZW50SWQiOiJvcGZnMHBoTXZSYU85ZkN3NDBnNCIsImF1dGhlbnRpY2F0b3JFbnJvbGxtZW50SWQiOiJwZmRnMHBmeVhQVDZFOGF6ZDBnNCIsImNoYWxsZW5nZUNvbnRleHQiOnsic2hvd1VzZXJMb2NhdGlvbkluTm90aWZpY2F0aW9uIjp0cnVlLCJjbGllbnRPUyI6IlVOS05PV04iLCJjbGllbnRMb2NhdGlvbiI6IlVua25vd24gbG9jYXRpb24iLCJ0cmFuc2FjdGlvblRpbWUiOiIyMDIyLTAyLTI0VDE3OjIzOjEzLjg0NVoiLCJ0cmFuc2FjdGlvblR5cGUiOiJDSUJBIiwiYmluZGluZ01lc3NhZ2UiOiJEaWQgeW91IG1ha2UgYSAkMzAwIHB1cmNoYXNlPyIsInVudXN1YWxBY3Rpdml0aWVzVGV4dEl0ZW1zIjpbXSwicmlza0xldmVsIjoiTk9ORSJ9LCJ1c2VySWQiOiIwMHVmbHpwY0lMMWpKdmpaUjBnNCIsInZlciI6MH0.oEClZXwmIxLZs4_k7v8SrNsYh3ffw3G1tzuFviA6dFT_cJwSh6e08sv_XV_MlDXwvCi-LmNjWcBUUTrIRawMPSFLoZ0eLtfK3jgZnsj4T_nYek_jV3tC07s2iMSho2jKSUDq_q5rNMA1xDoONiD4jgmg3PFHfIrAcOw1nMXl1o5BdZTHr_Jl5IdywHkG3AycV5org719sMzm1MuMyzUAq1_-A6uu-tPN4MJ4xmAIS9EAn7wvFpLj-zfziftMR3TKKNUbxr2VNtbzjzqdV6Jg5f4gCu1E2YcdxxE4yWni6uH8_8XKv1WPjJJ-ppQDI0j0YiaBh7TVaKqhtoR8lC9RUw"
    }

    class func pushChallengeCIBAJWTSpecialChars() -> String {
        return "eyJraWQiOiJoM0E0amNRd3lJcDJEbXNzWktlS3hPbFlEODdwd2w4bnNDUHB3ZkxKX3VFIiwidHlwIjoib2t0YS1wdXNoYmluZCtqd3QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2N1c3RvbXB1c2gub2t0YTEuY29tIiwiYXVkIjoib2t0YS42M2MwODFkYi0xZjEzLTUwODQtODgyZi1lNzllMWU1ZTJkYTciLCJleHAiOjE2NDU3MjM3MDAsImlhdCI6MTY0NTcyMzQwMCwianRpIjoiZnRMYV9ubWo2dEV1TnNyMGRLWExIa0taMmpyTlU3UUpSUyIsIm5vbmNlIjoiWDJtOGEtVnprdUVDTFZwNXp4M3oiLCJ0cmFuc2FjdGlvbklkIjoiZnRMYV9ubWo2dEV1TnNyMGRLWExIa0taMmpyTlU3UUpSUyIsInZlcmlmaWNhdGlvblVyaSI6Imh0dHBzOi8vY3VzdG9tcHVzaC5va3RhMS5jb20vYXBpL3YxL2F1dGhuL2ZhY3RvcnMvb3BmZzBwaE12UmFPOWZDdzQwZzQvdHJhbnNhY3Rpb25zL2Z0TGFfbm1qNnRFdU5zcjBkS1hMSGtLWjJqck5VN1FKUlMvdmVyaWZ5Iiwia2V5VHlwZSI6InByb29mT2ZQb3NzZXNzaW9uIiwia2V5VHlwZXMiOlsicHJvb2ZPZlBvc3Nlc3Npb24iXSwiZmFjdG9yVHlwZSI6InB1c2giLCJhcHBJbnN0YW5jZU5hbWUiOiJUZXN0QXBwIiwib3JnSWQiOiIwMG9mbHB3TnJ5czNqVll5cjBnNCIsIm1ldGhvZCI6InB1c2giLCJraWQiOiIwMDFFOTk1Ri01OUNCLTRDRjgtQTUwMC0yMEVBQ0REMTFBNjYiLCJtZXRob2RFbnJvbGxtZW50SWQiOiJvcGZnMHBoTXZSYU85ZkN3NDBnNCIsImF1dGhlbnRpY2F0b3JFbnJvbGxtZW50SWQiOiJwZmRnMHBmeVhQVDZFOGF6ZDBnNCIsImNoYWxsZW5nZUNvbnRleHQiOnsic2hvd1VzZXJMb2NhdGlvbkluTm90aWZpY2F0aW9uIjp0cnVlLCJjbGllbnRPUyI6IlVOS05PV04iLCJjbGllbnRMb2NhdGlvbiI6IlVua25vd24gbG9jYXRpb24iLCJ0cmFuc2FjdGlvblRpbWUiOiIyMDIyLTAyLTI0VDE3OjIzOjEzLjg0NVoiLCJ0cmFuc2FjdGlvblR5cGUiOiJDSUJBIiwiYmluZGluZ01lc3NhZ2UiOiJEaWQgeW91IG1ha2UgYSAkMzAwIHB1cmNoYXNlJTJFPyIsInVudXN1YWxBY3Rpdml0aWVzVGV4dEl0ZW1zIjpbXSwicmlza0xldmVsIjoiTk9ORSJ9LCJ1c2VySWQiOiIwMHVmbHpwY0lMMWpKdmpaUjBnNCIsInZlciI6MH0.HZ-EHPqiCGbwRU3Gtw1bSet8dk3SjlJQvMKK6yMw0UIN4_aP1lGNgvarkzMwQBsR5h3bejlT4b1uOPnvYH7h9MLgLgGygDWm3lyeqVIic7pC6Tswb60ripYMxYBFjHXc8K7vQ7-AlAMY1Jrinss8Vb3_ZXUDMHlnD1iK1vkXkeHVHpDhy8a7ZVi3hWRBUG_R-Ur1jnu3Z6Y0ctouKRro-fdt12VlDcWK0oVLwrf4vz7XnDZBGt-pTMwkcCfnTJwlHrzOy1_dpw3Dg8z188Tc82QmPO5mEoEMXuQ9dCDWDoCJh3j5KsOB3G8JnnOGyKvpKl7qZNLtewcKqWL-dGtZsg"
    }

    class func pushChallengeJWT_WithNoChallengeContext() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtcHVzaGJpbmQrand0In0.eyJpc3MiOiJodHRwczovL2lkeC5va3RhMS5jb20iLCJhdWQiOiJva3RhLjYzYzA4MWRiLTFmMTMtNTA4NC04ODJmLWU3OWUxZTVlMmRhNyIsImV4cCI6MTU5MTg0OTYwMywiaWF0IjoxNTkxODQ5MzAzLCJqdGkiOiJmdDhqVVZRUnVabGZSam5sOU1xako1ekVyX01NQUR1OXc5Iiwibm9uY2UiOiJOR0hQZGpVdExac0ZIT1o5dzJfalM1cThiWVhRQXdKYSIsInRyYW5zYWN0aW9uSWQiOiJmdDhqVVZRUnVabGZSam5sOU1xako1ekVyX01NQUR1OXc5Iiwic2lnbmFscyI6bnVsbCwidmVyaWZpY2F0aW9uVXJpIjoiaHR0cHM6Ly9pZHgub2t0YTEuY29tL3YxL2F1dGhuL2ZhY3RvcnMvMTIzNC90cmFuc2FjdGlvbnMvNDMyMS92ZXJpZnkiLCJrZXlUeXBlIjoicHJvb2ZPZlBvc3Nlc3Npb24iLCJtZXRob2QiOiJwdXNoIiwib3JnSWQiOiIwMG85Mmd4b3BlaTcydTRtZTB3NCIsImtpZCI6Ijk5MjBhOTIzLTVhZTMtNGQ5ZC1iZTBiLWNiMmYyZDUwODkyMCIsImF1dGhlbnRpY2F0b3JFbnJvbGxtZW50SWQiOiJhZW4xamlzTHd3VEc3cVJySDBnNCJ9.89rjGIkCtEpZSb_shM--I5b3aNqK_Potgp4oTB1VMeo"
    }

    class func validDeviceChallenge_WithUserIdAndLoginHint() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJrZXlUeXBlIjoicHJvb2ZPZlBvc3Nlc3Npb24iLCJsb2dpbkhpbnQiOiJ1c2VyQGRvbWFpbi5jb20iLCJ1c2VySWQiOiJ1c2VySWQiLCJtZXRob2QiOiJzaWduZWRfbm9uY2UiLCJ2ZXJpZmljYXRpb25VcmkiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tL2lkcC9pZHgvYXV0aGVudGljYXRvcnMvYXV0aGVudGljYXRvcklkL3RyYW5zYWN0aW9ucy90cmFuc2FjdGlvbklkL3ZlcmlmeSIsImludGVncmF0aW9ucyI6W3sibmFtZSI6Im5hbWVfMSJ9XX0.z-MtBuZO6Wti1cLnUJNjnmm57WTzcyZJFSUHc5Xalqw"
    }

    class func validDeviceChallenge_WithLoginHint() -> String {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZGV2aWNlYmluZCtqd3QifQ.eyJpc3MiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tIiwiYXVkIjoiaHR0cHM6Ly95b3VyLW9yZy5va3RhLmNvbSIsImlhdCI6MTQ2NzE0NTA5NCwiZXhwIjoxNDY3MTQ4Njk0LCJzaWduYWxzIjpbInNjcmVlbkxvY2siLCJyb290UHJpdmlsZWdlcyIsImZ1bGxEaXNrRW5jcnlwdGlvbiIsImlkIiwib3MiLCJvc1ZlcnNpb24iLCJtYW51ZmFjdHVyZXIiLCJtb2RlbCIsImRldmljZUF0dGVzdGF0aW9uIiwiYXBwSWQiLCJhcHBNYW5hZ2VkIl0sIm5vbmNlIjoiRldrZndGV2tmdzNqZmQzamZkIiwidHJhbnNhY3Rpb25JZCI6IjEyMzQ1Njc4OSIsIm9yZ0lkIjoiMDBvMW9mMTEwdFZCR1dGS0FXR0kiLCJrZXlUeXBlIjoicHJvb2ZPZlBvc3Nlc3Npb24iLCJsb2dpbkhpbnQiOiJ1c2VyQGRvbWFpbi5jb20iLCJtZXRob2QiOiJzaWduZWRfbm9uY2UiLCJ2ZXJpZmljYXRpb25VcmkiOiJodHRwczovL3lvdXItb3JnLm9rdGEuY29tL2lkcC9pZHgvYXV0aGVudGljYXRvcnMvYXV0aGVudGljYXRvcklkL3RyYW5zYWN0aW9ucy90cmFuc2FjdGlvbklkL3ZlcmlmeSIsImludGVncmF0aW9ucyI6W3sibmFtZSI6Im5hbWVfMSJ9XX0.rcQAxYQegIe1l9V2oOhiiqNaPC06xFn-9jEApAbsA2U"
    }
}
