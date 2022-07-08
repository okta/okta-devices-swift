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
import DeviceAuthenticator

class GoldenData {
    class func authenticatorMetaData() -> Data {
        let authenticatorJson: String = """
        [{
            "id": "autuowpr5VjVjQPU30g3",
            "key": "okta_verify",
            "type": "APP",
            "status": "ACTIVE",
            "name": "Okta Device Authenticator",
            "created": "2017-01-24T19:52:34.000Z",
            "lastUpdated": "2017-01-24T19:52:34.000Z",
            "settings": {
                "appInstanceId": "oidcAppId1234",
                "userVerification": "preferred"
            },
            "_links": {
                "enroll": {
                    "href": "https://atko.oktapreview.com/idp/authenticators",
                    "hints": {
                        "allow": ["POST"]
                    }
                }
            },
            "_embedded": {
                "methods": [{
                        "type": "signed_nonce",
                        "status": "INACTIVE",
                        "settings": {
                            "algorithms": ["RS256", "ES256"],
                            "keyProtection": "ANY"
                        }
                    },
                    {
                        "type": "push",
                        "status": "ACTIVE"
                    },
                    {
                        "type": "totp",
                        "status": "INACTIVE",
                        "settings": {
                            "timeIntervalInSeconds": 10,
                            "encoding": "Base32",
                            "algorithm": "HMACSHA1",
                            "passCodeLength": 6
                        }
                    }
                ]
            }
        }]
        """
        let jsonArray = try! JSONSerialization.jsonObject(with: authenticatorJson.data(using: .utf8)!, options: []) as! [Any]
        let jsonData = try! JSONSerialization.data(withJSONObject: jsonArray, options: .prettyPrinted)
        return jsonData
    }

    class func authenticatorMetaDataInactive() -> Data {
        let authenticatorJson: String = """
        [{
            "id": "autuowpr5VjVjQPU30g3",
            "key": "okta_verify",
            "type": "APP",
            "status": "INACTIVE",
            "name": "Okta Device Authenticator",
            "created": "2017-01-24T19:52:34.000Z",
            "lastUpdated": "2017-01-24T19:52:34.000Z",
            "settings": {
                "appInstanceId": "oidcAppId1234",
                "userVerification": "preferred"
            },
            "_links": {},
            "_embedded": {
                "methods": [{}]
        }]
        """
        let jsonArray = try! JSONSerialization.jsonObject(with: authenticatorJson.data(using: .utf8)!, options: []) as! [Any]
        let jsonData = try! JSONSerialization.data(withJSONObject: jsonArray, options: .prettyPrinted)
        return jsonData
    }
    
    class func authenticatorMetaDataWithEmptyEnrollLink() -> Data {
        let authenticatorJson: String = """
        [{
            "id": "autuowpr5VjVjQPU30g3",
            "key": "okta_verify",
            "type": "APP",
            "status": "ACTIVE",
            "name": "Okta Device Authenticator",
            "created": "2017-01-24T19:52:34.000Z",
            "lastUpdated": "2017-01-24T19:52:34.000Z",
            "settings": {
                "appInstanceId": "oidcAppId1234"
            },
            "_links": {},
            "_embedded": {
                "methods": [{
                        "type": "signed_nonce",
                        "status": "INACTIVE",
                        "settings": {
                            "algorithms": ["RS256", "ES256"],
                            "keyProtection": "ANY"
                        }
                    },
                    {
                        "type": "push",
                        "status": "ACTIVE"
                    },
                    {
                        "type": "totp",
                        "status": "INACTIVE"
                    }
                ]
            }
        }]
        """
        let jsonArray = try! JSONSerialization.jsonObject(with: authenticatorJson.data(using: .utf8)!, options: []) as! [Any]
        let jsonData = try! JSONSerialization.data(withJSONObject: jsonArray, options: .prettyPrinted)
        return jsonData
    }

    class func authenticatorData() -> Data {
        let authenticatorJson: String = """
        {
            "id": "aen1jisLwwTG7qRrH0g4",
            "authenticatorId": "autuowpr5VjVjQPU30g3",
            "key": "okta_verify",
            "status": "ACTIVE",
            "type": "APP",
            "createdDate": "Tue Dec 03 18:39:46 UTC 2019",
            "lastUpdated": "Tue Dec 03 18:39:46 UTC 2019",
            "device": {
                "id": "guotmkiKzYBTnhnC40g4",
                "status": "ACTIVE",
                "created": "2019-12-03T18:39:46.000Z",
                "lastUpdated": "2019-12-03T19:59:43.000Z",
                "profile": {
                    "displayName": "Test Device",
                    "platform": "IOS",
                    "manufacturer": "APPLE",
                    "model": "iPhone X",
                    "osVersion": "10",
                    "serialNumber": "2fc4b5912826ad1",
                    "imei": null,
                    "meid": null,
                    "udid": "2b6f0cc904d137be2e1730235f5664094b831186",
                    "sid": null
                },
                "clientInstanceId": "cli1zEPrHHW0w4i0ALF0",
            },
            "user": {
                "id": "00utmecoNjNd0lrWp0g4",
                "username": "test@okta.com"
            },
            "methods": [{
                    "type": "push",
                    "id": "opftmklWEf1vDZvr10g4",
                    "status": "ACTIVE",
                    "createdDate": "Tue Dec 03 18:39:46 UTC 2019",
                    "lastUpdated": "Tue Dec 03 18:39:46 UTC 2019",
                    "links": {
                        "update": {
                            "href": "https://qa-dt-platform.hioktane.com/api/v1/factors/guotmkiKzYBTnhnC40g4/lifecycle/update",
                            "hints": {
                                "allow": [
                                    "PUT"
                                ]
                            }
                        },
                        "pending": {
                            "href": "https://qa-dt-platform.hioktane.com/api/v1/factors/guotmkiKzYBTnhnC40g4/lifecycle/pending",
                            "hints": {
                                "allow": [
                                    "PUT"
                                ]
                            }
                        },
                        "activate": {
                            "href": "https://qa-dt-platform.hioktane.com/api/v1/devices/guotmkiKzYBTnhnC40g4/lifecycle/activate",
                            "hints": {
                                "allow": [
                                    "POST"
                                ]
                            }
                        }
                    }
                }
            ]
        }
        """
        let dict = try! JSONSerialization.jsonObject(with: authenticatorJson.data(using: .utf8)!, options: []) as! [String: Any]
        let jsonData = try! JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted)
        return jsonData
    }

    class func authenticatorDataWithEmptyMethods() -> Data {
        let authenticatorJson: String = """
        {
            "id": "aentmkkkgGrqnrBxB0g4",
            "authenticatorId": "autuowpr5VjVjQPU30g3",
            "key": "okta_verify",
            "status": "ACTIVE",
            "type": "APP",
            "createdDate": "Tue Dec 03 18:39:46 UTC 2019",
            "lastUpdated": "Tue Dec 03 18:39:46 UTC 2019",
            "device": {
                "id": "guotmkiKzYBTnhnC40g4",
                "status": "ACTIVE",
                "created": "2019-12-03T18:39:46.000Z",
                "lastUpdated": "2019-12-03T19:59:43.000Z",
                "profile": {
                    "displayName": "Test Device",
                    "platform": "IOS",
                    "manufacturer": "APPLE",
                    "model": "iPhone X",
                    "osVersion": "10",
                    "serialNumber": "2fc4b5912826ad1",
                    "imei": null,
                    "meid": null,
                    "udid": "2b6f0cc904d137be2e1730235f5664094b831186",
                    "sid": null
                },
                "clientInstanceId": "cli1zEPrHHW0w4i0ALF0",
            },
            "user": {
                "id": "00utmecoNjNd0lrWp0g4"
            },
            "methods": []
        }
        """
        let dict = try! JSONSerialization.jsonObject(with: authenticatorJson.data(using: .utf8)!, options: []) as! [String: Any]
        let jsonData = try! JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted)
        return jsonData
    }

    class func deviceSignalsData() -> Data {
        let deviceSignalsJson: String = """
        {
            "id": "guotmkiKzYBTnhnC40g4",
            "status": "ACTIVE",
            "created": "2019-12-03T18:39:46.000Z",
            "lastUpdated": "2019-12-03T19:59:43.000Z",
            "profile": {
                "displayName": "Test Device",
                "platform": "IOS",
                "manufacturer": "APPLE",
                "model": "iPhone X",
                "osVersion": "10.1.2",
                "serialNumber": "2fc4b5912826ad1",
                "imei": "abcd",
                "meid": "abcd",
                "udid": "2b6f0cc904d137be2e1730235f5664094b831186",
                "sid": "abcd",
                "screenLockType": "BIOMETRIC",
                "diskEncryptionType": "FULL",
        
            },
            "clientInstanceId": "cli1zEPrHHW0w4i0ALF0",
        }
        """
        let dict = try! JSONSerialization.jsonObject(with: deviceSignalsJson.data(using: .utf8)!, options: []) as! [String: Any]
        let jsonData = try! JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted)
        return jsonData
    }

    class func pendingPushChallengeData() -> Data {
        let pendingChallengeJson: String = """
        {
            "payloadVersion": "IDXv1",
            "challenge": "eyJ0eXAiOiJva3RhLXB1c2hiaW5kK2p3dCIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJodHRwczovL2lkeC5va3RhMS5jb20iLCJhdWQiOiJva3RhLjYzYzA4MWRiLTFmMTMtNTA4NC04ODJmLWU3OWUxZTVlMmRhNyIsImV4cCI6MTU5MTg0OTYwMywiaWF0IjoxNTkxODQ5MzAzLCJqdGkiOiJmdDhqVVZRUnVabGZSam5sOU1xako1ekVyX01NQUR1OXc5Iiwibm9uY2UiOiJOR0hQZGpVdExac0ZIT1o5dzJfalM1cThiWVhRQXdKYSIsInRyYW5zYWN0aW9uSWQiOiJmdDhqVVZRUnVabGZSam5sOU1xako1ekVyX01NQUR1OXc5Iiwic2lnbmFscyI6bnVsbCwidmVyaWZpY2F0aW9uVXJpIjoiaHR0cHM6Ly9pZHgub2t0YTEuY29tL3YxL2F1dGhuL2ZhY3RvcnMvMTIzNC90cmFuc2FjdGlvbnMvNDMyMS92ZXJpZnkiLCJrZXlUeXBlIjoicHJvb2ZPZlBvc3Nlc3Npb24iLCJtZXRob2QiOiJwdXNoIiwib3JnSWQiOiIwMG85Mmd4b3BlaTcydTRtZTB3NCIsImtpZCI6Ijk5MjBhOTIzLTVhZTMtNGQ5ZC1iZTBiLWNiMmYyZDUwODkyMCIsImNoYWxsZW5nZUNvbnRleHQiOnsic2hvd1VzZXJMb2NhdGlvbkluTm90aWZpY2F0aW9uIjp0cnVlLCJjbGllbnRPUyI6Ik1BQ19PU19YIiwiY2xpZW50TG9jYXRpb24iOiJLeWl2LCBLeWl2IENpdHksIFVrcmFpbmUiLCJ0cmFuc2FjdGlvblRpbWUiOiIyMDE1LTAyLTE3VDIyOjE3OjQ0LjAwMFoiLCJ0cmFuc2FjdGlvblR5cGUiOiJMT0dJTiJ9LCJhdXRoZW50aWNhdG9yRW5yb2xsbWVudElkIjoiYWVuMWppc0x3d1RHN3FSckgwZzQifQ.I7HASmKjSirv8lVBpMwXgvf7vrZLXx4qblaTgKYhaNE"
        }
        """
        let dict = try! JSONSerialization.jsonObject(with: pendingChallengeJson.data(using: .utf8)!, options: []) as! [String: Any]
        let jsonData = try! JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted)
        return jsonData
    }

    class func pendingChallengeData() -> Data {
        let pendingChallengeJson: String = """
        [
                {
                    "payloadVersion": "IDXv1",
                    "challenge": "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtcHVzaGJpbmQrand0In0.eyJpc3MiOiJodHRwczovL2lkeC5va3RhMS5jb20iLCJhdWQiOiJva3RhLjYzYzA4MWRiLTFmMTMtNTA4NC04ODJmLWU3OWUxZTVlMmRhNyIsImV4cCI6MTU5MTg0OTYwMywiaWF0IjoxNTkxODQ5MzAzLCJqdGkiOiJmdDhqVVZRUnVabGZSam5sOU1xako1ekVyX01NQUR1OXc5Iiwibm9uY2UiOiJOR0hQZGpVdExac0ZIT1o5dzJfalM1cThiWVhRQXdKYSIsInRyYW5zYWN0aW9uSWQiOiJmdDhqVVZRUnVabGZSam5sOU1xako1ekVyX01NQUR1OXc5Iiwic2lnbmFscyI6bnVsbCwidmVyaWZpY2F0aW9uVXJpIjoiaHR0cHM6Ly9pZHgub2t0YTEuY29tL3YxL2F1dGhuL2ZhY3RvcnMvMTIzNC90cmFuc2FjdGlvbnMvNDMyMS92ZXJpZnkiLCJrZXlUeXBlIjoicHJvb2ZPZlBvc3Nlc3Npb24iLCJtZXRob2QiOiJwdXNoIiwib3JnSWQiOiIwMG85Mmd4b3BlaTcydTRtZTB3NCIsImtpZCI6Ijk5MjBhOTIzLTVhZTMtNGQ5ZC1iZTBiLWNiMmYyZDUwODkyMCIsImNoYWxsZW5nZUNvbnRleHQiOnsic2hvd1VzZXJMb2NhdGlvbkluTm90aWZpY2F0aW9uIjp0cnVlLCJjbGllbnRPUyI6Ik1BQ19PU19YIiwiY2xpZW50TG9jYXRpb24iOiJLeWl2LCBLeWl2IENpdHksIFVrcmFpbmUiLCJ0cmFuc2FjdGlvblRpbWUiOiIyMDE1LTAyLTE3VDIyOjE3OjQ0LjAwMFoiLCJ0cmFuc2FjdGlvblR5cGUiOiJMT0dJTiJ9LCJhdXRoZW50aWNhdG9yRW5yb2xsbWVudElkIjoiYWVuMWppc0x3d1RHN3FSckgwZzQifQ.y_8uiWUJQC9qY8fg9eymuJMfnuSPUdDXn0nlx0E5HwA"
                }
        ]
        """
        let dict = try! JSONSerialization.jsonObject(with: pendingChallengeJson.data(using: .utf8)!, options: []) as! [[String: Any]]
        let jsonData = try! JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted)
        return jsonData
    }

    class func pendingChallengeData_WithMultipleChallenges() -> Data {
        let pendingChallengeJson: String = """
        [
                {
                    "payloadVersion": "IDXv1",
                    "challenge": "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZW5yb2xsbWVudHVwZGF0ZStqd3QifQ.eyJpc3MiOiJodHRwczovL2lkeC5va3RhMS5jb20iLCJhdWQiOiJva3RhLjYzYzA4MWRiLTFmMTMtNTA4NC04ODJmLWU3OWUxZTVlMmRhNyIsImV4cCI6MTU5MTg0OTYwMywiaWF0IjoxNTkxODQ5MzAzLCJqdGkiOiJmdDhqVVZRUnVabGZSam5sOU1xako1ekVyX01NQUR1OXc5Iiwibm9uY2UiOiJOR0hQZGpVdExac0ZIT1o5dzJfalM1cThiWVhRQXdKYSIsInRyYW5zYWN0aW9uSWQiOiJmdDhqVVZRUnVabGZSam5sOU1xako1ekVyX01NQUR1OXc5Iiwic2lnbmFscyI6bnVsbCwidmVyaWZpY2F0aW9uVXJpIjoiaHR0cHM6Ly9pZHgub2t0YTEuY29tL3YxL2F1dGhuL2ZhY3RvcnMvMTIzNC90cmFuc2FjdGlvbnMvNDMyMS92ZXJpZnkiLCJrZXlUeXBlIjoicHJvb2ZPZlBvc3Nlc3Npb24iLCJtZXRob2QiOiJwdXNoIiwib3JnSWQiOiIwMG85Mmd4b3BlaTcydTRtZTB3NCIsImtpZCI6Ijk5MjBhOTIzLTVhZTMtNGQ5ZC1iZTBiLWNiMmYyZDUwODkyMCIsImNoYWxsZW5nZUNvbnRleHQiOnsic2hvd1VzZXJMb2NhdGlvbkluTm90aWZpY2F0aW9uIjp0cnVlLCJjbGllbnRPUyI6Ik1BQ19PU19YIiwiY2xpZW50TG9jYXRpb24iOiJLeWl2LCBLeWl2IENpdHksIFVrcmFpbmUiLCJ0cmFuc2FjdGlvblRpbWUiOiIyMDE1LTAyLTE3VDIyOjE3OjQ0LjAwMFoiLCJ0cmFuc2FjdGlvblR5cGUiOiJMT0dJTiJ9LCJhdXRoZW50aWNhdG9yRW5yb2xsbWVudElkIjoiYWVuMWppc0x3d1RHN3FSckgwZzQifQ.y_8uiWUJQC9qY8fg9eymuJMfnuSPUdDXn0nlx0E5HwA"
                },
                {
                    "payloadVersion": "V1",
                    "challenge": "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtcHVzaGJpbmQrand0In0.eyJpc3MiOiJodHRwczovL2lkeC5va3RhMS5jb20iLCJhdWQiOiJva3RhLjYzYzA4MWRiLTFmMTMtNTA4NC04ODJmLWU3OWUxZTVlMmRhNyIsImV4cCI6MTU5MTg0OTYwMywiaWF0IjoxNTkxODQ5MzAzLCJqdGkiOiJmdDhqVVZRUnVabGZSam5sOU1xako1ekVyX01NQUR1OXc5Iiwibm9uY2UiOiJOR0hQZGpVdExac0ZIT1o5dzJfalM1cThiWVhRQXdKYSIsInRyYW5zYWN0aW9uSWQiOiJmdDhqVVZRUnVabGZSam5sOU1xako1ekVyX01NQUR1OXc5Iiwic2lnbmFscyI6bnVsbCwidmVyaWZpY2F0aW9uVXJpIjoiaHR0cHM6Ly9pZHgub2t0YTEuY29tL3YxL2F1dGhuL2ZhY3RvcnMvMTIzNC90cmFuc2FjdGlvbnMvNDMyMS92ZXJpZnkiLCJrZXlUeXBlIjoicHJvb2ZPZlBvc3Nlc3Npb24iLCJtZXRob2QiOiJwdXNoIiwib3JnSWQiOiIwMG85Mmd4b3BlaTcydTRtZTB3NCIsImtpZCI6Ijk5MjBhOTIzLTVhZTMtNGQ5ZC1iZTBiLWNiMmYyZDUwODkyMCIsImNoYWxsZW5nZUNvbnRleHQiOnsic2hvd1VzZXJMb2NhdGlvbkluTm90aWZpY2F0aW9uIjp0cnVlLCJjbGllbnRPUyI6Ik1BQ19PU19YIiwiY2xpZW50TG9jYXRpb24iOiJLeWl2LCBLeWl2IENpdHksIFVrcmFpbmUiLCJ0cmFuc2FjdGlvblRpbWUiOiIyMDE1LTAyLTE3VDIyOjE3OjQ0LjAwMFoiLCJ0cmFuc2FjdGlvblR5cGUiOiJMT0dJTiJ9LCJhdXRoZW50aWNhdG9yRW5yb2xsbWVudElkIjoiYWVuMWppc0x3d1RHN3FSckgwZzQifQ.I7HASmKjSirv8lVBpMwXgvf7vrZLXx4qblaTgKYhaNE"
                }
        ]
        """
        let dict = try! JSONSerialization.jsonObject(with: pendingChallengeJson.data(using: .utf8)!, options: []) as! [[String: Any]]
        let jsonData = try! JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted)
        return jsonData
    }

    class func pendingChallenge_Empty() -> Data {
        let pendingChallengeJson: String = """
        [
                {
                }
        ]
        """
        let dict = try! JSONSerialization.jsonObject(with: pendingChallengeJson.data(using: .utf8)!, options: []) as! [[String: Any]]
        let jsonData = try! JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted)
        return jsonData
    }

    class func pendingChallengeData_NoChallengeContextInBindJWT() -> Data {
        let pendingChallengeJson: String = """
        [
                {
                    "payloadVersion": "IDXv1",
                    "challenge": "eyJhbGciOiJIUzI1NiIsInR5cCI6Im9rdGEtZW5yb2xsbWVudHVwZGF0ZStqd3QifQ.eyJpc3MiOiJodHRwczovL2lkeC5va3RhMS5jb20iLCJhdWQiOiJva3RhLjYzYzA4MWRiLTFmMTMtNTA4NC04ODJmLWU3OWUxZTVlMmRhNyIsImV4cCI6MTU5MTg0OTYwMywiaWF0IjoxNTkxODQ5MzAzLCJqdGkiOiJmdDhqVVZRUnVabGZSam5sOU1xako1ekVyX01NQUR1OXc5Iiwibm9uY2UiOiJOR0hQZGpVdExac0ZIT1o5dzJfalM1cThiWVhRQXdKYSIsInRyYW5zYWN0aW9uSWQiOiJmdDhqVVZRUnVabGZSam5sOU1xako1ekVyX01NQUR1OXc5Iiwic2lnbmFscyI6bnVsbCwidmVyaWZpY2F0aW9uVXJpIjoiaHR0cHM6Ly9pZHgub2t0YTEuY29tL3YxL2F1dGhuL2ZhY3RvcnMvMTIzNC90cmFuc2FjdGlvbnMvNDMyMS92ZXJpZnkiLCJrZXlUeXBlIjoicHJvb2ZPZlBvc3Nlc3Npb24iLCJtZXRob2QiOiJwdXNoIiwib3JnSWQiOiIwMG85Mmd4b3BlaTcydTRtZTB3NCIsImtpZCI6Ijk5MjBhOTIzLTVhZTMtNGQ5ZC1iZTBiLWNiMmYyZDUwODkyMCIsImF1dGhlbnRpY2F0b3JFbnJvbGxtZW50SWQiOiJhZW4xamlzTHd3VEc3cVJySDBnNCJ9.HiXDccxGl9CFPRw99U_myYRG4LMSPO9jOj6a2zPewNw"
                }
        ]
        """
        let dict = try! JSONSerialization.jsonObject(with: pendingChallengeJson.data(using: .utf8)!, options: []) as! [[String: Any]]
        let jsonData = try! JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted)
        return jsonData
    }

    class func orgData() -> Data {
        let orgDataJson: String = """
        {"id":"00otiyyDFtNCyFbnC0g4","_links":{"organization":{"href":"https://qa-dt-auth1.hioktane.com"}}}
        """
        let dict = try! JSONSerialization.jsonObject(with: orgDataJson.data(using: .utf8)!, options: []) as! [String: Any]
        let jsonData = try! JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted)
        return jsonData
    }
    
    class func orgDataIncomplete() -> Data {
        let orgDataJson: String = """
        {"_links":{"organization":{"href":"https://qa-dt-auth1.hioktane.com"}}}
        """
        let dict = try! JSONSerialization.jsonObject(with: orgDataJson.data(using: .utf8)!, options: []) as! [String: Any]
        let jsonData = try! JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted)
        return jsonData
    }

    class func resourceNotFoundError() -> Data {
        let orgDataJson: String = """
        {"errorLink":"E0000154","errorSummary":"Not found: Resource not found: guo1vdb2WbcR7DXuJ0w5 (GenericUDObject)","errorCode":"E0000154","errorId":"oaeYckeiQ8aQ124WltauaZB_Q"}
        """
        let dict = try! JSONSerialization.jsonObject(with: orgDataJson.data(using: .utf8)!, options: []) as! [String: Any]
        let jsonData = try! JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted)
        return jsonData
    }

    class func verificationFlowErrorFormat() -> Data {
        let orgDataJson: String = """
        {"@type":"FACTOR","status":"REJECT","reasons":[],"contextualData":{},"credentialsAndLabel":{},"challengeChannels":["DEVICE_PROBING"]}
        """
        let dict = try! JSONSerialization.jsonObject(with: orgDataJson.data(using: .utf8)!, options: []) as! [String: Any]
        let jsonData = try! JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted)
        return jsonData
    }
}
