/*
* Copyright (c) 2021-Present, Okta, Inc. and/or its affiliates. All rights reserved.
* The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
*
* You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*
* See the License for the specific language governing permissions and limitations under the License.
*/

class SQLiteSchema_200: SQLiteSchemaProtocol {

    let version: DeviceSDKStorageVersion = .v2

    let schema =
    """
    CREATE TABLE 'Enrollment' (
    'enrollmentId' TEXT NOT NULL,
    'orgId' TEXT NOT NULL,
    'orgUrl' TEXT NOT NULL,
    'userId' TEXT NOT NULL,
    'username' BLOB DEFAULT NULL,
    'deviceId' TEXT NOT NULL,
    'serverErrorCode' TEXT DEFAULT NULL,
    'createdTimestamp' TEXT DEFAULT NULL,
    'updatedTimestamp' TEXT DEFAULT NULL
    );

    CREATE UNIQUE INDEX enrollment_index ON Enrollment(enrollmentId, orgId);

    CREATE TABLE 'EnrolledMethod' (
    'id' TEXT NOT NULL,
    'enrollmentId' TEXT NOT NULL,
    'orgId' TEXT NOT NULL,
    'type' INTEGER NOT NULL,
    'proofOfPossessionKeyTag' TEXT DEFAULT NULL,
    'userVerificationKeyTag' TEXT DEFAULT NULL,
    'links' BLOB DEFAULT NULL,
    'passCodeLength' INTEGER DEFAULT NULL,
    'timeIntervalSec' INTEGER DEFAULT NULL,
    'algorithm' INTEGER DEFAULT NULL,
    'sharedSecret' BLOB DEFAULT NULL,
    'createdTimestamp' TEXT DEFAULT NULL,
    'updatedTimestamp' TEXT DEFAULT NULL,
    'transactionTypes' INTEGER DEFAULT NULL
    );

    CREATE UNIQUE INDEX method_index ON EnrolledMethod(id, enrollmentId, orgId);

    CREATE TABLE 'AuthenticatorPolicy' (
    'policyId' TEXT NOT NULL,
    'orgId' TEXT NOT NULL,
    'activeMethods' TEXT DEFAULT NULL,
    'userVerification' TEXT DEFAULT NULL,
    'metadata' BLOB NOT NULL,
    'createdTimestamp' TEXT DEFAULT NULL,
    'updatedTimestamp' TEXT DEFAULT NULL
    );

    CREATE UNIQUE INDEX policy_index ON AuthenticatorPolicy(policyId, orgId);

    CREATE TABLE 'DeviceEnrollment' (
    'deviceId' TEXT NOT NULL,
    'orgId' TEXT NOT NULL,
    'clientInstanceId' TEXT DEFAULT NULL,
    'clientInstanceKeyTag' TEXT DEFAULT NULL,
    'deviceStatus' TEXT DEFAULT NULL,
    'createdTimestamp' TEXT DEFAULT NULL,
    'updatedTimestamp' TEXT DEFAULT NULL
    );

    CREATE UNIQUE INDEX device_index ON DeviceEnrollment(deviceId, orgId);
    """
}
