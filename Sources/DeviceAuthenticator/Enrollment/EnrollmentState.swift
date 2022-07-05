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

///  Last known enrollment state as returned by API calls
public enum EnrollmentState {
    ///  Enrollment is active, no errors
    case active
    ///  Enrollment is currently inactive, but may become active later
    case suspended
    ///  Enrollment is permanently inactive/deleted
    case deleted
    ///  Enrollment was reset, need to re-enroll
    case reset
}
