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

import Foundation

// Use OktaLock class in case if you want to synchronize access to shared resource. This implementation doesn't block cocurrent readers
// Active writer lock locks both pending readers and writers
// Active reader lock locks only pending writer
final class OktaLock {

    // call writeLock before updating the resource
    func writeLock() {
        pthread_rwlock_wrlock(&lock)
    }

    // call readLock before reading from the resource
    func readLock() {
        pthread_rwlock_rdlock(&lock)
    }

    // call unlock when you are done with reading/writing
    func unlock() {
        pthread_rwlock_unlock(&lock)
    }

    init() {
        self.lock = pthread_rwlock_t()
        pthread_rwlock_init(&self.lock, nil)
    }

    private var lock: pthread_rwlock_t
}
