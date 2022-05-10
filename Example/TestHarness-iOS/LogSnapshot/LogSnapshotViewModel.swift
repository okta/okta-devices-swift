/*
* Copyright (c) 2019-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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
import OktaLogger

protocol LogSnapshotViewModelProtocol {

    var view: LogSnapshotViewProtocol? { set get }
    var isLogsFileEmpty: Bool { get }
    var logsString: String { get }

    func start()
}

class LogSnapshotViewModel: LogSnapshotViewModelProtocol {

    private let logger: LoggerManagerProtocol

    weak var view: LogSnapshotViewProtocol?

    var logsString: String = ""
    var isLogsFileEmpty: Bool {
        logsString.isEmpty
    }

    init(logger: LoggerManagerProtocol) {
        self.logger = logger
    }

    func start() {
        logger.currentLogData(completion: { [weak self] dataArray in
            let logStrings = dataArray.compactMap { String(data: $0, encoding: .utf8) }
            self?.logsString = logStrings.joined(separator: "\n")
            self?.view?.updateData()
            DispatchQueue.main.async {
                self?.view?.updateUI()
            }
        })
    }
}
