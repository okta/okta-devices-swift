/*
* Copyright (c) 2022, Okta, Inc. and/or its affiliates. All rights reserved.
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

struct OktaFile {
    public let fileName: String
    public let attachment: Data
}

enum OktaFilesManagerError: Error {
    case directoryNotFound
    case failedToReadData(Error)
    case emptyDirectory
}

typealias OktaFilesManagerCompletionHandler = Result<[OktaFile], OktaFilesManagerError>

protocol OktaFilesManagerProtocol {
    func getFiles(from directoryURL: URL?, completion: @escaping (OktaFilesManagerCompletionHandler) -> Void)
}

class OktaFilesManager: OktaFilesManagerProtocol {
    static let shared = OktaFilesManager()

    private init() {}

    func getFiles(from directoryUrl: URL?, completion: @escaping (OktaFilesManagerCompletionHandler) -> Void) {
        guard let directoryUrl = directoryUrl else {
            completion(.failure(.directoryNotFound))
            return
        }

        DispatchQueue.global().async {
            do {
                let fileManager = FileManager.default
                let items = try fileManager.contentsOfDirectory(atPath: directoryUrl.path)
                let result: [OktaFile] = items.compactMap { item in
                    if let data = try? Data(contentsOf: directoryUrl.appendingPathComponent(item)) {
                        return OktaFile(fileName: item, attachment: data)
                    }
                    return nil
                }
                DispatchQueue.main.async {
                    if result.isEmpty {
                        completion(.failure(.emptyDirectory))
                    } else {
                        completion(.success(result))
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    completion(.failure(.failedToReadData(error)))
                }
            }
        }
    }
}
