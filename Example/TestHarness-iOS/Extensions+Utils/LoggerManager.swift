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

import OktaLogger
import OktaDeviceSDK

protocol LoggerManagerProtocol {
    func clear()

    func log(level: OktaLoggerLogLevel, event: LogEvent, properties: [AnyHashable: Any]?)
    func info(event: LogEvent, properties: [AnyHashable: Any]?)
    func warning(event: LogEvent, properties: [AnyHashable: Any]?)
    func error(event: LogEvent, properties: [AnyHashable: Any]?)

    func log(level: OktaLoggerLogLevel, event: LogEvent)
    func info(event: LogEvent)
    func warning(event: LogEvent)
    func error(event: LogEvent)

    func currentLogData(completion: @escaping ([Data]) -> Void)

    func injectFileLogger(_ entity: LoggerContainable)
}

class LoggerManager: LoggerManagerProtocol {
    private struct Constants {
        static let consoleLoggerId = "TestHarness-iOS.console.logger"
        static let fileLoggerId = "TestHarness-iOS.file.logger"
    }

    static let shared = LoggerManager()

    private let logger = OktaLogger()
    private let fileDestination: OktaLoggerFileLogger

    private init(fileManager: FileManager = FileManager.default) {
        let consoleDestination = OktaLoggerConsoleLogger(identifier: Constants.consoleLoggerId, level: .all, defaultProperties: nil)

        let config = OktaLoggerFileLoggerConfig()
        config.reuseLogFiles = true
        fileDestination = OktaLoggerFileLogger(logConfig: config, identifier: Constants.fileLoggerId, level: .all, defaultProperties: nil)

        [consoleDestination, fileDestination].forEach(logger.addDestination)

        logger.log(level: .debug, eventName: "FileLogger", message: fileDestination.logDirectoryAbsolutePath(), properties: nil)
    }

    func clear() {
        logger.destinations.compactMap { $0.value as? OktaLoggerDestinationBase }.filter { $0.logsCanBePurged() }.forEach { $0.purgeLogs() }
    }

    func log(level: OktaLoggerLogLevel, event: LogEvent, properties: [AnyHashable: Any]?) {
        logger.log(level: level, eventName: event.name, message: event.message, properties: properties)
    }

    func info(event: LogEvent, properties: [AnyHashable: Any]?) {
        log(level: .info, event: event, properties: properties)
    }

    func warning(event: LogEvent, properties: [AnyHashable: Any]?) {
        log(level: .warning, event: event, properties: properties)
    }

    func error(event: LogEvent, properties: [AnyHashable: Any]?) {
        log(level: .error, event: event, properties: properties)
    }

    func log(level: OktaLoggerLogLevel, event: LogEvent) {
        log(level: level, event: event, properties: nil)
    }

    func info(event: LogEvent) {
        info(event: event, properties: nil)
    }

    func warning(event: LogEvent) {
        warning(event: event, properties: nil)
    }

    func error(event: LogEvent) {
        error(event: event, properties: nil)
    }

    func currentLogData(completion: @escaping ([Data]) -> Void) {
        fileDestination.getLogs(completion: completion)
    }

    func injectFileLogger(_ entity: LoggerContainable) {
        entity.logger?.addDestination(fileDestination)
    }
}

enum LogEvent {
    case appInit(String?)
    case registerPushNotifications(String?)
    case pushTokenUpdate(String?)
    case enrollment(String?)
    case accountDetails(String?)
    case updatePushToken(String?)
    case deleteAccount(String?)
    case sendingSqliteFiles(String?)
    case pendingChallenge(String?)
}
extension LogEvent {
    var name: String {
        switch self {
        case .appInit: return "ApplicationStartup"
        case .registerPushNotifications: return "RegisterForRemoteNotifications"
        case .pushTokenUpdate: return "PushTokenUpdate"
        case .enrollment: return "Enrollment"
        case .accountDetails: return "AccountDetails"
        case .updatePushToken: return "UpdatePushToken"
        case .deleteAccount: return "DeleteAccount"
        case .sendingSqliteFiles: return "SendingSqliteFilesToEmail"
        case .pendingChallenge: return "PendingChallenge"
        }
    }

    var message: String? {
        switch self {
        case .appInit(let message): return message
        case .registerPushNotifications(let message): return message
        case .pushTokenUpdate(let message): return message
        case .enrollment(let message): return message
        case .accountDetails(let message): return message
        case .updatePushToken(let message): return message
        case .deleteAccount(let message): return message
        case .sendingSqliteFiles(let message): return message
        case .pendingChallenge(let message): return message
        }
    }
}

protocol LoggerContainable: AnyObject {
    var logger: OktaLogger! { get }
}
