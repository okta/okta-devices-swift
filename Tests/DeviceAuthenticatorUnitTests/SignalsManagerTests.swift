/*
* Copyright (c) 2021, Okta, Inc. and/or its affiliates. All rights reserved.
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
import XCTest
@testable import DeviceAuthenticator

class SignalsManagerTests: XCTestCase {
    var signalPath: String?
    let encoder = JSONEncoder()
    let decoder = JSONDecoder()
    static let testSignal = "test_signal"
    static let testErrorOne = DeviceAuthenticatorError.genericError("Signal collection failed")
    static let testErrorTwo = DeviceAuthenticatorError.genericError("Collection failed: default handler not yet implemented")
    static let testErrorThree = DeviceAuthenticatorError.genericError("configuration not found")
    static let testErrorFour = DeviceAuthenticatorError.genericError("Collection failed: signal plugins not yet initialized")
    static let testErrorOneEncoded = "\(testErrorOne)".data(using: .utf8)!.base64EncodedString()
    static let testErrorTwoEncoded = "\(testErrorTwo)".data(using: .utf8)!.base64EncodedString()
    static let testErrorThreeEncoded = "\(testErrorThree)".data(using: .utf8)!.base64EncodedString()
    static let testErrorFourEncoded = "\(testErrorFour)".data(using: .utf8)!.base64EncodedString()

    override func setUp() {
        let resourcesPath = Bundle(for: type(of: self)).resourcePath
        signalPath = resourcesPath! + "/pluginSignal.txt"
    }

    func testInitializeEDRProviders() {
        let signalsManager = SignalsManager(logger: OktaLoggerMock())
        var dataList: [Data] = []
        do {
            for entry in TestUtils.getValidEDRConfigs(path: signalPath) {
                dataList.append(try JSONSerialization.data(withJSONObject: entry, options: .prettyPrinted))
            }
        } catch {
            XCTFail()
        }
        signalsManager.initializeSignalPlugins(plugins: [], externalConfigs: dataList)
        let pluginCollection = signalsManager.signalPluginFactory?.signalPluginConfigCollection

        #if os(macOS)
        let integrationDataOne = signalsManager.collectSignals(with: "name_1")
        let integrationSignalOne = decodeSignal(integrationData: integrationDataOne)
        XCTAssertEqual(integrationSignalOne, SignalsManagerTests.testSignal)

        let integrationDataTwo = signalsManager.collectSignals(with: "name_2")
        let integrationErrorTwo = decodeError(integrationData: integrationDataTwo)
        XCTAssertEqual(integrationErrorTwo, "\(SignalsManagerTests.testErrorOneEncoded)")
        #else
        let integrationDataTwo = signalsManager.collectSignals(with: "name_2")
        let integrationErrorTwo = decodeError(integrationData: integrationDataTwo)
        XCTAssertEqual(integrationErrorTwo, "\(Self.testErrorTwo)")
        #endif

        let integrationDataThree = signalsManager.collectSignals(with: "name_3")
        let integrationErrorThree = decodeError(integrationData: integrationDataThree)
        XCTAssertEqual(integrationErrorThree, "\(Self.testErrorTwo)")

        let integrationDataFour = signalsManager.collectSignals(with: "name_4")
        let integrationErrorFour = decodeError(integrationData: integrationDataFour)
        XCTAssertEqual(integrationErrorFour, "\(Self.testErrorThree)")

        XCTAssertTrue(pluginCollection?.signalPluginConfigMap.count == 3)
        XCTAssertNotNil(pluginCollection?.signalPluginConfigMap["name_1"])
        XCTAssertNotNil(pluginCollection?.signalPluginConfigMap["name_2"])
        XCTAssertNotNil(pluginCollection?.signalPluginConfigMap["name_3"])

        signalsManager.updateAll(plugins: [], externalConfigs: [])
        let newPluginCollection = signalsManager.signalPluginFactory?.signalPluginConfigCollection
        XCTAssertTrue(newPluginCollection!.signalPluginConfigMap.isEmpty)
    }

    func testIntegrationConfigurationHandlerInitWithBadConfigs() {
        let signalsManager = SignalsManager(logger: OktaLoggerMock())
        let integrationData = signalsManager.collectSignals(with: "name_1")
        let integrationError = decodeError(integrationData: integrationData)
        XCTAssertEqual(integrationError, "\(Self.testErrorFour)")

        var dataList: [Data] = []
        do {
            for entry in TestUtils.getInvalidEDRConfigs() {
                dataList.append(try JSONSerialization.data(withJSONObject: entry, options: .prettyPrinted))
            }
        } catch {
            XCTFail()
        }
        signalsManager.initializeSignalPlugins(plugins: [], externalConfigs: dataList)
        let pluginCollection = signalsManager.signalPluginFactory?.signalPluginConfigCollection
        XCTAssertTrue(pluginCollection!.signalPluginConfigMap.isEmpty)
        XCTAssertNil(pluginCollection?.signalPluginConfigMap["name_1"])
        XCTAssertNil(pluginCollection?.signalPluginConfigMap["name_2"])
    }

    func testDeviceIntegritySignalProvider() {
        let name = "com.okta.device.integrity"
        let pluginMock = SignalPluginMock()
        pluginMock.config = _SignalPluginConfig(name: name, description: "", type: "", typeData: [: ])
        let signalsManager = SignalsManager(logger: OktaLoggerMock())
        signalsManager.initializeSignalPlugins(plugins: [pluginMock], externalConfigs: [])

        // first trigger an error
        var signals = signalsManager.collectSignals(with: name)
        var expected = _IntegrationData.error(SignalPluginMock.mockError)
        let encoder = JSONEncoder()
        XCTAssertEqual(try? encoder.encode(signals), try? encoder.encode(expected))

        // now produce real signals
        var signalMock = IntegritySignalMock()
        signalMock.hook = true
        signalMock.jailbreak = true

        let collectionTime = 12345
        let signal = String(data: try! encoder.encode(signalMock), encoding: .utf8)!
        let configuration = _DeviceChallengeTokenConfiguration.local
        let signalData = _PluginSignalData(name: name, configuration: configuration, signal: signal, timeCollected: collectionTime)
        pluginMock.signals = _IntegrationData.signal(signalData)

        signals = signalsManager.collectSignals(with: name)
        expected = pluginMock.signals
        XCTAssertEqual(try? encoder.encode(signals), try? encoder.encode(expected))

        if case .signal(let integrationData) = signals {
            XCTAssertEqual(integrationData.timeCollected, collectionTime)
            XCTAssertEqual(integrationData.name, name)
            XCTAssertEqual(integrationData.configuration.type, configuration.type)
            XCTAssertEqual(integrationData.signal, signal)
        } else {
            XCTFail()
        }

        // use a nonexistent name, expect error
        let fakeName = "hello world"
        signals = signalsManager.collectSignals(with: fakeName)
        expected = _IntegrationData.error(_PluginSignalError.notFoundError(name: fakeName))
        XCTAssertEqual(try? encoder.encode(signals), try? encoder.encode(expected))
    }

    // Verify that the integration response matches that expected by the API spec
    func testIntegrationDataResponse_DefaultType() {
        let expectedJson = "{\"configuration\":{\"type\":\"DEFAULT\",\"format\":\"JSON\"},\"name\":\"com.okta.integration\",\"signal\":\"exampleSignal\",\"timeCollected\":1591917512}"

        let config = _DeviceChallengeTokenConfiguration.local
        let signalData = _PluginSignalData(name: "com.okta.integration", configuration: config, signal: "exampleSignal", timeCollected: 1591917512)
        let integrationData = _IntegrationData.signal(signalData)

        guard let data = try? JSONEncoder().encode(integrationData),
              let json = String(data: data, encoding: .utf8) else {
                  XCTFail()
                  return
              }

        XCTAssertEqual(json, expectedJson)
    }

    func decodeError(integrationData: _IntegrationData) -> String {
        do {
            let data = try encoder.encode(integrationData)
            let dict = try? JSONSerialization.jsonObject(with: data, options: .allowFragments) as? [String: Any]
            return dict?["error"] as! String
        } catch {
            XCTFail()
            return ""
        }
    }

    func decodeSignal(integrationData: _IntegrationData) -> String {
        do {
            let data = try encoder.encode(integrationData)
            let dict = try? JSONSerialization.jsonObject(with: data, options: .allowFragments) as? [String: Any]
            let encodedSignal = dict?["signal"] as! String
            return String(data: Data(base64Encoded: encodedSignal)!, encoding: .utf8)!
        } catch {
            XCTFail()
            return ""
        }
    }
}


