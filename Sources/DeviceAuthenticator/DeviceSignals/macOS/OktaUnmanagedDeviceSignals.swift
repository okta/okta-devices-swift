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
// swiftlint:disable force_unwrapping
// swiftlint:disable file_types_order
import Foundation
import LocalAuthentication
import SystemConfiguration
import OktaLogger

class OktaUnmanagedDeviceSignals {
    static let logEventName = "OktaUnmanagedDeviceSignals"

    class func retrieveDeviceSignals(requestedSignals: Set<RequestableSignal>,
                                     customDeviceSignals: DeviceSignals?,
                                     logger: OktaLoggerProtocol,
                                     signalsHelper: BasicSignalsHelperProtocol = BasicSignalsHelper()) -> DeviceSignalsModel {

        let deviceSignals = DeviceSignalsModel(platform: nil, osVersion: nil, displayName: nil)

        if requestedSignals.contains(.platform) {
            deviceSignals.platform = .macOS
        }

        if requestedSignals.contains(.osVersion) {
            deviceSignals.osVersion = signalsHelper.osVersion
        }

        if requestedSignals.contains(.displayName) {
            // Currently backend expects a value for displayName so using this hardcoded value as last resort if other approaches don't work
            /*
             By default, use the name passed as part of custom signals,
             if no value passed try to fetch ComputerName,
             if failed to read ComputerName then read localHostName,
             and use default name as the fallback
             */
            let displayName = customDeviceSignals?.displayName ?? deviceDisplayName() ?? "macOS device"
            deviceSignals.displayName = displayName.stripHTMLTags()
        }

        if requestedSignals.contains(.serialNumber) {
            deviceSignals.serialNumber = getSerialNumber()
        }

        if requestedSignals.contains(.udid) {
            var udid: String? = customDeviceSignals?.udid
            udid = udid ?? getSystemUUID()
            deviceSignals.udid = udid
        }

        if requestedSignals.contains(.model) {
            deviceSignals.model = deviceModel()
        }

        if requestedSignals.contains(.manufacturer) {
            deviceSignals.manufacturer = signalsHelper.manufacturer
        }

        if requestedSignals.contains(.secureHardwarePresent) {
            deviceSignals.secureHardwarePresent = signalsHelper.secureHardwarePresent
        }

        if requestedSignals.contains(.deviceAttestation) {
            deviceSignals.deviceAttestation = customDeviceSignals?.deviceAttestation
        }

        if requestedSignals.contains(.screenLockType) {
            deviceSignals.screenLockType = screenLockType(logger: logger, signalsHelper: signalsHelper)
            logger.info(eventName: logEventName, message: "screenLockType is \(String(describing: deviceSignals.screenLockType))")
        }

        if requestedSignals.contains(.diskEncryptionType) {
            //if fail to read value of diskencryption then do not send the signal back in response
            if let diskEncryptionType = getVolumesEncruptionType(logger: logger) {
                logger.info(eventName: logEventName, message: "Diskencryption type is \(diskEncryptionType)")
                deviceSignals.diskEncryptionType = diskEncryptionType
            } else {
                logger.error(eventName: logEventName, message: "Failed to read diskencryption type")
            }
        }

        return deviceSignals
    }

    private class func isVolumeHidden(value: Bool?) -> Bool {
        if let isHidden = value {
            return isHidden
        }
        return false
    }

    private class func isVolumeEjectable(value: Bool?) -> Bool {
        if let volumeIsEjectable = value {
            return volumeIsEjectable
        }
        return false
    }

    private class func isVolumeRemovable(value: Bool?) -> Bool {
        if let volumeIsRemovable = value {
            return volumeIsRemovable
        }
        return false
    }

    private class func isVolumeInternal(value: Bool?) -> Bool {
        if let volumeIsInternal = value {
            return volumeIsInternal
        }
        return false
    }

    private class func isVolumeAutomounted(value: Bool?) -> Bool {
        if let volumeIsAutomounted = value {
            return volumeIsAutomounted
        }
        return false
    }

    class func diskEncryptionTypeForVolume(values: [URLResourceKey: Any?], volumeURL: URL, logger: OktaLoggerProtocol) -> (isVolumeEncrypted: Bool?, isSystemVolume: Bool?) {
        var isSystemVolume = false
        var isVolumeEncrypted = true
        // Check only internal and system volumes, ignore rest
        if isVolumeHidden(value: values[URLResourceKey.isHiddenKey] as? Bool) {
            logger.info(eventName: logEventName, message: "Ignoring hidden volume URL: \(volumeURL.absoluteString)")
            return (nil, nil)
        }
        if isVolumeEjectable(value: values[URLResourceKey.volumeIsEjectableKey] as? Bool) {
            logger.info(eventName: logEventName, message: "Ignoring ejectable volume URL: \(volumeURL.absoluteString)")
            return (nil, nil)
        }
        if isVolumeRemovable(value: values[URLResourceKey.volumeIsRemovableKey] as? Bool) {
            logger.info(eventName: logEventName, message: "Ignoring removable volume URL: \(volumeURL.absoluteString)")
            return (nil, nil)
        }
        if !isVolumeInternal(value: values[URLResourceKey.volumeIsInternalKey] as? Bool) {
            logger.info(eventName: logEventName, message: "Ignoring external volume URL: \(volumeURL.absoluteString)")
            return (nil, nil)
        }
        if isVolumeAutomounted(value: values[URLResourceKey.volumeIsAutomountedKey] as? Bool) {
            logger.info(eventName: logEventName, message: "Ignoring recovery(automounted) volume URL: \(volumeURL.absoluteString)")
            return (nil, nil)
        }
        //check encryption status of volume
        if #available(OSX 11.0, *) {
            if let isEncrypted = values[URLResourceKey.fileProtectionKey] as? FileProtectionType {
                if isEncrypted == FileProtectionType.none {
                    logger.info(eventName: logEventName, message: "Volume \(volumeURL.absoluteString) is not encrypted, FileProtectionType is .none ")
                    isVolumeEncrypted = false
                }
                if let volumeIsRootFileSystem = values[URLResourceKey.volumeIsRootFileSystemKey] as? Bool {
                    isSystemVolume = volumeIsRootFileSystem
                }
                return (isVolumeEncrypted, isSystemVolume)
            }
        }
        //NSURLVolumeIsEncryptedKey --> gives wrong value on T2 but good to use before (https://developer.apple.com/forums/thread/99931)
        if let volumeIsEncrypted = values[URLResourceKey.volumeIsEncryptedKey] as? Bool {
            if !volumeIsEncrypted {
                logger.info(eventName: logEventName, message: "Volume \(volumeURL.absoluteString) is not encrypted, volumeIsEncrypted is false")
                isVolumeEncrypted = false
            }
            if let volumeIsRootFileSystem = values[URLResourceKey.volumeIsRootFileSystemKey] as? Bool {
                isSystemVolume = volumeIsRootFileSystem
            }
        }
        return (isVolumeEncrypted, isSystemVolume)
    }

    class func getVolumesEncruptionType(logger: OktaLoggerProtocol) -> DiskEncryptionValue? {
        let resourceKeys: [URLResourceKey] = [
            .isHiddenKey,
            .volumeIsEjectableKey,
            .volumeIsRemovableKey,
            .volumeIsAutomountedKey,
            .volumeIsInternalKey,
            .fileProtectionKey,
            .volumeIsEncryptedKey,
            .volumeIsRootFileSystemKey
        ]
        var isSystemVolumeEncrupted: Bool?
        var areAllVolumesEncrypted: Bool?
        guard let mountedVolumeURLs = FileManager.default.mountedVolumeURLs(includingResourceValuesForKeys: resourceKeys, options: .skipHiddenVolumes) else {
            logger.error(eventName: logEventName, message: "Could not read mounted volume URLs")
            return nil
        }
        for volumeURL in mountedVolumeURLs {
            var values: URLResourceValues
            do {
                 values = try volumeURL.resourceValues(forKeys: Set(resourceKeys))
            } catch {
                logger.info(eventName: logEventName, message: "Could not read resouce values for volume URL: \(volumeURL.absoluteString) ")
                continue
            }
            let diskEncryptionStatus = diskEncryptionTypeForVolume(values: values.allValues, volumeURL: volumeURL, logger: logger)
            guard  let isVolumeEncrypted = diskEncryptionStatus.isVolumeEncrypted,
                   let isSystemVolume = diskEncryptionStatus.isSystemVolume else {
                continue
            }
            areAllVolumesEncrypted = isVolumeEncrypted
            if isSystemVolume {
                isSystemVolumeEncrupted = isVolumeEncrypted
            }
            guard let areAllVolumesEncrypted = areAllVolumesEncrypted,
                let isSystemVolumeEncrupted = isSystemVolumeEncrupted else {
                continue
            }
            if !areAllVolumesEncrypted && !isSystemVolumeEncrupted {
                logger.info(eventName: logEventName, message: "volumes are not encrypted, no need to check further volumes")
                return DiskEncryptionValue.none
            }
        }
        if let areAllVolumesEncrypted = areAllVolumesEncrypted {
            if areAllVolumesEncrypted {
                return DiskEncryptionValue.allInternal
            }
        }
        if let isSystemVolumeEncrupted = isSystemVolumeEncrupted {
            if isSystemVolumeEncrupted {
                return DiskEncryptionValue.systemVolume
            }
        }
        return nil
    }

    class func diskEncryptionType(logger: OktaLoggerProtocol, signalsHelper: BasicSignalsHelper) -> DiskEncryptionValue? {
        return getVolumesEncruptionType(logger: logger)
    }

    private class func passcodeKeychainIsAccessible(logger: OktaLoggerProtocol) -> Bool {
        let key = "com.okta.macov.unmanagedsignal"
        let object = "unamangedSignalScreenLock"
        let objectData = object.data(using: .utf8)

        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword as String,
            kSecValueData as String: objectData!,
            kSecAttrAccount as String: key,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly // to check if password is set or left blank
        ]
        if #available(macOS 10.15, *) {
            q[kSecUseDataProtectionKeychain as String] = kCFBooleanTrue
        }
        // Delete existing (if applicable)
        SecItemDelete(q as CFDictionary)

        let sanityCheck = SecItemAdd(q as CFDictionary, nil)
        if sanityCheck != noErr {
            logger.error(eventName: logEventName, message: "Error Storing to Keychain: \(sanityCheck.description)")
            return false
        }
        SecItemDelete(q as CFDictionary) //cleanup key
        return true
    }

    class func screenLockType(logger: OktaLoggerProtocol, signalsHelper: BasicSignalsHelperProtocol) -> ScreenLockValue {
        if signalsHelper.screenLockType == .passcode {
            //check if password is blank
            if passcodeKeychainIsAccessible(logger: logger) {
                  return ScreenLockValue.passcode
            }
            return ScreenLockValue.none
        }
        return signalsHelper.screenLockType
    }

    class func deviceDisplayName() -> String? {
        return (SCDynamicStoreCopyComputerName(nil, nil) as String?) ?? (SCDynamicStoreCopyLocalHostName(nil) as String?)
    }

    private class func deviceModel() -> String {
        var size = 0
        sysctlbyname("hw.model", nil, &size, nil, 0)
        var model = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.model", &model, &size, nil, 0)
        return String(cString: model)
    }

    private class func getSystemUUID() -> String? {
        let platformExpert = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice") )

        guard platformExpert > 0 else {
            return nil
        }

        guard let uuid = (IORegistryEntryCreateCFProperty(platformExpert, kIOPlatformUUIDKey as CFString, kCFAllocatorDefault, 0).takeUnretainedValue() as? String)?.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines) else {
                return nil
        }
        IOObjectRelease(platformExpert)
        return uuid
    }

    private class func getSerialNumber() -> String? {
        let platformExpert = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice") )

        guard platformExpert > 0 else {
            return nil
        }

        guard let serialNumber = (IORegistryEntryCreateCFProperty(platformExpert, kIOPlatformSerialNumberKey as CFString, kCFAllocatorDefault, 0).takeUnretainedValue() as? String)?.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines) else {
            return nil
        }
        IOObjectRelease(platformExpert)
        return serialNumber
    }
}
