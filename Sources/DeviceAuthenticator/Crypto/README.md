# Okta Encryption

Proposal for encryption stack

### Desired encyption capabilties:
- creation  of keys, 
- deletion of keys
- retrieval of keys 
- storage of keys
- Signing data using a private key
- verify signedn data using a public key
- transform signature format

### Proposed solution

#### Protocol 

```swift

enum Algorithm {
    case ES256
    case RS256
}

enum KeyType {
    case privateKey
    case publicKey
}

enum SignatureFormat {
    case RAW
    case BER_ASN
}

/// Protocol for managing public and private keys
protocol OktaCryptoProtocol {
    
    /// Generate public private key pair
    /// - Parameters:
    ///   - keyPairWithAlgorithm: algorith used for generating keys
    ///   - tag: unique identifier used to store or retrieve keys
    ///   - useSecureEnclave: option to store the key in secure enclave
    ///   - useBiometrics: option to store key protected by biometrics
    /// - Returns: true if sucessful
    func generate(keyPairWith algorithm: Algorithm,with tag: String, useSecureEnclave:Bool, useBiometrics:Bool) throws
    
    ///  Delete both public and private key pair
    /// - Parameter tag: unique identifier that was used to create the keys
    /// - Returns: true if key exists and key deletion was successful
    func delete(keyPairWith tag: String) -> Bool
    
    
    /// Retrieve reference to public private key pair. This method does not return binary data of the key itself.
    /// - Parameters:
    ///   - type: Public or private key
    ///   - tag: unique identifier that was used to create the public key
    /// - Returns: Reference to SecKey if it can find the key otherwise returns nil
    func get(keyOf type: KeyType,with tag: String) -> SecKey?
    
    
    /// Sign data using a private key
    /// - Parameters:
    ///   - data: input data for which signature will be generated
    ///   - tag: unique identifier that was used to create the private keys
    ///   - format: format in which signature will be returned
    /// - Returns: returns signed data in specific format
    func sign(data: Data,withPrivatekey tag: String,in format: SignatureFormat) -> Data?
    
    
    /// Verify a signature  using public key.
    /// - Parameters:
    ///   - signature: signature data in BER encoded ANS.1 format
    ///   - format: encoding format of the signature
    ///   - data: data for which signature was generated.
    ///   - tag: unique identifier that was used to store the public key
    /// - Returns: returns true if verification is successful
    func verify(signature: Data,in format: SignatureFormat,for data: Data,withPublicKey tag: String) -> Bool
}


protocol OktaSharedCryptoProtocol: OktaCryptoProtocol {
    var accessGroupId: String { get }
}
```


#### Default implementation. Developer can change default implementation by implementing `OktaSharedEncryptionProtocol` protocol

```swift
open class OktaCryptoManager: OktaSharedCryptoProtocol {
    public internal(set) var accessGroupId: String

    init(accessGroupId: String) {
        self.accessGroupId = accessGroupId
    }

    func generate(keyPairWith algorithm: Algorithm,with tag: String, useSecureEnclave:Bool, useBiometrics:Bool) throws { 
    }
    
    func delete(keyPairWith tag: String) -> Bool {
        return false
    }
    
    
    func get(keyOf type: KeyType,with tag: String) -> SecKey? {
        return nil
    }

    func sign(data: Data,withPrivatekey tag: String,in format: SignatureFormat) -> Data? {
        return nil
    }
    
    func verify(signature: Data,in format: SignatureFormat,for data: Data,withPublicKey tag: String) -> Bool {
        return false
    }
    
}


```


#### Usage example
```swift
let cryptoManager = OktaSharedCryptoManager(accessGroupId: accessGroupId))
cryptoManager.generategenerate(keyPairWith algorithm: .ES256,with tag: "user1-org1", useSecureEnclave:false, useBiometrics:false)
```
