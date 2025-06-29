# gopkcs11

A Go wrapper for PKCS#11 (Cryptoki) operations with HSM (Hardware Security Module) support.

## Features

- **Key Management**: Generate, import, and manage RSA/ECDSA key pairs and AES/DES symmetric keys
- **Digital Signing**: Support for multiple hash algorithms (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512)
- **Encryption/Decryption**: RSA encryption with PKCS#1 v1.5 and OAEP padding
- **Key Wrapping**: Secure key wrapping and unwrapping operations
- **Flexible Slot Identification**: Support for slot ID, slot index, token label, or token serial number
- **Thread-Safe**: Concurrent operations with proper session management
- **Comprehensive Error Handling**: Detailed PKCS#11 error codes and typed errors

## Installation

```bash
go get github.com/yeaops/gopkcs11
```

## Quick Start

### Basic Usage

```go
package main

import (
    "crypto"
    "crypto/rand"
    "crypto/sha256"
    "log"
    
    "github.com/yeaops/gopkcs11"
)

func main() {
    // Create configuration
    config := gopkcs11.NewConfigWithSlotID("/usr/lib/pkcs11/libpkcs11.so", 0, "userPIN")
    
    // Create client
    client, err := gopkcs11.NewClient(config)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()
    
    // Generate RSA key pair
    keyPair, err := client.GenerateRSAKeyPair("my-rsa-key", 2048)
    if err != nil {
        log.Fatal(err)
    }
    
    // Sign data
    signer := keyPair.AsSigner(client)
    data := []byte("Hello, World!")
    hash := sha256.Sum256(data)
    signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Signature: %x", signature)
}
```

### Environment Configuration

```bash
export PKCS11_LIBRARY_PATH="/usr/lib/pkcs11/libpkcs11.so"
export PKCS11_SLOT_ID="0"
export PKCS11_USER_PIN="your-pin"
```

```go
config, err := gopkcs11.NewConfigFromEnv()
if err != nil {
    log.Fatal(err)
}
client, err := gopkcs11.NewClient(config)
```

## Key Operations

### RSA Key Pair

```go
// Generate RSA key pair
keyPair, err := client.GenerateRSAKeyPair("my-rsa-key", 2048)

// Get RSA-specific operations
rsaKey, err := client.GetRSAKeyPair("my-rsa-key")

// Sign with different padding schemes
signature1, err := rsaKey.SignPKCS1v15(crypto.SHA256, hash)
signature2, err := rsaKey.SignPSS(crypto.SHA256, hash)

// Decrypt with different padding schemes
plaintext1, err := rsaKey.DecryptPKCS1v15(ciphertext)
plaintext2, err := rsaKey.DecryptOAEP(crypto.SHA256, ciphertext, nil)
```

### ECDSA Key Pair

```go
// Generate ECDSA key pair
keyPair, err := client.GenerateECDSAKeyPair("my-ecdsa-key", elliptic.P256())

// Get ECDSA-specific operations
ecdsaKey, err := client.GetECDSAKeyPair("my-ecdsa-key")

// Sign with ECDSA
signature, err := ecdsaKey.SignHash(crypto.SHA256, hash)
```

### Symmetric Keys

```go
// Generate AES key
aesKey, err := client.GenerateAESKey("my-aes-key", 256)

// Encrypt/decrypt data
ciphertext, err := client.EncryptData(aesKey, gopkcs11.CKM_AES_CBC, iv, data)
plaintext, err := client.DecryptData(aesKey, gopkcs11.CKM_AES_CBC, iv, ciphertext)
```

## Configuration Options

### Slot Identification Methods

```go
// By Slot ID (most common)
config := gopkcs11.NewConfigWithSlotID("/path/to/lib.so", 0, "pin")

// By Slot Index
config := gopkcs11.NewConfigWithSlotIndex("/path/to/lib.so", 0, "pin")

// By Token Label
config := gopkcs11.NewConfigWithTokenLabel("/path/to/lib.so", "MyToken", "pin")

// By Token Serial Number
config := gopkcs11.NewConfigWithTokenSerial("/path/to/lib.so", "123456", "pin")
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PKCS11_LIBRARY_PATH` | Path to PKCS#11 library | Auto-detect bundled SoftHSM |
| `PKCS11_USER_PIN` | User PIN for authentication | Required |
| `PKCS11_SLOT_ID` | Slot ID to use | - |
| `PKCS11_SLOT_INDEX` | Slot index to use | - |
| `PKCS11_TOKEN_LABEL` | Token label to use | - |
| `PKCS11_TOKEN_SERIAL` | Token serial number to use | - |

## Error Handling

```go
if gopkcs11.IsKeyNotFoundError(err) {
    // Handle key not found
}
if gopkcs11.IsAuthenticationError(err) {
    // Handle authentication failure
}
if gopkcs11.IsSessionError(err) {
    // Handle session-related errors
}
```

## Supported Algorithms

### Asymmetric Keys
- **RSA**: 2048, 4096 bits
- **ECDSA**: P-256, P-384 curves

### Hash Algorithms
- SHA-1, SHA-224, SHA-256, SHA-384, SHA-512

### RSA Padding Schemes
- PKCS#1 v1.5 (signing and encryption)
- PSS (signing)
- OAEP (encryption)

### Symmetric Keys
- **AES**: 128, 192, 256 bits
- **DES**: 64 bits
- **3DES**: 192 bits

## Security Considerations

- Private keys are marked as non-extractable and sensitive
- All cryptographic operations are performed within the HSM
- Session management includes proper cleanup and logout procedures
- Error messages avoid leaking sensitive information

## Testing

```bash
go test ./...
```

## License

This project is licensed under the MIT License.