# GoPKCS11

A Go wrapper for PKCS#11 (Cryptoki) operations with HSM (Hardware Security Module) support.

## Features

- **Multiple Key Types**: RSA, ECDSA, and ED25519 key pair support
- **Symmetric Encryption**: AES encryption with CBC mode and PKCS#7 padding
- **Standard Interfaces**: Implements Go's `crypto.Signer` and `crypto.Decrypter`
- **Comprehensive Testing**: Full test suite with SoftHSM integration

## Installation

```bash
go get github.com/yeaops/gopkcs11
```

## Quick Start

```go
package main

import (
    "context"
    "crypto"
    "crypto/sha256"
    "fmt"
    "time"

    "github.com/yeaops/gopkcs11"
)

func main() {
    // Configure connection to PKCS#11 device
    config := &gopkcs11.Config{
        LibraryPath:           "/usr/lib/softhsm/libsofthsm2.so",
        SlotID:                &[]uint{0}[0], // Use slot 0
        UserPIN:               "1234",
        MaxSessions:           10,
        SessionAcquireTimeout: 5 * time.Second,
    }

    // Create token connection
    token, err := gopkcs11.NewToken(config)
    if err != nil {
        panic(fmt.Sprintf("Failed to create token: %v", err))
    }
    defer token.Close()

    ctx := context.Background()

    // Generate RSA key pair
    keyPair, err := token.GenerateRSAKeyPair(ctx, "my-key", 2048)
    if err != nil {
        panic(fmt.Sprintf("Failed to generate key: %v", err))
    }

    // Use as standard crypto.Signer
    signer := keyPair.AsSigner()
    data := []byte("Hello, PKCS#11!")
    hash := sha256.Sum256(data)
    
    signature, err := signer.Sign(nil, hash[:], crypto.SHA256)
    if err != nil {
        panic(fmt.Sprintf("Failed to sign: %v", err))
    }

    fmt.Printf("Signature created: %d bytes\n", len(signature))
}
```
## Testing

### Unit Tests
```bash
# Run fast unit tests
go test -v -short ./...

# Run all tests including slower integration tests
go test -v ./...
```

### End-to-End Tests with SoftHSM
```bash
# Install SoftHSM (automated script)
cd test/e2e/softhsm
./install-softhsmv2.sh

# Run comprehensive e2e tests
go test -v ./...

# Run specific test categories
go test -run TestRSA -v          # RSA functionality
go test -run TestConcurrent -v   # Concurrency tests
go test -bench=. -v              # Benchmarks
```

### Custom PKCS#11 Library
```bash
# Test with your own PKCS#11 library
export PKCS11_LIBRARY_PATH="/path/to/your/pkcs11.so"
go test -v ./...
```

## Requirements

- **Go**: 1.24+ (uses `iter` package)
- **PKCS#11 Library**: Hardware HSM or software implementation
  - SoftHSM v2.6.1+ (for testing)
  - Utimaco HSM
- **Build Tools**:
  - Linux: `build-essential`, `libssl-dev`
  - macOS: Xcode tools
  - Windows: MSYS2/MinGW

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
