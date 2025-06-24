# gopkcs11

A Go library for PKCS#11 integration that provides a modern, idiomatic interface for working with Hardware Security Modules (HSMs) and other PKCS#11 cryptographic devices.

## Overview

`gopkcs11` is inspired by and builds upon the solid foundations of [miekg/pkcs11](https://github.com/miekg/pkcs11) and [ThalesGroup/crypto11](https://github.com/ThalesGroup/crypto11). It aims to provide:

- Clean, idiomatic Go API for PKCS#11 operations
- Standard Go cryptographic interfaces (`crypto.Signer`, `crypto.Decrypter`, etc.)
- Simplified session and object management
- Comprehensive security controls and best practices
- Thorough documentation and examples

## Features

- Simple initialization and configuration
- Key generation and management
- Cryptographic operations (signing, encryption/decryption)
- Certificate management
- Session handling
- Support for various HSM vendors

## Installation

```bash
go get github.com/yeaops/gopkcs11
```

## Build Options

gopkcs11 supports multiple build configurations to accommodate different PKCS#11 versions and vendor-specific extensions:

### Standard Builds

```bash
# Build with PKCS#11 v2.4 (default)
make build

# Build with PKCS#11 v3.0
make build-v30
```

### Vendor-Specific Builds

```bash
# Build with Utimaco HSM support (v2.4 + Utimaco extensions)
make build-utimaco

# Build with PKCS#11 v3.0 + Utimaco support
make build-v30-utimaco
```

### Manual Build Commands

```bash
# PKCS#11 v2.4 (default)
CGO_ENABLED=1 go build ./...

# PKCS#11 v3.0
CGO_ENABLED=1 CGO_CFLAGS="-DPKCS11_V30" go build ./...

# Utimaco HSM support
CGO_ENABLED=1 CGO_CFLAGS="-DUTIMACO_HSM" go build ./...

# PKCS#11 v3.0 + Utimaco
CGO_ENABLED=1 CGO_CFLAGS="-DPKCS11_V30 -DUTIMACO_HSM" go build ./...
```

## Header Files

The project includes official PKCS#11 headers and vendor-specific extensions:

- `include/pkcs11-v24/`: Official PKCS#11 v2.4 headers
- `include/pkcs11-v30/`: Official PKCS#11 v3.0 headers  
- `include/utimaco/`: Utimaco u.trust Anchor cHSM headers

## Basic Usage

```go
package main

import (
    "fmt"
    "github.com/yeaops/gopkcs11"
)

func main() {
    // Initialize with your PKCS#11 provider
    ctx, err := gopkcs11.New("/path/to/pkcs11/library.so")
    if err != nil {
        panic(err)
    }
    defer ctx.Finalize()
    
    // Check version and vendor support
    major, minor := ctx.CompileTimeVersion()
    fmt.Printf("Compiled with PKCS#11 v%d.%d\n", major, minor)
    
    if ctx.HasUtimacoSupport() {
        fmt.Println("Utimaco HSM support available")
    }
    
    // Get slots and open session
    slots, _ := ctx.GetSlotList(true)
    session, _ := slots[0].OpenSession(gopkcs11.CKF_SERIAL_SESSION | gopkcs11.CKF_RW_SESSION)
    defer session.Close()
    
    // Login and use PKCS#11 functionality
    session.Login(gopkcs11.CKU_USER, "1234")
    defer session.Logout()
    
    // Use cryptographic operations...
}
```

## Development Status

This project provides a complete, production-ready PKCS#11 interface for Go with support for multiple PKCS#11 versions and vendor extensions.

## License

[License to be determined]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.