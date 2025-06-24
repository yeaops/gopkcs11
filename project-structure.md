# Project Structure Plan

This document outlines the proposed structure for the gopkcs11 library.

## Directory Structure

```
gopkcs11/
├── cmd/
│   └── examples/         # Example applications
├── internal/             # Internal packages not meant for external use
├── pkcs11/              # Core PKCS#11 wrapper
│   ├── constants.go     # PKCS#11 constants
│   ├── types.go         # Go types mapping to PKCS#11 types
│   └── wrapper.go       # CGo wrapper functions
├── crypto/              # Implementation of crypto interfaces
├── session/             # Session management
├── token/               # Token and slot management
├── object/              # Object management (keys, certs)
├── mechanism/           # Cryptographic mechanisms
├── vendor/              # Vendor-specific extensions
│   ├── thales/          # Thales HSM extensions
│   ├── luna/            # Luna HSM extensions
│   ├── aws/             # AWS CloudHSM extensions
│   └── utimaco/         # Utimaco HSM extensions
├── test/                # Integration tests
│   └── softhsm/         # SoftHSM specific tests
└── examples/            # Example code for documentation
```

## Core Components

### PKCS#11 Version Compatibility

- Support for both PKCS#11 v2.4 and v3.0 standards
- Version detection at runtime
- Feature detection mechanism
- Conditional functionality based on version
- Version-specific types and constants

### Vendor Extension System

- Base interface for vendor extensions
- Registration system for vendor-specific functionality
- Type definitions for vendor-specific attributes, mechanisms, and functions
- Discovery mechanism for available extensions
- Documentation for supported vendor extensions

### Configuration

- Simple configuration via a struct or JSON/YAML file
- Token initialization options
- Authentication methods
- Performance and connection pooling
- Version-specific configurations

### Session Management

- Automatic session handling
- Session pooling
- Thread safety considerations

### Crypto Operations

- Implementation of Go crypto interfaces
- Support for various key types and algorithms
- Key generation and import/export

### Object Management

- Key management (create, find, delete)
- Certificate management
- Object attribute handling

## Supported PKCS#11 Features

- Initialize/finalize
- Open/close sessions
- Login/logout
- Key generation and management
- Cryptographic operations:
  - Signing/verification
  - Encryption/decryption
  - Digest
  - Authentication codes (HMAC, etc.)
- Random number generation

## Development Roadmap

1. Core PKCS#11 wrapper implementation with version detection
2. Basic session and token management
3. Key operations and crypto interface implementations
4. Certificate operations
5. Vendor extension framework
6. Individual vendor extension implementations
7. Advanced features and optimizations