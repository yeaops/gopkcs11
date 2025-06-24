# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`gopkcs11` is a modern Go library for PKCS#11 integration that provides an idiomatic Go interface for working with Hardware Security Modules (HSMs) and other PKCS#11 cryptographic devices. It builds upon established libraries like `miekg/pkcs11` and `ThalesGroup/crypto11` while providing a clean, simplified API.

## Development Environment

- Go version: 1.24.4
- Module path: github.com/yeaops/gopkcs11
- Main dependency: golang.org/x/sys for system-level integration

## Common Commands

### Build and Development

```bash
# Build with PKCS#11 v2.4 (default)
make build
# or manually:
CGO_ENABLED=1 go build ./...

# Build with PKCS#11 v3.0
make build-v30
# or manually:
CGO_ENABLED=1 CGO_CFLAGS="-DPKCS11_V30" go build ./...

# Build with Utimaco HSM support
make build-utimaco
# or manually:
CGO_ENABLED=1 CGO_CFLAGS="-DUTIMACO_HSM" go build ./...

# Build with PKCS#11 v3.0 + Utimaco support
make build-v30-utimaco
# or manually:
CGO_ENABLED=1 CGO_CFLAGS="-DPKCS11_V30 -DUTIMACO_HSM" go build ./...

# Run tests
make test
# or manually:
go test ./...

# Run tests with specific configurations
make test-v30        # Test with PKCS#11 v3.0
make test-utimaco    # Test with Utimaco support
```

### Code Quality

```bash
# Run golangci-lint
golangci-lint run

# Format code
go fmt ./...

# Vet code for potential issues
go vet ./...

# Tidy dependencies
go mod tidy
```

### Header File Organization

The project uses a structured approach to manage PKCS#11 headers:

```
include/
├── pkcs11-v24/     # Official PKCS#11 v2.4 headers
│   ├── pkcs11.h
│   ├── pkcs11f.h
│   └── pkcs11t.h
├── pkcs11-v30/     # Official PKCS#11 v3.0 headers
│   ├── pkcs11.h
│   ├── pkcs11f.h
│   └── pkcs11t.h
└── utimaco/        # Utimaco HSM vendor-specific headers
    ├── cryptoki.h
    ├── cs_pkcs11ext.h
    ├── pkcs11.h
    ├── pkcs11f.h
    ├── pkcs11f_cs.h
    ├── pkcs11t.h
    └── pkcs11t_cs.h
```

## Architecture Overview

The project follows a layered architecture with clear separation of concerns:

### Core Components

1. **Context (`context.go`)**: Main entry point that manages PKCS#11 module loading, session pooling, and vendor extensions. Provides `New()` and `NewWithConfig()` for initialization.

2. **Session (`session.go`)**: Manages PKCS#11 sessions with thread-safe operations. Handles login/logout, object finding, key generation, and cryptographic operations.

3. **Objects (`object.go`)**: Provides object-oriented interfaces for PKCS#11 objects:
   - `Object`: Base interface for all PKCS#11 objects
   - `Key`: Base interface for all key types
   - `PublicKey`, `PrivateKey`, `SecretKey`: Specific key interfaces
   - Implements Go's `crypto.Signer` interface for integration with standard crypto package

4. **Types (`types.go`)**: Defines all PKCS#11 constants, types, and enums including:
   - Attribute types (CKA_*)
   - Object classes (CKO_*)
   - Key types (CKK_*)
   - Mechanism types (CKM_*)
   - Error handling with custom error types

5. **Internal Package (`internal/pkcs11/`)**: Low-level PKCS#11 wrapper using CGO:
   - `wrapper.go`: Direct C bindings to PKCS#11 functions with version-aware includes
   - `types.go`: Internal type definitions
   - `constants.go`: Internal constants
   - Supports both PKCS#11 v2.4 and v3.0 based on compile-time flags

### Vendor Extensions

The architecture supports vendor-specific extensions through a plugin-like system:
- **Thales (`thales.go`)**: Thales-specific extensions
- **Utimaco (`utimaco.go`)**: Utimaco-specific extensions
- Vendor extensions are auto-detected and registered in `Context.vendorExtensions`

### Key Architectural Patterns

1. **Interface-driven design**: Heavy use of interfaces for flexibility and testing
2. **Session pooling**: Thread-safe session management in Context
3. **Resource lifecycle management**: Clear resource cleanup patterns with defer statements
4. **Error wrapping**: Structured error handling with PKCS#11 error codes
5. **Version compatibility**: Compile-time selection between PKCS#11 v2.4 and v3.0
6. **Vendor support**: Optional compile-time inclusion of vendor-specific extensions

## API Design Principles

The library follows these design principles (documented in `api-design.md`):

1. **Minimal API surface**: Single package import with clean interfaces
2. **Go idioms**: Implements standard Go interfaces like `crypto.Signer`
3. **Resource safety**: Clear resource lifecycle management
4. **Vendor agnostic**: Core functionality works across vendors with optional extensions
5. **Version aware**: Automatic feature detection based on PKCS#11 version

## Working with PKCS#11

### Session Management Pattern
```go
ctx, err := gopkcs11.New("/path/to/library.so")
if err != nil {
    return err
}
defer ctx.Finalize()

session, err := ctx.OpenSession(slotID, flags)
if err != nil {
    return err
}
defer session.Close()
```

### Object Finding Pattern
```go
objects, err := session.FindObjects([]*Attribute{
    NewAttributeClass(CKO_PRIVATE_KEY),
    NewAttribute(CKA_LABEL, "my-key"),
})
```

### Cryptographic Operations
The library provides both low-level PKCS#11 operations and high-level Go crypto interface implementations.

## Testing Strategy

- **Unit tests**: Test individual components in isolation
- **Integration tests**: Require SoftHSM or real HSM for full PKCS#11 testing
- **Vendor tests**: Specific tests for vendor extensions
- **CGO tests**: Ensure proper C integration

## Security Considerations

1. **Credential handling**: Never hardcode PINs or sensitive data
2. **Session management**: Proper login/logout and session cleanup
3. **Memory safety**: Careful handling of C memory in CGO wrapper
4. **Thread safety**: All public APIs are thread-safe
5. **Vendor isolation**: Vendor extensions are isolated from core functionality