# PKCS#11 E2E Tests with SoftHSM

End-to-end test suite for PKCS#11 functionality using SoftHSM as a software-based Hardware Security Module.

## Overview

This test suite validates:
- **Key Management**: RSA, ECDSA, AES key generation and discovery
- **Cryptographic Operations**: Digital signing, encryption/decryption, key wrapping
- **Performance**: Concurrent operations, large data handling, memory usage
- **Integration**: Complete workflows from key generation to certificate creation

## Quick Start

1. **Install SoftHSM**:
   ```bash
   ./install-softhsmv2.sh
   ```

2. **Run Basic Tests**:
   ```bash
   go test -v ./... -short=false
   ```

3. **Run Specific Test Categories**:
   ```bash
   # Basic functionality
   go test -run TestToken -v
   
   # Advanced features
   go test -run TestConcurrent -v
   
   # Performance benchmarks
   go test -bench=. -v
   ```

## Test Structure

- **`e2e_basic_test.go`** - Core functionality (connections, key gen, signing)
- **`e2e_advanced_test.go`** - Advanced features (concurrency, performance, PSS)
- **`e2e_softhsm_test.go`** - SoftHSM setup and configuration
- **`e2e_softhsm_common_test.go`** - Test utilities and helpers
- **`example_test.go`** - Usage examples and documentation

## Installation

### Automatic Installation
```bash
./install-softhsmv2.sh
```

### Manual Installation
See platform-specific instructions in the install script.

### Custom Library Path
```bash
export PKCS11_LIBRARY_PATH="/path/to/libsofthsm2.so"
go test -v ./...
```

## Configuration

### Environment Variables
- `PKCS11_LIBRARY_PATH` - Custom SoftHSM library path
- `SOFTHSM2_CONF` - Custom SoftHSM configuration file

### Test Modes
```bash
# Skip long-running tests
go test -v -short ./...

# Include benchmarks
go test -v -bench=. ./...

# Specific test pattern
go test -v -run TestRSA ./...
```

## Requirements

- Go 1.19+
- SoftHSM v2.6.1+ (installed via provided script)
- Platform-specific build tools:
  - **Linux**: build-essential, libssl-dev
  - **macOS**: Xcode tools, Homebrew
  - **Windows**: MSYS2/MinGW

## Cross-Platform Support

Tests run on:
- Linux (Ubuntu, CentOS, RHEL)
- macOS (Intel/Apple Silicon)
- Windows (MSYS2/MinGW)

## Notes

- Tests automatically skip in `-short` mode
- Each test runs in isolation with fresh SoftHSM tokens
- Automatic cleanup of test artifacts
- No external dependencies beyond SoftHSM
- Safe for CI/CD environments