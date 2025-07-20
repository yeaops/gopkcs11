# End-to-End Testing for Utimaco CryptoServer

This directory contains comprehensive end-to-end tests for the GoPKCS11 library with Utimaco CryptoServer HSMs.

## Overview

The Utimaco test suite provides:
- Automated configuration file generation using the `CS_PKCS11_R3_CFG` environment variable
- Support for both hardware devices and simulators
- Comprehensive cryptographic operation testing (RSA, ECDSA, ED25519, AES)
- Session pooling and concurrency testing
- Integration with the common e2e test framework

## Prerequisites

### Utimaco CryptoServer PKCS#11 Library

You need the Utimaco PKCS#11 library (`libcs_pkcs11_R3.so`) installed on your system. This library is typically located at:

- `/usr/lib/libcs_pkcs11_R3.so`
- `/opt/utimaco/lib/libcs_pkcs11_R3.so`
- `/usr/local/lib/libcs_pkcs11_R3.so`
- `/usr/lib64/libcs_pkcs11_R3.so`

### Utimaco Device or Simulator

You can test with either:
1. **Utimaco CryptoServer Simulator** (recommended for development)
2. **Physical Utimaco CryptoServer device**
3. **Remote Utimaco CryptoServer**

## Configuration

### Environment Variables

The following environment variables configure the Utimaco testing:

```bash
# Required: Path to Utimaco PKCS#11 library
export PKCS11_LIBRARY_PATH="/usr/lib/libcs_pkcs11_R3.so"

# Required: Device specification
# For simulator (default):
export UTIMACO_DEVICE="3001@127.0.0.1"
# For local PCI device:
export UTIMACO_DEVICE="/dev/cs2.0"
# For remote device:
export UTIMACO_DEVICE="192.168.1.100"
# For cluster:
export UTIMACO_DEVICE="{ 192.168.1.100 288@192.168.1.101 }"

# Optional: Authentication PIN (default: "12345678")
export UTIMACO_USER_PIN="your_pin_here"

# Optional: Specific slot ID (auto-detected if not specified)
export UTIMACO_SLOT_ID="0"
```

### Automatic Configuration

The test suite automatically:
1. Generates a configuration file using the template `utimaco-cs_pkcs11_R3.cfg.tmpl`
2. Sets the `CS_PKCS11_R3_CFG` environment variable to point to the generated config
3. Configures logging, session management, and device connection parameters
4. Cleans up temporary files after testing

## Quick Start

### 1. Setup Environment

Run the setup script to check your environment and get configuration guidance:

```bash
cd test/e2e/utimaco
./setup-utimaco.sh
```

### 2. Configure Environment Variables

Set the required environment variables based on your setup:

```bash
# Example for simulator
export PKCS11_LIBRARY_PATH="/usr/lib/libcs_pkcs11_R3.so"
export UTIMACO_DEVICE="3001@127.0.0.1"
export UTIMACO_USER_PIN="12345678"
```

### 3. Run Tests

```bash
# Run all Utimaco tests
go test -v ./...

# Run specific test categories
go test -run TestUtimacoToken -v        # Token management tests
go test -run TestUtimacoKeypair -v      # Key pair operations
go test -run TestUtimacoCipher -v       # Encryption/decryption tests
go test -run TestUtimacoSymmetric -v    # Symmetric key operations

# Run with verbose output and specific timeout
go test -v -timeout 30m ./...
```

## Test Structure

### Test Categories

1. **Token Tests** (`TestUtimacoTokenFunctionality`)
   - Token initialization and connection
   - Session management and pooling
   - Slot enumeration and selection

2. **Key Pair Tests** (`TestUtimacoKeypairFunctionality`)
   - RSA key generation and operations (2048, 4096 bits)
   - ECDSA key generation and signing (P-256, P-384, P-521)
   - ED25519 key generation and signing
   - Key import/export operations

3. **Cipher Tests** (`TestUtimacoCipherFunctionality`)
   - RSA encryption/decryption (PKCS#1 v1.5, OAEP)
   - AES encryption/decryption (ECB, CBC, GCM modes)
   - Large data handling and streaming operations

4. **Symmetric Key Tests** (`TestUtimacoSymmetricKeyFunctionality`)
   - AES key generation (128, 192, 256 bits)
   - Symmetric encryption operations
   - Key derivation and management

### Configuration Options

The test suite supports different configurations based on HSM capabilities:

```go
// Example configuration for Utimaco
config := &e2e.CommonTestConfig{
    SkipConcurrencyTests: false,        // Utimaco supports concurrency
    SkipLargeDataTests:   false,        // Hardware HSMs handle large data
    SkipPerformanceTests: false,        // Performance testing enabled
    MaxTestDataSize:      2 * 1024 * 1024, // 2MB max test data
    MaxConcurrentOps:     10,           // 10 concurrent operations
    SupportedRSAKeySizes: []int{2048, 4096},
    SupportedAESKeySizes: []int{128, 192, 256},
    SupportedECDSACurves: []string{"P256", "P384", "P521"},
    SupportedCipherModes: []string{"ECB", "CBC", "GCM"},
}
```

## Device-Specific Notes

### CryptoServer Simulator

For testing with the Utimaco simulator:
- Default device: `3001@127.0.0.1`
- Typically runs on port 3001
- No special authentication required beyond user PIN
- Supports all cryptographic operations

### Physical CryptoServer

For testing with physical devices:
- Device path: `/dev/cs2.0` (Linux) or `PCI:0` (Windows)
- May require specific authentication
- Performance will be different from simulator
- Hardware-specific limitations may apply

### Remote CryptoServer

For testing with remote devices:
- Specify IP address or hostname
- Ensure network connectivity
- May require VPN or specific network configuration
- Consider latency for performance tests

## Troubleshooting

### Common Issues

1. **Library not found**: Ensure `PKCS11_LIBRARY_PATH` points to valid library
2. **Device connection failed**: Check `UTIMACO_DEVICE` specification and network connectivity
3. **Authentication failed**: Verify `UTIMACO_USER_PIN` is correct
4. **Slot not found**: Check if slot is available and properly configured

### Debug Configuration

Enable verbose logging by modifying the configuration:

```bash
# The test suite automatically configures logging
# Logs are written to /tmp/utimaco-test/logs/
```

### Environment Validation

Use the setup script to validate your environment:

```bash
./setup-utimaco.sh
```

## Integration with CI/CD

For automated testing in CI/CD pipelines:

```bash
# Example CI script
export PKCS11_LIBRARY_PATH="/usr/lib/libcs_pkcs11_R3.so"
export UTIMACO_DEVICE="3001@127.0.0.1"  # Simulator
export UTIMACO_USER_PIN="12345678"

cd test/e2e/utimaco
go test -v -timeout 30m ./...
```

## Files

- `utimaco.go` - Main test implementation and HSM interface
- `utimaco_test.go` - Test cases and configuration
- `utimaco-cs_pkcs11_R3.cfg.tmpl` - Configuration file template
- `setup-utimaco.sh` - Environment setup script
- `README.md` - This documentation
