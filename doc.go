// Package gopkcs11 provides a high-level Go wrapper for PKCS#11 (Cryptoki) operations
// with Hardware Security Module (HSM) support. It simplifies interaction with PKCS#11
// compliant devices by providing abstractions for key management, digital signing,
// encryption/decryption, and symmetric key operations.
//
// The library is designed to be thread-safe and provides a clean, idiomatic Go interface
// for HSM operations while maintaining security best practices such as marking keys as
// non-extractable and sensitive.
//
// # Core Components
//
// The library is organized around several key components:
//
// **Token**: The main entry point that manages the PKCS#11 context, session, and
// authentication. It handles connection to HSM devices and provides methods for
// key generation, import, and management.
//
// **KeyPair**: Represents asymmetric key pairs (RSA, ECDSA, ED25519) stored in the HSM.
// Each key pair includes both private and public key handles, along with metadata
// such as label, ID, and key type.
//
// **SymmetricKey**: Represents symmetric encryption keys (AES, DES, 3DES) stored in the HSM.
// Used for bulk encryption/decryption operations and key wrapping/unwrapping.
//
// **BlockCipher**: Interface for block cipher operations with support for multiple
// AES modes (ECB, CBC, GCM) and streaming operations.
//
// **Error Handling**: Comprehensive error types that categorize PKCS#11 errors for
// easier handling and debugging.
//
// # Supported Key Types
//
// **Asymmetric Keys**:
//   - RSA: 2048-bit and 4096-bit keys with PKCS#1 v1.5 and PSS padding for signing,
//     PKCS#1 v1.5 and OAEP padding for encryption/decryption
//   - ECDSA: P-256 and P-384 curves for digital signing
//   - ED25519: Modern elliptic curve signatures with high security and performance
//
// **Symmetric Keys**:
//   - AES: 128-bit, 192-bit, and 256-bit keys with multiple cipher modes
//   - DES: 64-bit keys (included for legacy compatibility)
//   - 3DES: 192-bit keys (triple DES)
//
// # Connection Management
//
// The library supports multiple methods for identifying and connecting to HSM slots:
//   - Slot ID: Direct slot identifier
//   - Slot Index: Zero-based index into the slot list
//   - Token Label: Human-readable token label
//   - Token Serial Number: Unique token serial number
//
// # Configuration
//
// HSM connections are configured using the Config struct with various creation methods:
//
//	// Basic configuration with slot ID
//	config := &gopkcs11.Config{
//	    LibraryPath: "/path/to/pkcs11.so",
//	    SlotID:      &slotID,
//	    UserPIN:     "pin",
//	}
//
//	// Environment-based configuration
//	config, err := gopkcs11.NewConfigFromEnv()
//
// # Basic Usage
//
// **Creating a Token**:
//
//	config := &gopkcs11.Config{
//	    LibraryPath: "/usr/lib/softhsm/libsofthsm2.so",
//	    SlotID:      &slotID,
//	    UserPIN:     "userpin",
//	}
//
//	token, err := gopkcs11.NewToken(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer token.Close()
//
// **Key Generation**:
//
//	// Generate RSA key pair
//	rsaKey, err := token.GenerateRSAKeyPair(2048)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Generate ECDSA key pair
//	ecdsaKey, err := token.GenerateECDSAKeyPair(elliptic.P256())
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Generate ED25519 key pair
//	ed25519Key, err := token.GenerateED25519KeyPair()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// **Digital Signing**:
//
//	// Using generic crypto.Signer interface
//	signer := rsaKey.AsSigner()
//	data := []byte("Hello, World!")
//	hash := sha256.Sum256(data)
//	signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
//
//	// Using RSA-specific methods
//	rsaSigner, _ := rsaKey.AsRSAKeyPair(token)
//	signature, err := rsaSigner.SignPKCS1v15(crypto.SHA256, hash[:])
//	pssSignature, err := rsaSigner.SignPSS(crypto.SHA256, hash[:])
//
// **Symmetric Encryption**:
//
//	// Generate AES key
//	aesKey, err := token.GenerateAESKey(256)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Create cipher for encryption
//	iv := make([]byte, 16)
//	rand.Read(iv)
//	cipher, err := gopkcs11.NewAESCBCCipher(aesKey, iv)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Encrypt data
//	plaintext := []byte("sensitive data")
//	ciphertext := make([]byte, len(plaintext)+16) // Extra space for padding
//	err = cipher.Encrypt(ctx, ciphertext, plaintext)
//
// # Cryptographic Operations
//
// **RSA Operations**:
//   - Digital signing with PKCS#1 v1.5 and PSS padding
//   - Encryption/decryption with PKCS#1 v1.5 and OAEP padding
//   - Key wrapping and unwrapping
//
// **ECDSA Operations**:
//   - Digital signing with automatic DER encoding
//   - Support for multiple hash algorithms (SHA-1 through SHA-512)
//
// **ED25519 Operations**:
//   - Deterministic digital signing of raw messages
//   - High performance and security
//
// **Symmetric Operations**:
//   - Block encryption/decryption with multiple modes
//   - Streaming operations for large data
//   - Key wrapping and unwrapping
//
// # Thread Safety
//
// The library is designed to be thread-safe with proper synchronization:
//   - Token sessions are protected with read-write mutexes
//   - Multiple goroutines can safely use the same token
//   - Key operations are atomic and properly synchronized
//
// # Security Features
//
// **Key Protection**:
//   - Private keys are marked as non-extractable and sensitive
//   - All cryptographic operations are performed within the HSM
//   - Keys cannot be extracted from the HSM
//
// **Session Management**:
//   - Proper session cleanup and logout procedures
//   - Session validation before operations
//   - Automatic session management
//
// **Error Handling**:
//   - Categorized error types for better error handling
//   - No sensitive information leakage in error messages
//   - Comprehensive error context and wrapping
//
// # Performance Considerations
//
// **Concurrent Operations**:
//   - Thread-safe design allows concurrent key operations
//   - Session pooling for improved performance
//   - Efficient key lookup and caching
//
// **Memory Management**:
//   - Minimal memory allocation for crypto operations
//   - Efficient buffer management for streaming operations
//   - Proper cleanup of sensitive data
//
// # Error Handling
//
// The library provides comprehensive error handling with categorized error types:
//
//	if err != nil {
//	    if gopkcs11.IsAuthenticationError(err) {
//	        log.Printf("Authentication failed: %v", err)
//	    } else if gopkcs11.IsKeyNotFoundError(err) {
//	        log.Printf("Key not found: %v", err)
//	    } else {
//	        log.Printf("General error: %v", err)
//	    }
//	}
//
// # Environment Variables
//
// The library supports configuration through environment variables:
//   - PKCS11_LIBRARY_PATH: Path to PKCS#11 library
//   - PKCS11_USER_PIN: User PIN for authentication
//   - PKCS11_SLOT_ID: Slot ID to use
//   - PKCS11_SLOT_INDEX: Slot index to use
//   - PKCS11_TOKEN_LABEL: Token label to use
//   - PKCS11_TOKEN_SERIAL: Token serial number to use
//
// # Examples
//
// See example_usage.go for comprehensive usage examples demonstrating:
//   - Generic crypto.Signer interface usage
//   - RSA-specific operations (signing and decryption)
//   - ECDSA-specific operations (signing)
//   - ED25519-specific operations (message signing)
//   - Symmetric encryption with various modes
//
// # Testing
//
// The library includes comprehensive testing:
//   - Unit tests for core functionality
//   - End-to-end tests with SoftHSM
//   - Performance benchmarks
//   - Concurrency tests
//
// # Dependencies
//
// The library depends on:
//   - github.com/miekg/pkcs11: Core PKCS#11 bindings
//   - github.com/pkg/errors: Enhanced error handling
//   - github.com/rs/xid: Unique identifier generation
//
// # Platform Support
//
// The library supports:
//   - Linux (tested with SoftHSM and hardware HSMs)
//   - macOS (tested with SoftHSM)
//   - Windows (tested with SoftHSM)
//
// For more detailed examples and advanced usage, see the example_usage.go file
// and the test suite in the test/e2e directory.
package gopkcs11
