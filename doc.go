// Package pkcs11 provides a Go wrapper for PKCS#11 (Cryptoki) operations with HSM (Hardware Security Module) support.
//
// This package simplifies interaction with PKCS#11 compliant devices by providing high-level abstractions
// for common cryptographic operations including key management, digital signing, encryption/decryption,
// and key wrapping/unwrapping.
//
// # Key Features
//
//   - Connection management to PKCS#11 devices with automatic session handling
//   - Support for RSA and ECDSA asymmetric key pairs (generation, import, operations)
//   - Support for AES, DES, and 3DES symmetric keys (generation, import, operations)
//   - Digital signing with multiple hash algorithms (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512)
//   - RSA encryption/decryption with PKCS#1 v1.5 and OAEP padding
//   - Key wrapping and unwrapping operations
//   - Comprehensive error handling with detailed PKCS#11 error codes
//   - Thread-safe operations with proper session management
//
// # Basic Usage
//
// To use this package, first create a configuration and establish a connection to the PKCS#11 device:
//
//	config := pkcs11.NewConfig("/usr/lib/pkcs11/libpkcs11.so", 0, "userPIN")
//	client, err := pkcs11.NewClient(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
// # Environment Variable Configuration
//
// You can also configure the client using environment variables:
//
//	config, err := pkcs11.NewConfigFromEnv()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	client, err := pkcs11.NewClient(config)
//
// The following environment variables are supported:
//   - PKCS11_LIBRARY_PATH: Path to the PKCS#11 library (default: /usr/lib/pkcs11/libpkcs11.so)
//   - PKCS11_SLOT_ID: Slot ID to use (default: 0)
//   - PKCS11_USER_PIN: User PIN for authentication (required)
//
// # Key Pair Operations
//
// Generate an RSA key pair:
//
//	keyPair, err := client.GenerateRSAKeyPair("my-rsa-key", 2048)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Generate an ECDSA key pair:
//
//	keyPair, err := client.GenerateECDSAKeyPair("my-ecdsa-key", elliptic.P256())
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Find an existing key pair:
//
//	keyPair, err := client.FindKeyPairByLabel("my-key")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Digital Signing
//
// Get a signer for digital signatures:
//
//	signer, err := client.GetSigner("my-key")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Sign data (data will be hashed automatically)
//	hashingSigner, err := client.GetHashingSigner("my-key", crypto.SHA256)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	signature, err := hashingSigner.Sign(rand.Reader, data, crypto.SHA256)
//
// # Encryption and Decryption
//
// Get a decrypter for RSA operations:
//
//	decrypter, err := client.GetRSADecrypter("my-rsa-key")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Decrypt with PKCS#1 v1.5 padding
//	plaintext, err := decrypter.DecryptPKCS1v15(ciphertext)
//
//	// Decrypt with OAEP padding
//	plaintext, err := decrypter.DecryptOAEP(crypto.SHA256, ciphertext, nil)
//
// # Symmetric Key Operations
//
// Generate an AES key:
//
//	symKey, err := client.GenerateAESKey("my-aes-key", 256)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Encrypt and decrypt data:
//
//	ciphertext, err := client.EncryptData(symKey, pkcs11.CKM_AES_CBC, iv, data)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	plaintext, err := client.DecryptData(symKey, pkcs11.CKM_AES_CBC, iv, ciphertext)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Key Wrapping
//
// Wrap a key with another key:
//
//	wrappedKey, err := client.WrapKey(wrappingKey, targetKey.Handle, pkcs11.CKM_AES_KEY_WRAP, nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Error Handling
//
// The package provides comprehensive error handling with typed errors:
//
//	if pkcs11.IsKeyNotFoundError(err) {
//	    // Handle key not found
//	}
//	if pkcs11.IsAuthenticationError(err) {
//	    // Handle authentication failure
//	}
//	if pkcs11.IsSessionError(err) {
//	    // Handle session-related errors
//	}
//
// # Thread Safety
//
// This package is designed to be thread-safe. The Client maintains proper synchronization
// for session management and can be used concurrently from multiple goroutines.
//
// # Supported Algorithms
//
// Asymmetric Key Types:
//   - RSA (2048, 4096 bits)
//   - ECDSA (P-256, P-384 curves)
//
// Hash Algorithms (for signing):
//   - SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
//
// RSA Padding Schemes:
//   - PKCS#1 v1.5 (signing and encryption)
//   - PSS (signing)
//   - OAEP (encryption)
//
// Symmetric Key Types:
//   - AES (128, 192, 256 bits)
//   - DES (64 bits)
//   - 3DES (192 bits)
//
// # Security Considerations
//
// This package is designed for use with Hardware Security Modules (HSMs) and follows
// security best practices:
//   - Private keys are marked as non-extractable and sensitive
//   - All cryptographic operations are performed within the HSM
//   - Session management includes proper cleanup and logout procedures
//   - Error messages avoid leaking sensitive information
//
// # Limitations
//
//   - ECDSA encryption/decryption is not supported (only available for RSA)
//   - Key import requires the private key material in software (consider security implications)
//   - Some advanced PKCS#11 features are not exposed in this high-level interface
//
// For complete API documentation, see the individual type and function documentation.
package gopkcs11