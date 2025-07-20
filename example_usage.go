package gopkcs11

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// Example demonstrates how to use the new key-type-specific implementation.
// This example shows the improved design where each key type has consolidated functionality.
func Example() {
	// Assume we have a token and some key pairs
	var token *Token
	var rsaKeyPair, ecdsaKeyPair, ed25519KeyPair *KeyPair

	// Example 1: Using the generic crypto.Signer interface
	// Works for RSA, ECDSA, and ED25519 keys
	exampleGenericSigner(token, rsaKeyPair)
	exampleGenericSigner(token, ecdsaKeyPair)
	exampleGenericSigner(token, ed25519KeyPair)

	// Example 2: Using RSA-specific functionality
	exampleRSASpecificOperations(token, rsaKeyPair)

	// Example 3: Using ECDSA-specific functionality
	exampleECDSASpecificOperations(token, ecdsaKeyPair)

	// Example 4: Using ED25519-specific functionality
	exampleED25519SpecificOperations(token, ed25519KeyPair)

}

// exampleGenericSigner shows how to use any key type as a crypto.Signer
func exampleGenericSigner(token *Token, keyPair *KeyPair) {
	// Get a generic signer - works for both RSA and ECDSA
	signer := keyPair.AsSigner()
	if signer == nil {
		fmt.Printf("Unsupported key type: %v\n", keyPair.KeyType)
		return
	}

	// Use standard crypto.Signer interface
	data := []byte("Hello, World!")
	hash := sha256.Sum256(data)

	signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		fmt.Printf("Signing failed: %v\n", err)
		return
	}

	fmt.Printf("Signed %d bytes with %s key\n", len(signature), keyTypeToString(keyPair.KeyType))
}

// exampleRSASpecificOperations shows RSA-specific operations (signing + decryption)
func exampleRSASpecificOperations(token *Token, rsaKeyPair *KeyPair) {
	// Get RSA-specific implementation
	rsaKey, err := NewRSAKeyPair(rsaKeyPair)
	if err != nil {
		fmt.Printf("Not an RSA key: %v\n", err)
		return
	}

	// RSA can do both signing and decryption
	data := []byte("Hello, RSA!")
	hash := sha256.Sum256(data)

	// Sign with specific padding schemes
	sig1, _ := rsaKey.SignPKCS1v15(crypto.SHA256, hash[:])
	sig2, _ := rsaKey.SignPSS(crypto.SHA256, hash[:])
	fmt.Printf("RSA PKCS1v15 signature: %d bytes\n", len(sig1))
	fmt.Printf("RSA PSS signature: %d bytes\n", len(sig2))

	// Decrypt with specific padding schemes
	ciphertext := []byte("dummy ciphertext") // In real usage, this would be actual encrypted data
	plaintext1, _ := rsaKey.DecryptPKCS1v15(ciphertext)
	plaintext2, _ := rsaKey.DecryptOAEP(crypto.SHA256, ciphertext, nil)
	fmt.Printf("RSA PKCS1v15 decryption result: %d bytes\n", len(plaintext1))
	fmt.Printf("RSA OAEP decryption result: %d bytes\n", len(plaintext2))

	// Also works as generic crypto.Signer and crypto.Decrypter
	var signer crypto.Signer = rsaKey
	var decrypter crypto.Decrypter = rsaKey
	_ = signer
	_ = decrypter
}

// exampleECDSASpecificOperations shows ECDSA-specific operations (signing only)
func exampleECDSASpecificOperations(token *Token, ecdsaKeyPair *KeyPair) {
	// Get ECDSA-specific implementation
	ecdsaKey, err := NewECDSAKeyPair(ecdsaKeyPair)
	if err != nil {
		fmt.Printf("Not an ECDSA key: %v\n", err)
		return
	}

	// ECDSA can only do signing (no decryption)
	data := []byte("Hello, ECDSA!")
	hash := sha256.Sum256(data)

	// Sign with ECDSA
	signature, _ := ecdsaKey.SignHash(crypto.SHA256, hash[:])
	fmt.Printf("ECDSA signature: %d bytes\n", len(signature))

	// Also works as generic crypto.Signer
	var signer crypto.Signer = ecdsaKey
	_ = signer

	// But cannot be used as crypto.Decrypter (compile-time safety)
	// var decrypter crypto.Decrypter = ecdsaKey // This would not compile
}

// exampleED25519SpecificOperations shows how to use ED25519-specific functionality
func exampleED25519SpecificOperations(token *Token, keyPair *KeyPair) {
	// Get an ED25519-specific key pair
	ed25519Key, err := NewED25519KeyPair(keyPair)
	if err != nil {
		fmt.Printf("Key is not ED25519: %v\n", err)
		return
	}

	// ED25519 signs raw messages directly (no hashing required)
	message := []byte("Hello, ED25519!")

	// Sign the raw message
	signature, err := ed25519Key.SignMessage(message)
	if err != nil {
		fmt.Printf("ED25519 signing failed: %v\n", err)
		return
	}

	fmt.Printf("ED25519 signature (%d bytes): %x...\n", len(signature), signature[:8])

	// Get the public key for verification
	publicKey := ed25519Key.Public().(ed25519.PublicKey)

	// Verify the signature using Go's standard library
	if ed25519.Verify(publicKey, message, signature) {
		fmt.Println("ED25519 signature verification: SUCCESS")
	} else {
		fmt.Println("ED25519 signature verification: FAILED")
	}

	// Note: ED25519 signatures are deterministic and don't require random input
	// The signature will be the same every time for the same message and key

	// Also works as generic crypto.Signer
	var signer crypto.Signer = ed25519Key
	_ = signer

	// But cannot be used as crypto.Decrypter (like ECDSA)
	// var decrypter crypto.Decrypter = ed25519Key // This would not compile
}

func keyTypeToString(keyType KeyPairType) string {
	switch keyType {
	case KeyPairTypeRSA:
		return "RSA"
	case KeyPairTypeECDSA:
		return "ECDSA"
	case KeyPairTypeED25519:
		return "ED25519"
	default:
		return "Unknown"
	}
}
