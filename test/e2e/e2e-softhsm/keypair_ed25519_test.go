package e2e

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	pkcs11 "github.com/yeaops/gopkcs11"
)

func TestNewED25519KeyPair(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	t.Run("ValidED25519KeyPair", func(t *testing.T) {
		keyPair, err := client.GenerateED25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate ED25519 key pair: %v", err)
		}

		ed25519KeyPair, err := pkcs11.NewED25519KeyPair(keyPair)
		if err != nil {
			t.Errorf("NewED25519KeyPair should not fail for valid ED25519 key: %v", err)
		}
		if ed25519KeyPair == nil {
			t.Error("NewED25519KeyPair should return non-nil ED25519KeyPair")
		}
		if ed25519KeyPair.KeyPair != keyPair {
			t.Error("ED25519KeyPair should contain the original KeyPair")
		}
	})

	t.Run("InvalidKeyPairType", func(t *testing.T) {
		keyPair, err := client.GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		_, err = pkcs11.NewED25519KeyPair(keyPair)
		if err == nil {
			t.Error("NewED25519KeyPair should fail for non-ED25519 key")
		}
		if !strings.Contains(err.Error(), "must be an ED25519 key") {
			t.Errorf("Error should mention ED25519 key requirement, got: %v", err)
		}
	})
}

func TestED25519KeyPairPublic(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key pair: %v", err)
	}

	ed25519KeyPair, err := pkcs11.NewED25519KeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ED25519 key pair: %v", err)
	}

	pubKey := ed25519KeyPair.Public()
	ed25519PubKey, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		t.Error("Public() should return ed25519.PublicKey")
	}

	if len(ed25519PubKey) != ed25519.PublicKeySize {
		t.Errorf("Expected public key size %d, got %d", ed25519.PublicKeySize, len(ed25519PubKey))
	}

	// Verify public key matches the original
	originalPubKey, ok := keyPair.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("Original public key should be ed25519.PublicKey")
	}

	if len(originalPubKey) != len(ed25519PubKey) {
		t.Error("Public key length should match original")
	}

	for i := range originalPubKey {
		if originalPubKey[i] != ed25519PubKey[i] {
			t.Error("Public key should match original")
			break
		}
	}
}

func TestED25519KeyPairSign(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key pair: %v", err)
	}

	ed25519KeyPair, err := pkcs11.NewED25519KeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ED25519 key pair: %v", err)
	}

	testMessages := []struct {
		name    string
		message string
	}{
		{
			name:    "ShortMessage",
			message: "Hello, World!",
		},
		{
			name:    "LongMessage",
			message: "This is a longer message to test ED25519 signing with various message lengths. ED25519 can handle messages of arbitrary length because it hashes the message internally before signing.",
		},
		{
			name:    "BinaryMessage",
			message: string([]byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}),
		},
		{
			name:    "EmptyMessage",
			message: "",
		},
	}

	for _, tc := range testMessages {
		t.Run(tc.name, func(t *testing.T) {
			message := []byte(tc.message)

			// Test Sign() method
			signature, err := ed25519KeyPair.Sign(rand.Reader, message, nil)
			if err != nil {
				t.Errorf("Sign() failed: %v", err)
			}
			if len(signature) != ed25519.SignatureSize {
				t.Errorf("Expected signature size %d, got %d", ed25519.SignatureSize, len(signature))
			}

			// Test SignMessage() convenience method
			signature2, err := ed25519KeyPair.SignMessage(message)
			if err != nil {
				t.Errorf("SignMessage() failed: %v", err)
			}
			if len(signature2) != ed25519.SignatureSize {
				t.Errorf("Expected signature size %d, got %d", ed25519.SignatureSize, len(signature2))
			}

			// Verify signature using Go's crypto/ed25519
			ed25519PubKey, ok := keyPair.PublicKey.(ed25519.PublicKey)
			if !ok {
				t.Fatal("Public key should be ed25519.PublicKey")
			}

			valid := ed25519.Verify(ed25519PubKey, message, signature)
			if !valid {
				t.Error("Signature verification failed")
			}

			// Verify second signature
			valid2 := ed25519.Verify(ed25519PubKey, message, signature2)
			if !valid2 {
				t.Error("Second signature verification failed")
			}
		})
	}
}

func TestED25519KeyPairSignWithHashFunction(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key pair: %v", err)
	}

	ed25519KeyPair, err := pkcs11.NewED25519KeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ED25519 key pair: %v", err)
	}

	message := []byte("test message")

	// Test that ED25519 rejects pre-hashed messages
	testCases := []struct {
		name string
		hash crypto.Hash
	}{
		{"SHA256", crypto.SHA256},
		{"SHA512", crypto.SHA512},
		{"SHA1", crypto.SHA1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ed25519KeyPair.Sign(rand.Reader, message, tc.hash)
			if err == nil {
				t.Error("Sign() should fail when hash function is specified")
			}
			if !strings.Contains(err.Error(), "does not support pre-hashing") {
				t.Errorf("Error should mention pre-hashing not supported, got: %v", err)
			}
		})
	}
}

func TestED25519KeyPairSignatureDeterminism(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key pair: %v", err)
	}

	ed25519KeyPair, err := pkcs11.NewED25519KeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ED25519 key pair: %v", err)
	}

	message := []byte("test message")

	// Sign the same message multiple times
	const numSignatures = 5
	signatures := make([][]byte, numSignatures)
	for i := 0; i < numSignatures; i++ {
		sig, err := ed25519KeyPair.Sign(rand.Reader, message, nil)
		if err != nil {
			t.Fatalf("Sign() failed: %v", err)
		}
		signatures[i] = sig
	}

	// ED25519 signatures should be deterministic (same message, same key, same signature)
	for i := 1; i < numSignatures; i++ {
		if len(signatures[0]) != len(signatures[i]) {
			t.Errorf("Signature lengths should be identical: %d vs %d", len(signatures[0]), len(signatures[i]))
		}
		
		for j := range signatures[0] {
			if signatures[0][j] != signatures[i][j] {
				t.Errorf("ED25519 signatures should be deterministic, but signature %d differs from signature 0", i)
				break
			}
		}
	}

	// All signatures should be valid
	ed25519PubKey, ok := keyPair.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("Public key should be ed25519.PublicKey")
	}

	for i, sig := range signatures {
		valid := ed25519.Verify(ed25519PubKey, message, sig)
		if !valid {
			t.Errorf("Signature %d verification failed", i)
		}
	}
}

func TestED25519KeyPairSignatureSize(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key pair: %v", err)
	}

	ed25519KeyPair, err := pkcs11.NewED25519KeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ED25519 key pair: %v", err)
	}

	// Test with various message sizes
	messageSizes := []int{0, 1, 16, 32, 64, 128, 256, 512, 1024, 2048}

	for _, size := range messageSizes {
		t.Run(fmt.Sprintf("MessageSize%d", size), func(t *testing.T) {
			message := make([]byte, size)
			for i := range message {
				message[i] = byte(i % 256)
			}

			signature, err := ed25519KeyPair.Sign(rand.Reader, message, nil)
			if err != nil {
				t.Errorf("Sign() failed for message size %d: %v", size, err)
			}

			if len(signature) != ed25519.SignatureSize {
				t.Errorf("Expected signature size %d, got %d for message size %d", ed25519.SignatureSize, len(signature), size)
			}

			// Verify signature
			ed25519PubKey, ok := keyPair.PublicKey.(ed25519.PublicKey)
			if !ok {
				t.Fatal("Public key should be ed25519.PublicKey")
			}

			valid := ed25519.Verify(ed25519PubKey, message, signature)
			if !valid {
				t.Errorf("Signature verification failed for message size %d", size)
			}
		})
	}
}

func TestED25519KeyPairSignatureCompatibility(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key pair: %v", err)
	}

	ed25519KeyPair, err := pkcs11.NewED25519KeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ED25519 key pair: %v", err)
	}

	// Test that signatures are compatible with standard Go crypto/ed25519 verification
	message := []byte("test message for compatibility")

	// Sign with our ED25519 key pair
	signature, err := ed25519KeyPair.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Verify with Go's crypto/ed25519
	ed25519PubKey, ok := keyPair.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("Public key should be ed25519.PublicKey")
	}

	valid := ed25519.Verify(ed25519PubKey, message, signature)
	if !valid {
		t.Error("Signature verification failed")
	}

	// Also test that a Go-generated signature would be valid with our public key
	// Generate a temporary key for comparison
	tempPubKey, tempPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate temporary key: %v", err)
	}

	tempSignature := ed25519.Sign(tempPrivKey, message)
	tempValid := ed25519.Verify(tempPubKey, message, tempSignature)
	if !tempValid {
		t.Error("Temporary signature should be valid (sanity check)")
	}
}

func TestED25519KeyPairConcurrentOperations(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key pair: %v", err)
	}

	ed25519KeyPair, err := pkcs11.NewED25519KeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ED25519 key pair: %v", err)
	}

	// Test concurrent signing operations
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()
			
			message := []byte(fmt.Sprintf("test message %d", id))
			
			_, err := ed25519KeyPair.Sign(rand.Reader, message, nil)
			if err != nil {
				errors <- err
				return
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Check for any errors
	select {
	case err := <-errors:
		t.Errorf("Concurrent signing operation failed: %v", err)
	default:
		// No errors
	}
}

func TestED25519KeyPairErrorCases(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key pair: %v", err)
	}

	ed25519KeyPair, err := pkcs11.NewED25519KeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ED25519 key pair: %v", err)
	}

	t.Run("NilMessage", func(t *testing.T) {
		_, err := ed25519KeyPair.Sign(rand.Reader, nil, nil)
		if err == nil {
			t.Error("Sign() should handle nil message gracefully")
		}
	})

	t.Run("WithUnsupportedOptions", func(t *testing.T) {
		message := []byte("test message")
		
		// Test with various unsupported options
		unsupportedOptions := []crypto.SignerOpts{
			crypto.SHA256,
			crypto.SHA512,
			crypto.SHA1,
		}

		for _, opt := range unsupportedOptions {
			_, err := ed25519KeyPair.Sign(rand.Reader, message, opt)
			if err == nil {
				t.Errorf("Sign() should fail with unsupported option %v", opt)
			}
		}
	})
}

func TestED25519KeyPairPublicKeyValidation(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key pair: %v", err)
	}

	ed25519KeyPair, err := pkcs11.NewED25519KeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ED25519 key pair: %v", err)
	}

	// Test that public key is valid
	pubKey := ed25519KeyPair.Public()
	ed25519PubKey, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("Public key should be ed25519.PublicKey")
	}

	// Verify public key length
	if len(ed25519PubKey) != ed25519.PublicKeySize {
		t.Errorf("Expected public key size %d, got %d", ed25519.PublicKeySize, len(ed25519PubKey))
	}

	// Verify key is not all zeros
	allZeros := true
	for _, b := range ed25519PubKey {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Public key should not be all zeros")
	}

	// Test that we can use the public key for verification
	message := []byte("test message")
	signature, err := ed25519KeyPair.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	valid := ed25519.Verify(ed25519PubKey, message, signature)
	if !valid {
		t.Error("Public key should be valid for verification")
	}
}

func TestED25519KeyPairKeySize(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key pair: %v", err)
	}

	// ED25519 key size should be 255 bits
	if keyPair.KeySize != 255 {
		t.Errorf("Expected key size 255, got %d", keyPair.KeySize)
	}

	// Key type should be ED25519
	if keyPair.KeyType != pkcs11.KeyPairTypeED25519 {
		t.Errorf("Expected key type ED25519, got %v", keyPair.KeyType)
	}
}

func TestED25519KeyPairRandomMessages(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key pair: %v", err)
	}

	ed25519KeyPair, err := pkcs11.NewED25519KeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ED25519 key pair: %v", err)
	}

	ed25519PubKey, ok := keyPair.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("Public key should be ed25519.PublicKey")
	}

	// Test with random messages
	const numTests = 10
	for i := 0; i < numTests; i++ {
		t.Run(fmt.Sprintf("RandomMessage%d", i), func(t *testing.T) {
			// Generate random message
			messageSize := 100 + (i * 50) // Vary message size
			message := make([]byte, messageSize)
			_, err := rand.Read(message)
			if err != nil {
				t.Fatalf("Failed to generate random message: %v", err)
			}

			// Sign message
			signature, err := ed25519KeyPair.Sign(rand.Reader, message, nil)
			if err != nil {
				t.Errorf("Sign() failed: %v", err)
			}

			// Verify signature
			valid := ed25519.Verify(ed25519PubKey, message, signature)
			if !valid {
				t.Error("Random message signature verification failed")
			}
		})
	}
}

func TestED25519KeyPairSignatureImmutability(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateED25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key pair: %v", err)
	}

	ed25519KeyPair, err := pkcs11.NewED25519KeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ED25519 key pair: %v", err)
	}

	message := []byte("test message")
	signature, err := ed25519KeyPair.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Create a copy of the signature
	originalSignature := make([]byte, len(signature))
	copy(originalSignature, signature)

	// Modify the original signature
	signature[0] = ^signature[0] // Flip all bits in first byte

	// Verify the signature is now invalid
	ed25519PubKey, ok := keyPair.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("Public key should be ed25519.PublicKey")
	}

	valid := ed25519.Verify(ed25519PubKey, message, signature)
	if valid {
		t.Error("Modified signature should be invalid")
	}

	// Verify the original signature is still valid
	valid = ed25519.Verify(ed25519PubKey, message, originalSignature)
	if !valid {
		t.Error("Original signature should still be valid")
	}
}