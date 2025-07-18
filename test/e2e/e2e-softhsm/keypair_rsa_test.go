package e2e

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"strings"
	"testing"

	pkcs11 "github.com/yeaops/gopkcs11"
)

func TestNewRSAKeyPair(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	t.Run("ValidRSAKeyPair", func(t *testing.T) {
		keyPair, err := client.GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		rsaKeyPair, err := pkcs11.NewRSAKeyPair(keyPair)
		if err != nil {
			t.Errorf("NewRSAKeyPair should not fail for valid RSA key: %v", err)
		}
		if rsaKeyPair == nil {
			t.Error("NewRSAKeyPair should return non-nil RSAKeyPair")
		}
		if rsaKeyPair.KeyPair != keyPair {
			t.Error("RSAKeyPair should contain the original KeyPair")
		}
	})

	t.Run("InvalidKeyPairType", func(t *testing.T) {
		keyPair, err := client.GenerateECDSAKeyPair(elliptic.P256())
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key pair: %v", err)
		}

		_, err = pkcs11.NewRSAKeyPair(keyPair)
		if err == nil {
			t.Error("NewRSAKeyPair should fail for non-RSA key")
		}
		if !strings.Contains(err.Error(), "must be an RSA key") {
			t.Errorf("Error should mention RSA key requirement, got: %v", err)
		}
	})
}

func TestRSAKeyPairPublic(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	rsaKeyPair, err := pkcs11.NewRSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create RSA key pair: %v", err)
	}

	pubKey := rsaKeyPair.Public()
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		t.Error("Public() should return *rsa.PublicKey")
	}

	if rsaPubKey.Size() != 256 { // 2048 bits = 256 bytes
		t.Errorf("Expected key size 256 bytes, got %d", rsaPubKey.Size())
	}

	// Verify public key matches the original
	originalPubKey, ok := keyPair.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("Original public key should be *rsa.PublicKey")
	}

	if rsaPubKey.N.Cmp(originalPubKey.N) != 0 {
		t.Error("Public key modulus should match original")
	}
	if rsaPubKey.E != originalPubKey.E {
		t.Error("Public key exponent should match original")
	}
}

func TestRSAKeyPairSignPKCS1v15(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	rsaKeyPair, err := pkcs11.NewRSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create RSA key pair: %v", err)
	}

	testCases := []struct {
		name     string
		hash     crypto.Hash
		message  string
		hashFunc func([]byte) []byte
	}{
		{
			name:    "SHA1",
			hash:    crypto.SHA1,
			message: "test message for SHA1",
			hashFunc: func(data []byte) []byte {
				hash := sha1.Sum(data)
				return hash[:]
			},
		},
		{
			name:    "SHA256",
			hash:    crypto.SHA256,
			message: "test message for SHA256",
			hashFunc: func(data []byte) []byte {
				hash := sha256.Sum256(data)
				return hash[:]
			},
		},
		{
			name:    "SHA512",
			hash:    crypto.SHA512,
			message: "test message for SHA512",
			hashFunc: func(data []byte) []byte {
				hash := sha512.Sum512(data)
				return hash[:]
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			message := []byte(tc.message)
			digest := tc.hashFunc(message)

			// Test Sign() with PKCS#1 v1.5 (default)
			signature, err := rsaKeyPair.Sign(rand.Reader, digest, tc.hash)
			if err != nil {
				t.Errorf("Sign() failed: %v", err)
			}
			if len(signature) == 0 {
				t.Error("Signature should not be empty")
			}

			// Test SignPKCS1v15() convenience method
			signature2, err := rsaKeyPair.SignPKCS1v15(tc.hash, digest)
			if err != nil {
				t.Errorf("SignPKCS1v15() failed: %v", err)
			}
			if len(signature2) == 0 {
				t.Error("Signature should not be empty")
			}

			// Verify signature using Go's crypto/rsa
			rsaPubKey, ok := keyPair.PublicKey.(*rsa.PublicKey)
			if !ok {
				t.Fatal("Public key should be *rsa.PublicKey")
			}

			err = rsa.VerifyPKCS1v15(rsaPubKey, tc.hash, digest, signature)
			if err != nil {
				t.Errorf("Signature verification failed: %v", err)
			}
		})
	}
}

func TestRSAKeyPairSignPSS(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	rsaKeyPair, err := pkcs11.NewRSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create RSA key pair: %v", err)
	}

	testCases := []struct {
		name     string
		hash     crypto.Hash
		message  string
		hashFunc func([]byte) []byte
	}{
		{
			name:    "SHA256",
			hash:    crypto.SHA256,
			message: "test message for PSS SHA256",
			hashFunc: func(data []byte) []byte {
				hash := sha256.Sum256(data)
				return hash[:]
			},
		},
		{
			name:    "SHA512",
			hash:    crypto.SHA512,
			message: "test message for PSS SHA512",
			hashFunc: func(data []byte) []byte {
				hash := sha512.Sum512(data)
				return hash[:]
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			message := []byte(tc.message)
			digest := tc.hashFunc(message)

			// Test Sign() with PSS options
			pssOpts := &rsa.PSSOptions{
				Hash: tc.hash,
			}
			signature, err := rsaKeyPair.Sign(rand.Reader, digest, pssOpts)
			if err != nil {
				t.Errorf("Sign() with PSS failed: %v", err)
			}
			if len(signature) == 0 {
				t.Error("Signature should not be empty")
			}

			// Test SignPSS() convenience method
			signature2, err := rsaKeyPair.SignPSS(tc.hash, digest)
			if err != nil {
				t.Errorf("SignPSS() failed: %v", err)
			}
			if len(signature2) == 0 {
				t.Error("Signature should not be empty")
			}

			// Verify signature using Go's crypto/rsa
			rsaPubKey, ok := keyPair.PublicKey.(*rsa.PublicKey)
			if !ok {
				t.Fatal("Public key should be *rsa.PublicKey")
			}

			err = rsa.VerifyPSS(rsaPubKey, tc.hash, digest, signature, pssOpts)
			if err != nil {
				t.Errorf("PSS signature verification failed: %v", err)
			}
		})
	}
}

func TestRSAKeyPairDecryptPKCS1v15(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	rsaKeyPair, err := pkcs11.NewRSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create RSA key pair: %v", err)
	}

	rsaPubKey, ok := keyPair.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("Public key should be *rsa.PublicKey")
	}

	testCases := []struct {
		name     string
		plaintext string
	}{
		{
			name:     "ShortMessage",
			plaintext: "Hello, World!",
		},
		{
			name:     "LongerMessage",
			plaintext: "This is a longer message to test RSA decryption with PKCS#1 v1.5 padding.",
		},
		{
			name:     "BinaryData",
			plaintext: string([]byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD}),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			message := []byte(tc.plaintext)

			// Encrypt using Go's crypto/rsa
			ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPubKey, message)
			if err != nil {
				t.Fatalf("Failed to encrypt message: %v", err)
			}

			// Test Decrypt() with PKCS#1 v1.5 (default)
			decrypted, err := rsaKeyPair.Decrypt(rand.Reader, ciphertext, nil)
			if err != nil {
				t.Errorf("Decrypt() failed: %v", err)
			}
			if string(decrypted) != tc.plaintext {
				t.Errorf("Decrypted message doesn't match original. Expected: %s, Got: %s", tc.plaintext, decrypted)
			}

			// Test DecryptPKCS1v15() convenience method
			decrypted2, err := rsaKeyPair.DecryptPKCS1v15(ciphertext)
			if err != nil {
				t.Errorf("DecryptPKCS1v15() failed: %v", err)
			}
			if string(decrypted2) != tc.plaintext {
				t.Errorf("Decrypted message doesn't match original. Expected: %s, Got: %s", tc.plaintext, decrypted2)
			}
		})
	}
}

func TestRSAKeyPairDecryptOAEP(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	rsaKeyPair, err := pkcs11.NewRSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create RSA key pair: %v", err)
	}

	rsaPubKey, ok := keyPair.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("Public key should be *rsa.PublicKey")
	}

	testCases := []struct {
		name     string
		hash     crypto.Hash
		label    []byte
		plaintext string
	}{
		{
			name:     "SHA1_NoLabel",
			hash:     crypto.SHA1,
			label:    nil,
			plaintext: "Test message for OAEP SHA1",
		},
		{
			name:     "SHA256_NoLabel",
			hash:     crypto.SHA256,
			label:    nil,
			plaintext: "Test message for OAEP SHA256",
		},
		{
			name:     "SHA1_WithLabel",
			hash:     crypto.SHA1,
			label:    []byte("test-label"),
			plaintext: "Test message for OAEP SHA1 with label",
		},
		{
			name:     "SHA256_WithLabel",
			hash:     crypto.SHA256,
			label:    []byte("another-label"),
			plaintext: "Test message for OAEP SHA256 with label",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			message := []byte(tc.plaintext)

			// Encrypt using Go's crypto/rsa
			ciphertext, err := rsa.EncryptOAEP(tc.hash.New(), rand.Reader, rsaPubKey, message, tc.label)
			if err != nil {
				t.Fatalf("Failed to encrypt message: %v", err)
			}

			// Test Decrypt() with OAEP options
			oaepOpts := &rsa.OAEPOptions{
				Hash:  tc.hash,
				Label: tc.label,
			}
			decrypted, err := rsaKeyPair.Decrypt(rand.Reader, ciphertext, oaepOpts)
			if err != nil {
				t.Errorf("Decrypt() with OAEP failed: %v", err)
			}
			if string(decrypted) != tc.plaintext {
				t.Errorf("Decrypted message doesn't match original. Expected: %s, Got: %s", tc.plaintext, decrypted)
			}

			// Test DecryptOAEP() convenience method
			decrypted2, err := rsaKeyPair.DecryptOAEP(tc.hash, ciphertext, tc.label)
			if err != nil {
				t.Errorf("DecryptOAEP() failed: %v", err)
			}
			if string(decrypted2) != tc.plaintext {
				t.Errorf("Decrypted message doesn't match original. Expected: %s, Got: %s", tc.plaintext, decrypted2)
			}
		})
	}
}

func TestRSAKeyPairSignErrorCases(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	rsaKeyPair, err := pkcs11.NewRSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create RSA key pair: %v", err)
	}

	t.Run("InvalidDigestLength", func(t *testing.T) {
		// Test with wrong digest length for SHA256
		wrongDigest := make([]byte, 16) // Should be 32 for SHA256
		_, err := rsaKeyPair.Sign(rand.Reader, wrongDigest, crypto.SHA256)
		if err == nil {
			t.Error("Sign() should fail with wrong digest length")
		}
		if !strings.Contains(err.Error(), "digest length mismatch") {
			t.Errorf("Error should mention digest length mismatch, got: %v", err)
		}
	})

	t.Run("UnsupportedHashFunction", func(t *testing.T) {
		digest := make([]byte, 32)
		_, err := rsaKeyPair.Sign(rand.Reader, digest, crypto.Hash(999))
		if err == nil {
			t.Error("Sign() should fail with unsupported hash function")
		}
		if !strings.Contains(err.Error(), "unsupported hash function") {
			t.Errorf("Error should mention unsupported hash function, got: %v", err)
		}
	})

	t.Run("InvalidPSSOptions", func(t *testing.T) {
		digest := make([]byte, 32)
		pssOpts := &rsa.PSSOptions{
			Hash: crypto.Hash(999), // Invalid hash
		}
		_, err := rsaKeyPair.Sign(rand.Reader, digest, pssOpts)
		if err == nil {
			t.Error("Sign() should fail with invalid PSS options")
		}
	})
}

func TestRSAKeyPairDecryptErrorCases(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	rsaKeyPair, err := pkcs11.NewRSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create RSA key pair: %v", err)
	}

	t.Run("InvalidCiphertext", func(t *testing.T) {
		// Test with invalid ciphertext
		invalidCiphertext := []byte("invalid ciphertext")
		_, err := rsaKeyPair.Decrypt(rand.Reader, invalidCiphertext, nil)
		if err == nil {
			t.Error("Decrypt() should fail with invalid ciphertext")
		}
	})

	t.Run("EmptyCiphertext", func(t *testing.T) {
		// Test with empty ciphertext
		_, err := rsaKeyPair.Decrypt(rand.Reader, []byte{}, nil)
		if err == nil {
			t.Error("Decrypt() should fail with empty ciphertext")
		}
	})

	t.Run("UnsupportedDecryptionOptions", func(t *testing.T) {
		// Test with unsupported decryption options
		type unsupportedOpts struct{}
		ciphertext := make([]byte, 256) // Valid length for 2048-bit key
		_, err := rsaKeyPair.Decrypt(rand.Reader, ciphertext, &unsupportedOpts{})
		if err == nil {
			t.Error("Decrypt() should fail with unsupported options")
		}
		if !strings.Contains(err.Error(), "unsupported decryption options") {
			t.Errorf("Error should mention unsupported decryption options, got: %v", err)
		}
	})

	t.Run("UnsupportedOAEPHash", func(t *testing.T) {
		ciphertext := make([]byte, 256)
		oaepOpts := &rsa.OAEPOptions{
			Hash: crypto.Hash(999), // Unsupported hash
		}
		_, err := rsaKeyPair.Decrypt(rand.Reader, ciphertext, oaepOpts)
		if err == nil {
			t.Error("Decrypt() should fail with unsupported OAEP hash")
		}
		if !strings.Contains(err.Error(), "unsupported hash function") {
			t.Errorf("Error should mention unsupported hash function, got: %v", err)
		}
	})
}

func TestRSAKeyPairDifferentKeySizes(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keySizes := []int{2048, 4096}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("KeySize%d", keySize), func(t *testing.T) {
			keyPair, err := client.GenerateRSAKeyPair(keySize)
			if err != nil {
				t.Fatalf("Failed to generate RSA key pair of size %d: %v", keySize, err)
			}

			rsaKeyPair, err := pkcs11.NewRSAKeyPair(keyPair)
			if err != nil {
				t.Fatalf("Failed to create RSA key pair: %v", err)
			}

			// Test signing
			message := []byte("test message")
			digest := sha256.Sum256(message)
			signature, err := rsaKeyPair.Sign(rand.Reader, digest[:], crypto.SHA256)
			if err != nil {
				t.Errorf("Sign() failed for %d-bit key: %v", keySize, err)
			}

			expectedSigSize := keySize / 8
			if len(signature) != expectedSigSize {
				t.Errorf("Expected signature size %d, got %d", expectedSigSize, len(signature))
			}

			// Test decryption
			rsaPubKey, ok := keyPair.PublicKey.(*rsa.PublicKey)
			if !ok {
				t.Fatal("Public key should be *rsa.PublicKey")
			}

			plaintext := []byte("test plaintext")
			ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPubKey, plaintext)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}

			decrypted, err := rsaKeyPair.Decrypt(rand.Reader, ciphertext, nil)
			if err != nil {
				t.Errorf("Decrypt() failed for %d-bit key: %v", keySize, err)
			}

			if string(decrypted) != string(plaintext) {
				t.Errorf("Decrypted text doesn't match original")
			}
		})
	}
}

func TestRSAKeyPairSignatureCompatibility(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	rsaKeyPair, err := pkcs11.NewRSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create RSA key pair: %v", err)
	}

	// Test that signatures are compatible with standard Go crypto/rsa verification
	message := []byte("test message for compatibility")
	digest := sha256.Sum256(message)

	// Sign with our RSA key pair
	signature, err := rsaKeyPair.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Verify with Go's crypto/rsa
	rsaPubKey, ok := keyPair.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("Public key should be *rsa.PublicKey")
	}

	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, digest[:], signature)
	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}
}

func TestRSAKeyPairMechanismSelection(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	rsaKeyPair, err := pkcs11.NewRSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create RSA key pair: %v", err)
	}

	// Test that different signature options use different mechanisms
	message := []byte("test message")
	digest := sha256.Sum256(message)

	// PKCS#1 v1.5 signing (default)
	sig1, err := rsaKeyPair.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Errorf("PKCS#1 v1.5 signing failed: %v", err)
	}

	// PSS signing
	pssOpts := &rsa.PSSOptions{Hash: crypto.SHA256}
	sig2, err := rsaKeyPair.Sign(rand.Reader, digest[:], pssOpts)
	if err != nil {
		t.Errorf("PSS signing failed: %v", err)
	}

	// Signatures should be different (PSS is probabilistic)
	if len(sig1) != len(sig2) {
		t.Error("Signature lengths should be the same")
	}

	// Both should be valid
	rsaPubKey, ok := keyPair.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("Public key should be *rsa.PublicKey")
	}

	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, digest[:], sig1)
	if err != nil {
		t.Errorf("PKCS#1 v1.5 verification failed: %v", err)
	}

	err = rsa.VerifyPSS(rsaPubKey, crypto.SHA256, digest[:], sig2, pssOpts)
	if err != nil {
		t.Errorf("PSS verification failed: %v", err)
	}
}

func TestRSAKeyPairConcurrentOperations(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	rsaKeyPair, err := pkcs11.NewRSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create RSA key pair: %v", err)
	}

	// Test concurrent signing operations
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()
			
			message := []byte(fmt.Sprintf("test message %d", id))
			digest := sha256.Sum256(message)
			
			_, err := rsaKeyPair.Sign(rand.Reader, digest[:], crypto.SHA256)
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

func TestRSAKeyPairEdgeCases(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	rsaKeyPair, err := pkcs11.NewRSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create RSA key pair: %v", err)
	}

	t.Run("MaximumMessageSize", func(t *testing.T) {
		// Test with maximum message size for PKCS#1 v1.5 (key_size - 11)
		maxSize := (2048 / 8) - 11
		message := make([]byte, maxSize)
		for i := range message {
			message[i] = byte(i % 256)
		}

		rsaPubKey, ok := keyPair.PublicKey.(*rsa.PublicKey)
		if !ok {
			t.Fatal("Public key should be *rsa.PublicKey")
		}

		ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPubKey, message)
		if err != nil {
			t.Fatalf("Failed to encrypt maximum size message: %v", err)
		}

		decrypted, err := rsaKeyPair.Decrypt(rand.Reader, ciphertext, nil)
		if err != nil {
			t.Errorf("Failed to decrypt maximum size message: %v", err)
		}

		if len(decrypted) != len(message) {
			t.Errorf("Decrypted message length mismatch: expected %d, got %d", len(message), len(decrypted))
		}
	})

	t.Run("PSSWithCustomSaltLength", func(t *testing.T) {
		message := []byte("test message")
		digest := sha256.Sum256(message)

		// Test PSS with custom salt length
		pssOpts := &rsa.PSSOptions{
			Hash:       crypto.SHA256,
			SaltLength: 20, // Custom salt length
		}

		signature, err := rsaKeyPair.Sign(rand.Reader, digest[:], pssOpts)
		if err != nil {
			t.Errorf("PSS signing with custom salt length failed: %v", err)
		}

		// Verify the signature
		rsaPubKey, ok := keyPair.PublicKey.(*rsa.PublicKey)
		if !ok {
			t.Fatal("Public key should be *rsa.PublicKey")
		}

		err = rsa.VerifyPSS(rsaPubKey, crypto.SHA256, digest[:], signature, pssOpts)
		if err != nil {
			t.Errorf("PSS verification with custom salt length failed: %v", err)
		}
	})
}