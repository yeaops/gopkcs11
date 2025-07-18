package e2e

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"strings"
	"testing"

	pkcs11 "github.com/yeaops/gopkcs11"
)

func TestNewECDSAKeyPair(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	t.Run("ValidECDSAKeyPair", func(t *testing.T) {
		keyPair, err := client.GenerateECDSAKeyPair(elliptic.P256())
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key pair: %v", err)
		}

		ecdsaKeyPair, err := pkcs11.NewECDSAKeyPair(keyPair)
		if err != nil {
			t.Errorf("NewECDSAKeyPair should not fail for valid ECDSA key: %v", err)
		}
		if ecdsaKeyPair == nil {
			t.Error("NewECDSAKeyPair should return non-nil ECDSAKeyPair")
		}
		if ecdsaKeyPair.KeyPair != keyPair {
			t.Error("ECDSAKeyPair should contain the original KeyPair")
		}
	})

	t.Run("InvalidKeyPairType", func(t *testing.T) {
		keyPair, err := client.GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		_, err = pkcs11.NewECDSAKeyPair(keyPair)
		if err == nil {
			t.Error("NewECDSAKeyPair should fail for non-ECDSA key")
		}
		if !strings.Contains(err.Error(), "must be an ECDSA key") {
			t.Errorf("Error should mention ECDSA key requirement, got: %v", err)
		}
	})
}

func TestECDSAKeyPairPublic(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		{"P384", elliptic.P384()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			keyPair, err := client.GenerateECDSAKeyPair(tc.curve)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key pair: %v", err)
			}

			ecdsaKeyPair, err := pkcs11.NewECDSAKeyPair(keyPair)
			if err != nil {
				t.Fatalf("Failed to create ECDSA key pair: %v", err)
			}

			pubKey := ecdsaKeyPair.Public()
			ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
			if !ok {
				t.Error("Public() should return *ecdsa.PublicKey")
			}

			if ecdsaPubKey.Curve != tc.curve {
				t.Errorf("Expected curve %v, got %v", tc.curve, ecdsaPubKey.Curve)
			}

			// Verify public key matches the original
			originalPubKey, ok := keyPair.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				t.Fatal("Original public key should be *ecdsa.PublicKey")
			}

			if ecdsaPubKey.X.Cmp(originalPubKey.X) != 0 || ecdsaPubKey.Y.Cmp(originalPubKey.Y) != 0 {
				t.Error("Public key coordinates should match original")
			}
		})
	}
}

func TestECDSAKeyPairSign(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	testCases := []struct {
		name     string
		curve    elliptic.Curve
		hash     crypto.Hash
		message  string
		hashFunc func([]byte) []byte
	}{
		{
			name:    "P256_SHA1",
			curve:   elliptic.P256(),
			hash:    crypto.SHA1,
			message: "test message for P256 SHA1",
			hashFunc: func(data []byte) []byte {
				hash := sha1.Sum(data)
				return hash[:]
			},
		},
		{
			name:    "P256_SHA256",
			curve:   elliptic.P256(),
			hash:    crypto.SHA256,
			message: "test message for P256 SHA256",
			hashFunc: func(data []byte) []byte {
				hash := sha256.Sum256(data)
				return hash[:]
			},
		},
		{
			name:    "P256_SHA384",
			curve:   elliptic.P256(),
			hash:    crypto.SHA384,
			message: "test message for P256 SHA384",
			hashFunc: func(data []byte) []byte {
				hasher := crypto.SHA384.New()
				hasher.Write(data)
				return hasher.Sum(nil)
			},
		},
		{
			name:    "P256_SHA512",
			curve:   elliptic.P256(),
			hash:    crypto.SHA512,
			message: "test message for P256 SHA512",
			hashFunc: func(data []byte) []byte {
				hash := sha512.Sum512(data)
				return hash[:]
			},
		},
		{
			name:    "P384_SHA256",
			curve:   elliptic.P384(),
			hash:    crypto.SHA256,
			message: "test message for P384 SHA256",
			hashFunc: func(data []byte) []byte {
				hash := sha256.Sum256(data)
				return hash[:]
			},
		},
		{
			name:    "P384_SHA384",
			curve:   elliptic.P384(),
			hash:    crypto.SHA384,
			message: "test message for P384 SHA384",
			hashFunc: func(data []byte) []byte {
				hasher := crypto.SHA384.New()
				hasher.Write(data)
				return hasher.Sum(nil)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keyPair, err := client.GenerateECDSAKeyPair(tc.curve)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key pair: %v", err)
			}

			ecdsaKeyPair, err := pkcs11.NewECDSAKeyPair(keyPair)
			if err != nil {
				t.Fatalf("Failed to create ECDSA key pair: %v", err)
			}

			message := []byte(tc.message)
			digest := tc.hashFunc(message)

			// Test Sign() method
			signature, err := ecdsaKeyPair.Sign(rand.Reader, digest, tc.hash)
			if err != nil {
				t.Errorf("Sign() failed: %v", err)
			}
			if len(signature) == 0 {
				t.Error("Signature should not be empty")
			}

			// Test SignHash() convenience method
			signature2, err := ecdsaKeyPair.SignHash(tc.hash, digest)
			if err != nil {
				t.Errorf("SignHash() failed: %v", err)
			}
			if len(signature2) == 0 {
				t.Error("Signature should not be empty")
			}

			// Verify signature using Go's crypto/ecdsa
			ecdsaPubKey, ok := keyPair.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				t.Fatal("Public key should be *ecdsa.PublicKey")
			}

			valid := ecdsa.VerifyASN1(ecdsaPubKey, digest, signature)
			if !valid {
				t.Error("Signature verification failed")
			}
		})
	}
}

func TestECDSAKeyPairSignErrorCases(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateECDSAKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	ecdsaKeyPair, err := pkcs11.NewECDSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ECDSA key pair: %v", err)
	}

	t.Run("InvalidDigestLength", func(t *testing.T) {
		// Test with wrong digest length for SHA256
		wrongDigest := make([]byte, 16) // Should be 32 for SHA256
		_, err := ecdsaKeyPair.Sign(rand.Reader, wrongDigest, crypto.SHA256)
		if err == nil {
			t.Error("Sign() should fail with wrong digest length")
		}
		if !strings.Contains(err.Error(), "digest length mismatch") {
			t.Errorf("Error should mention digest length mismatch, got: %v", err)
		}
	})

	t.Run("UnsupportedHashFunction", func(t *testing.T) {
		digest := make([]byte, 32)
		_, err := ecdsaKeyPair.Sign(rand.Reader, digest, crypto.Hash(999))
		if err == nil {
			t.Error("Sign() should fail with unsupported hash function")
		}
		if !strings.Contains(err.Error(), "unsupported hash function") {
			t.Errorf("Error should mention unsupported hash function, got: %v", err)
		}
	})

	t.Run("EmptyDigest", func(t *testing.T) {
		_, err := ecdsaKeyPair.Sign(rand.Reader, []byte{}, crypto.SHA256)
		if err == nil {
			t.Error("Sign() should fail with empty digest")
		}
	})

	t.Run("NilDigest", func(t *testing.T) {
		_, err := ecdsaKeyPair.Sign(rand.Reader, nil, crypto.SHA256)
		if err == nil {
			t.Error("Sign() should fail with nil digest")
		}
	})
}

func TestECDSAKeyPairSignatureDeterminism(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateECDSAKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	ecdsaKeyPair, err := pkcs11.NewECDSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ECDSA key pair: %v", err)
	}

	message := []byte("test message")
	digest := sha256.Sum256(message)

	// Sign the same message multiple times
	const numSignatures = 5
	signatures := make([][]byte, numSignatures)
	for i := 0; i < numSignatures; i++ {
		sig, err := ecdsaKeyPair.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign() failed: %v", err)
		}
		signatures[i] = sig
	}

	// ECDSA signatures should be different each time (probabilistic)
	for i := 0; i < numSignatures; i++ {
		for j := i + 1; j < numSignatures; j++ {
			if len(signatures[i]) != len(signatures[j]) {
				// Different lengths are expected in some cases
				continue
			}
			
			// Check if signatures are identical (very unlikely but possible)
			identical := true
			for k := range signatures[i] {
				if signatures[i][k] != signatures[j][k] {
					identical = false
					break
				}
			}
			
			if identical {
				t.Logf("Warning: Signatures %d and %d are identical (rare but possible)", i, j)
			}
		}
	}

	// All signatures should be valid
	ecdsaPubKey, ok := keyPair.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("Public key should be *ecdsa.PublicKey")
	}

	for i, sig := range signatures {
		valid := ecdsa.VerifyASN1(ecdsaPubKey, digest[:], sig)
		if !valid {
			t.Errorf("Signature %d verification failed", i)
		}
	}
}

func TestECDSAKeyPairSignatureFormat(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateECDSAKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	ecdsaKeyPair, err := pkcs11.NewECDSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ECDSA key pair: %v", err)
	}

	message := []byte("test message")
	digest := sha256.Sum256(message)

	signature, err := ecdsaKeyPair.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Verify signature is in DER format
	if len(signature) < 6 {
		t.Error("Signature too short to be valid DER")
	}

	// DER signature should start with 0x30 (SEQUENCE tag)
	if signature[0] != 0x30 {
		t.Error("Signature should start with 0x30 (DER SEQUENCE)")
	}

	// Verify signature with Go's ecdsa.VerifyASN1 (expects DER format)
	ecdsaPubKey, ok := keyPair.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("Public key should be *ecdsa.PublicKey")
	}

	valid := ecdsa.VerifyASN1(ecdsaPubKey, digest[:], signature)
	if !valid {
		t.Error("DER signature verification failed")
	}
}

func TestECDSAKeyPairDifferentCurves(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	curves := []struct {
		name          string
		curve         elliptic.Curve
		expectedSize  int
		maxSigSize    int
	}{
		{"P256", elliptic.P256(), 256, 72},  // Max DER signature size for P256
		{"P384", elliptic.P384(), 384, 104}, // Max DER signature size for P384
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			keyPair, err := client.GenerateECDSAKeyPair(tc.curve)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key pair: %v", err)
			}

			if keyPair.KeySize != tc.expectedSize {
				t.Errorf("Expected key size %d, got %d", tc.expectedSize, keyPair.KeySize)
			}

			ecdsaKeyPair, err := pkcs11.NewECDSAKeyPair(keyPair)
			if err != nil {
				t.Fatalf("Failed to create ECDSA key pair: %v", err)
			}

			message := []byte("test message")
			digest := sha256.Sum256(message)

			signature, err := ecdsaKeyPair.Sign(rand.Reader, digest[:], crypto.SHA256)
			if err != nil {
				t.Errorf("Sign() failed for %s: %v", tc.name, err)
			}

			if len(signature) == 0 {
				t.Error("Signature should not be empty")
			}

			if len(signature) > tc.maxSigSize {
				t.Errorf("Signature too large: expected max %d, got %d", tc.maxSigSize, len(signature))
			}

			// Verify signature
			ecdsaPubKey, ok := keyPair.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				t.Fatal("Public key should be *ecdsa.PublicKey")
			}

			valid := ecdsa.VerifyASN1(ecdsaPubKey, digest[:], signature)
			if !valid {
				t.Errorf("Signature verification failed for %s", tc.name)
			}
		})
	}
}

func TestECDSAKeyPairSignatureCompatibility(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateECDSAKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	ecdsaKeyPair, err := pkcs11.NewECDSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ECDSA key pair: %v", err)
	}

	// Test that signatures are compatible with standard Go crypto/ecdsa verification
	message := []byte("test message for compatibility")
	digest := sha256.Sum256(message)

	// Sign with our ECDSA key pair
	signature, err := ecdsaKeyPair.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Verify with Go's crypto/ecdsa
	ecdsaPubKey, ok := keyPair.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("Public key should be *ecdsa.PublicKey")
	}

	valid := ecdsa.VerifyASN1(ecdsaPubKey, digest[:], signature)
	if !valid {
		t.Error("Signature verification failed")
	}
}

func TestECDSAKeyPairConcurrentOperations(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateECDSAKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	ecdsaKeyPair, err := pkcs11.NewECDSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ECDSA key pair: %v", err)
	}

	// Test concurrent signing operations
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()
			
			message := []byte("test message")
			digest := sha256.Sum256(message)
			
			_, err := ecdsaKeyPair.Sign(rand.Reader, digest[:], crypto.SHA256)
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

func TestECDSAKeyPairHashAlgorithmValidation(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateECDSAKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	ecdsaKeyPair, err := pkcs11.NewECDSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ECDSA key pair: %v", err)
	}

	// Test all supported hash algorithms with their expected digest lengths
	testCases := []struct {
		hash       crypto.Hash
		digestLen  int
		shouldPass bool
	}{
		{crypto.SHA1, 20, true},
		{crypto.SHA224, 28, true},
		{crypto.SHA256, 32, true},
		{crypto.SHA384, 48, true},
		{crypto.SHA512, 64, true},
		{crypto.MD5, 16, false},    // Should fail - unsupported
		{crypto.Hash(999), 32, false}, // Should fail - invalid hash
	}

	for _, tc := range testCases {
		t.Run(tc.hash.String(), func(t *testing.T) {
			digest := make([]byte, tc.digestLen)
			_, err := ecdsaKeyPair.Sign(rand.Reader, digest, tc.hash)
			
			if tc.shouldPass && err != nil {
				t.Errorf("Sign() should pass for %s: %v", tc.hash.String(), err)
			} else if !tc.shouldPass && err == nil {
				t.Errorf("Sign() should fail for %s", tc.hash.String())
			}
		})
	}
}

func TestECDSAKeyPairSignatureEdgeCases(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateECDSAKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	ecdsaKeyPair, err := pkcs11.NewECDSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ECDSA key pair: %v", err)
	}

	t.Run("AllZeroDigest", func(t *testing.T) {
		// Test with all-zero digest
		digest := make([]byte, 32)
		signature, err := ecdsaKeyPair.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			t.Errorf("Sign() should handle all-zero digest: %v", err)
		}

		// Verify signature
		ecdsaPubKey, ok := keyPair.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("Public key should be *ecdsa.PublicKey")
		}

		valid := ecdsa.VerifyASN1(ecdsaPubKey, digest, signature)
		if !valid {
			t.Error("All-zero digest signature verification failed")
		}
	})

	t.Run("AllOnesDigest", func(t *testing.T) {
		// Test with all-ones digest
		digest := make([]byte, 32)
		for i := range digest {
			digest[i] = 0xFF
		}
		
		signature, err := ecdsaKeyPair.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			t.Errorf("Sign() should handle all-ones digest: %v", err)
		}

		// Verify signature
		ecdsaPubKey, ok := keyPair.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("Public key should be *ecdsa.PublicKey")
		}

		valid := ecdsa.VerifyASN1(ecdsaPubKey, digest, signature)
		if !valid {
			t.Error("All-ones digest signature verification failed")
		}
	})

	t.Run("RandomDigest", func(t *testing.T) {
		// Test with random digest
		digest := make([]byte, 32)
		_, err := rand.Read(digest)
		if err != nil {
			t.Fatalf("Failed to generate random digest: %v", err)
		}
		
		signature, err := ecdsaKeyPair.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			t.Errorf("Sign() should handle random digest: %v", err)
		}

		// Verify signature
		ecdsaPubKey, ok := keyPair.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("Public key should be *ecdsa.PublicKey")
		}

		valid := ecdsa.VerifyASN1(ecdsaPubKey, digest, signature)
		if !valid {
			t.Error("Random digest signature verification failed")
		}
	})
}

func TestECDSAKeyPairPublicKeyValidation(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateECDSAKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	ecdsaKeyPair, err := pkcs11.NewECDSAKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Failed to create ECDSA key pair: %v", err)
	}

	// Test that public key is valid
	pubKey := ecdsaKeyPair.Public()
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("Public key should be *ecdsa.PublicKey")
	}

	// Verify public key is on the curve
	if !ecdsaPubKey.Curve.IsOnCurve(ecdsaPubKey.X, ecdsaPubKey.Y) {
		t.Error("Public key should be on the curve")
	}

	// Verify X and Y coordinates are not zero
	if ecdsaPubKey.X.Sign() == 0 || ecdsaPubKey.Y.Sign() == 0 {
		t.Error("Public key coordinates should not be zero")
	}
}