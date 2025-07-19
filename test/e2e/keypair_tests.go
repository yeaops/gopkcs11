package e2e

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	pkcs11 "github.com/yeaops/gopkcs11"
)

// RunKeypairTests runs the complete suite of keypair tests
func RunKeypairTests(t *testing.T, ctx *TestContext) {
	t.Run("KeyPairGeneration", func(t *testing.T) {
		TestKeypairGeneration(t, ctx)
	})
	
	t.Run("KeyPairString", func(t *testing.T) {
		TestKeypairString(t, ctx)
	})
	
	t.Run("KeyPairPublic", func(t *testing.T) {
		TestKeypairPublic(t, ctx)
	})
	
	t.Run("KeyPairAsSigner", func(t *testing.T) {
		TestKeypairAsSigner(t, ctx)
	})
	
	t.Run("KeyPairAsDecrypter", func(t *testing.T) {
		TestKeypairAsDecrypter(t, ctx)
	})
	
	t.Run("KeyPairEdgeCases", func(t *testing.T) {
		TestKeypairEdgeCases(t, ctx)
	})
	
	t.Run("KeyPairIDHexEncoding", func(t *testing.T) {
		TestKeypairIDHexEncoding(t, ctx)
	})
	
	if !ctx.Config.SkipConcurrencyTests {
		t.Run("KeyPairConcurrentAccess", func(t *testing.T) {
			TestKeypairConcurrentAccess(t, ctx)
		})
	}
	
	t.Run("KeyPairFieldValidation", func(t *testing.T) {
		TestKeypairFieldValidation(t, ctx)
	})
	
	// RSA-specific tests
	t.Run("RSA", func(t *testing.T) {
		TestRSAKeypairs(t, ctx)
	})
	
	// ECDSA-specific tests
	t.Run("ECDSA", func(t *testing.T) {
		TestECDSAKeypairs(t, ctx)
	})
	
	// ED25519-specific tests
	t.Run("ED25519", func(t *testing.T) {
		TestED25519Keypairs(t, ctx)
	})
}

// TestKeypairGeneration tests basic keypair generation for all supported types
func TestKeypairGeneration(t *testing.T, ctx *TestContext) {
	client, cleanup := ctx.CreateTestClient(t)
	defer cleanup()

	// Test RSA key generation
	for _, keySize := range ctx.Config.SupportedRSAKeySizes {
		t.Run("RSA_"+string(rune(keySize)), func(t *testing.T) {
			keyPair, err := client.GenerateRSAKeyPair(keySize)
			if err != nil {
				t.Fatalf("Failed to generate RSA %d key pair: %v", keySize, err)
			}
			if keyPair == nil {
				t.Error("GenerateRSAKeyPair should return non-nil keypair")
			}
			if keyPair.KeySize != keySize {
				t.Errorf("Expected key size %d, got %d", keySize, keyPair.KeySize)
			}
			if keyPair.KeyType != pkcs11.KeyPairTypeRSA {
				t.Errorf("Expected RSA key type, got %v", keyPair.KeyType)
			}
		})
	}

	// Test ECDSA key generation
	curves := map[string]elliptic.Curve{
		"P256": elliptic.P256(),
		"P384": elliptic.P384(),
	}
	for _, curveName := range ctx.Config.SupportedECDSACurves {
		if curve, ok := curves[curveName]; ok {
			t.Run("ECDSA_"+curveName, func(t *testing.T) {
				keyPair, err := client.GenerateECDSAKeyPair(curve)
				if err != nil {
					t.Fatalf("Failed to generate ECDSA %s key pair: %v", curveName, err)
				}
				if keyPair == nil {
					t.Error("GenerateECDSAKeyPair should return non-nil keypair")
				}
				if keyPair.KeyType != pkcs11.KeyPairTypeECDSA {
					t.Errorf("Expected ECDSA key type, got %v", keyPair.KeyType)
				}
			})
		}
	}

	// Test ED25519 key generation
	t.Run("ED25519", func(t *testing.T) {
		keyPair, err := client.GenerateED25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate ED25519 key pair: %v", err)
		}
		if keyPair == nil {
			t.Error("GenerateED25519KeyPair should return non-nil keypair")
		}
		if keyPair.KeyType != pkcs11.KeyPairTypeED25519 {
			t.Errorf("Expected ED25519 key type, got %v", keyPair.KeyType)
		}
		if keyPair.KeySize != 255 {
			t.Errorf("Expected key size 255, got %d", keyPair.KeySize)
		}
	})
}

// TestKeypairString tests string representation of keypairs
func TestKeypairString(t *testing.T, ctx *TestContext) {
	client, cleanup := ctx.CreateTestClient(t)
	defer cleanup()

	t.Run("RSAKeyPair", func(t *testing.T) {
		keySize := ctx.Config.SupportedRSAKeySizes[0]
		keyPair, err := client.GenerateRSAKeyPair(keySize)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		str := keyPair.String()
		if !strings.Contains(str, "Key{") {
			t.Error("String representation should contain 'Key{'")
		}
		if !strings.Contains(str, "Label:") {
			t.Error("String representation should contain 'Label:'")
		}
		if !strings.Contains(str, "Type:") {
			t.Error("String representation should contain 'Type:'")
		}
		if !strings.Contains(str, "Size:") {
			t.Error("String representation should contain 'Size:'")
		}
		if !strings.Contains(str, "ID: 0x") {
			t.Error("String representation should contain 'ID: 0x'")
		}
	})

	t.Run("ECDSAKeyPair", func(t *testing.T) {
		if len(ctx.Config.SupportedECDSACurves) == 0 {
			t.Skip("No ECDSA curves supported")
		}
		
		keyPair, err := client.GenerateECDSAKeyPair(elliptic.P256())
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key pair: %v", err)
		}

		str := keyPair.String()
		if !strings.Contains(str, "Size: 256") {
			t.Error("String representation should contain 'Size: 256'")
		}
	})

	t.Run("ED25519KeyPair", func(t *testing.T) {
		keyPair, err := client.GenerateED25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate ED25519 key pair: %v", err)
		}

		str := keyPair.String()
		if !strings.Contains(str, "Size: 255") {
			t.Error("String representation should contain 'Size: 255'")
		}
	})
}

// TestKeypairPublic tests public key extraction from keypairs
func TestKeypairPublic(t *testing.T, ctx *TestContext) {
	client, cleanup := ctx.CreateTestClient(t)
	defer cleanup()

	t.Run("RSAKeyPair", func(t *testing.T) {
		keySize := ctx.Config.SupportedRSAKeySizes[0]
		keyPair, err := client.GenerateRSAKeyPair(keySize)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		pubKey := keyPair.Public()
		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			t.Error("Public key should be *rsa.PublicKey")
		}
		expectedBytes := keySize / 8
		if rsaPubKey.Size() != expectedBytes {
			t.Errorf("Expected key size %d bytes, got %d", expectedBytes, rsaPubKey.Size())
		}
	})

	t.Run("ECDSAKeyPair", func(t *testing.T) {
		if len(ctx.Config.SupportedECDSACurves) == 0 {
			t.Skip("No ECDSA curves supported")
		}
		
		keyPair, err := client.GenerateECDSAKeyPair(elliptic.P256())
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key pair: %v", err)
		}

		pubKey := keyPair.Public()
		ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			t.Error("Public key should be *ecdsa.PublicKey")
		}
		if ecdsaPubKey.Curve != elliptic.P256() {
			t.Error("Expected P256 curve")
		}
	})

	t.Run("ED25519KeyPair", func(t *testing.T) {
		keyPair, err := client.GenerateED25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate ED25519 key pair: %v", err)
		}

		pubKey := keyPair.Public()
		ed25519PubKey, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			t.Error("Public key should be ed25519.PublicKey")
		}
		if len(ed25519PubKey) != ed25519.PublicKeySize {
			t.Errorf("Expected public key size %d, got %d", ed25519.PublicKeySize, len(ed25519PubKey))
		}
	})
}

// TestKeypairAsSigner tests crypto.Signer interface implementation
func TestKeypairAsSigner(t *testing.T, ctx *TestContext) {
	client, cleanup := ctx.CreateTestClient(t)
	defer cleanup()

	t.Run("RSAKeyPair", func(t *testing.T) {
		keySize := ctx.Config.SupportedRSAKeySizes[0]
		keyPair, err := client.GenerateRSAKeyPair(keySize)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		signer := keyPair.AsSigner()
		if signer == nil {
			t.Error("AsSigner should return non-nil signer")
		}

		// Test signing
		message := []byte("test message")
		hash := sha256.Sum256(message)
		signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
		if err != nil {
			t.Errorf("Failed to sign: %v", err)
		}
		if len(signature) == 0 {
			t.Error("Signature should not be empty")
		}
	})

	t.Run("ECDSAKeyPair", func(t *testing.T) {
		if len(ctx.Config.SupportedECDSACurves) == 0 {
			t.Skip("No ECDSA curves supported")
		}
		
		keyPair, err := client.GenerateECDSAKeyPair(elliptic.P256())
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key pair: %v", err)
		}

		signer := keyPair.AsSigner()
		if signer == nil {
			t.Error("AsSigner should return non-nil signer")
		}

		// Test signing
		message := []byte("test message")
		hash := sha256.Sum256(message)
		signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
		if err != nil {
			t.Errorf("Failed to sign: %v", err)
		}
		if len(signature) == 0 {
			t.Error("Signature should not be empty")
		}
	})

	t.Run("ED25519KeyPair", func(t *testing.T) {
		keyPair, err := client.GenerateED25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate ED25519 key pair: %v", err)
		}

		signer := keyPair.AsSigner()
		if signer == nil {
			t.Error("AsSigner should return non-nil signer")
		}

		// Test signing
		message := []byte("test message")
		signature, err := signer.Sign(rand.Reader, message, nil)
		if err != nil {
			t.Errorf("Failed to sign: %v", err)
		}
		if len(signature) != ed25519.SignatureSize {
			t.Errorf("Expected signature size %d, got %d", ed25519.SignatureSize, len(signature))
		}
	})

	t.Run("UnsupportedKeyType", func(t *testing.T) {
		// Create a key pair with invalid key type
		keyPair := &pkcs11.KeyPair{
			KeyType: pkcs11.KeyPairType(999), // Invalid key type
		}

		signer := keyPair.AsSigner()
		if signer != nil {
			t.Error("AsSigner should return nil for unsupported key type")
		}
	})
}

// TestKeypairAsDecrypter tests crypto.Decrypter interface implementation
func TestKeypairAsDecrypter(t *testing.T, ctx *TestContext) {
	client, cleanup := ctx.CreateTestClient(t)
	defer cleanup()

	t.Run("RSAKeyPair", func(t *testing.T) {
		keySize := ctx.Config.SupportedRSAKeySizes[0]
		keyPair, err := client.GenerateRSAKeyPair(keySize)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		decrypter, err := keyPair.AsDecrypter()
		if err != nil {
			t.Errorf("AsDecrypter should not return error for RSA key: %v", err)
		}
		if decrypter == nil {
			t.Error("AsDecrypter should return non-nil decrypter for RSA key")
		}
	})

	t.Run("ECDSAKeyPair", func(t *testing.T) {
		if len(ctx.Config.SupportedECDSACurves) == 0 {
			t.Skip("No ECDSA curves supported")
		}
		
		keyPair, err := client.GenerateECDSAKeyPair(elliptic.P256())
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key pair: %v", err)
		}

		decrypter, err := keyPair.AsDecrypter()
		if err == nil {
			t.Error("AsDecrypter should return error for ECDSA key")
		}
		if decrypter != nil {
			t.Error("AsDecrypter should return nil decrypter for ECDSA key")
		}
	})

	t.Run("ED25519KeyPair", func(t *testing.T) {
		keyPair, err := client.GenerateED25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate ED25519 key pair: %v", err)
		}

		decrypter, err := keyPair.AsDecrypter()
		if err == nil {
			t.Error("AsDecrypter should return error for ED25519 key")
		}
		if decrypter != nil {
			t.Error("AsDecrypter should return nil decrypter for ED25519 key")
		}
	})
}

// TestKeypairEdgeCases tests edge cases in keypair handling
func TestKeypairEdgeCases(t *testing.T, ctx *TestContext) {
	t.Run("EmptyKeyPair", func(t *testing.T) {
		keyPair := &pkcs11.KeyPair{}

		// Test String() with empty key pair
		str := keyPair.String()
		if !strings.Contains(str, "Key{") {
			t.Error("String should still contain 'Key{' even for empty key pair")
		}

		// Test Public() with empty key pair
		pubKey := keyPair.Public()
		if pubKey != nil {
			t.Error("Public() should return nil for empty key pair")
		}

		// Test AsSigner() with empty key pair
		signer := keyPair.AsSigner()
		if signer != nil {
			t.Error("AsSigner() should return nil for empty key pair")
		}
	})

	t.Run("KeyPairWithInvalidKeyType", func(t *testing.T) {
		keyPair := &pkcs11.KeyPair{
			KeyType: pkcs11.KeyPairTypeECDSA,
		}

		// Test AsDecrypter with non-RSA key
		_, err := keyPair.AsDecrypter()
		if err == nil {
			t.Error("AsDecrypter should return error for non-RSA key")
		}
	})
}

// TestKeypairIDHexEncoding tests hex encoding of keypair IDs
func TestKeypairIDHexEncoding(t *testing.T, ctx *TestContext) {
	client, cleanup := ctx.CreateTestClient(t)
	defer cleanup()

	keySize := ctx.Config.SupportedRSAKeySizes[0]
	keyPair, err := client.GenerateRSAKeyPair(keySize)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Test that ID is properly hex encoded in String()
	str := keyPair.String()
	if !strings.Contains(str, "ID: 0x") {
		t.Error("String should contain hex-encoded ID")
	}

	// Extract the hex part and verify it's valid hex
	parts := strings.Split(str, "ID: 0x")
	if len(parts) != 2 {
		t.Error("String should contain exactly one 'ID: 0x' substring")
	}

	hexPart := strings.Split(parts[1], ",")[0]
	if len(hexPart) == 0 {
		t.Error("Hex part should not be empty")
	}

	// Verify it's valid hex
	decoded, err := hex.DecodeString(hexPart)
	if err != nil {
		t.Errorf("ID should be valid hex: %v", err)
	}

	// Verify it matches the actual ID
	if string(decoded) != string(keyPair.ID) {
		t.Error("Hex-encoded ID should match actual ID")
	}
}

// TestKeypairConcurrentAccess tests concurrent access to keypair methods
func TestKeypairConcurrentAccess(t *testing.T, ctx *TestContext) {
	if ctx.Config.SkipConcurrencyTests {
		t.Skip("Concurrency tests disabled in configuration")
	}

	client, cleanup := ctx.CreateTestClient(t)
	defer cleanup()

	keySize := ctx.Config.SupportedRSAKeySizes[0]
	keyPair, err := client.GenerateRSAKeyPair(keySize)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Test concurrent access to key pair methods
	numGoroutines := ctx.Config.MaxConcurrentOps
	if numGoroutines <= 0 {
		numGoroutines = 10
	}
	
	done := make(chan bool, numGoroutines)

	for range numGoroutines {
		go func() {
			defer func() { done <- true }()

			// Test various methods concurrently
			_ = keyPair.String()
			_ = keyPair.Public()
			_ = keyPair.AsSigner()
			_, _ = keyPair.AsDecrypter()
		}()
	}

	// Wait for all goroutines to complete
	for range numGoroutines {
		<-done
	}
}

// TestKeypairFieldValidation tests that keypair fields are properly populated
func TestKeypairFieldValidation(t *testing.T, ctx *TestContext) {
	client, cleanup := ctx.CreateTestClient(t)
	defer cleanup()

	t.Run("RSAKeyPairFields", func(t *testing.T) {
		keySize := ctx.Config.SupportedRSAKeySizes[0]
		keyPair, err := client.GenerateRSAKeyPair(keySize)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		// Validate all fields are populated
		if keyPair.Handle == 0 {
			t.Error("Handle should not be zero")
		}
		if keyPair.PublicHandle == 0 {
			t.Error("PublicHandle should not be zero")
		}
		if keyPair.Label == "" {
			t.Error("Label should not be empty")
		}
		if len(keyPair.ID) == 0 {
			t.Error("ID should not be empty")
		}
		if keyPair.KeyType != pkcs11.KeyPairTypeRSA {
			t.Error("KeyType should be RSA")
		}
		if keyPair.KeySize != keySize {
			t.Errorf("KeySize should be %d", keySize)
		}
		if keyPair.PublicKey == nil {
			t.Error("PublicKey should not be nil")
		}
		if keyPair.Handle == keyPair.PublicHandle {
			t.Error("Handle and PublicHandle should be different")
		}
	})

	t.Run("ECDSAKeyPairFields", func(t *testing.T) {
		if len(ctx.Config.SupportedECDSACurves) == 0 {
			t.Skip("No ECDSA curves supported")
		}
		
		keyPair, err := client.GenerateECDSAKeyPair(elliptic.P384())
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key pair: %v", err)
		}

		if keyPair.KeyType != pkcs11.KeyPairTypeECDSA {
			t.Error("KeyType should be ECDSA")
		}
		if keyPair.KeySize != 384 {
			t.Error("KeySize should be 384")
		}

		// Validate public key is correct type
		ecdsaPubKey, ok := keyPair.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Error("PublicKey should be *ecdsa.PublicKey")
		}
		if ecdsaPubKey.Curve != elliptic.P384() {
			t.Error("Curve should be P384")
		}
	})

	t.Run("ED25519KeyPairFields", func(t *testing.T) {
		keyPair, err := client.GenerateED25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate ED25519 key pair: %v", err)
		}

		if keyPair.KeyType != pkcs11.KeyPairTypeED25519 {
			t.Error("KeyType should be ED25519")
		}
		if keyPair.KeySize != 255 {
			t.Error("KeySize should be 255")
		}

		// Validate public key is correct type
		ed25519PubKey, ok := keyPair.PublicKey.(ed25519.PublicKey)
		if !ok {
			t.Error("PublicKey should be ed25519.PublicKey")
		}
		if len(ed25519PubKey) != ed25519.PublicKeySize {
			t.Error("PublicKey should have correct size")
		}
	})
}

// TestRSAKeypairs runs RSA-specific keypair tests
func TestRSAKeypairs(t *testing.T, ctx *TestContext) {
	// RSA-specific tests would be implemented here
	// These would include detailed RSA signing, encryption, different key sizes, etc.
	t.Skip("Detailed RSA keypair tests should be implemented")
}

// TestECDSAKeypairs runs ECDSA-specific keypair tests
func TestECDSAKeypairs(t *testing.T, ctx *TestContext) {
	// ECDSA-specific tests would be implemented here
	// These would include different curves, signing algorithms, etc.
	t.Skip("Detailed ECDSA keypair tests should be implemented")
}

// TestED25519Keypairs runs ED25519-specific keypair tests
func TestED25519Keypairs(t *testing.T, ctx *TestContext) {
	// ED25519-specific tests would be implemented here
	// These would include signing, message handling, etc.
	t.Skip("Detailed ED25519 keypair tests should be implemented")
}