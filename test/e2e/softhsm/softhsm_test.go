package softhsm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/yeaops/gopkcs11"
	"github.com/yeaops/gopkcs11/test/e2e"
)

// getSoftHSMTestConfig returns a test configuration optimized for SoftHSM
func getSoftHSMTestConfig() *e2e.CommonTestConfig {
	config := e2e.DefaultCommonTestConfig()

	// SoftHSM is software-based, so it can handle most operations
	config.SkipConcurrencyTests = false
	config.SkipLargeDataTests = false
	config.SkipPerformanceTests = false

	// Increase limits for SoftHSM since it's software-based
	config.MaxTestDataSize = 10 * 1024 * 1024 // 10MB
	config.MaxConcurrentOps = 20

	// SoftHSM supports all standard algorithms
	config.SupportedRSAKeySizes = []int{2048, 4096}
	config.SupportedAESKeySizes = []int{128, 192, 256}
	config.SupportedECDSACurves = []string{"P256", "P384"}
	config.SupportedCipherModes = []string{"ECB", "CBC", "GCM"}

	return config
}

// TestNewSoftHSM tests basic SoftHSM setup functionality
func TestNewSoftHSM(t *testing.T) {
	hsm, err := NewTestSoftHSM()
	if err != nil || hsm == nil {
		t.Fatalf("Failed to create SoftHSM instance, err: %s", err)
	}
	defer hsm.Cleanup()

	token, err := hsm.CreateToken("test_token", "12345678", "12345678")
	if err != nil || token == nil {
		t.Fatalf("Failed to create token, err: %s", err)
	}
	defer token.Close()
}

// TestSoftHSMTokenFunctionality runs comprehensive token tests using the e2e framework
func TestSoftHSMTokenFunctionality(t *testing.T) {
	hsm, err := NewTestSoftHSM()
	if err != nil {
		t.Fatalf("Failed to create SoftHSM instance: %v", err)
	}
	defer hsm.Cleanup()

	ctx := e2e.NewTestContext(hsm, getSoftHSMTestConfig())
	e2e.RunTokenTests(t, ctx)
}

// TestSoftHSMKeypairFunctionality runs comprehensive keypair tests using the e2e framework
func TestSoftHSMKeypairFunctionality(t *testing.T) {
	hsm, err := NewTestSoftHSM()
	if err != nil {
		t.Fatalf("Failed to create SoftHSM instance: %v", err)
	}
	defer hsm.Cleanup()

	ctx := e2e.NewTestContext(hsm, getSoftHSMTestConfig())
	e2e.RunKeypairTests(t, ctx)
}

// TestSoftHSMCipherFunctionality runs comprehensive cipher tests using the e2e framework
func TestSoftHSMCipherFunctionality(t *testing.T) {
	hsm, err := NewTestSoftHSM()
	if err != nil {
		t.Fatalf("Failed to create SoftHSM instance: %v", err)
	}
	defer hsm.Cleanup()

	ctx := e2e.NewTestContext(hsm, getSoftHSMTestConfig())
	e2e.RunCipherTests(t, ctx)
}

// TestSoftHSMSymmetricKeyFunctionality runs comprehensive symmetric key tests using the e2e framework
func TestSoftHSMSymmetricKeyFunctionality(t *testing.T) {
	hsm, err := NewTestSoftHSM()
	if err != nil {
		t.Fatalf("Failed to create SoftHSM instance: %v", err)
	}
	defer hsm.Cleanup()

	ctx := e2e.NewTestContext(hsm, getSoftHSMTestConfig())
	e2e.RunSymmetricKeyTests(t, ctx)
}

// TestSoftHSMLibraryDetection tests SoftHSM library path detection across platforms
func TestSoftHSMLibraryDetection(t *testing.T) {
	// Test that we can detect SoftHSM library
	libraryPath, err := getBundledSoftHSMPath()
	if err != nil {
		t.Skipf("SoftHSM library not found (this is expected in some environments): %v", err)
	}

	if libraryPath == "" {
		t.Error("Library path should not be empty when no error is returned")
	}

	t.Logf("Detected SoftHSM library at: %s", libraryPath)
}

// TestSoftHSMTokenInitialization tests various token initialization scenarios
func TestSoftHSMTokenInitialization(t *testing.T) {
	hsm, err := NewTestSoftHSM()
	if err != nil {
		t.Fatalf("Failed to create SoftHSM instance: %v", err)
	}
	defer hsm.Cleanup()

	t.Run("StandardInitialization", func(t *testing.T) {
		token, err := hsm.CreateToken("test-token-1", "12345678", "87654321")
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}
		defer token.Close()

		if !token.IsConnected() {
			t.Error("Token should be connected after token creation")
		}
	})

}

// TestSoftHSMIntegration runs a comprehensive integration test combining multiple operations
func TestSoftHSMIntegration(t *testing.T) {
	hsm, err := NewTestSoftHSM()
	if err != nil {
		t.Fatalf("Failed to create SoftHSM instance: %v", err)
	}
	defer hsm.Cleanup()

	token, err := hsm.CreateToken("integration-test", "12345678", "87654321")
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}
	defer token.Close()

	t.Run("RSAKeypairOperations", func(t *testing.T) {
		// Generate RSA keypair
		keyPair, err := token.GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keypair: %v", err)
		}

		// Test signing
		signer := keyPair.AsSigner()
		if signer == nil {
			t.Fatal("Failed to get signer from RSA keypair")
		}

		message := []byte("test message for integration")
		// Use proper random source and hash for RSA signing
		hash := sha256.Sum256(message)
		signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}

		if len(signature) == 0 {
			t.Error("Signature should not be empty")
		}
	})

	t.Run("AESSymmetricOperations", func(t *testing.T) {
		// Generate AES key
		aesKey, err := token.GenerateAESKey(256)
		if err != nil {
			t.Fatalf("Failed to generate AES key: %v", err)
		}

		// Create cipher
		cipher, err := gopkcs11.NewAESECBCipher(aesKey)
		if err != nil {
			t.Fatalf("Failed to create AES cipher: %v", err)
		}

		// Test encryption/decryption
		plaintext := []byte("Hello SoftHSM Integration Test!")

		// Pad to block size for ECB mode
		blockSize := 16
		padding := blockSize - (len(plaintext) % blockSize)
		for i := 0; i < padding; i++ {
			plaintext = append(plaintext, byte(padding))
		}

		encrypted, err := cipher.Encrypt(context.Background(), plaintext)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		decrypted, err := cipher.Decrypt(context.Background(), encrypted)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if len(decrypted) != len(plaintext) {
			t.Errorf("Decrypted length mismatch: expected %d, got %d", len(plaintext), len(decrypted))
		}
	})
}
