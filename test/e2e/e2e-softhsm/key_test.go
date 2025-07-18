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

func TestKeyPairString(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	t.Run("RSAKeyPair", func(t *testing.T) {
		keyPair, err := client.GenerateRSAKeyPair(2048)
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
		if !strings.Contains(str, "Size: 2048") {
			t.Error("String representation should contain 'Size: 2048'")
		}
		if !strings.Contains(str, "ID: 0x") {
			t.Error("String representation should contain 'ID: 0x'")
		}
	})

	t.Run("ECDSAKeyPair", func(t *testing.T) {
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

func TestKeyPairPublic(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	t.Run("RSAKeyPair", func(t *testing.T) {
		keyPair, err := client.GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		pubKey := keyPair.Public()
		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			t.Error("Public key should be *rsa.PublicKey")
		}
		if rsaPubKey.Size() != 256 { // 2048 bits = 256 bytes
			t.Errorf("Expected key size 256 bytes, got %d", rsaPubKey.Size())
		}
	})

	t.Run("ECDSAKeyPair", func(t *testing.T) {
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

func TestKeyPairAsSigner(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	t.Run("RSAKeyPair", func(t *testing.T) {
		keyPair, err := client.GenerateRSAKeyPair(2048)
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

func TestKeyPairAsDecrypter(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	t.Run("RSAKeyPair", func(t *testing.T) {
		keyPair, err := client.GenerateRSAKeyPair(2048)
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

func TestKeyPairEdgeCases(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

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

	// Use client to suppress the unused variable warning
	_ = client
}

func TestKeyPairIDHexEncoding(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateRSAKeyPair(2048)
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

func TestKeyPairConcurrentAccess(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	keyPair, err := client.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Test concurrent access to key pair methods
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
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
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestSymmetricKeyConcurrentAccess(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	key, err := client.GenerateAESKey(256)
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	// Test concurrent access to symmetric key methods
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()

			// Test String() method concurrently
			_ = key.String()
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestKeyPairFieldValidation(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	t.Run("RSAKeyPairFields", func(t *testing.T) {
		keyPair, err := client.GenerateRSAKeyPair(2048)
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
		if keyPair.KeySize != 2048 {
			t.Error("KeySize should be 2048")
		}
		if keyPair.PublicKey == nil {
			t.Error("PublicKey should not be nil")
		}
		if keyPair.Handle == keyPair.PublicHandle {
			t.Error("Handle and PublicHandle should be different")
		}
	})

	t.Run("ECDSAKeyPairFields", func(t *testing.T) {
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

func TestSymmetricKeyFieldValidation(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	t.Run("AESKeyFields", func(t *testing.T) {
		key, err := client.GenerateAESKey(192)
		if err != nil {
			t.Fatalf("Failed to generate AES key: %v", err)
		}

		// Validate all fields are populated
		if key.Handle == 0 {
			t.Error("Handle should not be zero")
		}
		if key.Label == "" {
			t.Error("Label should not be empty")
		}
		if len(key.ID) == 0 {
			t.Error("ID should not be empty")
		}
		if key.KeyType != pkcs11.SymmetricKeyTypeAES {
			t.Error("KeyType should be AES")
		}
		if key.KeySize != 192 {
			t.Error("KeySize should be 192")
		}
	})

	t.Run("DESKeyFields", func(t *testing.T) {
		key, err := client.GenerateDESKey()
		if err != nil {
			t.Fatalf("Failed to generate DES key: %v", err)
		}

		if key.KeyType != pkcs11.SymmetricKeyTypeDES {
			t.Error("KeyType should be DES")
		}
		if key.KeySize != 64 {
			t.Error("KeySize should be 64")
		}
	})

	t.Run("3DESKeyFields", func(t *testing.T) {
		key, err := client.Generate3DESKey()
		if err != nil {
			t.Fatalf("Failed to generate 3DES key: %v", err)
		}

		if key.KeyType != pkcs11.SymmetricKeyType3DES {
			t.Error("KeyType should be 3DES")
		}
		if key.KeySize != 192 {
			t.Error("KeySize should be 192")
		}
	})
}
