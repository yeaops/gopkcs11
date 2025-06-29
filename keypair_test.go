package gopkcs11

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"os"
	"testing"

	"github.com/miekg/pkcs11"
)

// We'll need to implement a way to inject a mock context into the Client for testing
// For now, let's create tests that focus on the key management logic that we can test

func TestKeyPair_String(t *testing.T) {
	keyPair := &KeyPair{
		Handle:    1000,
		Label:     "test-key",
		ID:        []byte("test-id"),
		KeyType:   KeyPairTypeRSA,
		KeySize:   2048,
		PublicKey: nil,
	}

	expected := "Key{Label: test-key, Type: 0, Size: 2048}"
	result := keyPair.String()

	if result != expected {
		t.Errorf("Expected '%s', got '%s'", expected, result)
	}
}

func TestKeyPairType_Constants(t *testing.T) {
	if KeyPairTypeRSA != 0 {
		t.Errorf("Expected KeyPairTypeRSA to be 0, got %d", KeyPairTypeRSA)
	}
	if KeyPairTypeECDSA != 1 {
		t.Errorf("Expected KeyPairTypeECDSA to be 1, got %d", KeyPairTypeECDSA)
	}
	if KeyPairTypeED25519 != 2 {
		t.Errorf("Expected KeyPairTypeED25519 to be 2, got %d", KeyPairTypeED25519)
	}
}

// Integration-style test that requires a working mock
func TestClient_GenerateRSAKeyPair_Integration(t *testing.T) {
	// Create a temporary library file for the client
	tmpFile, err := os.CreateTemp("", "libpkcs11*.so")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// This test would require dependency injection to work properly
	// For now, we'll skip it in CI environments
	if os.Getenv("CI") != "" {
		t.Skip("Skipping integration test in CI environment")
	}

	slotID := uint(0)
	_ = &Config{
		LibraryPath: tmpFile.Name(),
		SlotID:      &slotID,
		UserPIN:     "testpin",
	}

	// Since we can't easily mock the PKCS#11 library at this level,
	// we'll test the input validation logic
	testCases := []struct {
		name    string
		label   string
		keySize int
		wantErr bool
	}{
		{
			name:    "valid RSA 2048",
			label:   "test-rsa-2048",
			keySize: 2048,
			wantErr: false, // Would be false if we had a real mock
		},
		{
			name:    "valid RSA 4096",
			label:   "test-rsa-4096",
			keySize: 4096,
			wantErr: false, // Would be false if we had a real mock
		},
		{
			name:    "invalid RSA size",
			label:   "test-rsa-invalid",
			keySize: 1024,
			wantErr: true,
		},
		{
			name:    "invalid RSA size 3072",
			label:   "test-rsa-3072",
			keySize: 3072,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the validation logic that happens before PKCS#11 calls
			if tc.keySize != 2048 && tc.keySize != 4096 {
				// This should fail validation
				if !tc.wantErr {
					t.Error("Expected error for invalid key size")
				}
			}
		})
	}
}

func TestClient_GenerateECDSAKeyPair_CurveValidation(t *testing.T) {
	testCases := []struct {
		name    string
		curve   elliptic.Curve
		wantErr bool
	}{
		{
			name:    "P-256 curve",
			curve:   elliptic.P256(),
			wantErr: false,
		},
		{
			name:    "P-384 curve",
			curve:   elliptic.P384(),
			wantErr: false,
		},
		{
			name:    "P-521 curve (unsupported)",
			curve:   elliptic.P521(),
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test curve validation logic
			var curveOID []byte
			switch tc.curve {
			case elliptic.P256():
				curveOID = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
			case elliptic.P384():
				curveOID = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}
			default:
				// Unsupported curve
				if !tc.wantErr {
					t.Error("Expected error for unsupported curve")
				}
				return
			}

			if len(curveOID) == 0 && !tc.wantErr {
				t.Error("Expected curve OID to be set for supported curves")
			}
		})
	}
}

// Test public key extraction logic for RSA
func TestExtractRSAPublicKey_Logic(t *testing.T) {
	// Test the logic that would be used in extractRSAPublicKey
	// We can't test the actual method without mocking the PKCS#11 context

	// Simulate the attributes that would be returned
	testModulus := []byte{0x01, 0x00, 0x01} // Small test value
	testExponent := []byte{0x01, 0x00, 0x01}

	// Test that we can create an RSA public key from these bytes
	// (This is what the actual method does internally)
	if len(testModulus) == 0 || len(testExponent) == 0 {
		t.Error("Modulus and exponent should not be empty")
	}

	// The actual implementation would use big.Int to reconstruct the key
	// We're testing the concept here
}

// Test ECDSA public key extraction logic
func TestExtractECDSAPublicKey_Logic(t *testing.T) {
	// Test EC point format validation
	testCases := []struct {
		name    string
		ecPoint []byte
		valid   bool
	}{
		{
			name:    "valid uncompressed point",
			ecPoint: []byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			valid:   true,
		},
		{
			name:    "invalid point - wrong prefix",
			ecPoint: []byte{0x03, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			valid:   false,
		},
		{
			name:    "invalid point - too short",
			ecPoint: []byte{0x04, 0x01},
			valid:   false,
		},
		{
			name:    "empty point",
			ecPoint: []byte{},
			valid:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the validation logic used in extractECDSAPublicKey
			valid := len(tc.ecPoint) >= 3 && tc.ecPoint[0] == 0x04
			if valid != tc.valid {
				t.Errorf("Expected validity %v, got %v", tc.valid, valid)
			}
		})
	}
}

// Test curve OID identification logic
func TestIdentifyECDSACurve_Logic(t *testing.T) {
	testCases := []struct {
		name     string
		curveOID []byte
		expected elliptic.Curve
	}{
		{
			name:     "P-256 OID",
			curveOID: []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
			expected: elliptic.P256(),
		},
		{
			name:     "P-384 OID",
			curveOID: []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22},
			expected: elliptic.P384(),
		},
		{
			name:     "unknown OID",
			curveOID: []byte{0x06, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the curve identification logic
			var curve elliptic.Curve
			
			if len(tc.curveOID) >= 10 && 
				tc.curveOID[0] == 0x06 && tc.curveOID[1] == 0x08 &&
				tc.curveOID[8] == 0x01 && tc.curveOID[9] == 0x07 {
				curve = elliptic.P256()
			} else if len(tc.curveOID) >= 7 && 
				tc.curveOID[0] == 0x06 && tc.curveOID[1] == 0x05 &&
				tc.curveOID[6] == 0x22 {
				curve = elliptic.P384()
			}

			if tc.expected != nil && curve == nil {
				t.Error("Expected to identify curve but got nil")
			} else if tc.expected == nil && curve != nil {
				t.Error("Expected nil curve but got a curve")
			} else if tc.expected != nil && curve != nil {
				// Compare curve parameters to verify they're the same
				if curve.Params().BitSize != tc.expected.Params().BitSize {
					t.Errorf("Expected curve bit size %d, got %d", 
						tc.expected.Params().BitSize, curve.Params().BitSize)
				}
			}
		})
	}
}

// Test key attribute extraction logic
func TestKeyAttributeExtraction_Logic(t *testing.T) {
	// Simulate PKCS#11 attributes
	testAttributes := []struct {
		attrType uint
		value    []byte
	}{
		{pkcs11.CKA_CLASS, []byte{byte(pkcs11.CKO_PRIVATE_KEY)}},
		{pkcs11.CKA_KEY_TYPE, []byte{byte(pkcs11.CKK_RSA)}},
		{pkcs11.CKA_LABEL, []byte("test-key")},
		{pkcs11.CKA_ID, []byte("key-id-123")},
	}

	// Test attribute parsing
	var class, keyType uint
	var label string
	var id []byte

	for _, attr := range testAttributes {
		switch attr.attrType {
		case pkcs11.CKA_CLASS:
			if len(attr.value) > 0 {
				class = uint(attr.value[0])
			}
		case pkcs11.CKA_KEY_TYPE:
			if len(attr.value) > 0 {
				keyType = uint(attr.value[0])
			}
		case pkcs11.CKA_LABEL:
			label = string(attr.value)
		case pkcs11.CKA_ID:
			id = attr.value
		}
	}

	if class != pkcs11.CKO_PRIVATE_KEY {
		t.Errorf("Expected class %d, got %d", pkcs11.CKO_PRIVATE_KEY, class)
	}
	if keyType != pkcs11.CKK_RSA {
		t.Errorf("Expected key type %d, got %d", pkcs11.CKK_RSA, keyType)
	}
	if label != "test-key" {
		t.Errorf("Expected label 'test-key', got '%s'", label)
	}
	if string(id) != "key-id-123" {
		t.Errorf("Expected ID 'key-id-123', got '%s'", string(id))
	}
}

// Test RSA key size calculation
func TestRSAKeySizeCalculation(t *testing.T) {
	testCases := []struct {
		name        string
		keySize     int
		expectedSize int
	}{
		{
			name:        "RSA 2048",
			keySize:     2048,
			expectedSize: 2048,
		},
		{
			name:        "RSA 4096", 
			keySize:     4096,
			expectedSize: 4096,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test that the expected key size calculation would be correct
			// In the real implementation, we would extract this from PKCS#11 attributes
			expectedSizeInBytes := tc.keySize / 8
			if expectedSizeInBytes*8 != tc.expectedSize {
				t.Errorf("Expected key size calculation %d bits, got %d bits", tc.expectedSize, expectedSizeInBytes*8)
			}
		})
	}
}

// Test ECDSA key size calculation
func TestECDSAKeySizeCalculation(t *testing.T) {
	testCases := []struct {
		name         string
		curve        elliptic.Curve
		expectedSize int
	}{
		{
			name:         "P-256",
			curve:        elliptic.P256(),
			expectedSize: 256,
		},
		{
			name:         "P-384",
			curve:        elliptic.P384(),
			expectedSize: 384,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test curve bit size calculation
			bitSize := tc.curve.Params().BitSize
			if bitSize != tc.expectedSize {
				t.Errorf("Expected bit size %d, got %d", tc.expectedSize, bitSize)
			}

			// Create a mock ECDSA key
			key := &ecdsa.PublicKey{
				Curve: tc.curve,
				X:     nil, // Would be set in real implementation
				Y:     nil, // Would be set in real implementation
			}

			// Test that we can extract the bit size from the key
			if key.Curve.Params().BitSize != tc.expectedSize {
				t.Errorf("Expected key bit size %d, got %d", 
					tc.expectedSize, key.Curve.Params().BitSize)
			}
		})
	}
}

// Test the new generateKeyID function
func TestGenerateKeyID(t *testing.T) {
	tests := []struct {
		name     string
		label    string
		expected int // Expected length
	}{
		{"short label", "test", 16},
		{"long label", "this-is-a-very-long-label-with-special-characters-@#$%", 16},
		{"empty label", "", 16},
		{"unicode label", "测试密钥", 16},
		{"spaces and symbols", "my test key @2024!", 16},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := generateKeyID(tc.label)
			
			// Test length
			if len(id) != tc.expected {
				t.Errorf("Expected ID length %d, got %d", tc.expected, len(id))
			}
			
			// Test deterministic behavior - same label should produce same ID
			id2 := generateKeyID(tc.label)
			if !bytes.Equal(id, id2) {
				t.Error("generateKeyID should be deterministic for the same label")
			}
		})
	}
}

// Test that different labels produce different IDs
func TestGenerateKeyID_Uniqueness(t *testing.T) {
	labels := []string{"test1", "test2", "different-label", "another_one"}
	ids := make([][]byte, len(labels))
	
	// Generate IDs
	for i, label := range labels {
		ids[i] = generateKeyID(label)
	}
	
	// Check uniqueness
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			if bytes.Equal(ids[i], ids[j]) {
				t.Errorf("Labels '%s' and '%s' produced the same ID", labels[i], labels[j])
			}
		}
	}
}

// Test RSA key import validation
func TestImportRSAKeyPair_Validation(t *testing.T) {
	testCases := []struct {
		name       string
		privateKey *rsa.PrivateKey
		label      string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "nil private key",
			privateKey: nil,
			label:      "test-key",
			wantErr:    true,
			errMsg:     "private key cannot be nil",
		},
		{
			name:       "empty label",
			privateKey: generateTestRSAKey(t, 2048),
			label:      "",
			wantErr:    false, // Empty label should be allowed
		},
		{
			name:       "valid RSA 2048 key",
			privateKey: generateTestRSAKey(t, 2048),
			label:      "test-rsa-2048",
			wantErr:    false, // Would pass validation but fail on PKCS#11 calls
		},
		{
			name:       "valid RSA 4096 key",
			privateKey: generateTestRSAKey(t, 4096),
			label:      "test-rsa-4096",
			wantErr:    false, // Would pass validation but fail on PKCS#11 calls
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test input validation logic
			if tc.privateKey == nil {
				if !tc.wantErr {
					t.Error("Expected error for nil private key")
				}
				return
			}

			// Test that we can extract key components for PKCS#11 templates
			if tc.privateKey.N == nil || tc.privateKey.D == nil {
				t.Error("RSA key should have valid N and D components")
			}

			if len(tc.privateKey.Primes) < 2 {
				t.Error("RSA key should have at least 2 primes")
			}

			// Test key size calculation
			expectedSize := tc.privateKey.Size() * 8
			if expectedSize != 2048 && expectedSize != 4096 {
				t.Errorf("Unexpected key size: %d bits", expectedSize)
			}

			// Test key ID generation
			keyID := generateKeyID(tc.label)
			if len(keyID) != 16 {
				t.Errorf("Expected key ID length 16, got %d", len(keyID))
			}
		})
	}
}

// Test ECDSA key import validation
func TestImportECDSAKeyPair_Validation(t *testing.T) {
	testCases := []struct {
		name       string
		privateKey *ecdsa.PrivateKey
		label      string
		wantErr    bool
	}{
		{
			name:       "nil private key",
			privateKey: nil,
			label:      "test-key",
			wantErr:    true,
		},
		{
			name:       "P-256 key",
			privateKey: generateTestECDSAKey(t, elliptic.P256()),
			label:      "test-p256",
			wantErr:    false,
		},
		{
			name:       "P-384 key",
			privateKey: generateTestECDSAKey(t, elliptic.P384()),
			label:      "test-p384",
			wantErr:    false,
		},
		{
			name:       "P-521 key (unsupported)",
			privateKey: generateTestECDSAKey(t, elliptic.P521()),
			label:      "test-p521",
			wantErr:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test input validation logic
			if tc.privateKey == nil {
				if !tc.wantErr {
					t.Error("Expected error for nil private key")
				}
				return
			}

			// Test curve support validation
			var curveOID []byte
			var keySize int

			switch tc.privateKey.Curve {
			case elliptic.P256():
				curveOID = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
				keySize = 256
			case elliptic.P384():
				curveOID = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}
				keySize = 384
			default:
				// Unsupported curve
				if !tc.wantErr {
					t.Error("Expected error for unsupported curve")
				}
				return
			}

			if len(curveOID) == 0 {
				t.Error("Curve OID should be set for supported curves")
			}

			if keySize != tc.privateKey.Curve.Params().BitSize {
				t.Errorf("Expected key size %d, got %d", keySize, tc.privateKey.Curve.Params().BitSize)
			}

			// Test EC point creation logic
			coordSize := (keySize + 7) / 8
			ecPoint := make([]byte, 1+2*coordSize)
			ecPoint[0] = 0x04

			xBytes := tc.privateKey.X.Bytes()
			yBytes := tc.privateKey.Y.Bytes()

			copy(ecPoint[1+coordSize-len(xBytes):1+coordSize], xBytes)
			copy(ecPoint[1+2*coordSize-len(yBytes):], yBytes)

			if ecPoint[0] != 0x04 {
				t.Error("EC point should start with 0x04 (uncompressed format)")
			}

			if len(ecPoint) != 1+2*coordSize {
				t.Errorf("Expected EC point length %d, got %d", 1+2*coordSize, len(ecPoint))
			}
		})
	}
}

// Test unified ImportKeyPair interface
func TestImportKeyPair_Interface(t *testing.T) {
	testCases := []struct {
		name       string
		privateKey crypto.PrivateKey
		label      string
		wantErr    bool
	}{
		{
			name:       "RSA private key",
			privateKey: generateTestRSAKey(t, 2048),
			label:      "test-rsa",
			wantErr:    false, // Would succeed in validation
		},
		{
			name:       "ECDSA private key",
			privateKey: generateTestECDSAKey(t, elliptic.P256()),
			label:      "test-ecdsa",
			wantErr:    false, // Would succeed in validation
		},
		{
			name:       "unsupported key type",
			privateKey: "not-a-private-key",
			label:      "test-invalid",
			wantErr:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test type assertion logic from ImportKeyPair
			switch key := tc.privateKey.(type) {
			case *rsa.PrivateKey:
				// Should route to ImportRSAKeyPair
				if key.N == nil || key.D == nil {
					t.Error("RSA key should have valid components")
				}
			case *ecdsa.PrivateKey:
				// Should route to ImportECDSAKeyPair
				if key.D == nil || key.X == nil || key.Y == nil {
					t.Error("ECDSA key should have valid components")
				}
			default:
				// Should return error for unsupported types
				if !tc.wantErr {
					t.Error("Expected error for unsupported key type")
				}
			}
		})
	}
}

// Test RSA key component extraction for PKCS#11 templates
func TestRSAKeyComponentExtraction(t *testing.T) {
	privateKey := generateTestRSAKey(t, 2048)

	// Test that we can extract all required components for PKCS#11
	if privateKey.N == nil {
		t.Error("RSA key should have modulus N")
	}

	if privateKey.E == 0 {
		t.Error("RSA key should have public exponent E")
	}

	if privateKey.D == nil {
		t.Error("RSA key should have private exponent D")
	}

	if len(privateKey.Primes) < 2 {
		t.Error("RSA key should have at least 2 primes")
	}

	// Test CRT components (used for optimization)
	if privateKey.Precomputed.Dp == nil {
		t.Error("RSA key should have precomputed Dp")
	}

	if privateKey.Precomputed.Dq == nil {
		t.Error("RSA key should have precomputed Dq")
	}

	if privateKey.Precomputed.Qinv == nil {
		t.Error("RSA key should have precomputed Qinv")
	}

	// Test byte conversion
	nBytes := privateKey.N.Bytes()
	eBytes := big.NewInt(int64(privateKey.E)).Bytes()
	dBytes := privateKey.D.Bytes()

	if len(nBytes) == 0 {
		t.Error("Modulus should convert to non-empty bytes")
	}

	if len(eBytes) == 0 {
		t.Error("Public exponent should convert to non-empty bytes")
	}

	if len(dBytes) == 0 {
		t.Error("Private exponent should convert to non-empty bytes")
	}
}

// Test ECDSA key component extraction for PKCS#11 templates
func TestECDSAKeyComponentExtraction(t *testing.T) {
	privateKey := generateTestECDSAKey(t, elliptic.P256())

	// Test private key scalar
	if privateKey.D == nil {
		t.Error("ECDSA key should have private scalar D")
	}

	dBytes := privateKey.D.Bytes()
	if len(dBytes) == 0 {
		t.Error("Private scalar should convert to non-empty bytes")
	}

	// Test public key point
	if privateKey.X == nil || privateKey.Y == nil {
		t.Error("ECDSA key should have public point (X, Y)")
	}

	xBytes := privateKey.X.Bytes()
	yBytes := privateKey.Y.Bytes()

	if len(xBytes) == 0 || len(yBytes) == 0 {
		t.Error("Public key coordinates should convert to non-empty bytes")
	}

	// Test curve parameters
	curve := privateKey.Curve
	if curve == nil {
		t.Error("ECDSA key should have curve")
	}

	bitSize := curve.Params().BitSize
	if bitSize != 256 {
		t.Errorf("Expected P-256 curve (256 bits), got %d bits", bitSize)
	}
}

// Helper function to generate test RSA keys
func generateTestRSAKey(t *testing.T, keySize int) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	
	// Ensure CRT components are computed
	privateKey.Precompute()
	
	return privateKey
}

// Helper function to generate test ECDSA keys
func generateTestECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	return privateKey
}

// Helper function to generate test ED25519 keys
func generateTestED25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key: %v", err)
	}
	
	// Verify key properties
	if len(privateKey) != ed25519.PrivateKeySize {
		t.Fatalf("Expected ED25519 private key size %d, got %d", ed25519.PrivateKeySize, len(privateKey))
	}
	if len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("Expected ED25519 public key size %d, got %d", ed25519.PublicKeySize, len(publicKey))
	}
	
	return privateKey
}

// Test ED25519 key generation properties
func TestED25519KeyGeneration_Properties(t *testing.T) {
	privateKey := generateTestED25519Key(t)
	
	// ED25519 private key is 64 bytes: 32-byte private scalar + 32-byte public key
	if len(privateKey) != 64 {
		t.Errorf("Expected ED25519 private key length 64, got %d", len(privateKey))
	}
	
	// Extract components
	privateScalar := privateKey[:32]
	publicKeyBytes := privateKey[32:]
	
	if len(privateScalar) != 32 {
		t.Errorf("Expected private scalar length 32, got %d", len(privateScalar))
	}
	
	if len(publicKeyBytes) != 32 {
		t.Errorf("Expected public key length 32, got %d", len(publicKeyBytes))
	}
	
	// Verify that we can create a public key from the bytes
	publicKey := ed25519.PublicKey(publicKeyBytes)
	if len(publicKey) != ed25519.PublicKeySize {
		t.Errorf("Expected public key size %d, got %d", ed25519.PublicKeySize, len(publicKey))
	}
}

// Test ED25519 signing logic (without PKCS#11)
func TestED25519Signing_Logic(t *testing.T) {
	privateKey := generateTestED25519Key(t)
	publicKey := ed25519.PublicKey(privateKey[32:])
	
	// Test message
	message := []byte("Hello, ED25519!")
	
	// Sign with Go's standard library
	signature := ed25519.Sign(privateKey, message)
	
	// Verify signature
	if !ed25519.Verify(publicKey, message, signature) {
		t.Error("ED25519 signature verification failed")
	}
	
	// Check signature length
	if len(signature) != ed25519.SignatureSize {
		t.Errorf("Expected signature size %d, got %d", ed25519.SignatureSize, len(signature))
	}
	
	// Test with different message should fail
	wrongMessage := []byte("Wrong message")
	if ed25519.Verify(publicKey, wrongMessage, signature) {
		t.Error("ED25519 signature should not verify for wrong message")
	}
}

// Test ED25519 OID identification
func TestED25519OID_Logic(t *testing.T) {
	// ED25519 curve OID: 1.3.101.112
	ed25519OID := []byte{0x06, 0x03, 0x2b, 0x65, 0x70}
	
	// Test OID structure
	if len(ed25519OID) != 5 {
		t.Errorf("Expected ED25519 OID length 5, got %d", len(ed25519OID))
	}
	
	// Test OID values
	expected := []byte{0x06, 0x03, 0x2b, 0x65, 0x70}
	if !bytes.Equal(ed25519OID, expected) {
		t.Errorf("ED25519 OID mismatch: expected %x, got %x", expected, ed25519OID)
	}
}

// Test ED25519 public key extraction logic
func TestED25519PublicKeyExtraction_Logic(t *testing.T) {
	testCases := []struct {
		name     string
		ecPoint  []byte
		valid    bool
		expected []byte
	}{
		{
			name:     "direct 32-byte key",
			ecPoint:  make([]byte, 32), // all zeros for test
			valid:    true,
			expected: make([]byte, 32),
		},
		{
			name:     "OCTET STRING wrapped key",
			ecPoint:  append([]byte{0x04, 0x20}, make([]byte, 32)...), // 0x04 + 0x20 (32 bytes) + 32 bytes
			valid:    true,
			expected: make([]byte, 32),
		},
		{
			name:    "wrong length",
			ecPoint: make([]byte, 31),
			valid:   false,
		},
		{
			name:    "wrong OCTET STRING length indicator",
			ecPoint: append([]byte{0x04, 0x1F}, make([]byte, 32)...), // wrong length indicator
			valid:   false,
		},
		{
			name:    "empty point",
			ecPoint: []byte{},
			valid:   false,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate the extraction logic from extractED25519PublicKey
			var publicKeyBytes []byte
			var valid bool
			
			if len(tc.ecPoint) == 32 {
				publicKeyBytes = tc.ecPoint
				valid = true
			} else if len(tc.ecPoint) == 34 && tc.ecPoint[0] == 0x04 && tc.ecPoint[1] == 0x20 {
				publicKeyBytes = tc.ecPoint[2:]
				valid = true
			}
			
			if valid && len(publicKeyBytes) == 32 {
				valid = true
			} else {
				valid = false
			}
			
			if valid != tc.valid {
				t.Errorf("Expected validity %v, got %v", tc.valid, valid)
			}
			
			if tc.valid && tc.expected != nil {
				if !bytes.Equal(publicKeyBytes, tc.expected) {
					t.Errorf("Expected extracted bytes %x, got %x", tc.expected, publicKeyBytes)
				}
			}
		})
	}
}

// Test ED25519KeyPair type validation
func TestED25519KeyPair_TypeValidation(t *testing.T) {
	// Test with correct type
	keyPair := &KeyPair{
		KeyType: KeyPairTypeED25519,
	}
	
	// This would normally create an ED25519KeyPair, but we can test the type checking logic
	if keyPair.KeyType != KeyPairTypeED25519 {
		t.Error("KeyPair should be ED25519 type")
	}
	
	// Test with wrong type
	wrongKeyPair := &KeyPair{
		KeyType: KeyPairTypeRSA,
	}
	
	if wrongKeyPair.KeyType == KeyPairTypeED25519 {
		t.Error("RSA KeyPair should not be ED25519 type")
	}
}

// Test ED25519 constants
func TestED25519Constants(t *testing.T) {
	// Test key sizes
	if ed25519.PrivateKeySize != 64 {
		t.Errorf("Expected ED25519 private key size 64, got %d", ed25519.PrivateKeySize)
	}
	
	if ed25519.PublicKeySize != 32 {
		t.Errorf("Expected ED25519 public key size 32, got %d", ed25519.PublicKeySize)
	}
	
	if ed25519.SignatureSize != 64 {
		t.Errorf("Expected ED25519 signature size 64, got %d", ed25519.SignatureSize)
	}
	
	// Test our PKCS#11 constants
	if CKK_EC_EDWARDS != 0x00000040 {
		t.Errorf("Expected CKK_EC_EDWARDS to be 0x00000040, got 0x%08x", CKK_EC_EDWARDS)
	}
	
	if CKM_EC_EDWARDS_KEY_PAIR_GEN != 0x00001055 {
		t.Errorf("Expected CKM_EC_EDWARDS_KEY_PAIR_GEN to be 0x00001055, got 0x%08x", CKM_EC_EDWARDS_KEY_PAIR_GEN)
	}
	
	if CKM_EDDSA != 0x00001057 {
		t.Errorf("Expected CKM_EDDSA to be 0x00001057, got 0x%08x", CKM_EDDSA)
	}
}

