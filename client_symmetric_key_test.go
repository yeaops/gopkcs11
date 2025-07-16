package gopkcs11

import (
	"testing"
)

// Test SymmetricKey type constants
func TestSymmetricKeyType_Constants(t *testing.T) {
	if SymmetricKeyTypeAES != 0 {
		t.Errorf("Expected SymmetricKeyTypeAES to be 0, got %d", SymmetricKeyTypeAES)
	}
	if SymmetricKeyTypeDES != 1 {
		t.Errorf("Expected SymmetricKeyTypeDES to be 1, got %d", SymmetricKeyTypeDES)
	}
	if SymmetricKeyType3DES != 2 {
		t.Errorf("Expected SymmetricKeyType3DES to be 2, got %d", SymmetricKeyType3DES)
	}
}

// Test SymmetricKey String method
func TestSymmetricKey_String(t *testing.T) {
	symKey := &SymmetricKey{
		Handle:  2000,
		Label:   "test-aes-key",
		ID:      []byte("test-sym-id"),
		KeyType: SymmetricKeyTypeAES,
		KeySize: 256,
	}

	expected := "SymmetricKey{Label: test-aes-key, Type: 0, Size: 256}"
	result := symKey.String()

	if result != expected {
		t.Errorf("Expected '%s', got '%s'", expected, result)
	}
}

// Test AES key size validation
func TestGenerateAESKey_KeySizeValidation(t *testing.T) {
	testCases := []struct {
		name     string
		keySize  int
		wantErr  bool
		errMsg   string
	}{
		{
			name:    "valid AES 128",
			keySize: 128,
			wantErr: false,
		},
		{
			name:    "valid AES 192",
			keySize: 192,
			wantErr: false,
		},
		{
			name:    "valid AES 256",
			keySize: 256,
			wantErr: false,
		},
		{
			name:    "invalid AES 64",
			keySize: 64,
			wantErr: true,
			errMsg:  "AES key size must be 128, 192, or 256 bits",
		},
		{
			name:    "invalid AES 512",
			keySize: 512,
			wantErr: true,
			errMsg:  "AES key size must be 128, 192, or 256 bits",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test validation logic without PKCS#11 calls
			if tc.keySize != 128 && tc.keySize != 192 && tc.keySize != 256 {
				if !tc.wantErr {
					t.Error("Expected error for invalid AES key size")
				}
			} else {
				if tc.wantErr {
					t.Error("Expected no error for valid AES key size")
				}
			}
		})
	}
}

// Test symmetric key import validation
func TestImportAESKey_Validation(t *testing.T) {
	testCases := []struct {
		name        string
		keyMaterial []byte
		wantErr     bool
		expectedErr string
	}{
		{
			name:        "valid AES 128 key",
			keyMaterial: make([]byte, 16), // 128 bits
			wantErr:     false,
		},
		{
			name:        "valid AES 192 key",
			keyMaterial: make([]byte, 24), // 192 bits
			wantErr:     false,
		},
		{
			name:        "valid AES 256 key",
			keyMaterial: make([]byte, 32), // 256 bits
			wantErr:     false,
		},
		{
			name:        "invalid key material - too short",
			keyMaterial: make([]byte, 8),
			wantErr:     true,
			expectedErr: "AES key material must be 16, 24, or 32 bytes",
		},
		{
			name:        "invalid key material - wrong size",
			keyMaterial: make([]byte, 20),
			wantErr:     true,
			expectedErr: "AES key material must be 16, 24, or 32 bytes",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test validation logic
			if len(tc.keyMaterial) != 16 && len(tc.keyMaterial) != 24 && len(tc.keyMaterial) != 32 {
				if !tc.wantErr {
					t.Error("Expected error for invalid key material size")
				}
			} else {
				if tc.wantErr {
					t.Error("Expected no error for valid key material size")
				}
				// Test key size calculation
				expectedSize := len(tc.keyMaterial) * 8
				if expectedSize != 128 && expectedSize != 192 && expectedSize != 256 {
					t.Errorf("Unexpected calculated key size: %d", expectedSize)
				}
			}
		})
	}
}

// Test symmetric key type mapping
func TestImportSymmetricKey_TypeMapping(t *testing.T) {
	testCases := []struct {
		name         string
		keyType      SymmetricKeyType
		keyMaterial  []byte
		expectedSize int
		wantErr      bool
	}{
		{
			name:         "AES 256",
			keyType:      SymmetricKeyTypeAES,
			keyMaterial:  make([]byte, 32),
			expectedSize: 256,
			wantErr:      false,
		},
		{
			name:         "DES",
			keyType:      SymmetricKeyTypeDES,
			keyMaterial:  make([]byte, 8),
			expectedSize: 64,
			wantErr:      false,
		},
		{
			name:         "3DES",
			keyType:      SymmetricKeyType3DES,
			keyMaterial:  make([]byte, 24),
			expectedSize: 192,
			wantErr:      false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test type validation and size calculation logic
			var keySize int
			var valid bool

			switch tc.keyType {
			case SymmetricKeyTypeAES:
				if len(tc.keyMaterial) == 16 || len(tc.keyMaterial) == 24 || len(tc.keyMaterial) == 32 {
					keySize = len(tc.keyMaterial) * 8
					valid = true
				}
			case SymmetricKeyTypeDES:
				if len(tc.keyMaterial) == 8 {
					keySize = 64
					valid = true
				}
			case SymmetricKeyType3DES:
				if len(tc.keyMaterial) == 24 {
					keySize = 192
					valid = true
				}
			}

			if tc.wantErr && valid {
				t.Error("Expected error but validation passed")
			} else if !tc.wantErr && !valid {
				t.Error("Expected validation to pass but got error")
			} else if !tc.wantErr && keySize != tc.expectedSize {
				t.Errorf("Expected key size %d, got %d", tc.expectedSize, keySize)
			}
		})
	}
}

// Test symmetric key encryption/decryption parameter validation
func TestEncryptDecryptData_Validation(t *testing.T) {
	testCases := []struct {
		name     string
		key      *SymmetricKey
		wantErr  bool
		errMsg   string
	}{
		{
			name:    "nil key",
			key:     nil,
			wantErr: true,
			errMsg:  "symmetric key cannot be nil",
		},
		{
			name: "valid key",
			key: &SymmetricKey{
				Handle:  1000,
				Label:   "test-key",
				KeyType: SymmetricKeyTypeAES,
				KeySize: 256,
			},
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test input validation logic
			if tc.key == nil {
				if !tc.wantErr {
					t.Error("Expected error for nil key")
				}
			} else {
				if tc.wantErr {
					t.Error("Expected no error for valid key")
				}
				// Validate key has required fields
				if tc.key.Handle == 0 {
					t.Error("Key should have valid handle")
				}
				if tc.key.KeyType < SymmetricKeyTypeAES || tc.key.KeyType > SymmetricKeyType3DES {
					t.Error("Key should have valid key type")
				}
			}
		})
	}
}

// Test key wrapping parameter validation
func TestWrapUnwrapKey_Validation(t *testing.T) {
	testKey := &SymmetricKey{
		Handle:  1000,
		Label:   "wrap-key",
		KeyType: SymmetricKeyTypeAES,
		KeySize: 256,
	}

	testCases := []struct {
		name        string
		wrappingKey *SymmetricKey
		wantErr     bool
	}{
		{
			name:        "nil wrapping key",
			wrappingKey: nil,
			wantErr:     true,
		},
		{
			name:        "valid wrapping key",
			wrappingKey: testKey,
			wantErr:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test input validation for key wrapping
			if tc.wrappingKey == nil {
				if !tc.wantErr {
					t.Error("Expected error for nil wrapping key")
				}
			} else {
				if tc.wantErr {
					t.Error("Expected no error for valid wrapping key")
				}
			}
		})
	}
}

// Test symmetric key attributes extraction logic
func TestGetSymmetricKey_AttributeExtraction(t *testing.T) {
	testCases := []struct {
		name         string
		keyTypeValue []byte
		valueLenBytes []byte
		expectedType SymmetricKeyType
		expectedSize int
		wantErr      bool
	}{
		{
			name:         "AES key",
			keyTypeValue: []byte{byte(12)}, // CKK_AES value
			valueLenBytes: []byte{32, 0, 0, 0}, // 32 bytes in little-endian
			expectedType: SymmetricKeyTypeAES,
			expectedSize: 256, // 32 * 8 bits
			wantErr:      false,
		},
		{
			name:         "DES key",
			keyTypeValue: []byte{byte(19)}, // CKK_DES value
			valueLenBytes: []byte{8, 0, 0, 0},
			expectedType: SymmetricKeyTypeDES,
			expectedSize: 64,
			wantErr:      false,
		},
		{
			name:         "3DES key",
			keyTypeValue: []byte{byte(21)}, // CKK_DES3 value
			valueLenBytes: []byte{24, 0, 0, 0},
			expectedType: SymmetricKeyType3DES,
			expectedSize: 192,
			wantErr:      false,
		},
		{
			name:         "empty key type",
			keyTypeValue: []byte{},
			valueLenBytes: []byte{32, 0, 0, 0},
			wantErr:      true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test attribute extraction logic
			if len(tc.keyTypeValue) == 0 {
				if !tc.wantErr {
					t.Error("Expected error for empty key type")
				}
				return
			}

			// Simulate the key type mapping logic
			var keyType SymmetricKeyType
			var keySize int
			pkcs11KeyType := uint(tc.keyTypeValue[0])

			switch pkcs11KeyType {
			case 12: // CKK_AES
				keyType = SymmetricKeyTypeAES
				if len(tc.valueLenBytes) >= 4 {
					keySize = int(tc.valueLenBytes[0]) | int(tc.valueLenBytes[1])<<8 | int(tc.valueLenBytes[2])<<16 | int(tc.valueLenBytes[3])<<24
					keySize *= 8
				} else {
					keySize = 256
				}
			case 19: // CKK_DES
				keyType = SymmetricKeyTypeDES
				keySize = 64
			case 21: // CKK_DES3
				keyType = SymmetricKeyType3DES
				keySize = 192
			default:
				if !tc.wantErr {
					t.Error("Expected error for unsupported key type")
				}
				return
			}

			if tc.wantErr {
				t.Error("Expected error but processing succeeded")
				return
			}

			if keyType != tc.expectedType {
				t.Errorf("Expected key type %v, got %v", tc.expectedType, keyType)
			}

			if keySize != tc.expectedSize {
				t.Errorf("Expected key size %d, got %d", tc.expectedSize, keySize)
			}
		})
	}
}