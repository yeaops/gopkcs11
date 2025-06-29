package gopkcs11

import (
	"os"
	"testing"
)

// Helper function to create uint pointer
func uintPtr(v uint) *uint {
	return &v
}

func TestNewConfig(t *testing.T) {
	config := NewConfig("/path/to/lib.so", 1, "1234")
	
	if config.LibraryPath != "/path/to/lib.so" {
		t.Errorf("Expected LibraryPath '/path/to/lib.so', got '%s'", config.LibraryPath)
	}
	if config.SlotID == nil || *config.SlotID != 1 {
		t.Errorf("Expected SlotID 1, got %v", config.SlotID)
	}
	if config.UserPIN != "1234" {
		t.Errorf("Expected UserPIN '1234', got '%s'", config.UserPIN)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config with temp library and SlotID",
			config: &Config{
				LibraryPath: "/tmp/libpkcs11.so",
				SlotID:      uintPtr(1),
				UserPIN:     "1234",
			},
			wantErr: false,
		},
		{
			name: "valid config with TokenLabel",
			config: &Config{
				LibraryPath: "/tmp/libpkcs11.so",
				TokenLabel:  "TestToken",
				UserPIN:     "1234",
			},
			wantErr: false,
		},
		{
			name: "empty library path",
			config: &Config{
				LibraryPath: "",
				SlotID:      uintPtr(1),
				UserPIN:     "1234",
			},
			wantErr: true,
		},
		{
			name: "empty user PIN",
			config: &Config{
				LibraryPath: "/tmp/libpkcs11.so",
				SlotID:      uintPtr(1),
				UserPIN:     "",
			},
			wantErr: true,
		},
		{
			name: "no slot identification method",
			config: &Config{
				LibraryPath: "/tmp/libpkcs11.so",
				UserPIN:     "1234",
			},
			wantErr: true,
		},
		{
			name: "multiple slot identification methods",
			config: &Config{
				LibraryPath: "/tmp/libpkcs11.so",
				SlotID:      uintPtr(1),
				TokenLabel:  "TestToken",
				UserPIN:     "1234",
			},
			wantErr: true,
		},
		{
			name: "non-existent library path",
			config: &Config{
				LibraryPath: "/non/existent/path/lib.so",
				SlotID:      uintPtr(1),
				UserPIN:     "1234",
			},
			wantErr: true,
		},
	}

	// Create a temporary library file for testing
	tmpFile, err := os.CreateTemp("", "libpkcs11*.so")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Update the valid test cases to use the actual temp file
	tests[0].config.LibraryPath = tmpFile.Name()
	tests[1].config.LibraryPath = tmpFile.Name()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewConfigFromEnv(t *testing.T) {
	// Save original environment
	envVarsToSave := []string{
		"PKCS11_LIBRARY_PATH", "PKCS11_USER_PIN", "PKCS11_SLOT_ID", 
		"PKCS11_SLOT_INDEX", "PKCS11_TOKEN_LABEL", "PKCS11_TOKEN_SERIAL",
	}
	originalEnv := make(map[string]string)
	for _, envVar := range envVarsToSave {
		originalEnv[envVar] = os.Getenv(envVar)
	}

	// Clean up after test
	defer func() {
		for _, envVar := range envVarsToSave {
			if originalEnv[envVar] != "" {
				os.Setenv(envVar, originalEnv[envVar])
			} else {
				os.Unsetenv(envVar)
			}
		}
	}()

	tests := []struct {
		name        string
		envVars     map[string]string
		expected    *Config
		wantErr     bool
	}{
		{
			name: "slot ID configuration",
			envVars: map[string]string{
				"PKCS11_LIBRARY_PATH": "/custom/path/lib.so",
				"PKCS11_SLOT_ID":      "2",
				"PKCS11_USER_PIN":     "secret",
			},
			expected: &Config{
				LibraryPath: "/custom/path/lib.so",
				SlotID:      uintPtr(2),
				UserPIN:     "secret",
			},
			wantErr: false,
		},
		{
			name: "token label configuration",
			envVars: map[string]string{
				"PKCS11_LIBRARY_PATH": "/custom/path/lib.so",
				"PKCS11_TOKEN_LABEL":  "TestToken",
				"PKCS11_USER_PIN":     "secret",
			},
			expected: &Config{
				LibraryPath: "/custom/path/lib.so",
				TokenLabel:  "TestToken",
				UserPIN:     "secret",
			},
			wantErr: false,
		},
		{
			name: "slot index configuration",
			envVars: map[string]string{
				"PKCS11_LIBRARY_PATH": "/custom/path/lib.so",
				"PKCS11_SLOT_INDEX":   "1",
				"PKCS11_USER_PIN":     "secret",
			},
			expected: &Config{
				LibraryPath: "/custom/path/lib.so",
				SlotIndex:   uintPtr(1),
				UserPIN:     "secret",
			},
			wantErr: false,
		},
		{
			name: "default values with required PIN (SlotID=0)",
			envVars: map[string]string{
				"PKCS11_USER_PIN": "secret",
			},
			expected: &Config{
				LibraryPath: "/usr/lib/pkcs11/libpkcs11.so",
				SlotID:      uintPtr(0),
				UserPIN:     "secret",
			},
			wantErr: false,
		},
		{
			name: "missing user PIN",
			envVars: map[string]string{
				"PKCS11_LIBRARY_PATH": "/path/lib.so",
				"PKCS11_SLOT_ID":      "1",
			},
			wantErr: true,
		},
		{
			name: "invalid slot ID",
			envVars: map[string]string{
				"PKCS11_SLOT_ID":  "invalid",
				"PKCS11_USER_PIN": "secret",
			},
			wantErr: true,
		},
		{
			name: "multiple slot identification methods",
			envVars: map[string]string{
				"PKCS11_SLOT_ID":     "1",
				"PKCS11_TOKEN_LABEL": "TestToken",
				"PKCS11_USER_PIN":    "secret",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			for _, envVar := range envVarsToSave {
				os.Unsetenv(envVar)
			}

			// Set test environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			config, err := NewConfigFromEnv()
			if (err != nil) != tt.wantErr {
				t.Errorf("NewConfigFromEnv() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil && tt.expected != nil {
				if config.LibraryPath != tt.expected.LibraryPath {
					t.Errorf("Expected LibraryPath '%s', got '%s'", tt.expected.LibraryPath, config.LibraryPath)
				}
				
				// Compare SlotID pointers
				if (config.SlotID == nil) != (tt.expected.SlotID == nil) {
					t.Errorf("SlotID pointer mismatch: got %v, expected %v", config.SlotID, tt.expected.SlotID)
				} else if config.SlotID != nil && tt.expected.SlotID != nil && *config.SlotID != *tt.expected.SlotID {
					t.Errorf("Expected SlotID %d, got %d", *tt.expected.SlotID, *config.SlotID)
				}
				
				// Compare SlotIndex pointers
				if (config.SlotIndex == nil) != (tt.expected.SlotIndex == nil) {
					t.Errorf("SlotIndex pointer mismatch: got %v, expected %v", config.SlotIndex, tt.expected.SlotIndex)
				} else if config.SlotIndex != nil && tt.expected.SlotIndex != nil && *config.SlotIndex != *tt.expected.SlotIndex {
					t.Errorf("Expected SlotIndex %d, got %d", *tt.expected.SlotIndex, *config.SlotIndex)
				}
				
				if config.TokenLabel != tt.expected.TokenLabel {
					t.Errorf("Expected TokenLabel '%s', got '%s'", tt.expected.TokenLabel, config.TokenLabel)
				}
				if config.UserPIN != tt.expected.UserPIN {
					t.Errorf("Expected UserPIN '%s', got '%s'", tt.expected.UserPIN, config.UserPIN)
				}
			}
		})
	}
}

func TestConfigString(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{
			name: "SlotID configuration",
			config: &Config{
				LibraryPath: "/path/to/lib.so",
				SlotID:      uintPtr(5),
				UserPIN:     "secret",
			},
			expected: "PKCS11Config{LibraryPath: /path/to/lib.so, SlotID: 5, UserPIN: [REDACTED]}",
		},
		{
			name: "TokenLabel configuration",
			config: &Config{
				LibraryPath: "/path/to/lib.so",
				TokenLabel:  "TestToken",
				UserPIN:     "secret",
			},
			expected: "PKCS11Config{LibraryPath: /path/to/lib.so, TokenLabel: TestToken, UserPIN: [REDACTED]}",
		},
		{
			name: "SlotIndex configuration",
			config: &Config{
				LibraryPath: "/path/to/lib.so",
				SlotIndex:   uintPtr(2),
				UserPIN:     "secret",
			},
			expected: "PKCS11Config{LibraryPath: /path/to/lib.so, SlotIndex: 2, UserPIN: [REDACTED]}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := tt.config.String()
			if str != tt.expected {
				t.Errorf("Expected string '%s', got '%s'", tt.expected, str)
			}

			// Ensure PIN is redacted
			if containsSubstring(str, "secret") {
				t.Error("Config.String() should not expose the actual PIN")
			}
		})
	}
}

func TestGetSlotIdentificationType(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected SlotIdentificationType
		wantErr  bool
	}{
		{
			name: "SlotID only",
			config: &Config{
				SlotID: uintPtr(1),
			},
			expected: SlotIdentificationByID,
			wantErr:  false,
		},
		{
			name: "TokenLabel only",
			config: &Config{
				TokenLabel: "TestToken",
			},
			expected: SlotIdentificationByTokenLabel,
			wantErr:  false,
		},
		{
			name: "SlotIndex only",
			config: &Config{
				SlotIndex: uintPtr(1),
			},
			expected: SlotIdentificationByIndex,
			wantErr:  false,
		},
		{
			name: "TokenSerialNumber only",
			config: &Config{
				TokenSerialNumber: "12345",
			},
			expected: SlotIdentificationByTokenSerial,
			wantErr:  false,
		},
		{
			name: "Multiple methods",
			config: &Config{
				SlotID:     uintPtr(1),
				TokenLabel: "TestToken",
			},
			wantErr: true,
		},
		{
			name:    "No methods",
			config:  &Config{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.config.GetSlotIdentificationType()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSlotIdentificationType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("GetSlotIdentificationType() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && s[len(s)-len(substr):] == substr || 
		   len(s) > len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}