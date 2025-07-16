package gopkcs11

import (
	"os"
	"testing"
)

// Helper function to create uint pointer
func uintPtr(v uint) *uint {
	return &v
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
