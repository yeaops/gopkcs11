package gopkcs11

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/pkg/errors"
)

// Config holds the configuration parameters for connecting to a PKCS#11 device.
type Config struct {
	// LibraryPath is the filesystem path to the PKCS#11 library (.so, .dll, or .dylib)
	LibraryPath string

	// Slot identification method (only one should be used)
	// SlotID is the slot id of the PKCS#11 device to use
	SlotID *uint
	// SlotIndex is the index of the slot to use (alternative to SlotID)
	SlotIndex *uint
	// TokenLabel is used to identify the token to use by label
	TokenLabel string
	// TokenSerialNumber is the serial number of the token to use
	TokenSerialNumber string

	// UserPIN is the PIN used to authenticate as a normal user (not SO)
	UserPIN string
}

// NewConfigFromEnv creates a new Config by reading configuration from environment variables.
//
// Environment variables:
//   - PKCS11_LIBRARY_PATH: Path to PKCS#11 library (default: auto-detect bundled SoftHSM)
//   - PKCS11_USER_PIN: User PIN for authentication (required)
//   
// Slot identification (only one should be set):
//   - PKCS11_SLOT_ID: Slot ID to use (uint)
//   - PKCS11_SLOT_INDEX: Slot index to use (uint)
//   - PKCS11_TOKEN_LABEL: Token label to use (string)
//   - PKCS11_TOKEN_SERIAL: Token serial number to use (string)
//
// If PKCS11_LIBRARY_PATH is not set, it will try to use the bundled SoftHSM library
// for the current platform.
//
// Returns an error if PKCS11_USER_PIN is not set, slot identification is invalid,
// or multiple slot identification methods are specified.
func NewConfigFromEnv() (*Config, error) {
	config := &Config{}

	// Set library path
	libraryPath := os.Getenv("PKCS11_LIBRARY_PATH")
	if libraryPath == "" {
		// Try to use bundled SoftHSM library
		bundledPath, err := getBundledSoftHSMPath()
		if err != nil {
			// Fall back to system default
			libraryPath = "/usr/lib/pkcs11/libpkcs11.so"
		} else {
			libraryPath = bundledPath
		}
	}
	config.LibraryPath = libraryPath

	// Set user PIN
	userPIN := os.Getenv("PKCS11_USER_PIN")
	if userPIN == "" {
		return nil, errors.New("PKCS11_USER_PIN environment variable is required")
	}
	config.UserPIN = userPIN

	// Set slot identification - check for mutual exclusivity
	var setMethods []string
	
	if slotIDStr := os.Getenv("PKCS11_SLOT_ID"); slotIDStr != "" {
		slotID, err := strconv.ParseUint(slotIDStr, 10, 32)
		if err != nil {
			return nil, errors.Wrap(err, "invalid PKCS11_SLOT_ID")
		}
		slotIDValue := uint(slotID)
		config.SlotID = &slotIDValue
		setMethods = append(setMethods, "PKCS11_SLOT_ID")
	}
	
	if slotIndexStr := os.Getenv("PKCS11_SLOT_INDEX"); slotIndexStr != "" {
		slotIndex, err := strconv.ParseUint(slotIndexStr, 10, 32)
		if err != nil {
			return nil, errors.Wrap(err, "invalid PKCS11_SLOT_INDEX")
		}
		slotIndexValue := uint(slotIndex)
		config.SlotIndex = &slotIndexValue
		setMethods = append(setMethods, "PKCS11_SLOT_INDEX")
	}
	
	if tokenLabel := os.Getenv("PKCS11_TOKEN_LABEL"); tokenLabel != "" {
		config.TokenLabel = tokenLabel
		setMethods = append(setMethods, "PKCS11_TOKEN_LABEL")
	}
	
	if tokenSerial := os.Getenv("PKCS11_TOKEN_SERIAL"); tokenSerial != "" {
		config.TokenSerialNumber = tokenSerial
		setMethods = append(setMethods, "PKCS11_TOKEN_SERIAL")
	}
	
	// Validate that only one slot identification method is set
	if len(setMethods) == 0 {
		// Default to SlotID 0 for backward compatibility
		defaultSlotID := uint(0)
		config.SlotID = &defaultSlotID
	} else if len(setMethods) > 1 {
		return nil, errors.Errorf("multiple slot identification environment variables set: %v - only one should be set", setMethods)
	}

	return config, nil
}

// NewConfigWithSlotID creates a new Config using slot ID identification.
func NewConfigWithSlotID(libraryPath string, slotID uint, userPIN string) *Config {
	return &Config{
		LibraryPath: libraryPath,
		SlotID:      &slotID,
		UserPIN:     userPIN,
	}
}

// NewConfigWithSlotIndex creates a new Config using slot index identification.
func NewConfigWithSlotIndex(libraryPath string, slotIndex uint, userPIN string) *Config {
	return &Config{
		LibraryPath: libraryPath,
		SlotIndex:   &slotIndex,
		UserPIN:     userPIN,
	}
}

// NewConfigWithTokenLabel creates a new Config using token label identification.
func NewConfigWithTokenLabel(libraryPath string, tokenLabel string, userPIN string) *Config {
	return &Config{
		LibraryPath: libraryPath,
		TokenLabel:  tokenLabel,
		UserPIN:     userPIN,
	}
}

// NewConfigWithTokenSerial creates a new Config using token serial number identification.
func NewConfigWithTokenSerial(libraryPath string, tokenSerial string, userPIN string) *Config {
	return &Config{
		LibraryPath:       libraryPath,
		TokenSerialNumber: tokenSerial,
		UserPIN:           userPIN,
	}
}

// NewConfig creates a new Config with slot ID (deprecated: use NewConfigWithSlotID).
// This method is kept for backward compatibility.
func NewConfig(libraryPath string, slotID uint, userPIN string) *Config {
	return NewConfigWithSlotID(libraryPath, slotID, userPIN)
}

// SlotIdentificationType represents the type of slot identification method used
type SlotIdentificationType int

const (
	SlotIdentificationByID SlotIdentificationType = iota
	SlotIdentificationByIndex
	SlotIdentificationByTokenLabel
	SlotIdentificationByTokenSerial
)

// String returns the string representation of the slot identification type
func (s SlotIdentificationType) String() string {
	switch s {
	case SlotIdentificationByID:
		return "SlotID"
	case SlotIdentificationByIndex:
		return "SlotIndex"
	case SlotIdentificationByTokenLabel:
		return "TokenLabel"
	case SlotIdentificationByTokenSerial:
		return "TokenSerialNumber"
	default:
		return "Unknown"
	}
}

// GetSlotIdentificationType returns the type of slot identification method configured
func (c *Config) GetSlotIdentificationType() (SlotIdentificationType, error) {
	var setFields []SlotIdentificationType
	
	if c.SlotID != nil {
		setFields = append(setFields, SlotIdentificationByID)
	}
	if c.SlotIndex != nil {
		setFields = append(setFields, SlotIdentificationByIndex)
	}
	if c.TokenLabel != "" {
		setFields = append(setFields, SlotIdentificationByTokenLabel)
	}
	if c.TokenSerialNumber != "" {
		setFields = append(setFields, SlotIdentificationByTokenSerial)
	}
	
	if len(setFields) == 0 {
		return SlotIdentificationByID, errors.New("no slot identification method specified - must set one of: SlotID, SlotIndex, TokenLabel, or TokenSerialNumber")
	}
	
	if len(setFields) > 1 {
		var fieldNames []string
		for _, field := range setFields {
			fieldNames = append(fieldNames, field.String())
		}
		return SlotIdentificationByID, errors.Errorf("multiple slot identification methods specified: %v - only one can be set", fieldNames)
	}
	
	return setFields[0], nil
}

// Validate checks that the configuration is valid and the library path exists.
// Returns an error if the library path is empty, the file doesn't exist, the user PIN is empty,
// or if multiple slot identification methods are specified.
func (c *Config) Validate() error {
	if c.LibraryPath == "" {
		return errors.New("library path cannot be empty")
	}

	if _, err := os.Stat(c.LibraryPath); os.IsNotExist(err) {
		return errors.Errorf("PKCS#11 library not found at: %s", c.LibraryPath)
	}

	if c.UserPIN == "" {
		return errors.New("user PIN cannot be empty")
	}

	// Validate slot identification method
	_, err := c.GetSlotIdentificationType()
	if err != nil {
		return errors.Wrap(err, "invalid slot identification configuration")
	}

	return nil
}

// String returns a string representation of the config with the PIN redacted for security.
func (c *Config) String() string {
	slotType, err := c.GetSlotIdentificationType()
	if err != nil {
		return fmt.Sprintf("PKCS11Config{LibraryPath: %s, SlotIdentification: INVALID, UserPIN: [REDACTED]}", c.LibraryPath)
	}
	
	var slotInfo string
	switch slotType {
	case SlotIdentificationByID:
		slotInfo = fmt.Sprintf("SlotID: %d", *c.SlotID)
	case SlotIdentificationByIndex:
		slotInfo = fmt.Sprintf("SlotIndex: %d", *c.SlotIndex)
	case SlotIdentificationByTokenLabel:
		slotInfo = fmt.Sprintf("TokenLabel: %s", c.TokenLabel)
	case SlotIdentificationByTokenSerial:
		slotInfo = fmt.Sprintf("TokenSerialNumber: %s", c.TokenSerialNumber)
	default:
		slotInfo = "Unknown"
	}
	
	return fmt.Sprintf("PKCS11Config{LibraryPath: %s, %s, UserPIN: [REDACTED]}", c.LibraryPath, slotInfo)
}

// getBundledSoftHSMPath returns the path to the bundled SoftHSM library for the current platform.
func getBundledSoftHSMPath() (string, error) {
	// Get current file's directory to locate the lib directory
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("could not determine current file path")
	}

	// Navigate to pkg/pkcs11/lib from current file location
	pkcs11Dir := filepath.Dir(currentFile)
	libDir := filepath.Join(pkcs11Dir, "lib")

	// Determine platform
	platform := runtime.GOOS + "-" + runtime.GOARCH

	// Convert Go architecture names to our naming convention
	switch runtime.GOARCH {
	case "amd64":
		// Keep as is
	case "arm64":
		// Keep as is
	default:
		return "", errors.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}

	// Construct library path
	libPath := filepath.Join(libDir, platform, "libsofthsm2.so")

	// Check if file exists
	if _, err := os.Stat(libPath); os.IsNotExist(err) {
		return "", errors.Errorf("bundled SoftHSM library not found at: %s", libPath)
	}

	return libPath, nil
}

// NewTestConfig creates a configuration suitable for testing.
// It attempts to use the bundled SoftHSM library if available, otherwise falls back to mock.
// Uses TokenLabel identification for more robust testing.
func NewTestConfig() *Config {
	// Try to get bundled SoftHSM path
	libraryPath, err := getBundledSoftHSMPath()
	if err != nil {
		// Use a placeholder path for mock testing
		libraryPath = "/tmp/mock-pkcs11.so"
	}

	return NewConfigWithTokenLabel(libraryPath, "TestToken", "1234")
}

// NewTestConfigWithSlotID creates a test configuration using slot ID.
// Use this for tests that specifically need slot ID identification.
func NewTestConfigWithSlotID() *Config {
	// Try to get bundled SoftHSM path
	libraryPath, err := getBundledSoftHSMPath()
	if err != nil {
		// Use a placeholder path for mock testing
		libraryPath = "/tmp/mock-pkcs11.so"
	}

	return NewConfigWithSlotID(libraryPath, 0, "1234")
}
