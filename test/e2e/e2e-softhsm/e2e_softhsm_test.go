package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pkg/errors"
	pkcs11 "github.com/yeaops/gopkcs11"
)

// SoftHSMTestConfig holds configuration for SoftHSM testing
type SoftHSMTestConfig struct {
	TokenDir   string
	TokenLabel string
	UserPIN    string
	SOPIN      string
	SlotID     uint
}

// NewSoftHSMTestConfig creates a default SoftHSM test configuration
func NewSoftHSMTestConfig() (*SoftHSMTestConfig, error) {

	// Get current file's directory to locate the bundled library
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return nil, errors.New("could not determine current file path using runtime.Caller")
	}

	currentDir := filepath.Dir(currentFile)

	tokenDir := filepath.Join(currentDir, "test-temp", fmt.Sprintf("tokens-%d", time.Now().UnixNano()))

	return &SoftHSMTestConfig{
		TokenDir:   tokenDir,
		TokenLabel: "TestToken",
		UserPIN:    "1234",
		SOPIN:      "5678",
		SlotID:     0,
	}, nil
}

// SetupSoftHSM initializes a SoftHSM token for testing
func SetupSoftHSM(t *testing.T) (*pkcs11.Config, func()) {
	t.Helper()

	// Check if we have a bundled SoftHSM library
	libraryPath, err := getBundledSoftHSMPath()
	if err != nil {
		t.Fatalf("SoftHSM library is required but not available: %v\n\nInstall SoftHSM with:\n ./install-softhsmv2.sh \n\nOr set PKCS11_LIBRARY_PATH to an existing SoftHSM library path.", err)
	}

	// Create test configuration
	testConfig, err := NewSoftHSMTestConfig()
	if err != nil {
		t.Fatalf("Failed to create test configuration: %v", err)
	}

	// Create token directory
	err = os.MkdirAll(testConfig.TokenDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create token directory: %v", err)
	}

	// Set up SoftHSM configuration
	configPath := filepath.Join(testConfig.TokenDir, "softhsm.conf")
	configContent := fmt.Sprintf(`
# SoftHSM v2 configuration file for testing
directories.tokendir = %s
objectstore.backend = file
log.level = ERROR
`, testConfig.TokenDir)

	err = os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write SoftHSM config: %v", err)
	}

	// Set environment variables for SoftHSM
	originalSoftHSMConf := os.Getenv("SOFTHSM2_CONF")
	os.Setenv("SOFTHSM2_CONF", configPath)

	// Initialize token using softhsm2-util if available
	if err := initializeSoftHSMToken(testConfig); err != nil {
		t.Logf("Failed to initialize token with softhsm2-util: %v", err)
		t.Log("Continuing with manual token initialization")
	}

	// Create PKCS#11 config using TokenLabel for better reliability
	// TokenLabel is more stable than SlotID across SoftHSM restarts
	pkcs11Config := &pkcs11.Config{
		LibraryPath: libraryPath,
		TokenLabel:  testConfig.TokenLabel,
		UserPIN:     testConfig.UserPIN,
	}

	// Cleanup function
	cleanup := func() {
		// Restore original environment
		if originalSoftHSMConf != "" {
			os.Setenv("SOFTHSM2_CONF", originalSoftHSMConf)
		} else {
			os.Unsetenv("SOFTHSM2_CONF")
		}

		// Remove test directory
		os.RemoveAll(testConfig.TokenDir)
	}

	return pkcs11Config, cleanup
}

// initializeSoftHSMToken attempts to initialize a SoftHSM token using softhsm2-util
func initializeSoftHSMToken(config *SoftHSMTestConfig) error {
	// Try to find softhsm2-util
	utilPath, err := exec.LookPath("softhsm2-util")
	if err != nil {
		return fmt.Errorf("softhsm2-util not found: %w", err)
	}

	// Initialize token
	cmd := exec.Command(utilPath,
		"--init-token",
		"--slot", fmt.Sprintf("%d", config.SlotID),
		"--label", config.TokenLabel,
		"--so-pin", config.SOPIN,
		"--pin", config.UserPIN)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to initialize token: %w, output: %s", err, output)
	}

	return nil
}

// IsSoftHSMAvailable checks if SoftHSM is available for testing
func IsSoftHSMAvailable() bool {
	_, err := getBundledSoftHSMPath()
	return err == nil
}

// getBundledSoftHSMPath returns the path to the bundled SoftHSM library for the current platform.
// It first checks the PKCS11_LIBRARY_PATH environment variable, then falls back to
// platform-specific bundled library paths.
func getBundledSoftHSMPath() (string, error) {
	// First, check if user has specified a custom library path
	if libPath := os.Getenv("PKCS11_LIBRARY_PATH"); libPath != "" {
		if err := validateLibraryPath(libPath); err != nil {
			return "", errors.Wrapf(err, "custom library path validation failed")
		}
		return libPath, nil
	}

	// Get current file's directory to locate the bundled library
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("could not determine current file path using runtime.Caller")
	}

	// Navigate to the bundled library directory
	e2eDir := filepath.Dir(currentFile)
	libDir := filepath.Join(e2eDir, "build", "lib", "softhsm")

	// Try to find the library with platform-specific extensions
	libPath, err := findSoftHSMLibrary(libDir)
	if err != nil {
		return "", errors.Wrapf(err, "failed to find SoftHSM library in %s", libDir)
	}

	return libPath, nil
}

// findSoftHSMLibrary searches for SoftHSM library files in the given directory.
// It tries multiple possible filenames based on the platform and common variations.
func findSoftHSMLibrary(libDir string) (string, error) {
	// Get possible library filenames for the current platform
	candidates := getSoftHSMLibraryCandidates()

	// Try each candidate filename
	for _, filename := range candidates {
		libPath := filepath.Join(libDir, filename)
		if err := validateLibraryPath(libPath); err == nil {
			return libPath, nil
		}
	}

	// If no library found, return detailed error
	return "", errors.Errorf("SoftHSM library not found in %s. Tried: %v", libDir, candidates)
}

// getSoftHSMLibraryCandidates returns a list of possible SoftHSM library filenames
// for the current platform, ordered by preference.
func getSoftHSMLibraryCandidates() []string {
	switch runtime.GOOS {
	case "linux":
		return []string{
			"libsofthsm2.so",
			"libsofthsm2.so.2", // versioned .so files
		}
	case "darwin":
		return []string{
			"libsofthsm2.dylib",
			"libsofthsm2.so", // some builds may use .so on macOS
		}
	case "windows":
		return []string{
			"softhsm2.dll",
			"libsofthsm2.dll",
			"libsofthsm2.so", // some builds may use .so on Windows
		}
	default:
		// For unknown platforms, try common extensions
		return []string{
			"libsofthsm2.so",
			"libsofthsm2.dylib",
			"softhsm2.dll",
			"libsofthsm2.dll",
		}
	}
}

// validateLibraryPath checks if the library file exists and is accessible.
func validateLibraryPath(libPath string) error {
	if libPath == "" {
		return errors.New("library path cannot be empty")
	}

	info, err := os.Stat(libPath)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.Errorf("library file does not exist: %s", libPath)
		}
		return errors.Wrapf(err, "failed to access library file: %s", libPath)
	}

	// Check if it's a regular file (not a directory)
	if info.IsDir() {
		return errors.Errorf("path is a directory, not a file: %s", libPath)
	}

	// Check if file is readable
	file, err := os.Open(libPath)
	if err != nil {
		return errors.Wrapf(err, "library file is not readable: %s", libPath)
	}
	file.Close()

	return nil
}

// RequireSoftHSM fails the test if SoftHSM is not available (SoftHSM is mandatory)
func RequireSoftHSM(t *testing.T) {
	t.Helper()
	if !IsSoftHSMAvailable() {
		platform := runtime.GOOS + "-" + runtime.GOARCH
		t.Fatalf("SoftHSM is required but not available for platform %s.\n\nInstall SoftHSM with:\n  ./install-softhsmv2.sh\n\nSoftHSM is a software-based HSM that should work on all platforms.", platform)
	}
}

// CreateTestClient creates a PKCS#11 client for testing with automatic cleanup
func CreateTestClient(t *testing.T) (*pkcs11.Client, func()) {
	t.Helper()

	config, cleanup := SetupSoftHSM(t)

	client, err := pkcs11.NewClient(config)
	if err != nil {
		cleanup()
		t.Fatalf("Failed to create PKCS#11 client: %v", err)
	}

	return client, func() {
		client.Close()
		cleanup()
	}
}
