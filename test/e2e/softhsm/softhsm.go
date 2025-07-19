package softhsm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/yeaops/gopkcs11"
)

const (
	defaultUserPIN = "1234"
	defaultSOPIN   = "5678"
	defaultLabel   = "TestToken"
)

type TestSoftHSM struct {
	libraryPath       string
	tokenDir          string
	softhsmConfigFile string

	cleanup func()
}

func NewTestSoftHSM() (*TestSoftHSM, error) {
	hsm := &TestSoftHSM{}

	os.Setenv("PKCS11_LIBRARY_PATH", "build/lib/softhsm/libsofthsm2.so")
	err := hsm.setup()
	if err != nil {
		return nil, err
	}

	// Set environment variable for SoftHSM config
	oldConfig := os.Getenv("SOFTHSM2_CONF")
	os.Setenv("SOFTHSM2_CONF", hsm.softhsmConfigFile)

	cleanup := func() {
		// Restore original config
		if oldConfig != "" {
			os.Setenv("SOFTHSM2_CONF", oldConfig)
		} else {
			os.Unsetenv("SOFTHSM2_CONF")
		}
		// Clean up temp directory
		os.RemoveAll(hsm.softhsmConfigFile)
		os.RemoveAll(hsm.tokenDir)
	}
	hsm.cleanup = cleanup

	return hsm, nil
}

// creates a temporary SoftHSM for testing
func (hsm *TestSoftHSM) setup() error {

	// Get the path to the bundled SoftHSM library
	libraryPath, err := getBundledSoftHSMPath()
	if err != nil {
		return fmt.Errorf("failed to get SoftHSM library path: %w", err)
	}
	hsm.libraryPath = libraryPath

	// Create temporary directory for this test
	tempDir := filepath.Join("test-temp", fmt.Sprintf("tokens-%d", time.Now().UnixNano()))
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}

	// set the token directory
	hsm.tokenDir = tempDir

	// Create SoftHSM configuration file
	configFile := filepath.Join(tempDir, "softhsm.conf")
	configContent := fmt.Sprintf(`
# SoftHSM configuration for testing
directories.tokendir = %s
objectstore.backend = file
log.level = ERROR
slots.removable = false
`, tempDir)
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		os.RemoveAll(tempDir)
		return fmt.Errorf("failed to write SoftHSM config: %w", err)
	}
	hsm.softhsmConfigFile = configFile

	return nil
}

// getBundledSoftHSMPath returns the path to the SoftHSM library
func getBundledSoftHSMPath() (string, error) {
	// Check environment variable first
	if path := os.Getenv("PKCS11_LIBRARY_PATH"); path != "" {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// Platform-specific paths for SoftHSM
	var candidates []string
	switch runtime.GOOS {
	case "darwin":
		candidates = []string{
			"/usr/local/lib/softhsm/libsofthsm2.so",
			"/opt/homebrew/lib/softhsm/libsofthsm2.so",
			"/usr/lib/softhsm/libsofthsm2.so",
		}
	case "linux":
		candidates = []string{
			"/usr/lib/softhsm/libsofthsm2.so",
			"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
			"/usr/local/lib/softhsm/libsofthsm2.so",
		}
	case "windows":
		candidates = []string{
			"C:\\SoftHSM2\\lib\\softhsm2.dll",
			"C:\\Program Files\\SoftHSM2\\lib\\softhsm2.dll",
		}
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("SoftHSM library not found - install SoftHSM v2 or set PKCS11_LIBRARY_PATH")
}

func (t *TestSoftHSM) Cleanup() error {
	t.cleanup()

	return nil
}

// During SoftHSMv2 token initialization, the latest slot index (slot-count - 1) is
// typically uninitialized and can be used as slot id to create a new token.
// However, after initialization, the slot id become dynamic.
// Therefore, to locate a specific token slot, you must find it either by
// its token label or by slot index (new-slot-count - 2).
func (t *TestSoftHSM) CreateToken(tokenLabel, soPin, userPin string) (*gopkcs11.Client, error) {
	fmt.Println(os.Getenv("SOFTHSM2_CONF"))

	err := t.initializeSoftHSMToken(0, tokenLabel, soPin, userPin)
	// err := t.initializeSoftHSMTokenByUtil(0, tokenLabel, soPin, userPin)
	if err != nil {
		return nil, err
	}

	slotCount, err := t.getSlotCount()
	if err != nil {
		return nil, err
	}

	slotIndex := slotCount - 2
	return gopkcs11.NewClient(&gopkcs11.Config{
		LibraryPath: t.libraryPath,
		SlotIndex:   &slotIndex,
		UserPIN:     userPin,
	})
}

// NewToken implements the HSMTestSuite interface for running e2e tests
func (t *TestSoftHSM) NewToken(tb testing.TB) (*gopkcs11.Client, func()) {
	tb.Helper()
	
	client, err := t.CreateToken(defaultLabel, defaultSOPIN, defaultUserPIN)
	if err != nil {
		tb.Fatalf("Failed to create SoftHSM token: %v", err)
	}
	
	cleanup := func() {
		if client != nil {
			client.Close()
		}
	}
	
	return client, cleanup
}

func (t *TestSoftHSM) getSlotCount() (uint, error) {
	// load SoftHSM library
	p11 := pkcs11.New(t.libraryPath)
	if p11 == nil {
		return 0, fmt.Errorf("Could not load PKCS#11 library")
	}
	defer p11.Destroy()

	if err := p11.Initialize(); err != nil {
		return 0, err
	}
	defer p11.Finalize()

	allSlots, err := p11.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("Could not get slot list: %v", err)
	}

	return uint(len(allSlots)), nil
}

func (t *TestSoftHSM) initializeSoftHSMToken(slotID uint, tokenLabel, soPin, userPin string) error {
	slotCount, err := t.getSlotCount()
	if err != nil {
		return err
	}

	// load SoftHSM library
	p11 := pkcs11.New(t.libraryPath)
	if p11 == nil {
		return fmt.Errorf("Could not load PKCS#11 library")
	}
	defer p11.Destroy()

	if err := p11.Initialize(); err != nil {
		return err
	}
	defer p11.Finalize()

	// Use the first available slot
	slotID = slotCount - 1

	err = p11.InitToken(slotID, soPin, tokenLabel)
	if err != nil {
		return fmt.Errorf("InitToken failed: %v", err)
	}

	// init user pin
	session, err := p11.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("OpenSession failed: %v", err)
	}
	defer p11.CloseSession(session)

	err = p11.Login(session, pkcs11.CKU_SO, soPin)
	if err != nil {
		return fmt.Errorf("SO login failed: %v", err)
	}
	defer p11.Logout(session)

	err = p11.InitPIN(session, userPin)
	if err != nil {
		return fmt.Errorf("InitPIN failed: %v", err)
	}

	return nil
}

// initializeSoftHSMToken attempts to initialize a SoftHSM token using softhsm2-util
func (t *TestSoftHSM) initializeSoftHSMTokenByUtil(slotId uint, tokenLabel, soPin, userPin string) error {
	slotCount, err := t.getSlotCount()
	if err != nil {
		return err
	}

	// Try to find softhsm2-util
	utilPath, err := exec.LookPath("softhsm2-util")
	if err != nil {
		return fmt.Errorf("softhsm2-util not found: %w", err)
	}

	// Initialize token
	slotId = slotCount - 1
	cmd := exec.Command(utilPath,
		"--init-token",
		"--slot", fmt.Sprintf("%d", slotId),
		"--label", tokenLabel,
		"--so-pin", soPin,
		"--pin", userPin)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to initialize token: %w, output: %s", err, output)
	}

	return nil
}
