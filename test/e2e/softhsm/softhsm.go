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

type TestSoftHSM struct {
	libraryPath       string
	tokenDir          string
	softhsmConfigFile string
	cleanup           func()
}

func NewTestSoftHSM() (*TestSoftHSM, error) {
	hsm := TestSoftHSM{}

	// Check environment variable first
	if path := os.Getenv("PKCS11_LIBRARY_PATH"); path == "" {
		os.Setenv("PKCS11_LIBRARY_PATH", "build/lib/softhsm/libsofthsm2.so")
	}
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

	return &hsm, nil
}

// creates a temporary SoftHSM for testing
func (hsm *TestSoftHSM) setup() error {

	// Get the path to the bundled SoftHSM library
	libraryPath, err := hsm.getBundledSoftHSMPath()
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
func (hsm *TestSoftHSM) getBundledSoftHSMPath() (string, error) {
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
func (t *TestSoftHSM) CreateToken(tb testing.TB) *gopkcs11.Token {
	tb.Helper()

	var tokenLabel, soPin, userPin string
	tokenLabel = "test-token"
	soPin = "12345678"
	userPin = "12345678"

	slotIndex, err := t.createToken(tokenLabel, soPin, userPin)
	if err != nil || slotIndex == nil {
		tb.Fatalf("could not create token: %v", err)
	}

	token, err := gopkcs11.NewToken(&gopkcs11.Config{
		LibraryPath: t.libraryPath,
		SlotIndex:   slotIndex,
		UserPIN:     userPin,
	})
	if err != nil {
		tb.Fatalf("could not create token: %v", err)
	}
	return token
}

func (t *TestSoftHSM) createToken(tokenLabel, soPin, userPin string) (*uint, error) {

	// init ctx
	// load SoftHSM library
	p11Ctx := pkcs11.New(t.libraryPath)
	if p11Ctx == nil {
		return nil, fmt.Errorf("could not create PKCS#11 context, path: %s", t.libraryPath)
	}
	defer p11Ctx.Destroy()

	if err := p11Ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("could not initialize PKCS#11 library: %v", err)
	}
	defer p11Ctx.Finalize()

	// fmt.Println(os.Getenv("SOFTHSM2_CONF"))
	err := t.initializeSoftHSMToken(p11Ctx, tokenLabel, soPin, userPin)
	// err := t.initializeSoftHSMTokenByUtil(p11Ctx, tokenLabel, soPin, userPin)
	if err != nil {
		return nil, fmt.Errorf("could not initialize SoftHSM token: %v", err)
	}

	slotCount, err := t.getSlotCount(p11Ctx)
	if err != nil {

		return nil, fmt.Errorf("could not get slot count: %v", err)
	}

	slotIndex := slotCount - 2

	return &slotIndex, nil
}

func (t *TestSoftHSM) getSlotCount(ctx *pkcs11.Ctx) (uint, error) {
	// load SoftHSM library
	allSlots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("could not get slot list: %v", err)
	}

	return uint(len(allSlots)), nil
}

func (t *TestSoftHSM) initializeSoftHSMToken(ctx *pkcs11.Ctx, tokenLabel, soPin, userPin string) error {
	slotCount, err := t.getSlotCount(ctx)
	if err != nil {
		return err
	}

	// Use the first available slot
	slotID := slotCount - 1

	err = ctx.InitToken(slotID, soPin, tokenLabel)
	if err != nil {
		return fmt.Errorf("InitToken failed: %v", err)
	}

	// init user pin
	sessionHandle, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("OpenSession failed: %v", err)
	}
	defer ctx.CloseSession(sessionHandle)

	err = ctx.Login(sessionHandle, pkcs11.CKU_SO, soPin)
	if err != nil {
		return fmt.Errorf("SO login failed: %v", err)
	}
	defer ctx.Logout(sessionHandle)

	err = ctx.InitPIN(sessionHandle, userPin)
	if err != nil {
		return fmt.Errorf("InitPIN failed: %v", err)
	}

	return nil
}

// initializeSoftHSMToken attempts to initialize a SoftHSM token using softhsm2-util
func (t *TestSoftHSM) initializeSoftHSMTokenByUtil(ctx *pkcs11.Ctx, tokenLabel, soPin, userPin string) error {
	slotCount, err := t.getSlotCount(ctx)
	if err != nil {
		return err
	}

	// Try to find softhsm2-util
	utilPath, err := exec.LookPath("softhsm2-util")
	if err != nil {
		return fmt.Errorf("softhsm2-util not found: %w", err)
	}

	// Initialize token
	slotId := slotCount - 1
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
