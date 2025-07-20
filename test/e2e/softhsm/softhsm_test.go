package softhsm

import (
	"fmt"
	"testing"

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

	token := hsm.CreateToken(t)
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

	fmt.Printf("TestSoftHSMCipherFunctionality hsm: %v\n", hsm)

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
