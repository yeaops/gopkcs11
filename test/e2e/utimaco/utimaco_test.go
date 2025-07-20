package utimaco

import (
	"testing"

	"github.com/yeaops/gopkcs11/test/e2e"
)

// getUtimacoTestConfig returns a test configuration optimized for Utimaco HSM
func getUtimacoTestConfig() *e2e.CommonTestConfig {
	config := e2e.DefaultCommonTestConfig()

	// Utimaco HSMs are hardware-based, adjust limits accordingly
	config.SkipConcurrencyTests = false
	config.SkipLargeDataTests = false
	config.SkipPerformanceTests = false

	// Conservative limits for hardware HSM
	config.MaxTestDataSize = 2 * 1024 * 1024 // 2MB
	config.MaxConcurrentOps = 10

	// Utimaco supports standard algorithms
	config.SupportedRSAKeySizes = []int{2048, 4096}
	config.SupportedAESKeySizes = []int{128, 192, 256}
	config.SupportedECDSACurves = []string{"P256", "P384", "P521"}
	config.SupportedCipherModes = []string{"ECB", "CBC", "GCM"}

	return config
}

// TestNewUtimaco tests basic Utimaco HSM setup functionality
func TestNewUtimaco(t *testing.T) {
	hsm, err := NewTestUtimaco()
	if err != nil {
		t.Fatalf("Failed to create Utimaco instance: %v", err)
	}
	defer hsm.Cleanup()

	token := hsm.CreateToken(t)
	defer token.Close()
}

// TestUtimacoTokenFunctionality runs comprehensive token tests using the e2e framework
func TestUtimacoTokenFunctionality(t *testing.T) {
	hsm, err := NewTestUtimaco()
	if err != nil {
		t.Fatalf("Failed to create Utimaco instance: %v", err)
	}
	defer hsm.Cleanup()

	ctx := e2e.NewTestContext(hsm, getUtimacoTestConfig())
	e2e.RunTokenTests(t, ctx)
}

// TestUtimacoKeypairFunctionality runs comprehensive keypair tests using the e2e framework
func TestUtimacoKeypairFunctionality(t *testing.T) {
	hsm, err := NewTestUtimaco()
	if err != nil {
		t.Fatalf("Failed to create Utimaco instance: %v", err)
	}
	defer hsm.Cleanup()

	ctx := e2e.NewTestContext(hsm, getUtimacoTestConfig())
	e2e.RunKeypairTests(t, ctx)
}

// TestUtimacoCipherFunctionality runs comprehensive cipher tests using the e2e framework
func TestUtimacoCipherFunctionality(t *testing.T) {
	hsm, err := NewTestUtimaco()
	if err != nil {
		t.Fatalf("Failed to create Utimaco instance: %v", err)
	}
	defer hsm.Cleanup()

	ctx := e2e.NewTestContext(hsm, getUtimacoTestConfig())
	e2e.RunCipherTests(t, ctx)
}

// TestUtimacoSymmetricKeyFunctionality runs comprehensive symmetric key tests using the e2e framework
func TestUtimacoSymmetricKeyFunctionality(t *testing.T) {
	hsm, err := NewTestUtimaco()
	if err != nil {
		t.Fatalf("Failed to create Utimaco instance: %v", err)
	}
	defer hsm.Cleanup()

	ctx := e2e.NewTestContext(hsm, getUtimacoTestConfig())
	e2e.RunSymmetricKeyTests(t, ctx)
}