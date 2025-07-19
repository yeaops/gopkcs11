package e2e

import (
	"testing"

	"github.com/yeaops/gopkcs11"
)

// HSMTestSuite defines the interface that HSM-specific implementations must satisfy
// to run the common e2e test suite.
type HSMTestSuite interface {
	NewToken(t testing.TB) (*gopkcs11.Client, func())
	Cleanup() error
}

// CommonTestConfig holds configuration options for common tests
type CommonTestConfig struct {
	// Skip specific test categories based on HSM capabilities
	SkipConcurrencyTests bool
	SkipLargeDataTests   bool
	SkipPerformanceTests bool

	// Test size limits for different HSMs
	MaxTestDataSize  int
	MaxConcurrentOps int

	// Supported key sizes and algorithms
	SupportedRSAKeySizes []int
	SupportedAESKeySizes []int
	SupportedECDSACurves []string
	SupportedCipherModes []string
}

// DefaultCommonTestConfig returns a default configuration suitable for most HSMs
func DefaultCommonTestConfig() *CommonTestConfig {
	return &CommonTestConfig{
		SkipConcurrencyTests: false,
		SkipLargeDataTests:   false,
		SkipPerformanceTests: false,
		MaxTestDataSize:      1024 * 1024, // 1MB
		MaxConcurrentOps:     10,
		SupportedRSAKeySizes: []int{2048, 4096},
		SupportedAESKeySizes: []int{128, 192, 256},
		SupportedECDSACurves: []string{"P256", "P384"},
		SupportedCipherModes: []string{"ECB", "CBC", "GCM"},
	}
}

// TestContext bundles the HSM test suite with configuration for running tests
type TestContext struct {
	HSM    HSMTestSuite
	Config *CommonTestConfig
}

// NewTestContext creates a new test context with the given HSM suite and optional config
func NewTestContext(hsm HSMTestSuite, config *CommonTestConfig) *TestContext {
	if config == nil {
		config = DefaultCommonTestConfig()
	}
	return &TestContext{
		HSM:    hsm,
		Config: config,
	}
}

// CreateTestClient is a convenience method that creates a test client using the HSM suite
func (ctx *TestContext) CreateTestClient(t testing.TB) (*gopkcs11.Client, func()) {
	t.Helper()
	return ctx.HSM.NewToken(t)
}
