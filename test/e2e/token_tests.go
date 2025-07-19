package e2e

import (
	"context"
	"strings"
	"sync"
	"testing"

	pkcs11 "github.com/yeaops/gopkcs11"
)

// RunTokenTests runs the complete suite of token functionality tests
func RunTokenTests(t *testing.T, ctx *TestContext) {
	t.Run("NewToken", func(t *testing.T) {
		TestNewToken(t, ctx)
	})

	t.Run("TokenSlotIdentification", func(t *testing.T) {
		TestTokenSlotIdentification(t, ctx)
	})

	t.Run("TokenSessionManagement", func(t *testing.T) {
		TestTokenSessionManagement(t, ctx)
	})

	t.Run("TokenConnectionState", func(t *testing.T) {
		TestTokenConnectionState(t, ctx)
	})

	t.Run("TokenClose", func(t *testing.T) {
		TestTokenClose(t, ctx)
	})

	t.Run("ConfigValidation", func(t *testing.T) {
		TestConfigValidation(t, ctx)
	})

	t.Run("ConfigString", func(t *testing.T) {
		TestConfigString(t, ctx)
	})

	t.Run("ConfigGetSlotIdentificationType", func(t *testing.T) {
		TestConfigGetSlotIdentificationType(t, ctx)
	})

	if !ctx.Config.SkipConcurrencyTests {
		t.Run("TokenConcurrentAccess", func(t *testing.T) {
			TestTokenConcurrentAccess(t, ctx)
		})
	}

	t.Run("SlotIdentificationTypeString", func(t *testing.T) {
		TestSlotIdentificationTypeString(t, ctx)
	})

	t.Run("TokenLifecycle", func(t *testing.T) {
		TestTokenLifecycle(t, ctx)
	})

	t.Run("TokenErrorHandling", func(t *testing.T) {
		TestTokenErrorHandling(t, ctx)
	})

	t.Run("TokenAttributeHelpers", func(t *testing.T) {
		TestTokenAttributeHelpers(t, ctx)
	})

	t.Run("TokenMemoryManagement", func(t *testing.T) {
		TestTokenMemoryManagement(t, ctx)
	})

	t.Run("TokenSessionHandleValidation", func(t *testing.T) {
		TestTokenSessionHandleValidation(t, ctx)
	})
}

// TestNewToken tests token creation with various configurations
func TestNewToken(t *testing.T, ctx *TestContext) {
	t.Run("ValidConfig", func(t *testing.T) {
		token, cleanup := ctx.CreateTestToken(t)
		defer cleanup()

		if token == nil {
			t.Error("NewToken should return non-nil token")
		}

		// Test that token is connected
		if !token.IsConnected() {
			t.Error("Token should be connected after creation")
		}
	})

	t.Run("InvalidLibraryPath", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: "/nonexistent/path/libpkcs11.so",
			SlotID:      &[]uint{0}[0],
			UserPIN:     "1234",
		}

		_, err := pkcs11.NewToken(config)
		if err == nil {
			t.Error("NewToken should fail with invalid library path")
		}
		if !strings.Contains(err.Error(), "PKCS#11 library not found") {
			t.Errorf("Error should mention library not found, got: %v", err)
		}
	})

	t.Run("EmptyLibraryPath", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: "",
			SlotID:      &[]uint{0}[0],
			UserPIN:     "1234",
		}

		_, err := pkcs11.NewToken(config)
		if err == nil {
			t.Error("NewToken should fail with empty library path")
		}
		if !strings.Contains(err.Error(), "library path cannot be empty") {
			t.Errorf("Error should mention empty library path, got: %v", err)
		}
	})
}

// TestTokenSlotIdentification tests various slot identification methods
func TestTokenSlotIdentification(t *testing.T, ctx *TestContext) {
	// These tests are HSM-specific in their implementation but the concept is common
	t.Skip("HSM-specific slot identification tests should be implemented in HSM packages")
}

// TestTokenSessionManagement tests session-related functionality
func TestTokenSessionManagement(t *testing.T, ctx *TestContext) {
	t.Run("GetSession", func(t *testing.T) {
		token, cleanup := ctx.CreateTestToken(t)
		defer cleanup()

		session, err := token.GetSession()
		if err != nil {
			t.Errorf("GetSession should not fail: %v", err)
		}
		if session == 0 {
			t.Error("GetSession should return non-zero session handle")
		}

		// Test multiple calls return same session
		session2, err := token.GetSession()
		if err != nil {
			t.Errorf("Second GetSession should not fail: %v", err)
		}
		if session != session2 {
			t.Error("GetSession should return same session handle")
		}
	})

	t.Run("GetSessionAfterClose", func(t *testing.T) {
		token, cleanup := ctx.CreateTestToken(t)
		defer cleanup()

		token.Close()

		_, err := token.GetSession()
		if err == nil {
			t.Error("GetSession should fail after token close")
		}
		if !strings.Contains(err.Error(), "not logged in") {
			t.Errorf("Error should mention not logged in, got: %v", err)
		}
	})

	t.Run("GetContext", func(t *testing.T) {
		token, cleanup := ctx.CreateTestToken(t)
		defer cleanup()

		ctx := token.GetContext()
		if ctx == nil {
			t.Error("GetContext should return non-nil context")
		}
	})
}

// TestTokenConnectionState tests connection state management
func TestTokenConnectionState(t *testing.T, ctx *TestContext) {
	t.Run("IsConnected", func(t *testing.T) {
		token, cleanup := ctx.CreateTestToken(t)
		defer cleanup()

		if !token.IsConnected() {
			t.Error("Token should be connected after creation")
		}

		token.Close()

		if token.IsConnected() {
			t.Error("Token should not be connected after close")
		}
	})

	t.Run("Ping", func(t *testing.T) {
		token, cleanup := ctx.CreateTestToken(t)
		defer cleanup()

		ctxBg := context.Background()
		err := token.Ping(ctxBg)
		if err != nil {
			t.Errorf("Ping should not fail: %v", err)
		}
	})

	t.Run("PingAfterClose", func(t *testing.T) {
		token, cleanup := ctx.CreateTestToken(t)
		defer cleanup()

		token.Close()

		ctxBg := context.Background()
		err := token.Ping(ctxBg)
		if err == nil {
			t.Error("Ping should fail after token close")
		}
	})
}

// TestTokenClose tests token close functionality
func TestTokenClose(t *testing.T, ctx *TestContext) {
	t.Run("BasicClose", func(t *testing.T) {
		token, cleanup := ctx.CreateTestToken(t)
		defer cleanup()

		err := token.Close()
		if err != nil {
			t.Errorf("Close should not fail: %v", err)
		}

		if token.IsConnected() {
			t.Error("Token should not be connected after close")
		}
	})

	t.Run("MultipleClose", func(t *testing.T) {
		token, cleanup := ctx.CreateTestToken(t)
		defer cleanup()

		// Close multiple times should not cause issues
		err1 := token.Close()
		err2 := token.Close()
		err3 := token.Close()

		if err1 != nil {
			t.Errorf("First close should not fail: %v", err1)
		}
		if err2 != nil {
			t.Errorf("Second close should not fail: %v", err2)
		}
		if err3 != nil {
			t.Errorf("Third close should not fail: %v", err3)
		}
	})
}

// TestConfigValidation tests configuration validation
func TestConfigValidation(t *testing.T, ctx *TestContext) {
	// These tests are HSM-specific as they depend on actual library paths
	t.Skip("HSM-specific config validation tests should be implemented in HSM packages")
}

// TestConfigString tests configuration string representation
func TestConfigString(t *testing.T, ctx *TestContext) {
	// These tests are HSM-specific as they depend on actual library paths
	t.Skip("HSM-specific config string tests should be implemented in HSM packages")
}

// TestConfigGetSlotIdentificationType tests slot identification type detection
func TestConfigGetSlotIdentificationType(t *testing.T, ctx *TestContext) {
	// These tests are HSM-specific as they depend on actual library paths
	t.Skip("HSM-specific slot identification type tests should be implemented in HSM packages")
}

// TestTokenConcurrentAccess tests concurrent access to token methods
func TestTokenConcurrentAccess(t *testing.T, ctx *TestContext) {
	if ctx.Config.SkipConcurrencyTests {
		t.Skip("Concurrency tests disabled in configuration")
	}

	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	// Test concurrent access to token methods
	numGoroutines := ctx.Config.MaxConcurrentOps
	if numGoroutines <= 0 {
		numGoroutines = 10
	}

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	for i := range numGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Test various methods concurrently
			_, err := token.GetSession()
			if err != nil {
				errors <- err
				return
			}

			_ = token.IsConnected()
			_ = token.GetContext()

			err = token.Ping(context.Background())
			if err != nil {
				errors <- err
				return
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Errorf("Concurrent operation failed: %v", err)
	}
}

// TestSlotIdentificationTypeString tests slot identification type string representation
func TestSlotIdentificationTypeString(t *testing.T, ctx *TestContext) {
	testCases := []struct {
		slotType pkcs11.SlotIdentificationType
		expected string
	}{
		{pkcs11.SlotIdentificationByID, "SlotID"},
		{pkcs11.SlotIdentificationByIndex, "SlotIndex"},
		{pkcs11.SlotIdentificationByTokenLabel, "TokenLabel"},
		{pkcs11.SlotIdentificationByTokenSerial, "TokenSerialNumber"},
		{pkcs11.SlotIdentificationType(999), "Unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			str := tc.slotType.String()
			if str != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, str)
			}
		})
	}
}

// TestTokenLifecycle tests complete token lifecycle
func TestTokenLifecycle(t *testing.T, ctx *TestContext) {
	t.Run("CreateUseClose", func(t *testing.T) {
		token, cleanup := ctx.CreateTestToken(t)
		defer cleanup()

		// Use the token
		session, err := token.GetSession()
		if err != nil {
			t.Errorf("GetSession failed: %v", err)
		}
		if session == 0 {
			t.Error("Session should not be zero")
		}

		// Test ping
		err = token.Ping(context.Background())
		if err != nil {
			t.Errorf("Ping failed: %v", err)
		}

		// Check connection state
		if !token.IsConnected() {
			t.Error("Token should be connected")
		}

		// Close
		err = token.Close()
		if err != nil {
			t.Errorf("Close failed: %v", err)
		}

		// Check connection state after close
		if token.IsConnected() {
			t.Error("Token should not be connected after close")
		}
	})
}

// TestTokenErrorHandling tests token error handling scenarios
func TestTokenErrorHandling(t *testing.T, ctx *TestContext) {
	t.Run("InvalidConfigValidation", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: "", // Invalid
			SlotID:      &[]uint{0}[0],
			UserPIN:     "1234",
		}

		_, err := pkcs11.NewToken(config)
		if err == nil {
			t.Error("NewToken should fail with invalid config")
		}
		if !strings.Contains(err.Error(), "invalid PKCS#11 configuration") {
			t.Errorf("Error should mention invalid configuration, got: %v", err)
		}
	})

	t.Run("ContextCreationFailure", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: "/dev/null", // Invalid library file
			SlotID:      &[]uint{0}[0],
			UserPIN:     "1234",
		}

		_, err := pkcs11.NewToken(config)
		if err == nil {
			t.Error("NewToken should fail with invalid library")
		}
	})
}

// TestTokenAttributeHelpers tests attribute helper functions
func TestTokenAttributeHelpers(t *testing.T, ctx *TestContext) {
	t.Run("NewIDAttribute", func(t *testing.T) {
		id := []byte{0x01, 0x02, 0x03}
		attr := pkcs11.NewIDAttribute(id)
		if attr == nil {
			t.Error("NewIDAttribute should return non-nil attribute")
		}
	})

	t.Run("NewLabelAttribute", func(t *testing.T) {
		label := "test-label"
		attr := pkcs11.NewLabelAttribute(label)
		if attr == nil {
			t.Error("NewLabelAttribute should return non-nil attribute")
		}
	})
}

// TestTokenMemoryManagement tests memory management during token operations
func TestTokenMemoryManagement(t *testing.T, ctx *TestContext) {
	// Test creating and closing many tokens
	const numTokens = 10
	for i := 0; i < numTokens; i++ {
		token, cleanup := ctx.CreateTestToken(t)

		// Use the token briefly
		_, err := token.GetSession()
		if err != nil {
			t.Errorf("GetSession failed for token %d: %v", i, err)
		}

		// Close immediately
		cleanup()
	}
}

// TestTokenSessionHandleValidation tests session handle validation
func TestTokenSessionHandleValidation(t *testing.T, ctx *TestContext) {
	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	// Get session multiple times and verify it's consistent
	sessions := make([]any, 5)
	for i := range sessions {
		session, err := token.GetSession()
		if err != nil {
			t.Errorf("GetSession failed: %v", err)
		}
		sessions[i] = session
	}

	// All sessions should be the same
	for i := 1; i < len(sessions); i++ {
		if sessions[0] != sessions[i] {
			t.Errorf("Session %d differs from session 0", i)
		}
	}
}
