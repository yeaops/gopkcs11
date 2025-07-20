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

	t.Run("TokenSessionManagement", func(t *testing.T) {
		TestTokenSessionManagement(t, ctx)
	})

	t.Run("TokenConnectionState", func(t *testing.T) {
		TestTokenConnectionState(t, ctx)
	})

	t.Run("TokenClose", func(t *testing.T) {
		TestTokenClose(t, ctx)
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

}

// TestNewToken tests token creation with various configurations
func TestNewToken(t *testing.T, ctx *TestContext) {
	t.Run("ValidConfig", func(t *testing.T) {
		token := ctx.CreateTestToken(t)
		defer token.Close()

		if token == nil {
			t.Error("NewToken should return non-nil token")
		}

		token.Close()
	})

	t.Run("InvalidLibraryPath", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: "/nonexistent/path/libpkcs11.so",
			SlotID:      &[]uint{0}[0],
			UserPIN:     "1234",
		}

		token, err := pkcs11.NewToken(config)
		if err == nil {
			token.Close()
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

		token, err := pkcs11.NewToken(config)
		if err == nil {
			token.Close()
			t.Error("NewToken should fail with empty library path")
		}
		if !strings.Contains(err.Error(), "library path cannot be empty") {
			t.Errorf("Error should mention empty library path, got: %v", err)
		}
	})
}

// TestTokenSessionManagement tests session-related functionality
func TestTokenSessionManagement(t *testing.T, ctx *TestContext) {

	t.Run("GetSession", func(t *testing.T) {
		token := ctx.CreateTestToken(t)
		defer token.Close()

		session, err := token.GetSession(context.Background())
		if err != nil {
			t.Errorf("GetContext should not fail: %v", err)
		}
		if session == nil {
			t.Error("GetContext should return non-nil context")
		}
		defer session.Release()

		// Test multiple calls return different sessions from pool
		session2, err := token.GetSession(context.Background())
		if err != nil {
			t.Errorf("Second GetSession should not fail: %v", err)
		}
		if session2 == nil {
			t.Error("GetSession should return valid context")
		}
		defer session2.Release()
	})

	t.Run("GetSessionAfterClose", func(t *testing.T) {
		token := ctx.CreateTestToken(t)
		token.Close()

		_, err := token.GetSession(context.Background())
		if err == nil {
			t.Error("GetContext should fail after token close")
		}
		if !strings.Contains(err.Error(), "context pool is closed") {
			t.Errorf("Error should mention not logged in, got: %v", err)
		}
	})

}

// TestTokenConnectionState tests connection state management
func TestTokenConnectionState(t *testing.T, ctx *TestContext) {

	t.Run("Ping", func(t *testing.T) {
		token := ctx.CreateTestToken(t)
		defer token.Close()

		ctxBg := context.Background()
		err := token.Ping(ctxBg)
		if err != nil {
			t.Errorf("Ping should not fail: %v", err)
		}
	})

	t.Run("PingAfterClose", func(t *testing.T) {
		token := ctx.CreateTestToken(t)
		defer token.Close()

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
		token := ctx.CreateTestToken(t)
		defer token.Close()

		err := token.Close()
		if err != nil {
			t.Errorf("Close should not fail: %v", err)
		}
	})

	t.Run("MultipleClose", func(t *testing.T) {
		token := ctx.CreateTestToken(t)
		defer token.Close()

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

// TestTokenConcurrentAccess tests concurrent access to token methods
func TestTokenConcurrentAccess(t *testing.T, ctx *TestContext) {
	if ctx.Config.SkipConcurrencyTests {
		t.Skip("Concurrency tests disabled in configuration")
	}

	token := ctx.CreateTestToken(t)
	defer token.Close()

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
			session, err := token.GetSession(context.Background())
			if err != nil {
				errors <- err
				return
			}
			defer session.Release()

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
		token := ctx.CreateTestToken(t)
		defer func() {
			err := token.Close()
			if err != nil {
				t.Errorf("Close failed: %v", err)
			}
		}()

		// Use the token
		session, err := token.GetSession(context.Background())
		if err != nil {
			t.Errorf("GetSession failed: %v", err)
		}
		if session == nil {
			t.Error("Session should not be nil")
		}
		defer session.Release()

		// Test ping
		err = token.Ping(context.Background())
		if err != nil {
			t.Errorf("Ping failed: %v", err)
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
		token := ctx.CreateTestToken(t)

		// Use the token briefly
		session, err := token.GetSession(context.Background())
		if err != nil {
			t.Errorf("GetContext failed for token %d: %v", i, err)
		}
		if session != nil {
			session.Release()
		}

		// Close immediately
		token.Close()
	}
}
