package e2e

import (
	"context"
	"strings"
	"sync"
	"testing"

	pkcs11 "github.com/yeaops/gopkcs11"
)

// RunClientTests runs the complete suite of client functionality tests
func RunClientTests(t *testing.T, ctx *TestContext) {
	t.Run("NewClient", func(t *testing.T) {
		TestNewClient(t, ctx)
	})
	
	t.Run("ClientSlotIdentification", func(t *testing.T) {
		TestClientSlotIdentification(t, ctx)
	})
	
	t.Run("ClientSessionManagement", func(t *testing.T) {
		TestClientSessionManagement(t, ctx)
	})
	
	t.Run("ClientConnectionState", func(t *testing.T) {
		TestClientConnectionState(t, ctx)
	})
	
	t.Run("ClientClose", func(t *testing.T) {
		TestClientClose(t, ctx)
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
		t.Run("ClientConcurrentAccess", func(t *testing.T) {
			TestClientConcurrentAccess(t, ctx)
		})
	}
	
	t.Run("SlotIdentificationTypeString", func(t *testing.T) {
		TestSlotIdentificationTypeString(t, ctx)
	})
	
	t.Run("ClientLifecycle", func(t *testing.T) {
		TestClientLifecycle(t, ctx)
	})
	
	t.Run("ClientErrorHandling", func(t *testing.T) {
		TestClientErrorHandling(t, ctx)
	})
	
	t.Run("ClientAttributeHelpers", func(t *testing.T) {
		TestClientAttributeHelpers(t, ctx)
	})
	
	t.Run("ClientMemoryManagement", func(t *testing.T) {
		TestClientMemoryManagement(t, ctx)
	})
	
	t.Run("ClientSessionHandleValidation", func(t *testing.T) {
		TestClientSessionHandleValidation(t, ctx)
	})
}

// TestNewClient tests client creation with various configurations
func TestNewClient(t *testing.T, ctx *TestContext) {
	t.Run("ValidConfig", func(t *testing.T) {
		client, cleanup := ctx.CreateTestClient(t)
		defer cleanup()

		if client == nil {
			t.Error("NewClient should return non-nil client")
		}

		// Test that client is connected
		if !client.IsConnected() {
			t.Error("Client should be connected after creation")
		}
	})

	t.Run("InvalidLibraryPath", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: "/nonexistent/path/libpkcs11.so",
			SlotID:      &[]uint{0}[0],
			UserPIN:     "1234",
		}

		_, err := pkcs11.NewClient(config)
		if err == nil {
			t.Error("NewClient should fail with invalid library path")
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

		_, err := pkcs11.NewClient(config)
		if err == nil {
			t.Error("NewClient should fail with empty library path")
		}
		if !strings.Contains(err.Error(), "library path cannot be empty") {
			t.Errorf("Error should mention empty library path, got: %v", err)
		}
	})
}

// TestClientSlotIdentification tests various slot identification methods
func TestClientSlotIdentification(t *testing.T, ctx *TestContext) {
	// These tests are HSM-specific in their implementation but the concept is common
	t.Skip("HSM-specific slot identification tests should be implemented in HSM packages")
}

// TestClientSessionManagement tests session-related functionality
func TestClientSessionManagement(t *testing.T, ctx *TestContext) {
	t.Run("GetSession", func(t *testing.T) {
		client, cleanup := ctx.CreateTestClient(t)
		defer cleanup()

		session, err := client.GetSession()
		if err != nil {
			t.Errorf("GetSession should not fail: %v", err)
		}
		if session == 0 {
			t.Error("GetSession should return non-zero session handle")
		}

		// Test multiple calls return same session
		session2, err := client.GetSession()
		if err != nil {
			t.Errorf("Second GetSession should not fail: %v", err)
		}
		if session != session2 {
			t.Error("GetSession should return same session handle")
		}
	})

	t.Run("GetSessionAfterClose", func(t *testing.T) {
		client, cleanup := ctx.CreateTestClient(t)
		defer cleanup()

		client.Close()

		_, err := client.GetSession()
		if err == nil {
			t.Error("GetSession should fail after client close")
		}
		if !strings.Contains(err.Error(), "not logged in") {
			t.Errorf("Error should mention not logged in, got: %v", err)
		}
	})

	t.Run("GetContext", func(t *testing.T) {
		client, cleanup := ctx.CreateTestClient(t)
		defer cleanup()

		ctx := client.GetContext()
		if ctx == nil {
			t.Error("GetContext should return non-nil context")
		}
	})
}

// TestClientConnectionState tests connection state management
func TestClientConnectionState(t *testing.T, ctx *TestContext) {
	t.Run("IsConnected", func(t *testing.T) {
		client, cleanup := ctx.CreateTestClient(t)
		defer cleanup()

		if !client.IsConnected() {
			t.Error("Client should be connected after creation")
		}

		client.Close()

		if client.IsConnected() {
			t.Error("Client should not be connected after close")
		}
	})

	t.Run("Ping", func(t *testing.T) {
		client, cleanup := ctx.CreateTestClient(t)
		defer cleanup()

		ctxBg := context.Background()
		err := client.Ping(ctxBg)
		if err != nil {
			t.Errorf("Ping should not fail: %v", err)
		}
	})

	t.Run("PingAfterClose", func(t *testing.T) {
		client, cleanup := ctx.CreateTestClient(t)
		defer cleanup()

		client.Close()

		ctxBg := context.Background()
		err := client.Ping(ctxBg)
		if err == nil {
			t.Error("Ping should fail after client close")
		}
	})
}

// TestClientClose tests client close functionality
func TestClientClose(t *testing.T, ctx *TestContext) {
	t.Run("BasicClose", func(t *testing.T) {
		client, cleanup := ctx.CreateTestClient(t)
		defer cleanup()

		err := client.Close()
		if err != nil {
			t.Errorf("Close should not fail: %v", err)
		}

		if client.IsConnected() {
			t.Error("Client should not be connected after close")
		}
	})

	t.Run("MultipleClose", func(t *testing.T) {
		client, cleanup := ctx.CreateTestClient(t)
		defer cleanup()

		// Close multiple times should not cause issues
		err1 := client.Close()
		err2 := client.Close()
		err3 := client.Close()

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

// TestClientConcurrentAccess tests concurrent access to client methods
func TestClientConcurrentAccess(t *testing.T, ctx *TestContext) {
	if ctx.Config.SkipConcurrencyTests {
		t.Skip("Concurrency tests disabled in configuration")
	}

	client, cleanup := ctx.CreateTestClient(t)
	defer cleanup()

	// Test concurrent access to client methods
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
			_, err := client.GetSession()
			if err != nil {
				errors <- err
				return
			}
			
			_ = client.IsConnected()
			_ = client.GetContext()
			
			err = client.Ping(context.Background())
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

// TestClientLifecycle tests complete client lifecycle
func TestClientLifecycle(t *testing.T, ctx *TestContext) {
	t.Run("CreateUseClose", func(t *testing.T) {
		client, cleanup := ctx.CreateTestClient(t)
		defer cleanup()

		// Use the client
		session, err := client.GetSession()
		if err != nil {
			t.Errorf("GetSession failed: %v", err)
		}
		if session == 0 {
			t.Error("Session should not be zero")
		}

		// Test ping
		err = client.Ping(context.Background())
		if err != nil {
			t.Errorf("Ping failed: %v", err)
		}

		// Check connection state
		if !client.IsConnected() {
			t.Error("Client should be connected")
		}

		// Close
		err = client.Close()
		if err != nil {
			t.Errorf("Close failed: %v", err)
		}

		// Check connection state after close
		if client.IsConnected() {
			t.Error("Client should not be connected after close")
		}
	})
}

// TestClientErrorHandling tests client error handling scenarios
func TestClientErrorHandling(t *testing.T, ctx *TestContext) {
	t.Run("InvalidConfigValidation", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: "", // Invalid
			SlotID:      &[]uint{0}[0],
			UserPIN:     "1234",
		}

		_, err := pkcs11.NewClient(config)
		if err == nil {
			t.Error("NewClient should fail with invalid config")
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

		_, err := pkcs11.NewClient(config)
		if err == nil {
			t.Error("NewClient should fail with invalid library")
		}
	})
}

// TestClientAttributeHelpers tests attribute helper functions
func TestClientAttributeHelpers(t *testing.T, ctx *TestContext) {
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

// TestClientMemoryManagement tests memory management during client operations
func TestClientMemoryManagement(t *testing.T, ctx *TestContext) {
	// Test creating and closing many clients
	const numClients = 10
	for i := 0; i < numClients; i++ {
		client, cleanup := ctx.CreateTestClient(t)

		// Use the client briefly
		_, err := client.GetSession()
		if err != nil {
			t.Errorf("GetSession failed for client %d: %v", i, err)
		}

		// Close immediately
		cleanup()
	}
}

// TestClientSessionHandleValidation tests session handle validation
func TestClientSessionHandleValidation(t *testing.T, ctx *TestContext) {
	client, cleanup := ctx.CreateTestClient(t)
	defer cleanup()

	// Get session multiple times and verify it's consistent
	sessions := make([]any, 5)
	for i := range sessions {
		session, err := client.GetSession()
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