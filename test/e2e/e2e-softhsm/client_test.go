package e2e

import (
	"context"
	"strings"
	"sync"
	"testing"

	pkcs11 "github.com/yeaops/gopkcs11"
)

func TestNewClient(t *testing.T) {
	RequireSoftHSM(t)

	t.Run("ValidConfig", func(t *testing.T) {
		config, cleanup := SetupSoftHSM(t)
		defer cleanup()

		client, err := pkcs11.NewClient(config)
		if err != nil {
			t.Fatalf("NewClient should not fail with valid config: %v", err)
		}
		if client == nil {
			t.Error("NewClient should return non-nil client")
		}

		// Test that client is connected
		if !client.IsConnected() {
			t.Error("Client should be connected after creation")
		}

		// Clean up
		client.Close()
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

	t.Run("InvalidSlotID", func(t *testing.T) {
		config, cleanup := SetupSoftHSM(t)
		defer cleanup()

		// Use a non-existent slot ID
		invalidSlotID := uint(999)
		config.SlotID = &invalidSlotID

		_, err := pkcs11.NewClient(config)
		if err == nil {
			t.Error("NewClient should fail with invalid slot ID")
		}
		if !strings.Contains(err.Error(), "failed to open session") {
			t.Errorf("Error should mention session failure, got: %v", err)
		}
	})

	t.Run("WrongPIN", func(t *testing.T) {
		config, cleanup := SetupSoftHSM(t)
		defer cleanup()

		// Use wrong PIN
		config.UserPIN = "wrongpin"

		_, err := pkcs11.NewClient(config)
		if err == nil {
			t.Error("NewClient should fail with wrong PIN")
		}
		if !strings.Contains(err.Error(), "failed to login") {
			t.Errorf("Error should mention login failure, got: %v", err)
		}
	})
}

func TestClientSlotIdentification(t *testing.T) {
	RequireSoftHSM(t)

	t.Run("BySlotID", func(t *testing.T) {
		config, cleanup := SetupSoftHSM(t)
		defer cleanup()

		client, err := pkcs11.NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		defer client.Close()

		if !client.IsConnected() {
			t.Error("Client should be connected")
		}
	})

	t.Run("ByTokenLabel", func(t *testing.T) {
		config, cleanup := SetupSoftHSM(t)
		defer cleanup()

		// Convert SlotID config to TokenLabel config
		tokenLabelConfig := &pkcs11.Config{
			LibraryPath: config.LibraryPath,
			TokenLabel:  config.TokenLabel,
			UserPIN:     config.UserPIN,
		}

		client, err := pkcs11.NewClient(tokenLabelConfig)
		if err != nil {
			t.Fatalf("NewClient with TokenLabel failed: %v", err)
		}
		defer client.Close()

		if !client.IsConnected() {
			t.Error("Client should be connected")
		}
	})

	t.Run("BySlotIndex", func(t *testing.T) {
		config, cleanup := SetupSoftHSM(t)
		defer cleanup()

		// Convert SlotID config to SlotIndex config
		slotIndex := uint(0)
		slotIndexConfig := &pkcs11.Config{
			LibraryPath: config.LibraryPath,
			SlotIndex:   &slotIndex,
			UserPIN:     config.UserPIN,
		}

		client, err := pkcs11.NewClient(slotIndexConfig)
		if err != nil {
			t.Fatalf("NewClient with SlotIndex failed: %v", err)
		}
		defer client.Close()

		if !client.IsConnected() {
			t.Error("Client should be connected")
		}
	})

	t.Run("InvalidTokenLabel", func(t *testing.T) {
		config, cleanup := SetupSoftHSM(t)
		defer cleanup()

		// Use non-existent token label
		invalidLabelConfig := &pkcs11.Config{
			LibraryPath: config.LibraryPath,
			TokenLabel:  "NonExistentToken",
			UserPIN:     config.UserPIN,
		}

		_, err := pkcs11.NewClient(invalidLabelConfig)
		if err == nil {
			t.Error("NewClient should fail with invalid token label")
		}
		if !strings.Contains(err.Error(), "token with label") {
			t.Errorf("Error should mention token label, got: %v", err)
		}
	})

	t.Run("InvalidSlotIndex", func(t *testing.T) {
		config, cleanup := SetupSoftHSM(t)
		defer cleanup()

		// Use out of range slot index
		invalidSlotIndex := uint(999)
		invalidIndexConfig := &pkcs11.Config{
			LibraryPath: config.LibraryPath,
			SlotIndex:   &invalidSlotIndex,
			UserPIN:     config.UserPIN,
		}

		_, err := pkcs11.NewClient(invalidIndexConfig)
		if err == nil {
			t.Error("NewClient should fail with invalid slot index")
		}
		if !strings.Contains(err.Error(), "out of range") {
			t.Errorf("Error should mention out of range, got: %v", err)
		}
	})
}

func TestClientSessionManagement(t *testing.T) {
	RequireSoftHSM(t)

	t.Run("GetSession", func(t *testing.T) {
		config, cleanup := SetupSoftHSM(t)
		defer cleanup()

		client, err := pkcs11.NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		defer client.Close()

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
		config, cleanup := SetupSoftHSM(t)
		defer cleanup()

		client, err := pkcs11.NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		client.Close()

		_, err = client.GetSession()
		if err == nil {
			t.Error("GetSession should fail after client close")
		}
		if !strings.Contains(err.Error(), "not logged in") {
			t.Errorf("Error should mention not logged in, got: %v", err)
		}
	})

	t.Run("GetContext", func(t *testing.T) {
		config, cleanup := SetupSoftHSM(t)
		defer cleanup()

		client, err := pkcs11.NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		defer client.Close()

		ctx := client.GetContext()
		if ctx == nil {
			t.Error("GetContext should return non-nil context")
		}
	})
}

func TestClientConnectionState(t *testing.T) {
	RequireSoftHSM(t)

	t.Run("IsConnected", func(t *testing.T) {
		config, cleanup := SetupSoftHSM(t)
		defer cleanup()

		client, err := pkcs11.NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		if !client.IsConnected() {
			t.Error("Client should be connected after creation")
		}

		client.Close()

		if client.IsConnected() {
			t.Error("Client should not be connected after close")
		}
	})

	t.Run("Ping", func(t *testing.T) {
		config, cleanup := SetupSoftHSM(t)
		defer cleanup()

		client, err := pkcs11.NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		defer client.Close()

		ctx := context.Background()
		err = client.Ping(ctx)
		if err != nil {
			t.Errorf("Ping should not fail: %v", err)
		}
	})

	t.Run("PingAfterClose", func(t *testing.T) {
		config, cleanup := SetupSoftHSM(t)
		defer cleanup()

		client, err := pkcs11.NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		client.Close()

		ctx := context.Background()
		err = client.Ping(ctx)
		if err == nil {
			t.Error("Ping should fail after client close")
		}
	})
}

func TestClientClose(t *testing.T) {
	RequireSoftHSM(t)

	t.Run("BasicClose", func(t *testing.T) {
		config, cleanup := SetupSoftHSM(t)
		defer cleanup()

		client, err := pkcs11.NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		err = client.Close()
		if err != nil {
			t.Errorf("Close should not fail: %v", err)
		}

		if client.IsConnected() {
			t.Error("Client should not be connected after close")
		}
	})

	t.Run("MultipleClose", func(t *testing.T) {
		config, cleanup := SetupSoftHSM(t)
		defer cleanup()

		client, err := pkcs11.NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

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

func TestConfigValidation(t *testing.T) {
	RequireSoftHSM(t)

	libraryPath, err := getBundledSoftHSMPath()
	if err != nil {
		t.Fatalf("Failed to get SoftHSM library path: %v", err)
	}

	t.Run("ValidConfig", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: libraryPath,
			SlotID:      &[]uint{0}[0],
			UserPIN:     "1234",
		}

		err := config.Validate()
		if err != nil {
			t.Errorf("Validate should not fail for valid config: %v", err)
		}
	})

	t.Run("EmptyLibraryPath", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: "",
			SlotID:      &[]uint{0}[0],
			UserPIN:     "1234",
		}

		err := config.Validate()
		if err == nil {
			t.Error("Validate should fail for empty library path")
		}
		if !strings.Contains(err.Error(), "library path cannot be empty") {
			t.Errorf("Error should mention empty library path, got: %v", err)
		}
	})

	t.Run("NonExistentLibraryPath", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: "/nonexistent/path/libpkcs11.so",
			SlotID:      &[]uint{0}[0],
			UserPIN:     "1234",
		}

		err := config.Validate()
		if err == nil {
			t.Error("Validate should fail for non-existent library path")
		}
		if !strings.Contains(err.Error(), "PKCS#11 library not found") {
			t.Errorf("Error should mention library not found, got: %v", err)
		}
	})

	t.Run("MultipleSlotIdentificationMethods", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: libraryPath,
			SlotID:      &[]uint{0}[0],
			SlotIndex:   &[]uint{0}[0],
			UserPIN:     "1234",
		}

		err := config.Validate()
		if err == nil {
			t.Error("Validate should fail for multiple slot identification methods")
		}
		if !strings.Contains(err.Error(), "multiple slot identification methods") {
			t.Errorf("Error should mention multiple slot identification methods, got: %v", err)
		}
	})

	t.Run("NoSlotIdentificationMethod", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: libraryPath,
			UserPIN:     "1234",
		}

		err := config.Validate()
		if err == nil {
			t.Error("Validate should fail for no slot identification method")
		}
		if !strings.Contains(err.Error(), "no slot identification method") {
			t.Errorf("Error should mention no slot identification method, got: %v", err)
		}
	})
}

func TestConfigString(t *testing.T) {
	RequireSoftHSM(t)

	libraryPath, err := getBundledSoftHSMPath()
	if err != nil {
		t.Fatalf("Failed to get SoftHSM library path: %v", err)
	}

	t.Run("SlotIDConfig", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: libraryPath,
			SlotID:      &[]uint{0}[0],
			UserPIN:     "1234",
		}

		str := config.String()
		if !strings.Contains(str, "PKCS11Config{") {
			t.Error("String should contain 'PKCS11Config{'")
		}
		if !strings.Contains(str, "SlotID: 0") {
			t.Error("String should contain 'SlotID: 0'")
		}
		if !strings.Contains(str, "UserPIN: [REDACTED]") {
			t.Error("String should contain redacted PIN")
		}
		if strings.Contains(str, "1234") {
			t.Error("String should not contain actual PIN")
		}
	})

	t.Run("TokenLabelConfig", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: libraryPath,
			TokenLabel:  "TestToken",
			UserPIN:     "1234",
		}

		str := config.String()
		if !strings.Contains(str, "TokenLabel: TestToken") {
			t.Error("String should contain 'TokenLabel: TestToken'")
		}
	})

	t.Run("SlotIndexConfig", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: libraryPath,
			SlotIndex:   &[]uint{1}[0],
			UserPIN:     "1234",
		}

		str := config.String()
		if !strings.Contains(str, "SlotIndex: 1") {
			t.Error("String should contain 'SlotIndex: 1'")
		}
	})

	t.Run("TokenSerialConfig", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath:       libraryPath,
			TokenSerialNumber: "123456",
			UserPIN:           "1234",
		}

		str := config.String()
		if !strings.Contains(str, "TokenSerialNumber: 123456") {
			t.Error("String should contain 'TokenSerialNumber: 123456'")
		}
	})

	t.Run("InvalidConfig", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: libraryPath,
			UserPIN:     "1234",
		}

		str := config.String()
		if !strings.Contains(str, "INVALID") {
			t.Error("String should contain 'INVALID' for invalid config")
		}
	})
}

func TestConfigGetSlotIdentificationType(t *testing.T) {
	RequireSoftHSM(t)

	libraryPath, err := getBundledSoftHSMPath()
	if err != nil {
		t.Fatalf("Failed to get SoftHSM library path: %v", err)
	}

	t.Run("SlotID", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: libraryPath,
			SlotID:      &[]uint{0}[0],
			UserPIN:     "1234",
		}

		slotType, err := config.GetSlotIdentificationType()
		if err != nil {
			t.Errorf("GetSlotIdentificationType should not fail: %v", err)
		}
		if slotType != pkcs11.SlotIdentificationByID {
			t.Errorf("Expected SlotIdentificationByID, got %v", slotType)
		}
	})

	t.Run("SlotIndex", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: libraryPath,
			SlotIndex:   &[]uint{0}[0],
			UserPIN:     "1234",
		}

		slotType, err := config.GetSlotIdentificationType()
		if err != nil {
			t.Errorf("GetSlotIdentificationType should not fail: %v", err)
		}
		if slotType != pkcs11.SlotIdentificationByIndex {
			t.Errorf("Expected SlotIdentificationByIndex, got %v", slotType)
		}
	})

	t.Run("TokenLabel", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath: libraryPath,
			TokenLabel:  "TestToken",
			UserPIN:     "1234",
		}

		slotType, err := config.GetSlotIdentificationType()
		if err != nil {
			t.Errorf("GetSlotIdentificationType should not fail: %v", err)
		}
		if slotType != pkcs11.SlotIdentificationByTokenLabel {
			t.Errorf("Expected SlotIdentificationByTokenLabel, got %v", slotType)
		}
	})

	t.Run("TokenSerialNumber", func(t *testing.T) {
		config := &pkcs11.Config{
			LibraryPath:       libraryPath,
			TokenSerialNumber: "123456",
			UserPIN:           "1234",
		}

		slotType, err := config.GetSlotIdentificationType()
		if err != nil {
			t.Errorf("GetSlotIdentificationType should not fail: %v", err)
		}
		if slotType != pkcs11.SlotIdentificationByTokenSerial {
			t.Errorf("Expected SlotIdentificationByTokenSerial, got %v", slotType)
		}
	})
}

func TestClientConcurrentAccess(t *testing.T) {
	RequireSoftHSM(t)

	config, cleanup := SetupSoftHSM(t)
	defer cleanup()

	client, err := pkcs11.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	// Test concurrent access to client methods
	const numGoroutines = 10
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
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

func TestSlotIdentificationTypeString(t *testing.T) {
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

func TestClientLifecycle(t *testing.T) {
	RequireSoftHSM(t)

	config, cleanup := SetupSoftHSM(t)
	defer cleanup()

	t.Run("CreateUseClose", func(t *testing.T) {
		client, err := pkcs11.NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

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

func TestClientErrorHandling(t *testing.T) {
	RequireSoftHSM(t)

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

func TestClientAttributeHelpers(t *testing.T) {
	t.Run("NewIDAttribute", func(t *testing.T) {
		id := []byte{0x01, 0x02, 0x03}
		attr := pkcs11.NewIDAttribute(id)
		if attr == nil {
			t.Error("NewIDAttribute should return non-nil attribute")
		}
		// Additional validation would require accessing internal fields
	})

	t.Run("NewLabelAttribute", func(t *testing.T) {
		label := "test-label"
		attr := pkcs11.NewLabelAttribute(label)
		if attr == nil {
			t.Error("NewLabelAttribute should return non-nil attribute")
		}
		// Additional validation would require accessing internal fields
	})
}

func TestClientMemoryManagement(t *testing.T) {
	RequireSoftHSM(t)

	config, cleanup := SetupSoftHSM(t)
	defer cleanup()

	// Test creating and closing many clients
	const numClients = 10
	for i := 0; i < numClients; i++ {
		client, err := pkcs11.NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed for client %d: %v", i, err)
		}

		// Use the client briefly
		_, err = client.GetSession()
		if err != nil {
			t.Errorf("GetSession failed for client %d: %v", i, err)
		}

		// Close immediately
		err = client.Close()
		if err != nil {
			t.Errorf("Close failed for client %d: %v", i, err)
		}
	}
}

func TestClientSessionHandleValidation(t *testing.T) {
	RequireSoftHSM(t)

	config, cleanup := SetupSoftHSM(t)
	defer cleanup()

	client, err := pkcs11.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	// Get session multiple times and verify it's consistent
	sessions := make([]interface{}, 5)
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

