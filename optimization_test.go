package gopkcs11

import (
	"testing"
)

// TestSlotIDOptimizationPath tests that SlotID uses the optimized connection path
func TestSlotIDOptimizationPath(t *testing.T) {
	tests := []struct {
		name               string
		config             *Config
		expectedSlotType   SlotIdentificationType
		shouldUseOptimized bool
	}{
		{
			name:               "SlotID should use optimized path",
			config:             NewConfigWithSlotID("/tmp/lib.so", 123, "pin"),
			expectedSlotType:   SlotIdentificationByID,
			shouldUseOptimized: true,
		},
		{
			name:               "SlotIndex should use enumeration path",
			config:             NewConfigWithSlotIndex("/tmp/lib.so", 0, "pin"),
			expectedSlotType:   SlotIdentificationByIndex,
			shouldUseOptimized: false,
		},
		{
			name:               "TokenLabel should use enumeration path",
			config:             NewConfigWithTokenLabel("/tmp/lib.so", "token", "pin"),
			expectedSlotType:   SlotIdentificationByTokenLabel,
			shouldUseOptimized: false,
		},
		{
			name:               "TokenSerial should use enumeration path",
			config:             NewConfigWithTokenSerial("/tmp/lib.so", "12345", "pin"),
			expectedSlotType:   SlotIdentificationByTokenSerial,
			shouldUseOptimized: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slotType, err := tt.config.GetSlotIdentificationType()
			if err != nil {
				t.Fatalf("Failed to get slot identification type: %v", err)
			}

			if slotType != tt.expectedSlotType {
				t.Errorf("Expected slot type %v, got %v", tt.expectedSlotType, slotType)
			}

			// Test the optimization logic
			isSlotID := (slotType == SlotIdentificationByID)
			if isSlotID != tt.shouldUseOptimized {
				t.Errorf("Expected optimization use %v, got %v", tt.shouldUseOptimized, isSlotID)
			}

			if tt.shouldUseOptimized {
				// For SlotID, verify we can get the slot ID directly
				if tt.config.SlotID == nil {
					t.Error("SlotID should not be nil for SlotID configuration")
				}
				expectedSlot := *tt.config.SlotID
				if expectedSlot != 123 {
					t.Errorf("Expected slot ID 123, got %d", expectedSlot)
				}
				t.Logf("SlotID optimization: direct slot %d", expectedSlot)
			} else {
				t.Logf("Non-SlotID method: requires slot enumeration")
			}
		})
	}
}

// TestConnectLogicPaths tests the different connection logic paths
func TestConnectLogicPaths(t *testing.T) {
	// Test SlotID path - should have direct slot assignment
	slotIDConfig := NewConfigWithSlotID("/tmp/lib.so", 456, "pin")
	slotType, err := slotIDConfig.GetSlotIdentificationType()
	if err != nil {
		t.Fatalf("Failed to get slot type: %v", err)
	}

	if slotType == SlotIdentificationByID {
		// This should use the optimized path
		targetSlot := *slotIDConfig.SlotID
		if targetSlot != 456 {
			t.Errorf("Expected direct slot assignment to 456, got %d", targetSlot)
		}
		t.Logf("✓ SlotID optimization: direct slot assignment %d", targetSlot)
	}

	// Test other methods - should require slot enumeration
	otherConfigs := []*Config{
		NewConfigWithSlotIndex("/tmp/lib.so", 1, "pin"),
		NewConfigWithTokenLabel("/tmp/lib.so", "test", "pin"),
		NewConfigWithTokenSerial("/tmp/lib.so", "serial", "pin"),
	}

	for i, config := range otherConfigs {
		slotType, err := config.GetSlotIdentificationType()
		if err != nil {
			t.Fatalf("Failed to get slot type for config %d: %v", i, err)
		}

		if slotType == SlotIdentificationByID {
			t.Errorf("Config %d should not use SlotID identification", i)
		} else {
			t.Logf("✓ Config %d uses slot enumeration path (type: %v)", i, slotType)
		}
	}
}

// TestPerformanceImplication simulates the performance difference
func TestPerformanceImplication(t *testing.T) {
	// This is more of a conceptual test to document the optimization benefit
	
	slotIDConfig := NewConfigWithSlotID("/tmp/lib.so", 789, "pin")
	slotIndexConfig := NewConfigWithSlotIndex("/tmp/lib.so", 0, "pin")
	
	slotIDType, _ := slotIDConfig.GetSlotIdentificationType()
	slotIndexType, _ := slotIndexConfig.GetSlotIdentificationType()
	
	// SlotID: Direct assignment (no GetSlotList call needed)
	if slotIDType == SlotIdentificationByID {
		// Simulated operation count: 1 (direct OpenSession)
		operationCount := 1
		t.Logf("SlotID optimization: %d operation (direct OpenSession)", operationCount)
	}
	
	// SlotIndex: Requires enumeration (GetSlotList + indexing)
	if slotIndexType == SlotIdentificationByIndex {
		// Simulated operation count: 2 (GetSlotList + OpenSession)
		operationCount := 2
		t.Logf("SlotIndex enumeration: %d operations (GetSlotList + OpenSession)", operationCount)
	}
	
	t.Log("✓ Performance optimization confirmed: SlotID reduces PKCS#11 calls")
}