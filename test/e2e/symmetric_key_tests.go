package e2e

import (
	"crypto/rand"
	"strings"
	"sync"
	"testing"

	pkcs11 "github.com/yeaops/gopkcs11"
)

// RunSymmetricKeyTests runs the complete suite of symmetric key tests
func RunSymmetricKeyTests(t *testing.T, ctx *TestContext) {
	t.Run("GenerateAESKey", func(t *testing.T) {
		TestGenerateAESKey(t, ctx)
	})

	t.Run("GenerateDESKey", func(t *testing.T) {
		TestGenerateDESKey(t, ctx)
	})

	t.Run("Generate3DESKey", func(t *testing.T) {
		TestGenerate3DESKey(t, ctx)
	})

	t.Run("ImportAESKey", func(t *testing.T) {
		TestImportAESKey(t, ctx)
	})

	t.Run("ImportDESKey", func(t *testing.T) {
		TestImportDESKey(t, ctx)
	})

	t.Run("Import3DESKey", func(t *testing.T) {
		TestImport3DESKey(t, ctx)
	})

	t.Run("GetSymmetricKey", func(t *testing.T) {
		TestGetSymmetricKey(t, ctx)
	})

	t.Run("ListSymmetricKeys", func(t *testing.T) {
		TestListSymmetricKeys(t, ctx)
	})

	t.Run("DeleteSymmetricKey", func(t *testing.T) {
		TestDeleteSymmetricKey(t, ctx)
	})

	t.Run("SymmetricKeyWithCustomAttributes", func(t *testing.T) {
		TestSymmetricKeyWithCustomAttributes(t, ctx)
	})

	if !ctx.Config.SkipConcurrencyTests {
		t.Run("SymmetricKeyConcurrentOperations", func(t *testing.T) {
			TestSymmetricKeyConcurrentOperations(t, ctx)
		})
	}

	t.Run("SymmetricKeyErrorCases", func(t *testing.T) {
		TestSymmetricKeyErrorCases(t, ctx)
	})

	t.Run("SymmetricKeyString", func(t *testing.T) {
		TestSymmetricKeyString(t, ctx)
	})

	t.Run("SymmetricKeyLifecycle", func(t *testing.T) {
		TestSymmetricKeyLifecycle(t, ctx)
	})

	t.Run("SymmetricKeyAttributeValidation", func(t *testing.T) {
		TestSymmetricKeyAttributeValidation(t, ctx)
	})

	t.Run("SymmetricKeyImportExportWorkflow", func(t *testing.T) {
		TestSymmetricKeyImportExportWorkflow(t, ctx)
	})

	t.Run("SymmetricKeyFilteredListing", func(t *testing.T) {
		TestSymmetricKeyFilteredListing(t, ctx)
	})
}

// TestGenerateAESKey tests AES key generation with various key sizes
func TestGenerateAESKey(t *testing.T, ctx *TestContext) {
	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	testCases := []struct {
		name    string
		keySize int
		valid   bool
	}{
		{"AES128", 128, true},
		{"AES192", 192, true},
		{"AES256", 256, true},
		{"AES64", 64, false},   // Invalid
		{"AES512", 512, false}, // Invalid
	}

	for _, tc := range testCases {
		// Only test key sizes that are configured as supported
		if tc.valid && !contains(ctx.Config.SupportedAESKeySizes, tc.keySize) {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			key, err := token.GenerateAESKey(tc.keySize)

			if tc.valid {
				if err != nil {
					t.Errorf("GenerateAESKey(%d) should not fail: %v", tc.keySize, err)
				}
				if key == nil {
					t.Error("GenerateAESKey should return non-nil key")
				}
				if key.KeySize != tc.keySize {
					t.Errorf("Expected key size %d, got %d", tc.keySize, key.KeySize)
				}
				if key.KeyType != pkcs11.SymmetricKeyTypeAES {
					t.Errorf("Expected AES key type, got %v", key.KeyType)
				}
				if key.Handle == 0 {
					t.Error("Key handle should not be zero")
				}
				if key.Label == "" {
					t.Error("Key label should not be empty")
				}
				if len(key.ID) == 0 {
					t.Error("Key ID should not be empty")
				}
			} else {
				if err == nil {
					t.Errorf("GenerateAESKey(%d) should fail", tc.keySize)
				}
				if key != nil {
					t.Error("GenerateAESKey should return nil key on error")
				}
			}
		})
	}
}

// TestGenerateDESKey tests DES key generation
func TestGenerateDESKey(t *testing.T, ctx *TestContext) {
	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	key, err := token.GenerateDESKey()
	if err != nil {
		t.Fatalf("GenerateDESKey should not fail: %v", err)
	}
	if key == nil {
		t.Error("GenerateDESKey should return non-nil key")
	}
	if key.KeySize != 64 {
		t.Errorf("Expected key size 64, got %d", key.KeySize)
	}
	if key.KeyType != pkcs11.SymmetricKeyTypeDES {
		t.Errorf("Expected DES key type, got %v", key.KeyType)
	}
	if key.Handle == 0 {
		t.Error("Key handle should not be zero")
	}
	if key.Label == "" {
		t.Error("Key label should not be empty")
	}
	if len(key.ID) == 0 {
		t.Error("Key ID should not be empty")
	}
}

// TestGenerate3DESKey tests 3DES key generation
func TestGenerate3DESKey(t *testing.T, ctx *TestContext) {
	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	key, err := token.Generate3DESKey()
	if err != nil {
		t.Fatalf("Generate3DESKey should not fail: %v", err)
	}
	if key == nil {
		t.Error("Generate3DESKey should return non-nil key")
	}
	if key.KeySize != 192 {
		t.Errorf("Expected key size 192, got %d", key.KeySize)
	}
	if key.KeyType != pkcs11.SymmetricKeyType3DES {
		t.Errorf("Expected 3DES key type, got %v", key.KeyType)
	}
	if key.Handle == 0 {
		t.Error("Key handle should not be zero")
	}
	if key.Label == "" {
		t.Error("Key label should not be empty")
	}
	if len(key.ID) == 0 {
		t.Error("Key ID should not be empty")
	}
}

// TestImportAESKey tests AES key import with various key sizes
func TestImportAESKey(t *testing.T, ctx *TestContext) {
	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	testCases := []struct {
		name       string
		keySize    int
		keyBytes   int
		shouldFail bool
	}{
		{"AES128", 128, 16, false},
		{"AES192", 192, 24, false},
		{"AES256", 256, 32, false},
		{"Invalid15Bytes", 120, 15, true},
		{"Invalid17Bytes", 136, 17, true},
		{"Invalid25Bytes", 200, 25, true},
	}

	for _, tc := range testCases {
		// Only test key sizes that are configured as supported
		if !tc.shouldFail && !contains(ctx.Config.SupportedAESKeySizes, tc.keySize) {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			keyMaterial := make([]byte, tc.keyBytes)
			_, err := rand.Read(keyMaterial)
			if err != nil {
				t.Fatalf("Failed to generate key material: %v", err)
			}

			key, err := token.ImportAESKey(keyMaterial)

			if tc.shouldFail {
				if err == nil {
					t.Error("ImportAESKey should fail with invalid key material")
				}
				if key != nil {
					t.Error("ImportAESKey should return nil key on error")
				}
			} else {
				if err != nil {
					t.Errorf("ImportAESKey should not fail: %v", err)
				}
				if key == nil {
					t.Error("ImportAESKey should return non-nil key")
				}
				if key.KeySize != tc.keySize {
					t.Errorf("Expected key size %d, got %d", tc.keySize, key.KeySize)
				}
				if key.KeyType != pkcs11.SymmetricKeyTypeAES {
					t.Errorf("Expected AES key type, got %v", key.KeyType)
				}
			}
		})
	}
}

// TestImportDESKey tests DES key import
func TestImportDESKey(t *testing.T, ctx *TestContext) {
	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	t.Run("ValidDESKey", func(t *testing.T) {
		keyMaterial := make([]byte, 8)
		_, err := rand.Read(keyMaterial)
		if err != nil {
			t.Fatalf("Failed to generate key material: %v", err)
		}

		key, err := token.ImportDESKey(keyMaterial)
		if err != nil {
			t.Errorf("ImportDESKey should not fail: %v", err)
		}
		if key == nil {
			t.Error("ImportDESKey should return non-nil key")
		}
		if key.KeySize != 64 {
			t.Errorf("Expected key size 64, got %d", key.KeySize)
		}
		if key.KeyType != pkcs11.SymmetricKeyTypeDES {
			t.Errorf("Expected DES key type, got %v", key.KeyType)
		}
	})

	t.Run("InvalidDESKeySize", func(t *testing.T) {
		keyMaterial := make([]byte, 7) // Wrong size
		_, err := rand.Read(keyMaterial)
		if err != nil {
			t.Fatalf("Failed to generate key material: %v", err)
		}

		key, err := token.ImportDESKey(keyMaterial)
		if err == nil {
			t.Error("ImportDESKey should fail with invalid key material size")
		}
		if key != nil {
			t.Error("ImportDESKey should return nil key on error")
		}
		if !strings.Contains(err.Error(), "must be exactly 8 bytes") {
			t.Errorf("Error should mention 8 bytes requirement, got: %v", err)
		}
	})
}

// TestImport3DESKey tests 3DES key import
func TestImport3DESKey(t *testing.T, ctx *TestContext) {
	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	t.Run("Valid3DESKey", func(t *testing.T) {
		keyMaterial := make([]byte, 24)
		_, err := rand.Read(keyMaterial)
		if err != nil {
			t.Fatalf("Failed to generate key material: %v", err)
		}

		key, err := token.Import3DESKey(keyMaterial)
		if err != nil {
			t.Errorf("Import3DESKey should not fail: %v", err)
		}
		if key == nil {
			t.Error("Import3DESKey should return non-nil key")
		}
		if key.KeySize != 192 {
			t.Errorf("Expected key size 192, got %d", key.KeySize)
		}
		if key.KeyType != pkcs11.SymmetricKeyType3DES {
			t.Errorf("Expected 3DES key type, got %v", key.KeyType)
		}
	})

	t.Run("Invalid3DESKeySize", func(t *testing.T) {
		keyMaterial := make([]byte, 23) // Wrong size
		_, err := rand.Read(keyMaterial)
		if err != nil {
			t.Fatalf("Failed to generate key material: %v", err)
		}

		key, err := token.Import3DESKey(keyMaterial)
		if err == nil {
			t.Error("Import3DESKey should fail with invalid key material size")
		}
		if key != nil {
			t.Error("Import3DESKey should return nil key on error")
		}
		if !strings.Contains(err.Error(), "must be exactly 24 bytes") {
			t.Errorf("Error should mention 24 bytes requirement, got: %v", err)
		}
	})
}

// TestGetSymmetricKey tests retrieving symmetric keys by ID
func TestGetSymmetricKey(t *testing.T, ctx *TestContext) {
	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	// Generate a key first
	keySize := ctx.Config.SupportedAESKeySizes[0]
	originalKey, err := token.GenerateAESKey(keySize)
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	// Retrieve the key
	retrievedKey, err := token.GetSymmetricKey(originalKey.ID)
	if err != nil {
		t.Errorf("GetSymmetricKey should not fail: %v", err)
	}
	if retrievedKey == nil {
		t.Error("GetSymmetricKey should return non-nil key")
	}

	// Verify key properties
	if retrievedKey.KeySize != originalKey.KeySize {
		t.Errorf("Key size mismatch: expected %d, got %d", originalKey.KeySize, retrievedKey.KeySize)
	}
	if retrievedKey.KeyType != originalKey.KeyType {
		t.Errorf("Key type mismatch: expected %v, got %v", originalKey.KeyType, retrievedKey.KeyType)
	}
	if retrievedKey.Label != originalKey.Label {
		t.Errorf("Key label mismatch: expected %s, got %s", originalKey.Label, retrievedKey.Label)
	}
	if len(retrievedKey.ID) != len(originalKey.ID) {
		t.Errorf("Key ID length mismatch: expected %d, got %d", len(originalKey.ID), len(retrievedKey.ID))
	}

	// Test with non-existent key
	nonExistentID := make([]byte, 16)
	rand.Read(nonExistentID)

	_, err = token.GetSymmetricKey(nonExistentID)
	if err == nil {
		t.Error("GetSymmetricKey should fail with non-existent key ID")
	}
}

// TestListSymmetricKeys tests listing all symmetric keys
func TestListSymmetricKeys(t *testing.T, ctx *TestContext) {
	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	// Generate several keys
	keys := []*pkcs11.SymmetricKey{}

	// Generate different types of keys
	keySize := ctx.Config.SupportedAESKeySizes[0]
	aesKey, err := token.GenerateAESKey(keySize)
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}
	keys = append(keys, aesKey)

	desKey, err := token.GenerateDESKey()
	if err != nil {
		t.Fatalf("Failed to generate DES key: %v", err)
	}
	keys = append(keys, desKey)

	tripleDesKey, err := token.Generate3DESKey()
	if err != nil {
		t.Fatalf("Failed to generate 3DES key: %v", err)
	}
	keys = append(keys, tripleDesKey)

	// List all keys
	allKeys, err := token.ListSymmetricKeys()
	if err != nil {
		t.Errorf("ListSymmetricKeys should not fail: %v", err)
	}
	if len(allKeys) < len(keys) {
		t.Errorf("Expected at least %d keys, got %d", len(keys), len(allKeys))
	}

	// Verify our keys are in the list
	for _, originalKey := range keys {
		found := false
		for _, listedKey := range allKeys {
			if listedKey.Label == originalKey.Label {
				found = true
				if listedKey.KeySize != originalKey.KeySize {
					t.Errorf("Key size mismatch for %s: expected %d, got %d", originalKey.Label, originalKey.KeySize, listedKey.KeySize)
				}
				if listedKey.KeyType != originalKey.KeyType {
					t.Errorf("Key type mismatch for %s: expected %v, got %v", originalKey.Label, originalKey.KeyType, listedKey.KeyType)
				}
				break
			}
		}
		if !found {
			t.Errorf("Generated key %s not found in list", originalKey.Label)
		}
	}
}

// TestDeleteSymmetricKey tests symmetric key deletion
func TestDeleteSymmetricKey(t *testing.T, ctx *TestContext) {
	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	// Generate a key
	keySize := ctx.Config.SupportedAESKeySizes[0]
	key, err := token.GenerateAESKey(keySize)
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	// Verify key exists
	_, err = token.GetSymmetricKey(key.ID)
	if err != nil {
		t.Errorf("Key should exist before deletion: %v", err)
	}

	// Delete the key
	err = token.DeleteSymmetricKey(key.ID)
	if err != nil {
		t.Errorf("DeleteSymmetricKey should not fail: %v", err)
	}

	// Verify key is deleted
	_, err = token.GetSymmetricKey(key.ID)
	if err == nil {
		t.Error("Key should not exist after deletion")
	}

	// Test deleting non-existent key
	nonExistentID := make([]byte, 16)
	rand.Read(nonExistentID)

	err = token.DeleteSymmetricKey(nonExistentID)
	if err == nil {
		t.Error("DeleteSymmetricKey should fail with non-existent key ID")
	}
}

// TestSymmetricKeyWithCustomAttributes tests keys with custom attributes
func TestSymmetricKeyWithCustomAttributes(t *testing.T, ctx *TestContext) {
	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	// Test with custom label
	customLabel := "custom-test-key"
	labelAttr := pkcs11.NewLabelAttribute(customLabel)

	keySize := ctx.Config.SupportedAESKeySizes[0]
	key, err := token.GenerateAESKey(keySize, labelAttr)
	if err != nil {
		t.Fatalf("Failed to generate AES key with custom attributes: %v", err)
	}

	if key.Label != customLabel {
		t.Errorf("Expected custom label %s, got %s", customLabel, key.Label)
	}

	// Test with custom ID
	customID := []byte("custom-id-12345")
	idAttr := pkcs11.NewIDAttribute(customID)

	key2, err := token.GenerateAESKey(128, idAttr)
	if err != nil {
		t.Fatalf("Failed to generate AES key with custom ID: %v", err)
	}

	if string(key2.ID) != string(customID) {
		t.Errorf("Expected custom ID %s, got %s", customID, key2.ID)
	}
}

// TestSymmetricKeyConcurrentOperations tests concurrent symmetric key operations
func TestSymmetricKeyConcurrentOperations(t *testing.T, ctx *TestContext) {
	if ctx.Config.SkipConcurrencyTests {
		t.Skip("Concurrency tests disabled in configuration")
	}

	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	// Test concurrent key generation
	numGoroutines := ctx.Config.MaxConcurrentOps
	if numGoroutines <= 0 {
		numGoroutines = 10
	}

	var wg sync.WaitGroup
	keys := make([]*pkcs11.SymmetricKey, numGoroutines)
	errors := make([]error, numGoroutines)

	keySize := ctx.Config.SupportedAESKeySizes[0]
	for i := range numGoroutines {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			key, err := token.GenerateAESKey(keySize)
			keys[index] = key
			errors[index] = err
		}(i)
	}

	wg.Wait()

	// Check results
	for i := range numGoroutines {
		if errors[i] != nil {
			t.Errorf("Concurrent key generation %d failed: %v", i, errors[i])
		}
		if keys[i] == nil {
			t.Errorf("Concurrent key generation %d returned nil key", i)
		}
	}

	// Verify all keys are unique
	labels := make(map[string]bool)
	for _, key := range keys {
		if key != nil {
			if labels[key.Label] {
				t.Errorf("Duplicate key label found: %s", key.Label)
			}
			labels[key.Label] = true
		}
	}
}

// TestSymmetricKeyErrorCases tests error handling scenarios
func TestSymmetricKeyErrorCases(t *testing.T, ctx *TestContext) {
	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	t.Run("InvalidAESKeySize", func(t *testing.T) {
		_, err := token.GenerateAESKey(200) // Invalid size
		if err == nil {
			t.Error("GenerateAESKey should fail with invalid key size")
		}
		if !strings.Contains(err.Error(), "must be 128, 192, or 256") {
			t.Errorf("Error should mention valid key sizes, got: %v", err)
		}
	})

	t.Run("NilKeyMaterial", func(t *testing.T) {
		_, err := token.ImportAESKey(nil)
		if err == nil {
			t.Error("ImportAESKey should fail with nil key material")
		}
	})

	t.Run("EmptyKeyMaterial", func(t *testing.T) {
		_, err := token.ImportAESKey([]byte{})
		if err == nil {
			t.Error("ImportAESKey should fail with empty key material")
		}
	})

	t.Run("NilKeyID", func(t *testing.T) {
		_, err := token.GetSymmetricKey(nil)
		if err == nil {
			t.Error("GetSymmetricKey should fail with nil key ID")
		}
	})

	t.Run("EmptyKeyID", func(t *testing.T) {
		_, err := token.GetSymmetricKey([]byte{})
		if err == nil {
			t.Error("GetSymmetricKey should fail with empty key ID")
		}
	})
}

// TestSymmetricKeyString tests string representation of symmetric keys
func TestSymmetricKeyString(t *testing.T, ctx *TestContext) {
	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	// Test AES key string representation
	keySize := ctx.Config.SupportedAESKeySizes[0]
	aesKey, err := token.GenerateAESKey(keySize)
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	str := aesKey.String()
	if !strings.Contains(str, "SymmetricKey{") {
		t.Error("String should contain 'SymmetricKey{'")
	}
	if !strings.Contains(str, "Label:") {
		t.Error("String should contain 'Label:'")
	}
	if !strings.Contains(str, "Type:") {
		t.Error("String should contain 'Type:'")
	}
	if !strings.Contains(str, "Size:") {
		t.Error("String should contain 'Size:'")
	}

	// Test DES key string representation
	desKey, err := token.GenerateDESKey()
	if err != nil {
		t.Fatalf("Failed to generate DES key: %v", err)
	}

	str = desKey.String()
	if !strings.Contains(str, "Size: 64") {
		t.Error("String should contain 'Size: 64'")
	}

	// Test 3DES key string representation
	tripleDesKey, err := token.Generate3DESKey()
	if err != nil {
		t.Fatalf("Failed to generate 3DES key: %v", err)
	}

	str = tripleDesKey.String()
	if !strings.Contains(str, "Size: 192") {
		t.Error("String should contain 'Size: 192'")
	}
}

// TestSymmetricKeyLifecycle tests complete symmetric key lifecycle
func TestSymmetricKeyLifecycle(t *testing.T, ctx *TestContext) {
	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	// Test complete lifecycle: generate -> retrieve -> list -> delete
	keySize := ctx.Config.SupportedAESKeySizes[0]
	key, err := token.GenerateAESKey(keySize)
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	// Retrieve
	retrievedKey, err := token.GetSymmetricKey(key.ID)
	if err != nil {
		t.Errorf("Failed to retrieve key: %v", err)
	}
	if retrievedKey.Label != key.Label {
		t.Error("Retrieved key should match original")
	}

	// List
	keys, err := token.ListSymmetricKeys()
	if err != nil {
		t.Errorf("Failed to list keys: %v", err)
	}

	found := false
	for _, listedKey := range keys {
		if listedKey.Label == key.Label {
			found = true
			break
		}
	}
	if !found {
		t.Error("Key should be found in list")
	}

	// Delete
	err = token.DeleteSymmetricKey(key.ID)
	if err != nil {
		t.Errorf("Failed to delete key: %v", err)
	}

	// Verify deletion
	_, err = token.GetSymmetricKey(key.ID)
	if err == nil {
		t.Error("Key should not exist after deletion")
	}
}

// TestSymmetricKeyAttributeValidation tests symmetric key attribute validation
func TestSymmetricKeyAttributeValidation(t *testing.T, ctx *TestContext) {
	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	// Test that generated keys have proper attributes
	keySize := ctx.Config.SupportedAESKeySizes[0]
	key, err := token.GenerateAESKey(keySize)
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	// Verify key has all required fields
	if key.Handle == 0 {
		t.Error("Key should have valid handle")
	}
	if key.Label == "" {
		t.Error("Key should have non-empty label")
	}
	if len(key.ID) == 0 {
		t.Error("Key should have non-empty ID")
	}
	if key.KeyType != pkcs11.SymmetricKeyTypeAES {
		t.Error("Key should have correct type")
	}
	if key.KeySize != keySize {
		t.Error("Key should have correct size")
	}
}

// TestSymmetricKeyImportExportWorkflow tests import/export workflow
func TestSymmetricKeyImportExportWorkflow(t *testing.T, ctx *TestContext) {
	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	// Generate key material
	keyMaterial := make([]byte, 32) // 256 bits
	_, err := rand.Read(keyMaterial)
	if err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}

	// Import the key
	importedKey, err := token.ImportAESKey(keyMaterial)
	if err != nil {
		t.Fatalf("Failed to import AES key: %v", err)
	}

	// Verify imported key properties
	if importedKey.KeySize != 256 {
		t.Errorf("Expected key size 256, got %d", importedKey.KeySize)
	}
	if importedKey.KeyType != pkcs11.SymmetricKeyTypeAES {
		t.Errorf("Expected AES key type, got %v", importedKey.KeyType)
	}

	// Use the imported key (by retrieving it)
	retrievedKey, err := token.GetSymmetricKey(importedKey.ID)
	if err != nil {
		t.Errorf("Failed to retrieve imported key: %v", err)
	}

	// Verify retrieved key matches imported key
	if retrievedKey.KeySize != importedKey.KeySize {
		t.Error("Retrieved key size should match imported key")
	}
	if retrievedKey.KeyType != importedKey.KeyType {
		t.Error("Retrieved key type should match imported key")
	}
	if retrievedKey.Label != importedKey.Label {
		t.Error("Retrieved key label should match imported key")
	}

	// Clean up
	err = token.DeleteSymmetricKey(importedKey.ID)
	if err != nil {
		t.Errorf("Failed to delete imported key: %v", err)
	}
}

// TestSymmetricKeyFilteredListing tests filtered listing of symmetric keys
func TestSymmetricKeyFilteredListing(t *testing.T, ctx *TestContext) {
	token, cleanup := ctx.CreateTestToken(t)
	defer cleanup()

	// Generate keys with specific labels
	label1 := "test-key-1"
	label2 := "test-key-2"

	keySize := ctx.Config.SupportedAESKeySizes[0]
	key1, err := token.GenerateAESKey(keySize, pkcs11.NewLabelAttribute(label1))
	if err != nil {
		t.Fatalf("Failed to generate first key: %v", err)
	}

	key2, err := token.GenerateAESKey(128, pkcs11.NewLabelAttribute(label2))
	if err != nil {
		t.Fatalf("Failed to generate second key: %v", err)
	}

	// List all keys
	allKeys, err := token.ListSymmetricKeys()
	if err != nil {
		t.Errorf("Failed to list all keys: %v", err)
	}

	// Verify both keys are in the list
	found1, found2 := false, false
	for _, key := range allKeys {
		if key.Label == label1 {
			found1 = true
		}
		if key.Label == label2 {
			found2 = true
		}
	}

	if !found1 {
		t.Error("First key should be found in listing")
	}
	if !found2 {
		t.Error("Second key should be found in listing")
	}

	// Clean up
	token.DeleteSymmetricKey(key1.ID)
	token.DeleteSymmetricKey(key2.ID)
}

// Helper function to check if a slice contains a value
func contains(slice []int, value int) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}
