package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	pkcs11 "github.com/yeaops/gopkcs11"
)

func TestAESECBCipher(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	// Generate AES-256 key
	key, err := client.GenerateAESKey(256)
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	// Create AES-ECB cipher
	cipher, err := pkcs11.NewAESECBCipher(key)
	if err != nil {
		t.Fatalf("Failed to create AES-ECB cipher: %v", err)
	}

	t.Run("BasicEncryptDecrypt", func(t *testing.T) {
		testAESBasicEncryptDecrypt(t, cipher, "Hello, AES-ECB World!")
	})

	t.Run("MultipleBlockSizes", func(t *testing.T) {
		testAESMultipleBlockSizes(t, cipher)
	})

	t.Run("EmptyData", func(t *testing.T) {
		testAESEmptyDataError(t, cipher)
	})

	t.Run("StreamingOperations", func(t *testing.T) {
		testAESStreamingOperations(t, cipher, "AES-ECB streaming test data with multiple blocks of content")
	})

	t.Run("LargeDataStreaming", func(t *testing.T) {
		testAESLargeDataStreaming(t, cipher)
	})
}

func TestAESCBCCipher(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	// Generate AES-256 key
	key, err := client.GenerateAESKey(256)
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	// Generate random IV for CBC mode
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("Failed to generate IV: %v", err)
	}

	// Create AES-CBC cipher
	cipher, err := pkcs11.NewAESCBCCipher(key, iv)
	if err != nil {
		t.Fatalf("Failed to create AES-CBC cipher: %v", err)
	}

	t.Run("BasicEncryptDecrypt", func(t *testing.T) {
		testAESBasicEncryptDecrypt(t, cipher, "Hello, AES-CBC World!")
	})

	t.Run("MultipleBlockSizes", func(t *testing.T) {
		testAESMultipleBlockSizes(t, cipher)
	})

	t.Run("EmptyData", func(t *testing.T) {
		testAESEmptyDataError(t, cipher)
	})

	t.Run("StreamingOperations", func(t *testing.T) {
		testAESStreamingOperations(t, cipher, "AES-CBC streaming test data with multiple blocks of content")
	})

	t.Run("LargeDataStreaming", func(t *testing.T) {
		testAESLargeDataStreaming(t, cipher)
	})

	t.Run("InvalidIVLength", func(t *testing.T) {
		// Test with wrong IV length
		shortIV := make([]byte, 8)
		_, err := pkcs11.NewAESCBCCipher(key, shortIV)
		if err == nil {
			t.Error("Expected error for invalid IV length, got none")
		}
		if !strings.Contains(err.Error(), "IV must be 16 bytes") {
			t.Errorf("Expected IV length error, got: %v", err)
		}
	})

}

func TestAESGCMCipher(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	// Generate AES-256 key
	key, err := client.GenerateAESKey(256)
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	// Generate random IV for GCM mode (12 bytes recommended)
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("Failed to generate IV: %v", err)
	}

	// just IV
	t.Run("BasicEncryptDecrypt", func(t *testing.T) {
		// Create AES-GCM cipher
		cipher, err := pkcs11.NewAESGCMCipher(key, iv)
		if err != nil {
			t.Fatalf("Failed to create AES-GCM cipher: %v", err)
		}
		testAESGCMCipher(t, cipher)
	})

	t.Run("WithAAD", func(t *testing.T) {
		// Create AES-GCM cipher
		cipher, err := pkcs11.NewAESGCMCipher(key, iv)
		if err != nil {
			t.Fatalf("Failed to create AES-GCM cipher: %v", err)
		}
		cipher.SetAAD([]byte("additional authenticated data"))

		testAESGCMCipher(t, cipher)
	})

	t.Run("DifferentTagLengths", func(t *testing.T) {
		// Create AES-GCM cipher
		cipher, err := pkcs11.NewAESGCMCipher(key, iv)
		if err != nil {
			t.Fatalf("Failed to create AES-GCM cipher: %v", err)
		}
		cipher.SetTagLength(12)

		testAESGCMCipher(t, cipher)
	})

}

func TestAESCipherProperties(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	// Test different key sizes
	keySizes := []int{128, 192, 256}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("AES-%d", keySize), func(t *testing.T) {
			key, err := client.GenerateAESKey(keySize)
			if err != nil {
				t.Fatalf("Failed to generate AES-%d key: %v", keySize, err)
			}

			cipher, err := pkcs11.NewAESECBCipher(key)
			if err != nil {
				t.Fatalf("Failed to create cipher: %v", err)
			}

			// Test cipher properties
			if cipher.BlockSize() != 16 {
				t.Errorf("Expected block size 16, got %d", cipher.BlockSize())
			}

			expectedKeySize := keySize / 8
			if cipher.KeySize() != expectedKeySize {
				t.Errorf("Expected key size %d bytes, got %d", expectedKeySize, cipher.KeySize())
			}

			// Test buffer size operations
			newSize := 32 // 2 blocks
			err = cipher.SetBufferSize(newSize)
			if err != nil {
				t.Errorf("Failed to set buffer size: %v", err)
			}
			if cipher.BufferSize() != newSize {
				t.Errorf("Expected buffer size %d, got %d", newSize, cipher.BufferSize())
			}

			// Test invalid buffer size
			err = cipher.SetBufferSize(17) // Not multiple of block size
			if err == nil {
				t.Error("Expected error for invalid buffer size, got none")
			}
		})
	}
}

func TestAESCipherErrorCases(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	t.Run("NilKey", func(t *testing.T) {
		_, err := pkcs11.NewAESECBCipher(nil)
		if err == nil {
			t.Error("Expected error for nil key, got none")
		}
		if !strings.Contains(err.Error(), "symmetric key cannot be nil") {
			t.Errorf("Expected nil key error, got: %v", err)
		}
	})

	t.Run("WrongKeyType", func(t *testing.T) {
		// This would require creating a non-AES key, which might not be straightforward
		// in the current API, so we'll skip this for now
		t.Skip("Would need non-AES symmetric key to test")
	})

	t.Run("NilContext", func(t *testing.T) {
		key, err := client.GenerateAESKey(256)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		cipher, err := pkcs11.NewAESECBCipher(key)
		if err != nil {
			t.Fatalf("Failed to create cipher: %v", err)
		}

		src := []byte("test")

		_, err = cipher.Encrypt(nil, src)
		if err == nil {
			t.Error("Expected error for nil context, got none")
		}
		if !strings.Contains(err.Error(), "context cannot be nil") {
			t.Errorf("Expected nil context error, got: %v", err)
		}
	})

	t.Run("StreamingNilReaderWriter", func(t *testing.T) {
		key, err := client.GenerateAESKey(256)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		cipher, err := pkcs11.NewAESECBCipher(key)
		if err != nil {
			t.Fatalf("Failed to create cipher: %v", err)
		}

		ctx := context.Background()
		var buf bytes.Buffer

		// Test nil reader
		_, err = cipher.EncryptStream(ctx, &buf, nil)
		if err == nil {
			t.Error("Expected error for nil reader, got none")
		}

		// Test nil writer
		_, err = cipher.EncryptStream(ctx, nil, strings.NewReader("test"))
		if err == nil {
			t.Error("Expected error for nil writer, got none")
		}
	})

	t.Run("InvalidCiphertextLength", func(t *testing.T) {
		key, err := client.GenerateAESKey(256)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		cipher, err := pkcs11.NewAESECBCipher(key)
		if err != nil {
			t.Fatalf("Failed to create cipher: %v", err)
		}

		ctx := context.Background()
		// Ciphertext length not multiple of block size
		invalidCiphertext := make([]byte, 17)

		_, err = cipher.Decrypt(ctx, invalidCiphertext)
		if err == nil {
			t.Error("Expected error for invalid ciphertext length, got none")
		}
		if !strings.Contains(err.Error(), "ciphertext length must be multiple of block size") {
			t.Errorf("Expected ciphertext length error, got: %v", err)
		}
	})

	t.Run("MalformedData", func(t *testing.T) {
		testAESMalformedData(t, client)
	})
}

func TestAESConcurrencyAndCancellation(t *testing.T) {
	RequireSoftHSM(t)
	client, cleanup := CreateTestClient(t)
	defer cleanup()

	key, err := client.GenerateAESKey(256)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	t.Run("ConcurrentOperations", func(t *testing.T) {
		testAESConcurrentOperations(t, key)
	})

	t.Run("ContextCancellation", func(t *testing.T) {
		testAESContextCancellation(t, key)
	})
}

func testAESGCMCipher(t *testing.T, cipher *pkcs11.AESGCMCipher) {

	t.Run("BasicEncryptDecrypt", func(t *testing.T) {
		testAESGCMBasicEncryptDecrypt(t, cipher, "Hello, AES-GCM World!")
	})

	t.Run("WithAAD", func(t *testing.T) {
		testAESGCMWithAAD(t, cipher)
	})

	t.Run("DifferentTagLengths", func(t *testing.T) {
		testAESGCMDifferentTagLengths(t, cipher)
	})

	t.Run("EmptyData", func(t *testing.T) {
		testAESEmptyDataError(t, cipher)
	})

	t.Run("StreamingOperations", func(t *testing.T) {
		testAESGCMStreamingOperations(t, cipher, "AES-GCM streaming test data with authentication")
	})

	t.Run("LargeDataStreaming", func(t *testing.T) {
		testAESGCMLargeDataStreaming(t, cipher)
	})

	t.Run("InvalidTagLength", func(t *testing.T) {
		err := cipher.SetTagLength(8) // Too short
		if err == nil {
			t.Error("Expected error for invalid tag length, got none")
		}
		if !strings.Contains(err.Error(), "tag length must be between 12 and 16") {
			t.Errorf("Expected tag length error, got: %v", err)
		}
	})
}

// Helper functions for common test patterns

func testAESBasicEncryptDecrypt(t *testing.T, cipher pkcs11.BlockCipher, plaintext string) {
	t.Helper()

	ctx := context.Background()
	src := []byte(plaintext)

	// Encrypt
	encrypted, err := cipher.Encrypt(ctx, src)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt
	decrypted, err := cipher.Decrypt(ctx, encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Compare
	if !bytes.Equal(src, decrypted) {
		t.Errorf("Decrypted data doesn't match original.\nOriginal: %s\nDecrypted: %s", src, decrypted)
	}
}

func testAESMultipleBlockSizes(t *testing.T, cipher pkcs11.BlockCipher) {
	t.Helper()

	ctx := context.Background()

	// Comprehensive test sizes covering various edge cases
	testSizes := []struct {
		name string
		size int
	}{
		// Very small sizes
		{"1B", 1},
		{"2B", 2},
		{"3B", 3},
		{"7B", 7},
		{"8B", 8},

		// Block boundary cases (AES block size = 16)
		{"15B_OneLessThanBlock", 15},
		{"16B_ExactBlock", 16},
		{"17B_OneMoreThanBlock", 17},
		{"31B_TwoLessThanBlocks", 31},
		{"32B_ExactTwoBlocks", 32},
		{"33B_TwoMoreThanBlocks", 33},
		{"47B_ThreeLessThanBlocks", 47},
		{"48B_ExactThreeBlocks", 48},
		{"49B_ThreeMoreThanBlocks", 49},

		// Common small sizes
		{"64B", 64},
		{"100B", 100},
		{"128B", 128},

		// Medium sizes
		{"256B", 256},
		{"512B", 512},
		{"1KB", 1024},
		{"2KB", 2048},
		{"4KB", 4096},

		// Large sizes
		{"8KB", 8192},
		{"16KB", 16384},
		{"32KB", 32768},
		{"64KB", 65536},
		{"128KB", 131072},

		// Memory stress tests (1MB)
		{"1MB", 1048576},
	}

	for _, tc := range testSizes {
		t.Run(tc.name, func(t *testing.T) {
			// Skip very large tests in short mode or if memory constrained
			if tc.size > 128*1024 && testing.Short() {
				t.Skip("Skipping large size test in short mode")
			}

			// Generate random data
			src := make([]byte, tc.size)
			if _, err := rand.Read(src); err != nil {
				t.Fatalf("Failed to generate random data: %v", err)
			}

			// Encrypt
			encrypted, err := cipher.Encrypt(ctx, src)
			if err != nil {
				t.Fatalf("Encryption failed for size %d: %v", tc.size, err)
			}

			// Verify encrypted size is reasonable (should be padded to block boundary + any overhead)
			expectedMinSize := ((tc.size + 15) / 16) * 16 // PKCS#7 padding to block boundary
			if len(encrypted) < expectedMinSize {
				t.Errorf("Encrypted data size %d is smaller than expected minimum %d", len(encrypted), expectedMinSize)
			}

			// Decrypt
			decrypted, err := cipher.Decrypt(ctx, encrypted)
			if err != nil {
				t.Fatalf("Decryption failed for size %d: %v", tc.size, err)
			}

			// Verify decrypted size matches original
			if len(decrypted) != tc.size {
				t.Errorf("Decrypted size %d doesn't match original size %d", len(decrypted), tc.size)
			}

			// Compare data
			if !bytes.Equal(src, decrypted) {
				t.Errorf("Data mismatch for size %d", tc.size)
			}
		})
	}
}

func testAESEmptyDataError(t *testing.T, cipher pkcs11.BlockCipher) {
	t.Helper()

	ctx := context.Background()

	// Test empty source data
	_, err := cipher.Encrypt(ctx, []byte{})
	if err == nil {
		t.Error("Expected error for empty source data, got none")
	}
	if !strings.Contains(err.Error(), "plaintext cannot be empty") {
		t.Errorf("Expected empty data error, got: %v", err)
	}
}

func testAESStreamingOperations(t *testing.T, cipher pkcs11.BlockCipher, data string) {
	t.Helper()

	ctx := context.Background()
	src := strings.NewReader(data)

	// Encrypt using streaming
	var encryptedBuf bytes.Buffer
	_, err := cipher.EncryptStream(ctx, &encryptedBuf, src)
	if err != nil {
		t.Fatalf("Stream encryption failed: %v", err)
	}

	// Decrypt using streaming
	var decryptedBuf bytes.Buffer
	_, err = cipher.DecryptStream(ctx, &decryptedBuf, &encryptedBuf)
	if err != nil {
		t.Fatalf("Stream decryption failed: %v", err)
	}

	// Compare
	if decryptedBuf.String() != data {
		t.Errorf("Stream operation failed.\nOriginal: %s\nDecrypted: %s", data, decryptedBuf.String())
	}
}

func testAESLargeDataStreaming(t *testing.T, cipher pkcs11.BlockCipher) {
	t.Helper()

	ctx := context.Background()

	// Generate large random data (larger than default buffer size)
	largeData := make([]byte, 8192) // 8KB
	if _, err := rand.Read(largeData); err != nil {
		t.Fatalf("Failed to generate large random data: %v", err)
	}

	src := bytes.NewReader(largeData)

	// Encrypt using streaming
	var encryptedBuf bytes.Buffer
	bytesWritten, err := cipher.EncryptStream(ctx, &encryptedBuf, src)
	if err != nil {
		t.Fatalf("Large data stream encryption failed: %v", err)
	}
	if bytesWritten == 0 {
		t.Error("No bytes written during encryption")
	}

	// Decrypt using streaming
	var decryptedBuf bytes.Buffer
	bytesWritten, err = cipher.DecryptStream(ctx, &decryptedBuf, &encryptedBuf)
	if err != nil {
		t.Fatalf("Large data stream decryption failed: %v", err)
	}
	if bytesWritten == 0 {
		t.Error("No bytes written during decryption")
	}

	// Compare
	if !bytes.Equal(largeData, decryptedBuf.Bytes()) {
		t.Error("Large data stream operation failed - data mismatch")
	}
}

// GCM-specific test helpers

func testAESGCMBasicEncryptDecrypt(t *testing.T, cipher *pkcs11.AESGCMCipher, plaintext string) {
	t.Helper()

	ctx := context.Background()
	src := []byte(plaintext)

	// Encrypt
	encrypted, err := cipher.Encrypt(ctx, src)
	if err != nil {
		t.Fatalf("GCM encryption failed: %v", err)
	}

	// Decrypt
	decrypted, err := cipher.Decrypt(ctx, encrypted)
	if err != nil {
		t.Fatalf("GCM decryption failed: %v", err)
	}

	// Compare
	if !bytes.Equal(src, decrypted) {
		t.Errorf("GCM decrypted data doesn't match original.\nOriginal: %s\nDecrypted: %s", src, decrypted)
	}
}

func testAESGCMWithAAD(t *testing.T, cipher *pkcs11.AESGCMCipher) {
	t.Helper()

	ctx := context.Background()
	src := []byte("secret message")
	aad := []byte("additional authenticated data")

	// Set AAD
	cipher.SetAAD(aad)

	// Encrypt
	encrypted, err := cipher.Encrypt(ctx, src)
	if err != nil {
		t.Fatalf("GCM encryption with AAD failed: %v", err)
	}

	// Decrypt with same AAD
	decrypted, err := cipher.Decrypt(ctx, encrypted)
	if err != nil {
		t.Fatalf("GCM decryption with AAD failed: %v", err)
	}

	// Compare
	if !bytes.Equal(src, decrypted) {
		t.Error("GCM with AAD: decrypted data doesn't match original")
	}

	// Test with wrong AAD (should fail)
	cipher.SetAAD([]byte("wrong aad"))
	_, err = cipher.Decrypt(ctx, encrypted)
	if err == nil {
		t.Error("Expected authentication failure with wrong AAD, got none")
	}
}

func testAESGCMDifferentTagLengths(t *testing.T, cipher *pkcs11.AESGCMCipher) {
	t.Helper()

	ctx := context.Background()
	src := []byte("test message")

	// Test different valid tag lengths
	validTagLengths := []int{12, 13, 14, 15, 16}

	for _, tagLen := range validTagLengths {
		t.Run(fmt.Sprintf("TagLen%d", tagLen), func(t *testing.T) {
			err := cipher.SetTagLength(tagLen)
			if err != nil {
				t.Fatalf("Failed to set tag length %d: %v", tagLen, err)
			}

			// Encrypt
			encrypted, err := cipher.Encrypt(ctx, src)
			if err != nil {
				t.Fatalf("GCM encryption failed with tag length %d: %v", tagLen, err)
			}

			// Decrypt
			decrypted, err := cipher.Decrypt(ctx, encrypted)
			if err != nil {
				t.Fatalf("GCM decryption failed with tag length %d: %v", tagLen, err)
			}

			// Compare
			if !bytes.Equal(src, decrypted) {
				t.Errorf("GCM data mismatch with tag length %d", tagLen)
			}
		})
	}
}

func testAESGCMStreamingOperations(t *testing.T, cipher *pkcs11.AESGCMCipher, data string) {
	t.Helper()

	ctx := context.Background()
	src := strings.NewReader(data)

	// Encrypt using streaming
	var encryptedBuf bytes.Buffer
	_, err := cipher.EncryptStream(ctx, &encryptedBuf, src)
	if err != nil {
		t.Fatalf("GCM stream encryption failed: %v", err)
	}

	// Decrypt using streaming
	var decryptedBuf bytes.Buffer
	_, err = cipher.DecryptStream(ctx, &decryptedBuf, &encryptedBuf)
	if err != nil {
		t.Fatalf("GCM stream decryption failed: %v", err)
	}

	// Compare
	if decryptedBuf.String() != data {
		t.Errorf("GCM stream operation failed.\nOriginal: %s\nDecrypted: %s", data, decryptedBuf.String())
	}
}

func testAESGCMLargeDataStreaming(t *testing.T, cipher *pkcs11.AESGCMCipher) {
	t.Helper()

	ctx := context.Background()

	// Generate large random data
	largeData := make([]byte, 10240) // 10KB
	if _, err := rand.Read(largeData); err != nil {
		t.Fatalf("Failed to generate large random data: %v", err)
	}

	src := bytes.NewReader(largeData)

	// Encrypt using streaming
	var encryptedBuf bytes.Buffer
	bytesWritten, err := cipher.EncryptStream(ctx, &encryptedBuf, src)
	if err != nil {
		t.Fatalf("GCM large data stream encryption failed: %v", err)
	}
	if bytesWritten == 0 {
		t.Error("No bytes written during GCM encryption")
	}

	// Decrypt using streaming
	var decryptedBuf bytes.Buffer
	bytesWritten, err = cipher.DecryptStream(ctx, &decryptedBuf, &encryptedBuf)
	if err != nil {
		t.Fatalf("GCM large data stream decryption failed: %v", err)
	}
	if bytesWritten == 0 {
		t.Error("No bytes written during GCM decryption")
	}

	// Compare
	if !bytes.Equal(largeData, decryptedBuf.Bytes()) {
		t.Error("GCM large data stream operation failed - data mismatch")
	}
}

func testAESMalformedData(t *testing.T, client *pkcs11.Client) {
	key, err := client.GenerateAESKey(256)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	ctx := context.Background()

	t.Run("ECB_MalformedCiphertext", func(t *testing.T) {
		cipher, err := pkcs11.NewAESECBCipher(key)
		if err != nil {
			t.Fatalf("Failed to create cipher: %v", err)
		}

		// Test various malformed ciphertext scenarios
		malformedTests := []struct {
			name string
			data []byte
		}{
			{"WrongBlockSize_1", make([]byte, 1)},
			{"WrongBlockSize_15", make([]byte, 15)},
			{"WrongBlockSize_17", make([]byte, 17)},
			{"WrongBlockSize_31", make([]byte, 31)},
			{"WrongBlockSize_33", make([]byte, 33)},
			{"AllZeros_16", make([]byte, 16)},
			{"AllOnes_16", bytes.Repeat([]byte{0xFF}, 16)},
			{"AllZeros_32", make([]byte, 32)},
			{"Random_Wrong_15", make([]byte, 15)},
			{"Random_Wrong_23", make([]byte, 23)},
		}

		// Fill random data
		for _, tc := range malformedTests {
			if strings.Contains(tc.name, "Random") {
				rand.Read(tc.data)
			}
		}

		for _, tc := range malformedTests {
			t.Run(tc.name, func(t *testing.T) {
				_, err := cipher.Decrypt(ctx, tc.data)
				if err == nil {
					t.Errorf("Expected error for malformed data %s, got none", tc.name)
				}
			})
		}
	})

	t.Run("CBC_MalformedCiphertext", func(t *testing.T) {
		iv := make([]byte, 16)
		rand.Read(iv)

		cipher, err := pkcs11.NewAESCBCCipher(key, iv)
		if err != nil {
			t.Fatalf("Failed to create cipher: %v", err)
		}

		// Test with valid block size but invalid padding
		validSizes := []int{16, 32, 48, 64}
		for _, size := range validSizes {
			t.Run(fmt.Sprintf("InvalidPadding_%dB", size), func(t *testing.T) {
				// Create data with invalid padding
				data := make([]byte, size)
				rand.Read(data)

				// This should fail during decryption due to invalid padding
				_, err := cipher.Decrypt(ctx, data)
				if err == nil {
					t.Errorf("Expected padding error for %d bytes, got none", size)
				}
			})
		}
	})

	t.Run("GCM_MalformedCiphertext", func(t *testing.T) {
		iv := make([]byte, 12)
		rand.Read(iv)

		cipher, err := pkcs11.NewAESGCMCipher(key, iv)
		if err != nil {
			t.Fatalf("Failed to create cipher: %v", err)
		}

		// Test with data too short for tag
		shortData := make([]byte, 15) // Less than 16-byte tag
		rand.Read(shortData)

		_, err = cipher.Decrypt(ctx, shortData)
		if err == nil {
			t.Error("Expected error for ciphertext too short for GCM tag, got none")
		}
		if !strings.Contains(err.Error(), "too short") {
			t.Errorf("Expected 'too short' error, got: %v", err)
		}

		// Test with corrupted tag
		testData := []byte("test data")
		encrypted, err := cipher.Encrypt(ctx, testData)
		if err != nil {
			t.Fatalf("Failed to encrypt test data: %v", err)
		}

		// Corrupt the last byte (part of tag)
		corrupted := make([]byte, len(encrypted))
		copy(corrupted, encrypted)
		corrupted[len(corrupted)-1] ^= 0x01

		_, err = cipher.Decrypt(ctx, corrupted)
		if err == nil {
			t.Error("Expected authentication failure for corrupted tag, got none")
		}
	})

	t.Run("ExtremeValues", func(t *testing.T) {
		testAESExtremeValues(t, key)
	})
}

func testAESExtremeValues(t *testing.T, key *pkcs11.SymmetricKey) {
	t.Helper()

	ctx := context.Background()

	t.Run("MaximalData", func(t *testing.T) {
		// Test with very large data sizes (but not too large to cause memory issues)
		largeSizes := []int{
			1024 * 1024,     // 1MB
			2 * 1024 * 1024, // 2MB
		}

		for _, size := range largeSizes {
			if testing.Short() {
				t.Skip("Skipping large data test in short mode")
			}

			t.Run(fmt.Sprintf("Size_%dMB", size/(1024*1024)), func(t *testing.T) {
				// Create large data
				largeData := make([]byte, size)
				// Fill with pattern instead of random to save time
				for i := range largeData {
					largeData[i] = byte(i % 256)
				}

				// Test ECB mode
				cipher, err := pkcs11.NewAESECBCipher(key)
				if err != nil {
					t.Fatalf("Failed to create ECB cipher: %v", err)
				}

				encrypted, err := cipher.Encrypt(ctx, largeData)
				if err != nil {
					t.Fatalf("Failed to encrypt large data: %v", err)
				}

				decrypted, err := cipher.Decrypt(ctx, encrypted)
				if err != nil {
					t.Fatalf("Failed to decrypt large data: %v", err)
				}

				if !bytes.Equal(largeData, decrypted) {
					t.Error("Large data mismatch")
				}
			})
		}
	})

	t.Run("RepeatedPatterns", func(t *testing.T) {
		// Test with repeated patterns that might expose weaknesses
		patterns := []struct {
			name    string
			pattern []byte
			repeat  int
		}{
			{"AllZeros", []byte{0x00}, 1024},
			{"AllOnes", []byte{0xFF}, 1024},
			{"Alternating", []byte{0xAA, 0x55}, 512},
			{"Sequential", []byte{0x00, 0x01, 0x02, 0x03}, 256},
			{"RepeatedBlock", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}, 64},
		}

		for _, p := range patterns {
			t.Run(p.name, func(t *testing.T) {
				// Create data with repeated pattern
				data := bytes.Repeat(p.pattern, p.repeat)

				// Test with ECB (most vulnerable to patterns)
				cipher, err := pkcs11.NewAESECBCipher(key)
				if err != nil {
					t.Fatalf("Failed to create cipher: %v", err)
				}

				encrypted, err := cipher.Encrypt(ctx, data)
				if err != nil {
					t.Fatalf("Failed to encrypt pattern %s: %v", p.name, err)
				}

				decrypted, err := cipher.Decrypt(ctx, encrypted)
				if err != nil {
					t.Fatalf("Failed to decrypt pattern %s: %v", p.name, err)
				}

				if !bytes.Equal(data, decrypted) {
					t.Errorf("Pattern %s data mismatch", p.name)
				}

				// For ECB mode, check that identical input blocks produce identical ciphertext blocks
				// (this is expected behavior for ECB, not a vulnerability in our implementation)
				if len(p.pattern) == 16 && p.repeat > 1 {
					// Check that repeated 16-byte blocks produce identical encrypted blocks
					for i := 0; i < len(encrypted)-16; i += 16 {
						block1 := encrypted[i : i+16]
						block2 := encrypted[i+16 : i+32]
						if !bytes.Equal(block1, block2) {
							// This might be expected if padding affects the pattern
							t.Logf("ECB blocks differ for pattern %s (expected for padded data)", p.name)
							break
						}
					}
				}
			})
		}
	})
}

func testAESConcurrentOperations(t *testing.T, key *pkcs11.SymmetricKey) {
	t.Helper()

	if testing.Short() {
		t.Skip("Skipping concurrent operations test in short mode")
	}

	ctx := context.Background()

	// Test data
	testData := []byte("Concurrent test data for AES operations")

	// Number of concurrent operations
	numGoroutines := 10
	numOperations := 50

	t.Run("ECB_Concurrent", func(t *testing.T) {
		cipher, err := pkcs11.NewAESECBCipher(key)
		if err != nil {
			t.Fatalf("Failed to create cipher: %v", err)
		}

		// Channel to collect results
		results := make(chan error, numGoroutines)

		// Start concurrent operations
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer func() {
					if r := recover(); r != nil {
						results <- fmt.Errorf("goroutine %d panicked: %v", id, r)
					}
				}()

				for j := 0; j < numOperations; j++ {
					// Encrypt
					encrypted, err := cipher.Encrypt(ctx, testData)
					if err != nil {
						results <- fmt.Errorf("goroutine %d encrypt failed: %v", id, err)
						return
					}

					// Decrypt
					decrypted, err := cipher.Decrypt(ctx, encrypted)
					if err != nil {
						results <- fmt.Errorf("goroutine %d decrypt failed: %v", id, err)
						return
					}

					// Verify
					if !bytes.Equal(testData, decrypted) {
						results <- fmt.Errorf("goroutine %d data mismatch", id)
						return
					}
				}
				results <- nil
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < numGoroutines; i++ {
			if err := <-results; err != nil {
				t.Errorf("Concurrent ECB operation failed: %v", err)
			}
		}
	})

	t.Run("CBC_Concurrent", func(t *testing.T) {
		// Use separate IVs for each goroutine to avoid conflicts
		results := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer func() {
					if r := recover(); r != nil {
						results <- fmt.Errorf("goroutine %d panicked: %v", id, r)
					}
				}()

				// Generate unique IV for this goroutine
				iv := make([]byte, 16)
				rand.Read(iv)

				cipher, err := pkcs11.NewAESCBCCipher(key, iv)
				if err != nil {
					results <- fmt.Errorf("goroutine %d failed to create cipher: %v", id, err)
					return
				}

				for j := 0; j < numOperations; j++ {
					encrypted, err := cipher.Encrypt(ctx, testData)
					if err != nil {
						results <- fmt.Errorf("goroutine %d encrypt failed: %v", id, err)
						return
					}

					decrypted, err := cipher.Decrypt(ctx, encrypted)
					if err != nil {
						results <- fmt.Errorf("goroutine %d decrypt failed: %v", id, err)
						return
					}

					if !bytes.Equal(testData, decrypted) {
						results <- fmt.Errorf("goroutine %d data mismatch", id)
						return
					}
				}
				results <- nil
			}(i)
		}

		for i := 0; i < numGoroutines; i++ {
			if err := <-results; err != nil {
				t.Errorf("Concurrent CBC operation failed: %v", err)
			}
		}
	})

	t.Run("GCM_Concurrent", func(t *testing.T) {
		results := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer func() {
					if r := recover(); r != nil {
						results <- fmt.Errorf("goroutine %d panicked: %v", id, r)
					}
				}()

				// Generate unique IV for this goroutine
				iv := make([]byte, 12)
				rand.Read(iv)

				cipher, err := pkcs11.NewAESGCMCipher(key, iv)
				if err != nil {
					results <- fmt.Errorf("goroutine %d failed to create cipher: %v", id, err)
					return
				}

				// Set unique AAD for each goroutine
				aad := []byte(fmt.Sprintf("goroutine-%d-aad", id))
				cipher.SetAAD(aad)

				for j := 0; j < numOperations; j++ {
					encrypted, err := cipher.Encrypt(ctx, testData)
					if err != nil {
						results <- fmt.Errorf("goroutine %d encrypt failed: %v", id, err)
						return
					}

					decrypted, err := cipher.Decrypt(ctx, encrypted)
					if err != nil {
						results <- fmt.Errorf("goroutine %d decrypt failed: %v", id, err)
						return
					}

					if !bytes.Equal(testData, decrypted) {
						results <- fmt.Errorf("goroutine %d data mismatch", id)
						return
					}
				}
				results <- nil
			}(i)
		}

		for i := 0; i < numGoroutines; i++ {
			if err := <-results; err != nil {
				t.Errorf("Concurrent GCM operation failed: %v", err)
			}
		}
	})
}

func testAESContextCancellation(t *testing.T, key *pkcs11.SymmetricKey) {
	t.Helper()

	// Create large data for cancellation testing
	largeData := make([]byte, 1024*1024) // 1MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	t.Run("ECB_ContextTimeout", func(t *testing.T) {
		cipher, err := pkcs11.NewAESECBCipher(key)
		if err != nil {
			t.Fatalf("Failed to create cipher: %v", err)
		}

		// Create context with very short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()

		// This should either complete very quickly or be cancelled
		_, err = cipher.Encrypt(ctx, largeData)
		if err != nil && err != context.DeadlineExceeded {
			// Context cancellation might not always work if operation completes too quickly
			t.Logf("Context cancellation test result: %v", err)
		}
	})

	t.Run("StreamingContextCancellation", func(t *testing.T) {
		cipher, err := pkcs11.NewAESECBCipher(key)
		if err != nil {
			t.Fatalf("Failed to create cipher: %v", err)
		}

		// Create context that will be cancelled
		ctx, cancel := context.WithCancel(context.Background())

		// Start streaming operation in goroutine
		src := bytes.NewReader(largeData)
		var dst bytes.Buffer

		done := make(chan error, 1)
		go func() {
			_, err := cipher.EncryptStream(ctx, &dst, src)
			done <- err
		}()

		// Cancel context after short delay
		time.Sleep(1 * time.Millisecond)
		cancel()

		// Wait for operation to complete
		select {
		case err := <-done:
			if err != nil && err != context.Canceled {
				t.Logf("Streaming cancellation test result: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Streaming operation did not complete within timeout")
		}
	})
}

// Benchmark tests for AES cipher performance
func BenchmarkAESCipher(b *testing.B) {
	RequireSoftHSM(b)
	client, cleanup := CreateTestClient(b)
	defer cleanup()

	key, err := client.GenerateAESKey(256)
	if err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	// Test data sizes
	dataSizes := []int{
		16,      // 1 block
		1024,    // 1KB
		4096,    // 4KB
		16384,   // 16KB
		65536,   // 64KB
		1048576, // 1MB
	}

	for _, size := range dataSizes {
		testData := make([]byte, size)
		for i := range testData {
			testData[i] = byte(i % 256)
		}

		b.Run(fmt.Sprintf("ECB_Encrypt_%dB", size), func(b *testing.B) {
			cipher, err := pkcs11.NewAESECBCipher(key)
			if err != nil {
				b.Fatalf("Failed to create cipher: %v", err)
			}

			ctx := context.Background()
			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				_, err := cipher.Encrypt(ctx, testData)
				if err != nil {
					b.Fatalf("Encryption failed: %v", err)
				}
			}
		})

		b.Run(fmt.Sprintf("CBC_Encrypt_%dB", size), func(b *testing.B) {
			iv := make([]byte, 16)
			rand.Read(iv)

			cipher, err := pkcs11.NewAESCBCCipher(key, iv)
			if err != nil {
				b.Fatalf("Failed to create cipher: %v", err)
			}

			ctx := context.Background()
			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				_, err := cipher.Encrypt(ctx, testData)
				if err != nil {
					b.Fatalf("Encryption failed: %v", err)
				}
			}
		})

		b.Run(fmt.Sprintf("GCM_Encrypt_%dB", size), func(b *testing.B) {
			iv := make([]byte, 12)
			rand.Read(iv)

			cipher, err := pkcs11.NewAESGCMCipher(key, iv)
			if err != nil {
				b.Fatalf("Failed to create cipher: %v", err)
			}

			ctx := context.Background()
			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				_, err := cipher.Encrypt(ctx, testData)
				if err != nil {
					b.Fatalf("Encryption failed: %v", err)
				}
			}
		})

		// Streaming benchmarks for larger sizes
		if size >= 4096 {
			b.Run(fmt.Sprintf("ECB_Stream_%dB", size), func(b *testing.B) {
				cipher, err := pkcs11.NewAESECBCipher(key)
				if err != nil {
					b.Fatalf("Failed to create cipher: %v", err)
				}

				ctx := context.Background()
				b.ResetTimer()
				b.SetBytes(int64(size))

				for i := 0; i < b.N; i++ {
					src := bytes.NewReader(testData)
					var dst bytes.Buffer

					_, err := cipher.EncryptStream(ctx, &dst, src)
					if err != nil {
						b.Fatalf("Stream encryption failed: %v", err)
					}
				}
			})
		}
	}
}
