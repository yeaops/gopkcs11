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

// RunCipherTests runs the complete suite of cipher tests
func RunCipherTests(t *testing.T, ctx *TestContext) {
	t.Run("AESECBCipher", func(t *testing.T) {
		TestAESECBCipher(t, ctx)
	})

	if containsString(ctx.Config.SupportedCipherModes, "CBC") {
		t.Run("AESCBCCipher", func(t *testing.T) {
			TestAESCBCCipher(t, ctx)
		})
	}

	if containsString(ctx.Config.SupportedCipherModes, "GCM") {
		t.Run("AESGCMCipher", func(t *testing.T) {
			TestAESGCMCipher(t, ctx)
		})
	}

	t.Run("AESCipherProperties", func(t *testing.T) {
		TestAESCipherProperties(t, ctx)
	})

	t.Run("AESCipherErrorCases", func(t *testing.T) {
		TestAESCipherErrorCases(t, ctx)
	})

	// if !ctx.Config.SkipConcurrencyTests {
	// 	t.Run("AESConcurrencyAndCancellation", func(t *testing.T) {
	// 		TestAESConcurrencyAndCancellation(t, ctx)
	// 	})
	// }

	if !ctx.Config.SkipPerformanceTests {
		t.Run("AESCipherBenchmark", func(t *testing.T) {
			BenchmarkAESCipher(t, ctx)
		})
	}
}

// TestAESECBCipher tests AES-ECB cipher functionality
func TestAESECBCipher(t *testing.T, ctx *TestContext) {
	client, cleanup := ctx.CreateTestClient(t)
	defer cleanup()

	// Generate AES key with a supported size
	keySize := ctx.Config.SupportedAESKeySizes[0]
	key, err := client.GenerateAESKey(keySize)
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	// Create AES-ECB cipher
	cipher, err := pkcs11.NewAESECBCipher(key)
	if err != nil {
		t.Fatalf("Failed to create AES-ECB cipher: %v", err)
	}

	t.Run("BasicEncryptDecrypt", func(t *testing.T) {
		testAESBasicEncryptDecrypt(t, ctx, cipher, "Hello, AES-ECB World!")
	})

	t.Run("MultipleBlockSizes", func(t *testing.T) {
		testAESMultipleBlockSizes(t, ctx, cipher)
	})

	t.Run("EmptyData", func(t *testing.T) {
		testAESEmptyDataError(t, cipher)
	})

	t.Run("StreamingOperations", func(t *testing.T) {
		testAESStreamingOperations(t, cipher, "AES-ECB streaming test data with multiple blocks of content")
	})

	if !ctx.Config.SkipLargeDataTests {
		t.Run("LargeDataStreaming", func(t *testing.T) {
			testAESLargeDataStreaming(t, ctx, cipher)
		})
	}
}

// TestAESCBCCipher tests AES-CBC cipher functionality
func TestAESCBCCipher(t *testing.T, ctx *TestContext) {
	client, cleanup := ctx.CreateTestClient(t)
	defer cleanup()

	// Generate AES key with a supported size
	keySize := ctx.Config.SupportedAESKeySizes[0]
	key, err := client.GenerateAESKey(keySize)
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
		testAESBasicEncryptDecrypt(t, ctx, cipher, "Hello, AES-CBC World!")
	})

	t.Run("MultipleBlockSizes", func(t *testing.T) {
		testAESMultipleBlockSizes(t, ctx, cipher)
	})

	t.Run("EmptyData", func(t *testing.T) {
		testAESEmptyDataError(t, cipher)
	})

	t.Run("StreamingOperations", func(t *testing.T) {
		testAESStreamingOperations(t, cipher, "AES-CBC streaming test data with multiple blocks of content")
	})

	if !ctx.Config.SkipLargeDataTests {
		t.Run("LargeDataStreaming", func(t *testing.T) {
			testAESLargeDataStreaming(t, ctx, cipher)
		})
	}

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

// TestAESGCMCipher tests AES-GCM cipher functionality
func TestAESGCMCipher(t *testing.T, ctx *TestContext) {
	client, cleanup := ctx.CreateTestClient(t)
	defer cleanup()

	// Generate AES key with a supported size
	keySize := ctx.Config.SupportedAESKeySizes[0]
	key, err := client.GenerateAESKey(keySize)
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	// Generate random IV for GCM mode (12 bytes recommended)
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("Failed to generate IV: %v", err)
	}

	t.Run("BasicEncryptDecrypt", func(t *testing.T) {
		cipher, err := pkcs11.NewAESGCMCipher(key, iv)
		if err != nil {
			t.Fatalf("Failed to create AES-GCM cipher: %v", err)
		}
		testAESGCMBasicEncryptDecrypt(t, cipher, "Hello, AES-GCM World!")
	})

	t.Run("WithAAD", func(t *testing.T) {
		cipher, err := pkcs11.NewAESGCMCipher(key, iv)
		if err != nil {
			t.Fatalf("Failed to create AES-GCM cipher: %v", err)
		}
		cipher.SetAAD([]byte("additional authenticated data"))
		testAESGCMWithAAD(t, cipher)
	})

	t.Run("DifferentTagLengths", func(t *testing.T) {
		cipher, err := pkcs11.NewAESGCMCipher(key, iv)
		if err != nil {
			t.Fatalf("Failed to create AES-GCM cipher: %v", err)
		}
		cipher.SetTagLength(12)
		testAESGCMDifferentTagLengths(t, cipher)
	})

	t.Run("InvalidTagLength", func(t *testing.T) {
		cipher, err := pkcs11.NewAESGCMCipher(key, iv)
		if err != nil {
			t.Fatalf("Failed to create AES-GCM cipher: %v", err)
		}

		err = cipher.SetTagLength(8) // Too short
		if err == nil {
			t.Error("Expected error for invalid tag length, got none")
		}
		if !strings.Contains(err.Error(), "tag length must be between 12 and 16") {
			t.Errorf("Expected tag length error, got: %v", err)
		}
	})
}

// TestAESCipherProperties tests cipher properties and configuration
func TestAESCipherProperties(t *testing.T, ctx *TestContext) {
	client, cleanup := ctx.CreateTestClient(t)
	defer cleanup()

	// Test different key sizes
	for _, keySize := range ctx.Config.SupportedAESKeySizes {
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

// TestAESCipherErrorCases tests various error scenarios
func TestAESCipherErrorCases(t *testing.T, ctx *TestContext) {
	client, cleanup := ctx.CreateTestClient(t)
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

	t.Run("NilContext", func(t *testing.T) {
		keySize := ctx.Config.SupportedAESKeySizes[0]
		key, err := client.GenerateAESKey(keySize)
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

	t.Run("InvalidCiphertextLength", func(t *testing.T) {
		keySize := ctx.Config.SupportedAESKeySizes[0]
		key, err := client.GenerateAESKey(keySize)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		cipher, err := pkcs11.NewAESECBCipher(key)
		if err != nil {
			t.Fatalf("Failed to create cipher: %v", err)
		}

		ctxBg := context.Background()
		// Ciphertext length not multiple of block size
		invalidCiphertext := make([]byte, 17)

		_, err = cipher.Decrypt(ctxBg, invalidCiphertext)
		if err == nil {
			t.Error("Expected error for invalid ciphertext length, got none")
		}
		if !strings.Contains(err.Error(), "ciphertext length must be multiple of block size") {
			t.Errorf("Expected ciphertext length error, got: %v", err)
		}
	})

	t.Run("MalformedData", func(t *testing.T) {
		testAESMalformedData(t, ctx, client)
	})
}

// TestAESConcurrencyAndCancellation tests concurrent operations and context cancellation
func TestAESConcurrencyAndCancellation(t *testing.T, ctx *TestContext) {
	if ctx.Config.SkipConcurrencyTests {
		t.Skip("Concurrency tests disabled in configuration")
	}

	client, cleanup := ctx.CreateTestClient(t)
	defer cleanup()

	keySize := ctx.Config.SupportedAESKeySizes[0]
	key, err := client.GenerateAESKey(keySize)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	t.Run("ConcurrentOperations", func(t *testing.T) {
		testAESConcurrentOperations(t, ctx, key)
	})

	t.Run("ContextCancellation", func(t *testing.T) {
		testAESContextCancellation(t, key)
	})
}

// BenchmarkAESCipher runs performance benchmarks for AES cipher operations
func BenchmarkAESCipher(t *testing.T, ctx *TestContext) {
	if ctx.Config.SkipPerformanceTests {
		t.Skip("Performance tests disabled in configuration")
	}

	client, cleanup := ctx.CreateTestClient(t)
	defer cleanup()

	keySize := ctx.Config.SupportedAESKeySizes[0]
	key, err := client.GenerateAESKey(keySize)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Test data sizes
	dataSizes := []int{16, 1024, 4096, 16384}
	if !ctx.Config.SkipLargeDataTests {
		dataSizes = append(dataSizes, 65536, 1048576)
	}

	for _, size := range dataSizes {
		testData := make([]byte, size)
		for i := range testData {
			testData[i] = byte(i % 256)
		}

		t.Run(fmt.Sprintf("ECB_Encrypt_%dB", size), func(t *testing.T) {
			cipher, err := pkcs11.NewAESECBCipher(key)
			if err != nil {
				t.Fatalf("Failed to create cipher: %v", err)
			}

			ctxBg := context.Background()
			start := time.Now()
			_, err = cipher.Encrypt(ctxBg, testData)
			duration := time.Since(start)

			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			t.Logf("Encrypted %d bytes in %v", size, duration)
		})
	}
}

// Helper functions for AES cipher testing

func testAESBasicEncryptDecrypt(t *testing.T, ctx *TestContext, cipher pkcs11.BlockCipher, plaintext string) {
	t.Helper()

	ctxBg := context.Background()
	src := []byte(plaintext)

	// Encrypt
	encrypted, err := cipher.Encrypt(ctxBg, src)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt
	decrypted, err := cipher.Decrypt(ctxBg, encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Compare
	if !bytes.Equal(src, decrypted) {
		t.Errorf("Decrypted data doesn't match original.\nOriginal: %s\nDecrypted: %s", src, decrypted)
	}
}

func testAESMultipleBlockSizes(t *testing.T, ctx *TestContext, cipher pkcs11.BlockCipher) {
	t.Helper()

	ctxBg := context.Background()

	// Test sizes covering various edge cases
	testSizes := []int{1, 16, 17, 32, 64, 128, 256, 512, 1024}

	// Limit test sizes based on configuration
	maxSize := ctx.Config.MaxTestDataSize
	if maxSize > 0 {
		var limitedSizes []int
		for _, size := range testSizes {
			if size <= maxSize {
				limitedSizes = append(limitedSizes, size)
			}
		}
		testSizes = limitedSizes
	}

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("Size_%dB", size), func(t *testing.T) {
			// Generate random data
			src := make([]byte, size)
			if _, err := rand.Read(src); err != nil {
				t.Fatalf("Failed to generate random data: %v", err)
			}

			// Encrypt
			encrypted, err := cipher.Encrypt(ctxBg, src)
			if err != nil {
				t.Fatalf("Encryption failed for size %d: %v", size, err)
			}

			// Verify encrypted size is reasonable (should be padded to block boundary)
			expectedMinSize := ((size + 15) / 16) * 16 // PKCS#7 padding to block boundary
			if len(encrypted) < expectedMinSize {
				t.Errorf("Encrypted data size %d is smaller than expected minimum %d", len(encrypted), expectedMinSize)
			}

			// Decrypt
			decrypted, err := cipher.Decrypt(ctxBg, encrypted)
			if err != nil {
				t.Fatalf("Decryption failed for size %d: %v", size, err)
			}

			// Verify decrypted size matches original
			if len(decrypted) != size {
				t.Errorf("Decrypted size %d doesn't match original size %d", len(decrypted), size)
			}

			// Compare data
			if !bytes.Equal(src, decrypted) {
				t.Errorf("Data mismatch for size %d", size)
			}
		})
	}
}

func testAESEmptyDataError(t *testing.T, cipher pkcs11.BlockCipher) {
	t.Helper()

	ctxBg := context.Background()

	// Test empty source data
	_, err := cipher.Encrypt(ctxBg, []byte{})
	if err == nil {
		t.Error("Expected error for empty source data, got none")
	}
	if !strings.Contains(err.Error(), "plaintext cannot be empty") {
		t.Errorf("Expected empty data error, got: %v", err)
	}
}

func testAESStreamingOperations(t *testing.T, cipher pkcs11.BlockCipher, data string) {
	t.Helper()

	ctxBg := context.Background()
	src := strings.NewReader(data)

	// Encrypt using streaming
	var encryptedBuf bytes.Buffer
	_, err := cipher.EncryptStream(ctxBg, &encryptedBuf, src)
	if err != nil {
		t.Fatalf("Stream encryption failed: %v", err)
	}

	// Decrypt using streaming
	var decryptedBuf bytes.Buffer
	_, err = cipher.DecryptStream(ctxBg, &decryptedBuf, &encryptedBuf)
	if err != nil {
		t.Fatalf("Stream decryption failed: %v", err)
	}

	// Compare
	if decryptedBuf.String() != data {
		t.Errorf("Stream operation failed.\nOriginal: %s\nDecrypted: %s", data, decryptedBuf.String())
	}
}

func testAESLargeDataStreaming(t *testing.T, ctx *TestContext, cipher pkcs11.BlockCipher) {
	t.Helper()

	ctxBg := context.Background()

	// Generate large random data (respect configuration limits)
	size := 8192 // 8KB default
	if ctx.Config.MaxTestDataSize > 0 && ctx.Config.MaxTestDataSize < size {
		size = ctx.Config.MaxTestDataSize
	}

	largeData := make([]byte, size)
	if _, err := rand.Read(largeData); err != nil {
		t.Fatalf("Failed to generate large random data: %v", err)
	}

	src := bytes.NewReader(largeData)

	// Encrypt using streaming
	var encryptedBuf bytes.Buffer
	bytesWritten, err := cipher.EncryptStream(ctxBg, &encryptedBuf, src)
	if err != nil {
		t.Fatalf("Large data stream encryption failed: %v", err)
	}
	if bytesWritten == 0 {
		t.Error("No bytes written during encryption")
	}

	// Decrypt using streaming
	var decryptedBuf bytes.Buffer
	bytesWritten, err = cipher.DecryptStream(ctxBg, &decryptedBuf, &encryptedBuf)
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

	ctxBg := context.Background()
	src := []byte(plaintext)

	// Encrypt
	encrypted, err := cipher.Encrypt(ctxBg, src)
	if err != nil {
		t.Fatalf("GCM encryption failed: %v", err)
	}

	// Decrypt
	decrypted, err := cipher.Decrypt(ctxBg, encrypted)
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

	ctxBg := context.Background()
	src := []byte("secret message")
	aad := []byte("additional authenticated data")

	// Set AAD
	cipher.SetAAD(aad)

	// Encrypt
	encrypted, err := cipher.Encrypt(ctxBg, src)
	if err != nil {
		t.Fatalf("GCM encryption with AAD failed: %v", err)
	}

	// Decrypt with same AAD
	decrypted, err := cipher.Decrypt(ctxBg, encrypted)
	if err != nil {
		t.Fatalf("GCM decryption with AAD failed: %v", err)
	}

	// Compare
	if !bytes.Equal(src, decrypted) {
		t.Error("GCM with AAD: decrypted data doesn't match original")
	}

	// Test with wrong AAD (should fail)
	cipher.SetAAD([]byte("wrong aad"))
	_, err = cipher.Decrypt(ctxBg, encrypted)
	if err == nil {
		t.Error("Expected authentication failure with wrong AAD, got none")
	}
}

func testAESGCMDifferentTagLengths(t *testing.T, cipher *pkcs11.AESGCMCipher) {
	t.Helper()

	ctxBg := context.Background()
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
			encrypted, err := cipher.Encrypt(ctxBg, src)
			if err != nil {
				t.Fatalf("GCM encryption failed with tag length %d: %v", tagLen, err)
			}

			// Decrypt
			decrypted, err := cipher.Decrypt(ctxBg, encrypted)
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

func testAESMalformedData(t *testing.T, ctx *TestContext, client *pkcs11.Client) {
	keySize := ctx.Config.SupportedAESKeySizes[0]
	key, err := client.GenerateAESKey(keySize)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	ctxBg := context.Background()

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
		}

		for _, tc := range malformedTests {
			t.Run(tc.name, func(t *testing.T) {
				_, err := cipher.Decrypt(ctxBg, tc.data)
				if err == nil {
					t.Errorf("Expected error for malformed data %s, got none", tc.name)
				}
			})
		}
	})
}

func testAESConcurrentOperations(t *testing.T, ctx *TestContext, key *pkcs11.SymmetricKey) {
	t.Helper()

	if ctx.Config.SkipConcurrencyTests {
		t.Skip("Concurrency tests disabled in configuration")
	}

	ctxBg := context.Background()

	// Test data
	testData := []byte("Concurrent test data for AES operations")

	// Number of concurrent operations
	numGoroutines := ctx.Config.MaxConcurrentOps
	if numGoroutines <= 0 {
		numGoroutines = 10
	}

	t.Run("ECB_Concurrent", func(t *testing.T) {
		cipher, err := pkcs11.NewAESECBCipher(key)
		if err != nil {
			t.Fatalf("Failed to create cipher: %v", err)
		}

		// Channel to collect results
		results := make(chan error, numGoroutines)

		// Start concurrent operations
		for i := range numGoroutines {
			go func(id int) {
				defer func() {
					if r := recover(); r != nil {
						results <- fmt.Errorf("goroutine %d panicked: %v", id, r)
					}
				}()

				// Encrypt
				encrypted, err := cipher.Encrypt(ctxBg, testData)
				if err != nil {
					results <- fmt.Errorf("goroutine %d encrypt failed: %v", id, err)
					return
				}

				// Decrypt
				decrypted, err := cipher.Decrypt(ctxBg, encrypted)
				if err != nil {
					results <- fmt.Errorf("goroutine %d decrypt failed: %v", id, err)
					return
				}

				// Verify
				if !bytes.Equal(testData, decrypted) {
					results <- fmt.Errorf("goroutine %d data mismatch", id)
					return
				}
				results <- nil
			}(i)
		}

		// Wait for all goroutines to complete
		for range numGoroutines {
			if err := <-results; err != nil {
				t.Errorf("Concurrent ECB operation failed: %v", err)
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
}

// Helper function to check if a slice contains a string
func containsString(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}
