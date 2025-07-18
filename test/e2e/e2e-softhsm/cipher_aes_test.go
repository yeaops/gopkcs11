package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

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

	t.Run("BufferSizeTooSmall", func(t *testing.T) {
		testAESBufferSizeTooSmall(t, cipher)
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

	t.Run("BufferSizeTooSmall", func(t *testing.T) {
		testAESBufferSizeTooSmall(t, cipher)
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

	// Create AES-GCM cipher
	cipher, err := pkcs11.NewAESGCMCipher(key, iv)
	if err != nil {
		t.Fatalf("Failed to create AES-GCM cipher: %v", err)
	}

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

	// Test various data sizes
	testSizes := []int{1, 15, 16, 17, 31, 32, 48, 64, 100}

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("Size%d", size), func(t *testing.T) {
			// Generate random data
			src := make([]byte, size)
			if _, err := rand.Read(src); err != nil {
				t.Fatalf("Failed to generate random data: %v", err)
			}

			// Encrypt
			encrypted, err := cipher.Encrypt(ctx, src)
			if err != nil {
				t.Fatalf("Encryption failed for size %d: %v", size, err)
			}

			// Decrypt
			decrypted, err := cipher.Decrypt(ctx, encrypted)
			if err != nil {
				t.Fatalf("Decryption failed for size %d: %v", size, err)
			}

			// Compare
			if !bytes.Equal(src, decrypted[:size]) {
				t.Errorf("Data mismatch for size %d", size)
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

func testAESBufferSizeTooSmall(t *testing.T, cipher pkcs11.BlockCipher) {
	t.Helper()

	// This test is no longer relevant with the new interface
	// since the cipher now returns the encrypted data directly
	// and handles buffer sizing internally
	_ = cipher // unused parameter
	t.Skip("Buffer size test not applicable with new interface")
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
}
