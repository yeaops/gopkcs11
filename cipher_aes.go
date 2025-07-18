package gopkcs11

import (
	"context"
	"io"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

const (
	// AES BlockSize is 16 bytes.
	AES_BLOCK_SIZE = 16
	// DEFAULT_AES_STREAM_BUFFER_SIZE is the default buffer size for AES streaming operations.
	// It's set to AES_BLOCK_SIZE * 256 = 4096 bytes for optimal performance.
	DEFAULT_AES_STREAM_BUFFER_SIZE = AES_BLOCK_SIZE * 256
)

// pkcs11PaddingPKCS7 adds PKCS#7 padding to the data.
func pkcs11PaddingPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// pkcs11UnpaddingPKCS7 removes PKCS#7 padding from the data.
func pkcs11UnpaddingPKCS7(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("data cannot be empty")
	}
	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, errors.New("invalid padding")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-padding], nil
}

// AESECBCipher implements the BlockCipher interface for AES-ECB mode.
// ECB mode does not use an initialization vector (IV) and is not recommended
// for most applications due to security concerns, but is included for compatibility.
type AESECBCipher struct {
	key        *SymmetricKey
	bufferSize int
}

// NewAESECBCipher creates a new AES-ECB cipher with the given symmetric key.
func NewAESECBCipher(key *SymmetricKey) (*AESECBCipher, error) {
	if key == nil {
		return nil, errors.New("symmetric key cannot be nil")
	}
	if key.KeyType != SymmetricKeyTypeAES {
		return nil, errors.New("key must be AES type")
	}
	return &AESECBCipher{
		key:        key,
		bufferSize: DEFAULT_AES_STREAM_BUFFER_SIZE,
	}, nil
}

// BlockSize returns the block size for AES (16 bytes).
func (c *AESECBCipher) BlockSize() int {
	return AES_BLOCK_SIZE
}

// KeySize returns the key size in bytes.
func (c *AESECBCipher) KeySize() int {
	return c.key.KeySize / 8
}

// BufferSize returns the current buffer size for streaming operations.
func (c *AESECBCipher) BufferSize() int {
	return c.bufferSize
}

// SetBufferSize sets the buffer size for streaming operations.
// The buffer size must be a positive multiple of AES_BLOCK_SIZE.
func (c *AESECBCipher) SetBufferSize(size int) error {
	if size <= 0 {
		return errors.New("buffer size must be positive")
	}
	if size%AES_BLOCK_SIZE != 0 {
		return errors.Errorf("buffer size must be a multiple of AES block size (%d bytes)", AES_BLOCK_SIZE)
	}
	c.bufferSize = size
	return nil
}

// Encrypt encrypts the source data and writes the result to destination.
// For ECB mode, data is padded using PKCS#7 padding.
func (c *AESECBCipher) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("context cannot be nil")
	}
	if len(plaintext) == 0 {
		return nil, errors.New("plaintext cannot be empty")
	}

	// Pad the data for ECB mode
	paddedData := pkcs11PaddingPKCS7(plaintext, c.BlockSize())

	session, err := c.key.client.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil)
	if err := c.key.client.ctx.EncryptInit(session, []*pkcs11.Mechanism{mechanism}, c.key.Handle); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	ciphertext, err := c.key.client.ctx.Encrypt(session, paddedData)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return ciphertext, nil
}

// Decrypt decrypts the source data and returns the result.
// For ECB mode, PKCS#7 padding is removed from the result.
func (c *AESECBCipher) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("context cannot be nil")
	}
	if len(ciphertext) == 0 {
		return nil, errors.New("ciphertext cannot be empty")
	}
	if len(ciphertext)%c.BlockSize() != 0 {
		return nil, errors.New("ciphertext length must be multiple of block size")
	}

	session, err := c.key.client.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil)
	if err := c.key.client.ctx.DecryptInit(session, []*pkcs11.Mechanism{mechanism}, c.key.Handle); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	paddedData, err := c.key.client.ctx.Decrypt(session, ciphertext)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Remove PKCS#7 padding
	plaintext, err := pkcs11UnpaddingPKCS7(paddedData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to remove padding")
	}

	return plaintext, nil
}

// EncryptStream encrypts data from src and writes to dst in streaming fashion.
// For ECB mode, data is processed efficiently with manual PKCS#7 padding at the end.
func (c *AESECBCipher) EncryptStream(ctx context.Context, dst io.Writer, src io.Reader) (int, error) {
	if ctx == nil {
		return 0, errors.New("context cannot be nil")
	}
	if src == nil {
		return 0, errors.New("source reader cannot be nil")
	}
	if dst == nil {
		return 0, errors.New("destination writer cannot be nil")
	}

	session, err := c.key.client.GetSession()
	if err != nil {
		return 0, ConvertPKCS11Error(err)
	}

	// Initialize encryption
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil)
	if err := c.key.client.ctx.EncryptInit(session, []*pkcs11.Mechanism{mechanism}, c.key.Handle); err != nil {
		return 0, ConvertPKCS11Error(err)
	}

	buffer := make([]byte, c.bufferSize)
	var totalWritten int
	var pendingData []byte // Buffer for incomplete blocks
	var processData []byte // Buffer for complete blocks to process
	blockSize := c.BlockSize()

	for {
		select {
		case <-ctx.Done():
			return totalWritten, ctx.Err()
		default:
		}

		n, err := src.Read(buffer)
		if err != nil && err != io.EOF {
			return totalWritten, err
		}

		// Append new data to pending buffer
		if n > 0 {
			pendingData = append(pendingData, buffer[:n]...)

			if len(pendingData) >= blockSize {
				completeBlocks := (len(pendingData) / blockSize) * blockSize
				processData = pendingData[:completeBlocks]
				pendingData = pendingData[completeBlocks:]
			}
		}

		// If EOF, process all remaining data with padding and exit
		if err == io.EOF {
			// Add PKCS#7 padding to all remaining data
			processData = pkcs11PaddingPKCS7(pendingData, blockSize)
		}

		if len(processData) > 0 {
			ciphertext, err := c.key.client.ctx.EncryptUpdate(session, processData)
			if err != nil {
				return totalWritten, ConvertPKCS11Error(err)
			}
			if len(ciphertext) > 0 {
				written, err := dst.Write(ciphertext)
				if err != nil {
					return totalWritten, err
				}
				totalWritten += written
			}
		}

		if err == io.EOF {
			break
		}
	}

	// Call EncryptFinal to complete the operation
	finalCiphertext, err := c.key.client.ctx.EncryptFinal(session)
	if err != nil {
		return totalWritten, ConvertPKCS11Error(err)
	}
	if len(finalCiphertext) > 0 {
		written, err := dst.Write(finalCiphertext)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += written
	}

	return totalWritten, nil
}

// DecryptStream decrypts data from src and writes to dst in streaming fashion.
// For ECB mode, PKCS#7 padding is manually removed from the final result.
func (c *AESECBCipher) DecryptStream(ctx context.Context, dst io.Writer, src io.Reader) (int, error) {
	if ctx == nil {
		return 0, errors.New("context cannot be nil")
	}
	if src == nil {
		return 0, errors.New("source reader cannot be nil")
	}
	if dst == nil {
		return 0, errors.New("destination writer cannot be nil")
	}

	session, err := c.key.client.GetSession()
	if err != nil {
		return 0, ConvertPKCS11Error(err)
	}

	// Initialize decryption
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil)
	if err := c.key.client.ctx.DecryptInit(session, []*pkcs11.Mechanism{mechanism}, c.key.Handle); err != nil {
		return 0, ConvertPKCS11Error(err)
	}

	buffer := make([]byte, c.bufferSize)
	var totalWritten int
	var allPlaintext []byte // Buffer to collect all decrypted data for padding removal

	for {
		select {
		case <-ctx.Done():
			return totalWritten, ctx.Err()
		default:
		}

		n, err := src.Read(buffer)
		if err != nil && err != io.EOF {
			return totalWritten, err
		}
		if n == 0 {
			break
		}

		data := buffer[:n]

		// Always use DecryptUpdate for data chunks
		plaintext, err := c.key.client.ctx.DecryptUpdate(session, data)
		if err != nil {
			return totalWritten, ConvertPKCS11Error(err)
		}

		// Collect all plaintext data instead of writing immediately
		if len(plaintext) > 0 {
			allPlaintext = append(allPlaintext, plaintext...)
		}

		if err == io.EOF {
			break
		}
	}

	// Call DecryptFinal to complete the operation
	finalPlaintext, err := c.key.client.ctx.DecryptFinal(session)
	if err != nil {
		return totalWritten, ConvertPKCS11Error(err)
	}
	if len(finalPlaintext) > 0 {
		allPlaintext = append(allPlaintext, finalPlaintext...)
	}

	// Manually remove PKCS#7 padding from the complete result
	if len(allPlaintext) > 0 {
		unpaddedData, err := pkcs11UnpaddingPKCS7(allPlaintext)
		if err != nil {
			return totalWritten, errors.Wrap(err, "failed to remove padding")
		}

		// Write the unpadded data to output
		written, err := dst.Write(unpaddedData)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += written
	}

	return totalWritten, nil
}

// AESCBCCipher implements the BlockCipher interface for AES-CBC mode.
// CBC mode requires an initialization vector (IV) for security.
type AESCBCCipher struct {
	key        *SymmetricKey
	iv         []byte
	bufferSize int
}

// NewAESCBCCipher creates a new AES-CBC cipher with the given symmetric key and IV.
// The IV must be exactly 16 bytes (AES block size).
func NewAESCBCCipher(key *SymmetricKey, iv []byte) (*AESCBCCipher, error) {
	if key == nil {
		return nil, errors.New("symmetric key cannot be nil")
	}
	if key.KeyType != SymmetricKeyTypeAES {
		return nil, errors.New("key must be AES type")
	}
	if len(iv) != 16 {
		return nil, errors.New("IV must be 16 bytes for AES-CBC")
	}
	return &AESCBCCipher{
		key:        key,
		iv:         iv,
		bufferSize: DEFAULT_AES_STREAM_BUFFER_SIZE,
	}, nil
}

// BlockSize returns the block size for AES (16 bytes).
func (c *AESCBCCipher) BlockSize() int {
	return AES_BLOCK_SIZE
}

// KeySize returns the key size in bytes.
func (c *AESCBCCipher) KeySize() int {
	return c.key.KeySize / 8
}

// BufferSize returns the current buffer size for streaming operations.
func (c *AESCBCCipher) BufferSize() int {
	return c.bufferSize
}

// SetBufferSize sets the buffer size for streaming operations.
// The buffer size must be a positive multiple of AES_BLOCK_SIZE.
func (c *AESCBCCipher) SetBufferSize(size int) error {
	if size <= 0 {
		return errors.New("buffer size must be positive")
	}
	if size%AES_BLOCK_SIZE != 0 {
		return errors.Errorf("buffer size must be a multiple of AES block size (%d bytes)", AES_BLOCK_SIZE)
	}
	c.bufferSize = size
	return nil
}

// Encrypt encrypts the source data and returns the result.
// For CBC mode, data is padded using PKCS#7 padding.
func (c *AESCBCCipher) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("context cannot be nil")
	}
	if len(plaintext) == 0 {
		return nil, errors.New("plaintext cannot be empty")
	}

	// Pad the data for CBC mode
	paddedData := pkcs11PaddingPKCS7(plaintext, c.BlockSize())

	session, err := c.key.client.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, c.iv)
	if err := c.key.client.ctx.EncryptInit(session, []*pkcs11.Mechanism{mechanism}, c.key.Handle); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	ciphertext, err := c.key.client.ctx.Encrypt(session, paddedData)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return ciphertext, nil
}

// Decrypt decrypts the source data and returns the result.
// For CBC mode, PKCS#7 padding is removed from the result.
func (c *AESCBCCipher) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("context cannot be nil")
	}
	if len(ciphertext) == 0 {
		return nil, errors.New("ciphertext cannot be empty")
	}
	if len(ciphertext)%c.BlockSize() != 0 {
		return nil, errors.New("ciphertext length must be multiple of block size")
	}

	session, err := c.key.client.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, c.iv)
	if err := c.key.client.ctx.DecryptInit(session, []*pkcs11.Mechanism{mechanism}, c.key.Handle); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	paddedData, err := c.key.client.ctx.Decrypt(session, ciphertext)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Remove PKCS#7 padding
	plaintext, err := pkcs11UnpaddingPKCS7(paddedData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to remove padding")
	}

	return plaintext, nil
}

// EncryptStream encrypts data from src and writes to dst in streaming fashion.
// For CBC mode, data is processed efficiently with manual PKCS#7 padding at the end.
func (c *AESCBCCipher) EncryptStream(ctx context.Context, dst io.Writer, src io.Reader) (int, error) {
	if ctx == nil {
		return 0, errors.New("context cannot be nil")
	}
	if src == nil {
		return 0, errors.New("source reader cannot be nil")
	}
	if dst == nil {
		return 0, errors.New("destination writer cannot be nil")
	}

	session, err := c.key.client.GetSession()
	if err != nil {
		return 0, ConvertPKCS11Error(err)
	}

	// Initialize encryption
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, c.iv)
	if err := c.key.client.ctx.EncryptInit(session, []*pkcs11.Mechanism{mechanism}, c.key.Handle); err != nil {
		return 0, ConvertPKCS11Error(err)
	}

	buffer := make([]byte, c.bufferSize)
	var totalWritten int
	var pendingData []byte // Buffer for incomplete blocks
	var processData []byte // Buffer for complete blocks to process
	blockSize := c.BlockSize()

	for {
		select {
		case <-ctx.Done():
			return totalWritten, ctx.Err()
		default:
		}

		n, err := src.Read(buffer)
		if err != nil && err != io.EOF {
			return totalWritten, err
		}

		// Append new data to pending buffer
		if n > 0 {
			pendingData = append(pendingData, buffer[:n]...)

			if len(pendingData) >= blockSize {
				completeBlocks := (len(pendingData) / blockSize) * blockSize
				processData = pendingData[:completeBlocks]
				pendingData = pendingData[completeBlocks:]
			}
		}

		// If EOF, process all remaining data with padding and exit
		if err == io.EOF {
			// Add PKCS#7 padding to all remaining data
			processData = pkcs11PaddingPKCS7(pendingData, blockSize)
		}

		if len(processData) > 0 {
			ciphertext, err := c.key.client.ctx.EncryptUpdate(session, processData)
			if err != nil {
				return totalWritten, ConvertPKCS11Error(err)
			}
			if len(ciphertext) > 0 {
				written, err := dst.Write(ciphertext)
				if err != nil {
					return totalWritten, err
				}
				totalWritten += written
			}
		}

		if err == io.EOF {
			break
		}
	}

	// Call EncryptFinal to complete the operation
	finalCiphertext, err := c.key.client.ctx.EncryptFinal(session)
	if err != nil {
		return totalWritten, ConvertPKCS11Error(err)
	}
	if len(finalCiphertext) > 0 {
		written, err := dst.Write(finalCiphertext)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += written
	}

	return totalWritten, nil
}

// DecryptStream decrypts data from src and writes to dst in streaming fashion.
// For CBC mode, PKCS#7 padding is removed from the result.
func (c *AESCBCCipher) DecryptStream(ctx context.Context, dst io.Writer, src io.Reader) (int, error) {
	if ctx == nil {
		return 0, errors.New("context cannot be nil")
	}
	if src == nil {
		return 0, errors.New("source reader cannot be nil")
	}
	if dst == nil {
		return 0, errors.New("destination writer cannot be nil")
	}

	session, err := c.key.client.GetSession()
	if err != nil {
		return 0, ConvertPKCS11Error(err)
	}

	// Initialize decryption
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, c.iv)
	if err := c.key.client.ctx.DecryptInit(session, []*pkcs11.Mechanism{mechanism}, c.key.Handle); err != nil {
		return 0, ConvertPKCS11Error(err)
	}

	buffer := make([]byte, c.bufferSize)
	var totalWritten int
	var allPlaintext []byte // Buffer to collect all decrypted data for padding removal

	for {
		select {
		case <-ctx.Done():
			return totalWritten, ctx.Err()
		default:
		}

		n, err := src.Read(buffer)
		if err != nil && err != io.EOF {
			return totalWritten, err
		}
		if n == 0 {
			break
		}

		data := buffer[:n]

		// Always use DecryptUpdate for data chunks
		plaintext, err := c.key.client.ctx.DecryptUpdate(session, data)
		if err != nil {
			return totalWritten, ConvertPKCS11Error(err)
		}

		// Collect all plaintext data instead of writing immediately
		if len(plaintext) > 0 {
			allPlaintext = append(allPlaintext, plaintext...)
		}

		if err == io.EOF {
			break
		}
	}

	// Call DecryptFinal to complete the operation
	finalPlaintext, err := c.key.client.ctx.DecryptFinal(session)
	if err != nil {
		return totalWritten, ConvertPKCS11Error(err)
	}
	if len(finalPlaintext) > 0 {
		allPlaintext = append(allPlaintext, finalPlaintext...)
	}

	// Manually remove PKCS#7 padding from the complete result
	if len(allPlaintext) > 0 {
		unpaddedData, err := pkcs11UnpaddingPKCS7(allPlaintext)
		if err != nil {
			return totalWritten, errors.Wrap(err, "failed to remove padding")
		}

		// Write the unpadded data to output
		written, err := dst.Write(unpaddedData)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += written
	}

	return totalWritten, nil
}

// AESGCMCipher implements the BlockCipher interface for AES-GCM mode.
// GCM mode provides authenticated encryption with additional data (AEAD).
type AESGCMCipher struct {
	key        *SymmetricKey
	iv         []byte
	aad        []byte
	tagLength  int
	bufferSize int
}

// NewAESGCMCipher creates a new AES-GCM cipher with the given symmetric key and IV.
// The IV should be 12 bytes for optimal security in GCM mode.
// Additional authenticated data (AAD) is set to nil by default.
// Tag length is set to 16 bytes by default.
// AAD and tag length can be set using SetAAD and SetTagLength methods.
func NewAESGCMCipher(key *SymmetricKey, iv []byte) (*AESGCMCipher, error) {
	if key == nil {
		return nil, errors.New("symmetric key cannot be nil")
	}
	if key.KeyType != SymmetricKeyTypeAES {
		return nil, errors.New("key must be AES type")
	}
	if len(iv) == 0 {
		return nil, errors.New("IV cannot be empty for AES-GCM")
	}
	return &AESGCMCipher{
		key:        key,
		iv:         iv,
		tagLength:  16, // Default GCM tag length
		bufferSize: DEFAULT_AES_STREAM_BUFFER_SIZE,
	}, nil
}

// SetAAD sets the additional authenticated data for GCM mode.
func (c *AESGCMCipher) SetAAD(aad []byte) {
	c.aad = aad
}

// SetTagLength sets the authentication tag length for GCM mode.
// Valid tag lengths are 12, 13, 14, 15, or 16 bytes(96, 104, 112, 120, or 128 bits).
// The default is 16 bytes (128 bits).
// NIST SP 800-38D recommends 12 bytes (96 bits) for most applications.
// (96, 104, 112, 120, or 128 bits)
func (c *AESGCMCipher) SetTagLength(length int) error {
	if length < 12 || length > 16 {
		return errors.New("GCM tag length must be between 12 and 16 bytes")
	}
	c.tagLength = length
	return nil
}

// BlockSize returns the block size for AES (16 bytes).
func (c *AESGCMCipher) BlockSize() int {
	return AES_BLOCK_SIZE
}

// KeySize returns the key size in bytes.
func (c *AESGCMCipher) KeySize() int {
	return c.key.KeySize / 8
}

// BufferSize returns the current buffer size for streaming operations.
func (c *AESGCMCipher) BufferSize() int {
	return c.bufferSize
}

// SetBufferSize sets the buffer size for streaming operations.
// The buffer size must be a positive multiple of AES_BLOCK_SIZE.
func (c *AESGCMCipher) SetBufferSize(size int) error {
	if size <= 0 {
		return errors.New("buffer size must be positive")
	}
	if size%AES_BLOCK_SIZE != 0 {
		return errors.Errorf("buffer size must be a multiple of AES block size (%d bytes)", AES_BLOCK_SIZE)
	}
	c.bufferSize = size
	return nil
}

// Encrypt encrypts the source data and returns the result.
// For GCM mode, the result includes the authentication tag.
func (c *AESGCMCipher) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("context cannot be nil")
	}
	if len(plaintext) == 0 {
		return nil, errors.New("plaintext cannot be empty")
	}

	session, err := c.key.client.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Create GCM parameters with IV, AAD, and tag size in bits
	gcmParams := pkcs11.NewGCMParams(c.iv, c.aad, c.tagLength*8)
	defer gcmParams.Free()

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcmParams)
	if err := c.key.client.ctx.EncryptInit(session, []*pkcs11.Mechanism{mechanism}, c.key.Handle); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	ciphertext, err := c.key.client.ctx.Encrypt(session, plaintext)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return ciphertext, nil
}

// Decrypt decrypts the source data and returns the result.
// For GCM mode, the source data should include the authentication tag.
func (c *AESGCMCipher) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("context cannot be nil")
	}
	if len(ciphertext) <= c.tagLength {
		return nil, errors.New("ciphertext too short for GCM tag")
	}

	session, err := c.key.client.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Create GCM parameters with IV, AAD, and tag size in bits
	gcmParams := pkcs11.NewGCMParams(c.iv, c.aad, c.tagLength*8)
	defer gcmParams.Free()

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcmParams)
	if err := c.key.client.ctx.DecryptInit(session, []*pkcs11.Mechanism{mechanism}, c.key.Handle); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	plaintext, err := c.key.client.ctx.Decrypt(session, ciphertext)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return plaintext, nil
}

// EncryptStream encrypts data from src and writes to dst in streaming fashion.
// For GCM mode, the authentication tag is included in the output at the end.
func (c *AESGCMCipher) EncryptStream(ctx context.Context, dst io.Writer, src io.Reader) (int, error) {
	if ctx == nil {
		return 0, errors.New("context cannot be nil")
	}
	if src == nil {
		return 0, errors.New("source reader cannot be nil")
	}
	if dst == nil {
		return 0, errors.New("destination writer cannot be nil")
	}

	session, err := c.key.client.GetSession()
	if err != nil {
		return 0, ConvertPKCS11Error(err)
	}

	// Initialize encryption
	gcmParams := pkcs11.NewGCMParams(c.iv, c.aad, c.tagLength*8)
	defer gcmParams.Free()

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcmParams)
	if err := c.key.client.ctx.EncryptInit(session, []*pkcs11.Mechanism{mechanism}, c.key.Handle); err != nil {
		return 0, ConvertPKCS11Error(err)
	}

	buffer := make([]byte, c.bufferSize)
	var totalWritten int

	for {
		select {
		case <-ctx.Done():
			return totalWritten, ctx.Err()
		default:
		}

		n, err := src.Read(buffer)
		if err != nil && err != io.EOF {
			return totalWritten, err
		}
		if n == 0 {
			break
		}

		data := buffer[:n]

		// Always use EncryptUpdate for data chunks
		ciphertext, err := c.key.client.ctx.EncryptUpdate(session, data)
		if err != nil {
			return totalWritten, ConvertPKCS11Error(err)
		}

		if len(ciphertext) > 0 {
			written, err := dst.Write(ciphertext)
			if err != nil {
				return totalWritten, err
			}
			totalWritten += written
		}

		if err == io.EOF {
			break
		}
	}

	// Always call EncryptFinal to complete the operation and get the authentication tag
	finalCiphertext, err := c.key.client.ctx.EncryptFinal(session)
	if err != nil {
		return totalWritten, ConvertPKCS11Error(err)
	}
	if len(finalCiphertext) > 0 {
		written, err := dst.Write(finalCiphertext)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += written
	}

	return totalWritten, nil
}

// DecryptStream decrypts data from src and writes to dst in streaming fashion.
// For GCM mode, the authentication tag is expected to be included in the input.
func (c *AESGCMCipher) DecryptStream(ctx context.Context, dst io.Writer, src io.Reader) (int, error) {
	if ctx == nil {
		return 0, errors.New("context cannot be nil")
	}
	if src == nil {
		return 0, errors.New("source reader cannot be nil")
	}
	if dst == nil {
		return 0, errors.New("destination writer cannot be nil")
	}

	session, err := c.key.client.GetSession()
	if err != nil {
		return 0, ConvertPKCS11Error(err)
	}

	// Initialize decryption
	gcmParams := pkcs11.NewGCMParams(c.iv, c.aad, c.tagLength*8)
	defer gcmParams.Free()

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcmParams)
	if err := c.key.client.ctx.DecryptInit(session, []*pkcs11.Mechanism{mechanism}, c.key.Handle); err != nil {
		return 0, ConvertPKCS11Error(err)
	}

	buffer := make([]byte, c.bufferSize)
	var totalWritten int

	for {
		select {
		case <-ctx.Done():
			return totalWritten, ctx.Err()
		default:
		}

		n, err := src.Read(buffer)
		if err != nil && err != io.EOF {
			return totalWritten, err
		}
		if n == 0 {
			break
		}

		data := buffer[:n]

		// Always use DecryptUpdate for data chunks
		plaintext, err := c.key.client.ctx.DecryptUpdate(session, data)
		if err != nil {
			return totalWritten, ConvertPKCS11Error(err)
		}

		if len(plaintext) > 0 {
			written, err := dst.Write(plaintext)
			if err != nil {
				return totalWritten, err
			}
			totalWritten += written
		}

		if err == io.EOF {
			break
		}
	}

	// Always call DecryptFinal to complete the operation and verify the authentication tag
	finalPlaintext, err := c.key.client.ctx.DecryptFinal(session)
	if err != nil {
		return totalWritten, ConvertPKCS11Error(err)
	}
	if len(finalPlaintext) > 0 {
		written, err := dst.Write(finalPlaintext)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += written
	}

	return totalWritten, nil
}
