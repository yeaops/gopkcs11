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
	key *SymmetricKey
}

// NewAESECBCipher creates a new AES-ECB cipher with the given symmetric key.
func NewAESECBCipher(key *SymmetricKey) (*AESECBCipher, error) {
	if key == nil {
		return nil, errors.New("symmetric key cannot be nil")
	}
	if key.KeyType != SymmetricKeyTypeAES {
		return nil, errors.New("key must be AES type")
	}
	return &AESECBCipher{key: key}, nil
}

// BlockSize returns the block size for AES (16 bytes).
func (c *AESECBCipher) BlockSize() int {
	return AES_BLOCK_SIZE
}

// KeySize returns the key size in bytes.
func (c *AESECBCipher) KeySize() int {
	return c.key.KeySize / 8
}

// Encrypt encrypts the source data and writes the result to destination.
// For ECB mode, data is padded using PKCS#7 padding.
func (c *AESECBCipher) Encrypt(ctx context.Context, dst, src []byte) error {
	if ctx == nil {
		return errors.New("context cannot be nil")
	}
	if len(src) == 0 {
		return errors.New("source data cannot be empty")
	}

	// Pad the data for ECB mode
	paddedData := pkcs11PaddingPKCS7(src, c.BlockSize())
	if len(dst) < len(paddedData) {
		return errors.New("destination buffer too small")
	}

	session, err := c.key.client.GetSession()
	if err != nil {
		return ConvertPKCS11Error(err)
	}

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil)
	if err := c.key.client.ctx.EncryptInit(session, []*pkcs11.Mechanism{mechanism}, c.key.Handle); err != nil {
		return ConvertPKCS11Error(err)
	}

	ciphertext, err := c.key.client.ctx.Encrypt(session, paddedData)
	if err != nil {
		return ConvertPKCS11Error(err)
	}

	copy(dst, ciphertext)
	return nil
}

// Decrypt decrypts the source data and writes the result to destination.
// For ECB mode, PKCS#7 padding is removed from the result.
func (c *AESECBCipher) Decrypt(ctx context.Context, dst, src []byte) error {
	if ctx == nil {
		return errors.New("context cannot be nil")
	}
	if len(src) == 0 {
		return errors.New("source data cannot be empty")
	}
	if len(src)%c.BlockSize() != 0 {
		return errors.New("ciphertext length must be multiple of block size")
	}

	session, err := c.key.client.GetSession()
	if err != nil {
		return ConvertPKCS11Error(err)
	}

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil)
	if err := c.key.client.ctx.DecryptInit(session, []*pkcs11.Mechanism{mechanism}, c.key.Handle); err != nil {
		return ConvertPKCS11Error(err)
	}

	plaintext, err := c.key.client.ctx.Decrypt(session, src)
	if err != nil {
		return ConvertPKCS11Error(err)
	}

	// Remove PKCS#7 padding
	unpaddedData, err := pkcs11UnpaddingPKCS7(plaintext)
	if err != nil {
		return errors.Wrap(err, "failed to remove padding")
	}

	if len(dst) < len(unpaddedData) {
		return errors.New("destination buffer too small")
	}

	copy(dst, unpaddedData)
	return nil
}

// EncryptStream encrypts data from src and writes to dst in streaming fashion.
// For ECB mode, data is processed in blocks with appropriate padding.
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

	const bufferSize = 4096
	buffer := make([]byte, bufferSize)
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

		// Process the data
		data := buffer[:n]
		paddedData := pkcs11PaddingPKCS7(data, c.BlockSize())
		ciphertext := make([]byte, len(paddedData))

		if err := c.Encrypt(ctx, ciphertext, data); err != nil {
			return totalWritten, err
		}

		written, err := dst.Write(ciphertext)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += written

		if err == io.EOF {
			break
		}
	}

	return totalWritten, nil
}

// DecryptStream decrypts data from src and writes to dst in streaming fashion.
// For ECB mode, PKCS#7 padding is removed from the result.
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

	const bufferSize = 4096
	buffer := make([]byte, bufferSize)
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

		// Process the data
		data := buffer[:n]
		plaintext := make([]byte, len(data))

		if err := c.Decrypt(ctx, plaintext, data); err != nil {
			return totalWritten, err
		}

		written, err := dst.Write(plaintext)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += written

		if err == io.EOF {
			break
		}
	}

	return totalWritten, nil
}

// AESCBCCipher implements the BlockCipher interface for AES-CBC mode.
// CBC mode requires an initialization vector (IV) for security.
type AESCBCCipher struct {
	key *SymmetricKey
	iv  []byte
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
	return &AESCBCCipher{key: key, iv: iv}, nil
}

// BlockSize returns the block size for AES (16 bytes).
func (c *AESCBCCipher) BlockSize() int {
	return AES_BLOCK_SIZE
}

// KeySize returns the key size in bytes.
func (c *AESCBCCipher) KeySize() int {
	return c.key.KeySize / 8
}

// Encrypt encrypts the source data and writes the result to destination.
// For CBC mode, data is padded using PKCS#7 padding.
func (c *AESCBCCipher) Encrypt(ctx context.Context, dst, src []byte) error {
	if ctx == nil {
		return errors.New("context cannot be nil")
	}
	if len(src) == 0 {
		return errors.New("source data cannot be empty")
	}

	// Pad the data for CBC mode
	paddedData := pkcs11PaddingPKCS7(src, c.BlockSize())
	if len(dst) < len(paddedData) {
		return errors.New("destination buffer too small")
	}

	session, err := c.key.client.GetSession()
	if err != nil {
		return ConvertPKCS11Error(err)
	}

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, c.iv)
	if err := c.key.client.ctx.EncryptInit(session, []*pkcs11.Mechanism{mechanism}, c.key.Handle); err != nil {
		return ConvertPKCS11Error(err)
	}

	ciphertext, err := c.key.client.ctx.Encrypt(session, paddedData)
	if err != nil {
		return ConvertPKCS11Error(err)
	}

	copy(dst, ciphertext)
	return nil
}

// Decrypt decrypts the source data and writes the result to destination.
// For CBC mode, PKCS#7 padding is removed from the result.
func (c *AESCBCCipher) Decrypt(ctx context.Context, dst, src []byte) error {
	if ctx == nil {
		return errors.New("context cannot be nil")
	}
	if len(src) == 0 {
		return errors.New("source data cannot be empty")
	}
	if len(src)%c.BlockSize() != 0 {
		return errors.New("ciphertext length must be multiple of block size")
	}

	session, err := c.key.client.GetSession()
	if err != nil {
		return ConvertPKCS11Error(err)
	}

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, c.iv)
	if err := c.key.client.ctx.DecryptInit(session, []*pkcs11.Mechanism{mechanism}, c.key.Handle); err != nil {
		return ConvertPKCS11Error(err)
	}

	plaintext, err := c.key.client.ctx.Decrypt(session, src)
	if err != nil {
		return ConvertPKCS11Error(err)
	}

	// Remove PKCS#7 padding
	unpaddedData, err := pkcs11UnpaddingPKCS7(plaintext)
	if err != nil {
		return errors.Wrap(err, "failed to remove padding")
	}

	if len(dst) < len(unpaddedData) {
		return errors.New("destination buffer too small")
	}

	copy(dst, unpaddedData)
	return nil
}

// EncryptStream encrypts data from src and writes to dst in streaming fashion.
// For CBC mode, data is processed in blocks with appropriate padding.
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

	const bufferSize = 4096
	buffer := make([]byte, bufferSize)
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

		// Process the data
		data := buffer[:n]
		paddedData := pkcs11PaddingPKCS7(data, c.BlockSize())
		ciphertext := make([]byte, len(paddedData))

		if err := c.Encrypt(ctx, ciphertext, data); err != nil {
			return totalWritten, err
		}

		written, err := dst.Write(ciphertext)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += written

		if err == io.EOF {
			break
		}
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

	const bufferSize = 4096
	buffer := make([]byte, bufferSize)
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

		// Process the data
		data := buffer[:n]
		plaintext := make([]byte, len(data))

		if err := c.Decrypt(ctx, plaintext, data); err != nil {
			return totalWritten, err
		}

		written, err := dst.Write(plaintext)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += written

		if err == io.EOF {
			break
		}
	}

	return totalWritten, nil
}

// AESGCMCipher implements the BlockCipher interface for AES-GCM mode.
// GCM mode provides authenticated encryption with additional data (AEAD).
type AESGCMCipher struct {
	key       *SymmetricKey
	iv        []byte
	aad       []byte
	tagLength int
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
		key:       key,
		iv:        iv,
		tagLength: 16, // Default GCM tag length
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

// Encrypt encrypts the source data and writes the result to destination.
// For GCM mode, the result includes the authentication tag.
func (c *AESGCMCipher) Encrypt(ctx context.Context, dst, src []byte) error {
	if ctx == nil {
		return errors.New("context cannot be nil")
	}
	if len(src) == 0 {
		return errors.New("source data cannot be empty")
	}

	// GCM ciphertext includes the tag
	expectedLen := len(src) + c.tagLength
	if len(dst) < expectedLen {
		return errors.New("destination buffer too small")
	}

	session, err := c.key.client.GetSession()
	if err != nil {
		return ConvertPKCS11Error(err)
	}

	// Create GCM parameters with IV, AAD, and tag size in bits
	gcmParams := pkcs11.NewGCMParams(c.iv, c.aad, c.tagLength*8)
	defer gcmParams.Free()

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcmParams)
	if err := c.key.client.ctx.EncryptInit(session, []*pkcs11.Mechanism{mechanism}, c.key.Handle); err != nil {
		return ConvertPKCS11Error(err)
	}

	ciphertext, err := c.key.client.ctx.Encrypt(session, src)
	if err != nil {
		return ConvertPKCS11Error(err)
	}

	copy(dst, ciphertext)
	return nil
}

// Decrypt decrypts the source data and writes the result to destination.
// For GCM mode, the source data should include the authentication tag.
func (c *AESGCMCipher) Decrypt(ctx context.Context, dst, src []byte) error {
	if ctx == nil {
		return errors.New("context cannot be nil")
	}
	if len(src) <= c.tagLength {
		return errors.New("source data too short for GCM tag")
	}

	expectedLen := len(src) - c.tagLength
	if len(dst) < expectedLen {
		return errors.New("destination buffer too small")
	}

	session, err := c.key.client.GetSession()
	if err != nil {
		return ConvertPKCS11Error(err)
	}

	// Create GCM parameters with IV, AAD, and tag size in bits
	gcmParams := pkcs11.NewGCMParams(c.iv, c.aad, c.tagLength*8)
	defer gcmParams.Free()

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcmParams)
	if err := c.key.client.ctx.DecryptInit(session, []*pkcs11.Mechanism{mechanism}, c.key.Handle); err != nil {
		return ConvertPKCS11Error(err)
	}

	plaintext, err := c.key.client.ctx.Decrypt(session, src)
	if err != nil {
		return ConvertPKCS11Error(err)
	}

	copy(dst, plaintext)
	return nil
}

// EncryptStream encrypts data from src and writes to dst in streaming fashion.
// For GCM mode, the authentication tag is included in the output.
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

	const bufferSize = 4096
	buffer := make([]byte, bufferSize)
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

		// Process the data
		data := buffer[:n]
		ciphertext := make([]byte, len(data)+c.tagLength)

		if err := c.Encrypt(ctx, ciphertext, data); err != nil {
			return totalWritten, err
		}

		written, err := dst.Write(ciphertext)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += written

		if err == io.EOF {
			break
		}
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

	const bufferSize = 4096
	buffer := make([]byte, bufferSize)
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

		// Process the data
		data := buffer[:n]
		if len(data) <= c.tagLength {
			continue // Skip if data is too short for GCM tag
		}

		plaintext := make([]byte, len(data)-c.tagLength)

		if err := c.Decrypt(ctx, plaintext, data); err != nil {
			return totalWritten, err
		}

		written, err := dst.Write(plaintext)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += written

		if err == io.EOF {
			break
		}
	}

	return totalWritten, nil
}
