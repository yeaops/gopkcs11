package gopkcs11

import (
	"fmt"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

// SymmetricKeyType represents the type of symmetric encryption key.
type SymmetricKeyType int

const (
	// SymmetricKeyTypeAES represents AES symmetric keys (128, 192, 256 bits)
	SymmetricKeyTypeAES SymmetricKeyType = iota
	// SymmetricKeyTypeDES represents DES symmetric keys (64 bits)
	SymmetricKeyTypeDES
	// SymmetricKeyType3DES represents 3DES symmetric keys (192 bits)
	SymmetricKeyType3DES
)

// SymmetricKey represents a symmetric encryption key stored in the PKCS#11 HSM.
// It can be used for encryption, decryption, key wrapping, and key unwrapping operations.
type SymmetricKey struct {
	// Handle is the PKCS#11 object handle for the symmetric key
	Handle pkcs11.ObjectHandle
	// Label is the human-readable label for the symmetric key
	Label string
	// ID is the unique identifier for the symmetric key (generated from label)
	ID []byte
	// KeyType indicates the type of symmetric key (AES, DES, 3DES)
	KeyType SymmetricKeyType
	// KeySize is the key size in bits
	KeySize int
}

// GenerateAESKey generates a new AES symmetric key in the PKCS#11 device.
// Supported key sizes are 128, 192, and 256 bits.
// The generated key is marked as non-extractable and sensitive for security.
func (c *Client) GenerateAESKey(label string, keySize int) (*SymmetricKey, error) {
	if keySize != 128 && keySize != 192 && keySize != 256 {
		return nil, errors.New("AES key size must be 128, 192, or 256 bits")
	}

	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	keyID := generateKeyID(label)

	// AES key generation template
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, keySize/8),
	}

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)
	handle, err := c.ctx.GenerateKey(session, []*pkcs11.Mechanism{mechanism}, template)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return &SymmetricKey{
		Handle:  handle,
		Label:   label,
		ID:      keyID,
		KeyType: SymmetricKeyTypeAES,
		KeySize: keySize,
	}, nil
}

// GenerateDESKey generates a new DES symmetric key (64 bits) in the PKCS#11 device.
// The generated key is marked as non-extractable and sensitive for security.
func (c *Client) GenerateDESKey(label string) (*SymmetricKey, error) {
	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	keyID := generateKeyID(label)

	// DES key generation template
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_DES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_DES_KEY_GEN, nil)
	handle, err := c.ctx.GenerateKey(session, []*pkcs11.Mechanism{mechanism}, template)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return &SymmetricKey{
		Handle:  handle,
		Label:   label,
		ID:      keyID,
		KeyType: SymmetricKeyTypeDES,
		KeySize: 64, // DES is always 64 bits
	}, nil
}

// Generate3DESKey generates a new 3DES symmetric key (192 bits) in the PKCS#11 device.
// The generated key is marked as non-extractable and sensitive for security.
func (c *Client) Generate3DESKey(label string) (*SymmetricKey, error) {
	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	keyID := generateKeyID(label)

	// 3DES key generation template
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_DES3),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_DES3_KEY_GEN, nil)
	handle, err := c.ctx.GenerateKey(session, []*pkcs11.Mechanism{mechanism}, template)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return &SymmetricKey{
		Handle:  handle,
		Label:   label,
		ID:      keyID,
		KeyType: SymmetricKeyType3DES,
		KeySize: 192, // 3DES is 192 bits (3 * 64)
	}, nil
}

// ImportAESKey imports existing AES key material into the PKCS#11 device.
// Supported key sizes are 16, 24, or 32 bytes (128, 192, or 256 bits).
// The imported key is marked as non-extractable and sensitive for security.
func (c *Client) ImportAESKey(label string, keyMaterial []byte) (*SymmetricKey, error) {
	if len(keyMaterial) != 16 && len(keyMaterial) != 24 && len(keyMaterial) != 32 {
		return nil, errors.New("AES key material must be 16, 24, or 32 bytes (128, 192, or 256 bits)")
	}

	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	keyID := generateKeyID(label)
	keySize := len(keyMaterial) * 8

	// AES key import template
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, keyMaterial),
	}

	handle, err := c.ctx.CreateObject(session, template)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return &SymmetricKey{
		Handle:  handle,
		Label:   label,
		ID:      keyID,
		KeyType: SymmetricKeyTypeAES,
		KeySize: keySize,
	}, nil
}

// ImportSymmetricKey imports existing symmetric key material into the PKCS#11 device.
// It automatically validates the key material size based on the specified key type.
// The imported key is marked as non-extractable and sensitive for security.
func (c *Client) ImportSymmetricKey(label string, keyType SymmetricKeyType, keyMaterial []byte) (*SymmetricKey, error) {
	if len(keyMaterial) == 0 {
		return nil, errors.New("key material cannot be empty")
	}

	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	keyID := generateKeyID(label)
	var pkcs11KeyType uint
	var keySize int

	switch keyType {
	case SymmetricKeyTypeAES:
		if len(keyMaterial) != 16 && len(keyMaterial) != 24 && len(keyMaterial) != 32 {
			return nil, errors.New("AES key material must be 16, 24, or 32 bytes")
		}
		pkcs11KeyType = pkcs11.CKK_AES
		keySize = len(keyMaterial) * 8
	case SymmetricKeyTypeDES:
		if len(keyMaterial) != 8 {
			return nil, errors.New("DES key material must be 8 bytes")
		}
		pkcs11KeyType = pkcs11.CKK_DES
		keySize = 64
	case SymmetricKeyType3DES:
		if len(keyMaterial) != 24 {
			return nil, errors.New("3DES key material must be 24 bytes")
		}
		pkcs11KeyType = pkcs11.CKK_DES3
		keySize = 192
	default:
		return nil, errors.New("unsupported symmetric key type")
	}

	// Symmetric key import template
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11KeyType),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, keyMaterial),
	}

	handle, err := c.ctx.CreateObject(session, template)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return &SymmetricKey{
		Handle:  handle,
		Label:   label,
		ID:      keyID,
		KeyType: keyType,
		KeySize: keySize,
	}, nil
}

// EncryptData encrypts data using the symmetric key with the specified PKCS#11 mechanism.
// Common mechanisms include CKM_AES_CBC, CKM_AES_GCM, CKM_DES_CBC, etc.
// The iv parameter is used for mechanisms that require an initialization vector.
func (c *Client) EncryptData(key *SymmetricKey, mechanism uint, iv []byte, data []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("symmetric key cannot be nil")
	}

	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Create mechanism with IV if provided
	var mech *pkcs11.Mechanism
	if len(iv) > 0 {
		mech = pkcs11.NewMechanism(mechanism, iv)
	} else {
		mech = pkcs11.NewMechanism(mechanism, nil)
	}

	// Initialize encryption
	if err := c.ctx.EncryptInit(session, []*pkcs11.Mechanism{mech}, key.Handle); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Perform encryption
	ciphertext, err := c.ctx.Encrypt(session, data)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return ciphertext, nil
}

// DecryptData decrypts data using the symmetric key with the specified PKCS#11 mechanism.
// The mechanism and iv parameters must match those used for encryption.
func (c *Client) DecryptData(key *SymmetricKey, mechanism uint, iv []byte, ciphertext []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("symmetric key cannot be nil")
	}

	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Create mechanism with IV if provided
	var mech *pkcs11.Mechanism
	if len(iv) > 0 {
		mech = pkcs11.NewMechanism(mechanism, iv)
	} else {
		mech = pkcs11.NewMechanism(mechanism, nil)
	}

	// Initialize decryption
	if err := c.ctx.DecryptInit(session, []*pkcs11.Mechanism{mech}, key.Handle); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Perform decryption
	plaintext, err := c.ctx.Decrypt(session, ciphertext)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return plaintext, nil
}

// WrapKey wraps a target key using a wrapping key with the specified PKCS#11 mechanism.
// This is used for secure key transport and storage.
// Common mechanisms include CKM_AES_KEY_WRAP, CKM_AES_CBC, etc.
func (c *Client) WrapKey(wrappingKey *SymmetricKey, targetKeyHandle pkcs11.ObjectHandle, mechanism uint, iv []byte) ([]byte, error) {
	if wrappingKey == nil {
		return nil, errors.New("wrapping key cannot be nil")
	}

	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Create mechanism with IV if provided
	var mech *pkcs11.Mechanism
	if len(iv) > 0 {
		mech = pkcs11.NewMechanism(mechanism, iv)
	} else {
		mech = pkcs11.NewMechanism(mechanism, nil)
	}

	// Wrap the key
	wrappedKey, err := c.ctx.WrapKey(session, []*pkcs11.Mechanism{mech}, wrappingKey.Handle, targetKeyHandle)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return wrappedKey, nil
}

// UnwrapKey unwraps a wrapped key using an unwrapping key with the specified PKCS#11 mechanism.
// The keyTemplate parameter specifies the attributes for the unwrapped key object.
// Returns the handle to the newly created unwrapped key.
func (c *Client) UnwrapKey(unwrappingKey *SymmetricKey, wrappedKey []byte, mechanism uint, iv []byte, keyTemplate []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	if unwrappingKey == nil {
		return 0, errors.New("unwrapping key cannot be nil")
	}

	session, err := c.GetSession()
	if err != nil {
		return 0, ConvertPKCS11Error(err)
	}

	// Create mechanism with IV if provided
	var mech *pkcs11.Mechanism
	if len(iv) > 0 {
		mech = pkcs11.NewMechanism(mechanism, iv)
	} else {
		mech = pkcs11.NewMechanism(mechanism, nil)
	}

	// Unwrap the key
	handle, err := c.ctx.UnwrapKey(session, []*pkcs11.Mechanism{mech}, unwrappingKey.Handle, wrappedKey, keyTemplate)
	if err != nil {
		return 0, ConvertPKCS11Error(err)
	}

	return handle, nil
}

// FindSymmetricKeyByLabel searches for a symmetric key by its label.
// Returns an error if no key is found with the specified label.
func (c *Client) FindSymmetricKeyByLabel(label string) (*SymmetricKey, error) {
	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	if err := c.ctx.FindObjectsInit(session, template); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	handles, _, err := c.ctx.FindObjects(session, 1)
	if err != nil {
		c.ctx.FindObjectsFinal(session)
		return nil, ConvertPKCS11Error(err)
	}

	if err := c.ctx.FindObjectsFinal(session); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	if len(handles) == 0 {
		return nil, NewPKCS11Error(ErrKeyNotFound, "symmetric key not found", nil)
	}

	return c.getSymmetricKey(session, handles[0])
}

// FindSymmetricKeyByID searches for a symmetric key by its unique ID.
// Returns an error if no key is found with the specified ID.
func (c *Client) FindSymmetricKeyByID(id []byte) (*SymmetricKey, error) {
	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	if err := c.ctx.FindObjectsInit(session, template); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	handles, _, err := c.ctx.FindObjects(session, 1)
	if err != nil {
		c.ctx.FindObjectsFinal(session)
		return nil, ConvertPKCS11Error(err)
	}

	if err := c.ctx.FindObjectsFinal(session); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	if len(handles) == 0 {
		return nil, NewPKCS11Error(ErrKeyNotFound, "symmetric key not found", nil)
	}

	return c.getSymmetricKey(session, handles[0])
}

// ListSymmetricKeys returns all symmetric keys stored in the PKCS#11 device.
// Keys that cannot be processed (due to unsupported types, etc.) are silently skipped.
func (c *Client) ListSymmetricKeys() ([]*SymmetricKey, error) {
	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
	}

	if err := c.ctx.FindObjectsInit(session, template); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	var keys []*SymmetricKey
	for {
		handles, more, err := c.ctx.FindObjects(session, 10)
		if err != nil {
			c.ctx.FindObjectsFinal(session)
			return nil, ConvertPKCS11Error(err)
		}

		for _, handle := range handles {
			key, err := c.getSymmetricKey(session, handle)
			if err != nil {
				continue // Skip keys that can't be processed
			}
			keys = append(keys, key)
		}

		if !more {
			break
		}
	}

	if err := c.ctx.FindObjectsFinal(session); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return keys, nil
}

// getSymmetricKey retrieves symmetric key information from a PKCS#11 object handle.
// It extracts the key attributes and constructs a SymmetricKey structure.
func (c *Client) getSymmetricKey(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) (*SymmetricKey, error) {
	attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil),
	}

	attrs, err := c.ctx.GetAttributeValue(session, handle, attrs)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	label := string(attrs[0].Value)
	id := attrs[1].Value
	keyTypeValue := attrs[2].Value
	valueLenBytes := attrs[3].Value

	if len(keyTypeValue) == 0 {
		return nil, errors.New("unable to determine key type")
	}

	var keyType SymmetricKeyType
	var keySize int
	pkcs11KeyType := uint(keyTypeValue[0])

	switch pkcs11KeyType {
	case pkcs11.CKK_AES:
		keyType = SymmetricKeyTypeAES
		if len(valueLenBytes) >= 4 {
			// Convert bytes to int (assuming little-endian)
			keySize = int(valueLenBytes[0]) | int(valueLenBytes[1])<<8 | int(valueLenBytes[2])<<16 | int(valueLenBytes[3])<<24
			keySize *= 8 // Convert bytes to bits
		} else {
			keySize = 256 // Default AES key size if can't determine
		}
	case pkcs11.CKK_DES:
		keyType = SymmetricKeyTypeDES
		keySize = 64
	case pkcs11.CKK_DES3:
		keyType = SymmetricKeyType3DES
		keySize = 192
	default:
		return nil, errors.New("unsupported symmetric key type")
	}

	return &SymmetricKey{
		Handle:  handle,
		Label:   label,
		ID:      id,
		KeyType: keyType,
		KeySize: keySize,
	}, nil
}

// String returns a string representation of the symmetric key.
func (k *SymmetricKey) String() string {
	return fmt.Sprintf("SymmetricKey{Label: %s, Type: %v, Size: %d}", k.Label, k.KeyType, k.KeySize)
}