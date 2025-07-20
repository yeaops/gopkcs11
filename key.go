package gopkcs11

import (
	"crypto"
	"encoding/hex"
	"fmt"

	"github.com/miekg/pkcs11"
)

// Additional PKCS#11 constants for ED25519 support (from PKCS#11 v3.0)
const (
	CKK_EC_EDWARDS              = 0x00000040
	CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x00001055
	CKM_EDDSA                   = 0x00001057
)

// KeyPairType represents the type of asymmetric key pair.
type KeyPairType int

const (
	// KeyPairTypeRSA represents RSA key pairs for signing and encryption
	KeyPairTypeRSA KeyPairType = iota + 1
	// KeyPairTypeECDSA represents ECDSA key pairs for signing
	KeyPairTypeECDSA
	// KeyPairTypeED25519 represents ED25519 key pairs for signing
	KeyPairTypeED25519
)

// KeyPair represents an asymmetric key pair stored in the PKCS#11 device.
// It contains both the handle to the private key in the HSM and the public key material.
type KeyPair struct {
	token *Token

	// Handle is the PKCS#11 object handle for the private key
	Handle pkcs11.ObjectHandle
	// PublicHandle is the PKCS#11 object handle for the public key
	PublicHandle pkcs11.ObjectHandle
	// Label is the human-readable label for the key pair
	Label string
	// ID is the unique identifier for the key pair (generated from label)
	ID []byte
	// KeyType indicates whether this is an RSA or ECDSA key pair
	KeyType KeyPairType
	// KeySize is the key size in bits (e.g., 2048 for RSA, 256 for P-256)
	KeySize int
	// PublicKey is the public key material extracted from the HSM
	PublicKey crypto.PublicKey
}

// String returns a string representation of the key pair with label, type, and size.
func (k *KeyPair) String() string {
	return fmt.Sprintf("Key{ID: 0x%s, Label: %s, Type: %v, Size: %d}", hex.EncodeToString(k.ID), k.Label, k.KeyType, k.KeySize)
}

func (kp *KeyPair) Public() crypto.PublicKey {
	return kp.PublicKey
}

// AsSigner returns a crypto.Signer implementation for this key pair.
// Supports RSA, ECDSA, and ED25519 key types.
func (kp *KeyPair) AsSigner() crypto.Signer {
	switch kp.KeyType {
	case KeyPairTypeRSA:
		signer, _ := NewRSAKeyPair(kp)
		return signer
	case KeyPairTypeECDSA:
		signer, _ := NewECDSAKeyPair(kp)
		return signer
	case KeyPairTypeED25519:
		signer, _ := NewED25519KeyPair(kp)
		return signer
	default:
		return nil
	}
}

// AsDecrypter returns a crypto.Decrypter implementation for this key pair.
// Only RSA keys support decryption operations.
func (kp *KeyPair) AsDecrypter() (crypto.Decrypter, error) {
	if kp.KeyType != KeyPairTypeRSA {
		return nil, NewPKCS11Error(ErrUnknown, "decryption is only supported for RSA keys", nil)
	}
	return NewRSAKeyPair(kp)
}

// SymmetricKeyType represents the type of symmetric encryption key.
type SymmetricKeyType int

const (
	// SymmetricKeyTypeAES represents AES symmetric keys (128, 192, 256 bits)
	SymmetricKeyTypeAES SymmetricKeyType = iota + 1
	// SymmetricKeyTypeDES represents DES symmetric keys (64 bits)
	SymmetricKeyTypeDES
	// SymmetricKeyType3DES represents 3DES symmetric keys (192 bits)
	SymmetricKeyType3DES
)

// SymmetricKey represents a symmetric encryption key stored in the PKCS#11 HSM.
// It can be used for encryption, decryption, key wrapping, and key unwrapping operations.
type SymmetricKey struct {
	token *Token

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

// String returns a string representation of the symmetric key.
func (k *SymmetricKey) String() string {
	return fmt.Sprintf("SymmetricKey{Label: %s, Type: %v, Size: %d}", k.Label, k.KeyType, k.KeySize)
}
