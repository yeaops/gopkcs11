package gopkcs11

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
)

// Object represents a PKCS#11 object
type Object interface {
	Handle() uint
	GetAttribute(attributeType AttributeType) (*Attribute, error)
	GetAttributeValue(template []*Attribute) ([]*Attribute, error)
	GetObjectClass() (ObjectClass, error)
	GetLabel() (string, error)
	GetID() ([]byte, error)
}

// object is the internal implementation of Object
type object struct {
	session *Session
	handle  uint
}

// Handle returns the object handle
func (o *object) Handle() uint {
	return o.handle
}

// GetAttribute gets an attribute value
func (o *object) GetAttribute(attributeType AttributeType) (*Attribute, error) {
	template := []*Attribute{
		{Type: attributeType},
	}

	attributes, err := o.session.GetAttributeValue(o, template)
	if err != nil {
		return nil, err
	}

	if len(attributes) != 1 {
		return nil, fmt.Errorf("unexpected number of attributes returned")
	}

	return attributes[0], nil
}

// GetAttributeValue gets the values of multiple attributes
func (o *object) GetAttributeValue(template []*Attribute) ([]*Attribute, error) {
	return o.session.GetAttributeValue(o, template)
}

// GetObjectClass gets the object class
func (o *object) GetObjectClass() (ObjectClass, error) {
	attr, err := o.GetAttribute(CKA_CLASS)
	if err != nil {
		return 0, err
	}

	value, err := attr.GetUint()
	if err != nil {
		return 0, err
	}

	return ObjectClass(value), nil
}

// GetLabel gets the object label
func (o *object) GetLabel() (string, error) {
	attr, err := o.GetAttribute(CKA_LABEL)
	if err != nil {
		return "", err
	}

	return attr.GetString()
}

// GetID gets the object ID
func (o *object) GetID() ([]byte, error) {
	attr, err := o.GetAttribute(CKA_ID)
	if err != nil {
		return nil, err
	}

	return attr.GetBytes()
}

// Key is a PKCS#11 key object
type Key interface {
	Object
	GetKeyType() (KeyType, error)
}

// PublicKey is a PKCS#11 public key
type PublicKey interface {
	Key
	UsageEncrypt() (bool, error)
	UsageVerify() (bool, error)
	UsageWrap() (bool, error)
	Modulus() ([]byte, error)
	PublicExponent() ([]byte, error)
	ECParams() ([]byte, error)
	ECPoint() ([]byte, error)
}

// PrivateKey is a PKCS#11 private key
type PrivateKey interface {
	Key
	UsageDecrypt() (bool, error)
	UsageSign() (bool, error)
	UsageUnwrap() (bool, error)
}

// SecretKey is a PKCS#11 secret key
type SecretKey interface {
	Key
	UsageEncrypt() (bool, error)
	UsageDecrypt() (bool, error)
	UsageWrap() (bool, error)
	UsageUnwrap() (bool, error)
	GetValueLen() (uint, error)
}

// publicKey is the internal implementation of PublicKey
type publicKey struct {
	object Object
}

// Handle returns the object handle
func (k *publicKey) Handle() uint {
	return k.object.Handle()
}

// GetAttribute gets an attribute value
func (k *publicKey) GetAttribute(attributeType AttributeType) (*Attribute, error) {
	return k.object.GetAttribute(attributeType)
}

// GetAttributeValue gets the values of multiple attributes
func (k *publicKey) GetAttributeValue(template []*Attribute) ([]*Attribute, error) {
	return k.object.GetAttributeValue(template)
}

// GetObjectClass gets the object class
func (k *publicKey) GetObjectClass() (ObjectClass, error) {
	return k.object.GetObjectClass()
}

// GetLabel gets the object label
func (k *publicKey) GetLabel() (string, error) {
	return k.object.GetLabel()
}

// GetID gets the object ID
func (k *publicKey) GetID() ([]byte, error) {
	return k.object.GetID()
}

// GetKeyType gets the key type
func (k *publicKey) GetKeyType() (KeyType, error) {
	attr, err := k.GetAttribute(CKA_KEY_TYPE)
	if err != nil {
		return 0, err
	}

	value, err := attr.GetUint()
	if err != nil {
		return 0, err
	}

	return KeyType(value), nil
}

// UsageEncrypt checks if the key can be used for encryption
func (k *publicKey) UsageEncrypt() (bool, error) {
	attr, err := k.GetAttribute(CKA_ENCRYPT)
	if err != nil {
		return false, err
	}

	return attr.GetBool()
}

// UsageVerify checks if the key can be used for verification
func (k *publicKey) UsageVerify() (bool, error) {
	attr, err := k.GetAttribute(CKA_VERIFY)
	if err != nil {
		return false, err
	}

	return attr.GetBool()
}

// UsageWrap checks if the key can be used for wrapping
func (k *publicKey) UsageWrap() (bool, error) {
	attr, err := k.GetAttribute(CKA_WRAP)
	if err != nil {
		return false, err
	}

	return attr.GetBool()
}

// Modulus gets the RSA modulus
func (k *publicKey) Modulus() ([]byte, error) {
	keyType, err := k.GetKeyType()
	if err != nil {
		return nil, err
	}

	if keyType != CKK_RSA {
		return nil, fmt.Errorf("not an RSA key")
	}

	attr, err := k.GetAttribute(CKA_MODULUS)
	if err != nil {
		return nil, err
	}

	return attr.GetBytes()
}

// PublicExponent gets the RSA public exponent
func (k *publicKey) PublicExponent() ([]byte, error) {
	keyType, err := k.GetKeyType()
	if err != nil {
		return nil, err
	}

	if keyType != CKK_RSA {
		return nil, fmt.Errorf("not an RSA key")
	}

	attr, err := k.GetAttribute(CKA_PUBLIC_EXPONENT)
	if err != nil {
		return nil, err
	}

	return attr.GetBytes()
}

// ECParams gets the EC parameters
func (k *publicKey) ECParams() ([]byte, error) {
	keyType, err := k.GetKeyType()
	if err != nil {
		return nil, err
	}

	if keyType != CKK_EC {
		return nil, fmt.Errorf("not an EC key")
	}

	attr, err := k.GetAttribute(CKA_EC_PARAMS)
	if err != nil {
		return nil, err
	}

	return attr.GetBytes()
}

// ECPoint gets the EC point
func (k *publicKey) ECPoint() ([]byte, error) {
	keyType, err := k.GetKeyType()
	if err != nil {
		return nil, err
	}

	if keyType != CKK_EC {
		return nil, fmt.Errorf("not an EC key")
	}

	attr, err := k.GetAttribute(CKA_EC_POINT)
	if err != nil {
		return nil, err
	}

	return attr.GetBytes()
}

// privateKey is the internal implementation of PrivateKey
type privateKey struct {
	object Object
}

// Handle returns the object handle
func (k *privateKey) Handle() uint {
	return k.object.Handle()
}

// GetAttribute gets an attribute value
func (k *privateKey) GetAttribute(attributeType AttributeType) (*Attribute, error) {
	return k.object.GetAttribute(attributeType)
}

// GetAttributeValue gets the values of multiple attributes
func (k *privateKey) GetAttributeValue(template []*Attribute) ([]*Attribute, error) {
	return k.object.GetAttributeValue(template)
}

// GetObjectClass gets the object class
func (k *privateKey) GetObjectClass() (ObjectClass, error) {
	return k.object.GetObjectClass()
}

// GetLabel gets the object label
func (k *privateKey) GetLabel() (string, error) {
	return k.object.GetLabel()
}

// GetID gets the object ID
func (k *privateKey) GetID() ([]byte, error) {
	return k.object.GetID()
}

// GetKeyType gets the key type
func (k *privateKey) GetKeyType() (KeyType, error) {
	attr, err := k.GetAttribute(CKA_KEY_TYPE)
	if err != nil {
		return 0, err
	}

	value, err := attr.GetUint()
	if err != nil {
		return 0, err
	}

	return KeyType(value), nil
}

// UsageDecrypt checks if the key can be used for decryption
func (k *privateKey) UsageDecrypt() (bool, error) {
	attr, err := k.GetAttribute(CKA_DECRYPT)
	if err != nil {
		return false, err
	}

	return attr.GetBool()
}

// UsageSign checks if the key can be used for signing
func (k *privateKey) UsageSign() (bool, error) {
	attr, err := k.GetAttribute(CKA_SIGN)
	if err != nil {
		return false, err
	}

	return attr.GetBool()
}

// UsageUnwrap checks if the key can be used for unwrapping
func (k *privateKey) UsageUnwrap() (bool, error) {
	attr, err := k.GetAttribute(CKA_UNWRAP)
	if err != nil {
		return false, err
	}

	return attr.GetBool()
}

// secretKey is the internal implementation of SecretKey
type secretKey struct {
	object Object
}

// Handle returns the object handle
func (k *secretKey) Handle() uint {
	return k.object.Handle()
}

// GetAttribute gets an attribute value
func (k *secretKey) GetAttribute(attributeType AttributeType) (*Attribute, error) {
	return k.object.GetAttribute(attributeType)
}

// GetAttributeValue gets the values of multiple attributes
func (k *secretKey) GetAttributeValue(template []*Attribute) ([]*Attribute, error) {
	return k.object.GetAttributeValue(template)
}

// GetObjectClass gets the object class
func (k *secretKey) GetObjectClass() (ObjectClass, error) {
	return k.object.GetObjectClass()
}

// GetLabel gets the object label
func (k *secretKey) GetLabel() (string, error) {
	return k.object.GetLabel()
}

// GetID gets the object ID
func (k *secretKey) GetID() ([]byte, error) {
	return k.object.GetID()
}

// GetKeyType gets the key type
func (k *secretKey) GetKeyType() (KeyType, error) {
	attr, err := k.GetAttribute(CKA_KEY_TYPE)
	if err != nil {
		return 0, err
	}

	value, err := attr.GetUint()
	if err != nil {
		return 0, err
	}

	return KeyType(value), nil
}

// UsageEncrypt checks if the key can be used for encryption
func (k *secretKey) UsageEncrypt() (bool, error) {
	attr, err := k.GetAttribute(CKA_ENCRYPT)
	if err != nil {
		return false, err
	}

	return attr.GetBool()
}

// UsageDecrypt checks if the key can be used for decryption
func (k *secretKey) UsageDecrypt() (bool, error) {
	attr, err := k.GetAttribute(CKA_DECRYPT)
	if err != nil {
		return false, err
	}

	return attr.GetBool()
}

// UsageWrap checks if the key can be used for wrapping
func (k *secretKey) UsageWrap() (bool, error) {
	attr, err := k.GetAttribute(CKA_WRAP)
	if err != nil {
		return false, err
	}

	return attr.GetBool()
}

// UsageUnwrap checks if the key can be used for unwrapping
func (k *secretKey) UsageUnwrap() (bool, error) {
	attr, err := k.GetAttribute(CKA_UNWRAP)
	if err != nil {
		return false, err
	}

	return attr.GetBool()
}

// GetValueLen gets the key length in bytes
func (k *secretKey) GetValueLen() (uint, error) {
	attr, err := k.GetAttribute(CKA_VALUE_LEN)
	if err != nil {
		return 0, err
	}

	return attr.GetUint()
}

// signer implements the crypto.Signer interface
type signer struct {
	session *Session
	key     PrivateKey
	pubKey  crypto.PublicKey
}

// Public returns the public key corresponding to the opaque private key
func (s *signer) Public() crypto.PublicKey {
	return s.pubKey
}

// Sign signs digest with the private key
func (s *signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	keyType, err := s.key.GetKeyType()
	if err != nil {
		return nil, err
	}

	var mechanism *Mechanism

	switch keyType {
	case CKK_RSA:
		if opts != nil && opts.HashFunc() != crypto.Hash(0) {
			switch opts.HashFunc() {
			case crypto.SHA1:
				mechanism = NewMechanism(CKM_SHA1_RSA_PKCS, nil)
			case crypto.SHA256:
				mechanism = NewMechanism(CKM_SHA256_RSA_PKCS, nil)
			case crypto.SHA384:
				mechanism = NewMechanism(CKM_SHA384_RSA_PKCS, nil)
			case crypto.SHA512:
				mechanism = NewMechanism(CKM_SHA512_RSA_PKCS, nil)
			default:
				mechanism = NewMechanism(CKM_RSA_PKCS, nil)
			}
		} else {
			mechanism = NewMechanism(CKM_RSA_PKCS, nil)
		}
	case CKK_EC:
		mechanism = NewMechanism(CKM_ECDSA, nil)
	default:
		return nil, fmt.Errorf("unsupported key type")
	}

	if err := s.session.SignInit(mechanism, s.key); err != nil {
		return nil, err
	}

	signature, err = s.session.Sign(digest)
	if err != nil {
		return nil, err
	}

	if keyType == CKK_EC {
		// Convert ASN.1 signature to raw R || S format
		type ECDSASignature struct {
			R, S *big.Int
		}

		var ecdsaSig ECDSASignature
		if _, err := asn1.Unmarshal(signature, &ecdsaSig); err != nil {
			return nil, err
		}

		// Determine curve size from public key
		curve := s.pubKey.(*ecdsa.PublicKey).Curve
		keySize := (curve.Params().BitSize + 7) / 8

		// Pad R and S to curve size
		rBytes := ecdsaSig.R.Bytes()
		sBytes := ecdsaSig.S.Bytes()

		rawSig := make([]byte, keySize*2)
		copy(rawSig[keySize-len(rBytes):keySize], rBytes)
		copy(rawSig[keySize*2-len(sBytes):keySize*2], sBytes)

		signature = rawSig
	}

	return signature, nil
}

// NewSigner creates a new crypto.Signer interface for the given private key
func (ctx *Context) NewSigner(session *Session, privKey PrivateKey) (crypto.Signer, error) {
	keyType, err := privKey.GetKeyType()
	if err != nil {
		return nil, err
	}

	// Get key ID to find corresponding public key
	id, err := privKey.GetID()
	if err != nil {
		return nil, err
	}

	// Find corresponding public key
	publicKeys, err := session.FindObjects([]*Attribute{
		NewAttributeClass(CKO_PUBLIC_KEY),
		NewAttribute(CKA_ID, id),
	})
	if err != nil || len(publicKeys) == 0 {
		return nil, fmt.Errorf("public key not found")
	}

	pubKey := &publicKey{object: publicKeys[0]}

	var cryptoPubKey crypto.PublicKey

	switch keyType {
	case CKK_RSA:
		modBytes, err := pubKey.Modulus()
		if err != nil {
			return nil, err
		}

		expBytes, err := pubKey.PublicExponent()
		if err != nil {
			return nil, err
		}

		modulus := new(big.Int).SetBytes(modBytes)

		var exponent int
		switch len(expBytes) {
		case 1:
			exponent = int(expBytes[0])
		case 2:
			exponent = int(binary.BigEndian.Uint16(expBytes))
		case 3:
			exponent = int(binary.BigEndian.Uint32(append([]byte{0}, expBytes...)))
		case 4:
			exponent = int(binary.BigEndian.Uint32(expBytes))
		default:
			return nil, fmt.Errorf("unsupported exponent size")
		}

		cryptoPubKey = &rsa.PublicKey{
			N: modulus,
			E: exponent,
		}
	case CKK_EC:
		paramBytes, err := pubKey.ECParams()
		if err != nil {
			return nil, err
		}

		pointBytes, err := pubKey.ECPoint()
		if err != nil {
			return nil, err
		}

		// Determine the curve from the OID
		var curve elliptic.Curve
		oid := paramBytes

		// The most common curves
		// ANSI X9.62 prime256v1 (OID: 1.2.840.10045.3.1.7)
		prime256v1 := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
		// secp384r1 (OID: 1.3.132.0.34)
		secp384r1 := []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}
		// secp521r1 (OID: 1.3.132.0.35)
		secp521r1 := []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23}

		if bytes.Equal(oid, prime256v1) {
			curve = elliptic.P256()
		} else if bytes.Equal(oid, secp384r1) {
			curve = elliptic.P384()
		} else if bytes.Equal(oid, secp521r1) {
			curve = elliptic.P521()
		} else {
			return nil, fmt.Errorf("unsupported curve")
		}

		// EC points are typically encoded with a 0x04 prefix to indicate uncompressed format,
		// followed by the x and y coordinates
		x, y := elliptic.Unmarshal(curve, pointBytes[2:]) // Skip ASN.1 header bytes
		if x == nil {
			return nil, fmt.Errorf("invalid EC point")
		}

		cryptoPubKey = &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}
	default:
		return nil, fmt.Errorf("unsupported key type")
	}

	return &signer{
		session: session,
		key:     privKey,
		pubKey:  cryptoPubKey,
	}, nil
}
