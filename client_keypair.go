package gopkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"
	"github.com/rs/xid"
)

// GenerateRSAKeyPair generates a new RSA key pair in the PKCS#11 device.
// Supported key sizes are 2048 and 4096 bits.
// The generated keys are marked as non-extractable and sensitive for security.
func (c *Client) GenerateRSAKeyPair(keySize int, attrs ...*Attribute) (*KeyPair, error) {
	if keySize != 2048 && keySize != 4096 {
		return nil, NewPKCS11Error(ErrInvalidInput, "RSA key size must be 2048 or 4096", nil)
	}

	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// default attributes
	newId := xid.New()
	label := newId.String()
	keyID := newId.Bytes()
	defaultPublicKeyTemplateMap := map[uint]any{
		pkcs11.CKA_CLASS:    pkcs11.CKO_PUBLIC_KEY,
		pkcs11.CKA_KEY_TYPE: pkcs11.CKK_RSA,
		pkcs11.CKA_LABEL:    label,
		pkcs11.CKA_ID:       keyID,
		pkcs11.CKA_TOKEN:    true,

		pkcs11.CKA_VERIFY:  true,
		pkcs11.CKA_ENCRYPT: true,
		pkcs11.CKA_WRAP:    true,

		pkcs11.CKA_MODULUS_BITS:    keySize,
		pkcs11.CKA_PUBLIC_EXPONENT: []byte{0x01, 0x00, 0x01},
	}
	defaultPrivateKeyTemplateMap := map[uint]any{
		pkcs11.CKA_CLASS:    pkcs11.CKO_PRIVATE_KEY,
		pkcs11.CKA_KEY_TYPE: pkcs11.CKK_RSA,
		pkcs11.CKA_LABEL:    label,
		pkcs11.CKA_ID:       keyID,
		pkcs11.CKA_TOKEN:    true,

		pkcs11.CKA_SIGN:    true,
		pkcs11.CKA_DECRYPT: true,
		pkcs11.CKA_UNWRAP:  true,

		pkcs11.CKA_PRIVATE:     true,
		pkcs11.CKA_SENSITIVE:   true,
		pkcs11.CKA_EXTRACTABLE: false,
	}

	pubHandle, privHandle, err := c.ctx.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		attributeMap2Slice(mergeAttribute(defaultPublicKeyTemplateMap, attrs)),
		attributeMap2Slice(mergeAttribute(defaultPrivateKeyTemplateMap, attrs)),
	)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	publicKey, err := c.extractRSAPublicKey(pubHandle)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		client: c,

		Handle:       privHandle,
		PublicHandle: pubHandle,
		Label:        label,
		ID:           keyID,
		KeyType:      KeyPairTypeRSA,
		KeySize:      keySize,
		PublicKey:    publicKey,
	}, nil
}

// GenerateECDSAKeyPair generates a new ECDSA key pair in the PKCS#11 device.
// Supported curves are P-256 and P-384.
// The generated keys are marked as non-extractable and sensitive for security.
func (c *Client) GenerateECDSAKeyPair(curve elliptic.Curve, attrs ...*Attribute) (*KeyPair, error) {
	var curveOID []byte
	var keySize int

	switch curve {
	case elliptic.P256():
		curveOID = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
		keySize = 256
	case elliptic.P384():
		curveOID = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}
		keySize = 384
	default:
		return nil, NewPKCS11Error(ErrUnknown, "unsupported elliptic curve", nil)
	}

	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// default attributes
	newId := xid.New()
	label := newId.String()
	keyID := newId.Bytes()

	defaultPublicKeyTemplateMap := map[uint]any{
		pkcs11.CKA_CLASS:    pkcs11.CKO_PUBLIC_KEY,
		pkcs11.CKA_KEY_TYPE: pkcs11.CKK_ECDSA,
		pkcs11.CKA_LABEL:    label,
		pkcs11.CKA_ID:       keyID,
		pkcs11.CKA_TOKEN:    true,

		pkcs11.CKA_VERIFY:  true,
		pkcs11.CKA_ENCRYPT: true,
		pkcs11.CKA_WRAP:    true,

		pkcs11.CKA_EC_PARAMS: curveOID,
	}
	defaultPrivateKeyTemplateMap := map[uint]any{
		pkcs11.CKA_CLASS:    pkcs11.CKO_PRIVATE_KEY,
		pkcs11.CKA_KEY_TYPE: pkcs11.CKK_ECDSA,
		pkcs11.CKA_LABEL:    label,
		pkcs11.CKA_ID:       keyID,
		pkcs11.CKA_TOKEN:    true,

		pkcs11.CKA_SIGN:    true,
		pkcs11.CKA_DECRYPT: true,
		pkcs11.CKA_UNWRAP:  true,

		pkcs11.CKA_PRIVATE:     true,
		pkcs11.CKA_SENSITIVE:   true,
		pkcs11.CKA_EXTRACTABLE: false,
	}

	pubHandle, privHandle, err := c.ctx.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		attributeMap2Slice(mergeAttribute(defaultPublicKeyTemplateMap, attrs)),
		attributeMap2Slice(mergeAttribute(defaultPrivateKeyTemplateMap, attrs)),
	)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	publicKey, err := c.extractECDSAPublicKey(pubHandle)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		client: c,

		Handle:       privHandle,
		PublicHandle: pubHandle,
		Label:        label,
		ID:           keyID,
		KeyType:      KeyPairTypeECDSA,
		KeySize:      keySize,
		PublicKey:    publicKey,
	}, nil
}

// GenerateED25519KeyPair generates a new ED25519 key pair in the PKCS#11 device.
// ED25519 is a modern elliptic curve signature scheme providing high security and performance.
// The generated keys are marked as non-extractable and sensitive for security.
func (c *Client) GenerateED25519KeyPair(attrs ...*Attribute) (*KeyPair, error) {
	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// ED25519 curve OID: 1.3.101.112
	ed25519OID := []byte{0x06, 0x03, 0x2b, 0x65, 0x70}

	// default attributes
	newId := xid.New()
	label := newId.String()
	keyID := newId.Bytes()

	defaultPublicKeyTemplateMap := map[uint]any{
		pkcs11.CKA_CLASS:    pkcs11.CKO_PUBLIC_KEY,
		pkcs11.CKA_KEY_TYPE: CKK_EC_EDWARDS,
		pkcs11.CKA_LABEL:    label,
		pkcs11.CKA_ID:       keyID,
		pkcs11.CKA_TOKEN:    true,

		pkcs11.CKA_VERIFY:  true,
		pkcs11.CKA_ENCRYPT: true,
		pkcs11.CKA_WRAP:    true,

		pkcs11.CKA_EC_PARAMS: ed25519OID,
	}

	defaultPrivateKeyTemplateMap := map[uint]any{
		pkcs11.CKA_CLASS:    pkcs11.CKO_PRIVATE_KEY,
		pkcs11.CKA_KEY_TYPE: CKK_EC_EDWARDS,
		pkcs11.CKA_LABEL:    label,
		pkcs11.CKA_ID:       keyID,
		pkcs11.CKA_TOKEN:    true,

		pkcs11.CKA_SIGN:    true,
		pkcs11.CKA_DECRYPT: true,
		pkcs11.CKA_UNWRAP:  true,

		pkcs11.CKA_PRIVATE:     true,
		pkcs11.CKA_SENSITIVE:   true,
		pkcs11.CKA_EXTRACTABLE: false,
	}

	pubHandle, privHandle, err := c.ctx.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_EC_EDWARDS_KEY_PAIR_GEN, nil)},
		attributeMap2Slice(mergeAttribute(defaultPublicKeyTemplateMap, attrs)),
		attributeMap2Slice(mergeAttribute(defaultPrivateKeyTemplateMap, attrs)),
	)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	publicKey, err := c.extractED25519PublicKey(pubHandle)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		client: c,

		Handle:       privHandle,
		PublicHandle: pubHandle,
		Label:        label,
		ID:           keyID,
		KeyType:      KeyPairTypeED25519,
		KeySize:      255, // ED25519 uses 255-bit keys
		PublicKey:    publicKey,
	}, nil
}

// GetKeyPair searches for a key pair by its unique ID.
// Returns an error if no key is found with the specified ID.
func (c *Client) GetKeyPair(id []byte) (*KeyPair, error) {
	privHandle, err := c.getPrivateKeyHandle(id)
	if err != nil {
		return nil, err
	}

	return c.getKeyPair(privHandle)
}

// ListKeyPairs returns all key pairs stored in the PKCS#11 device.
// Keys that cannot be processed (due to unsupported types, etc.) are silently skipped.
func (c *Client) ListKeyPairs(attrs ...*Attribute) ([]*KeyPair, error) {
	privateHandles, err := c.listPrivateKeyHandles(attrs...)
	if err != nil {
		return nil, err
	}

	// construct all keypairs
	var keys []*KeyPair
	for _, handle := range privateHandles {
		keyPair, err := c.getKeyPair(handle)
		if err != nil {
			continue
		}
		keys = append(keys, keyPair)
	}

	return keys, nil
}

// ImportRSAKeyPair imports an existing RSA private key into the PKCS#11 device.
// The imported key is marked as non-extractable and sensitive for security.
// Both the private and public key objects are created in the device.
func (c *Client) ImportRSAKeyPair(privateKey *rsa.PrivateKey, attrs ...*Attribute) (*KeyPair, error) {
	if privateKey == nil {
		return nil, NewPKCS11Error(ErrInvalidInput, "private key cannot be nil", nil)
	}

	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// default attributes
	newId := xid.New()
	label := newId.String()
	keyID := newId.Bytes()

	// Import private key
	defaultPrivateKeyTemplateMap := map[uint]any{
		pkcs11.CKA_CLASS:    pkcs11.CKO_PRIVATE_KEY,
		pkcs11.CKA_KEY_TYPE: pkcs11.CKK_RSA,
		pkcs11.CKA_LABEL:    label,
		pkcs11.CKA_ID:       keyID,
		pkcs11.CKA_TOKEN:    true,

		pkcs11.CKA_SIGN:    true,
		pkcs11.CKA_DECRYPT: true,
		pkcs11.CKA_UNWRAP:  false,

		pkcs11.CKA_PRIVATE:     true,
		pkcs11.CKA_SENSITIVE:   true,
		pkcs11.CKA_EXTRACTABLE: false,

		pkcs11.CKA_MODULUS:          privateKey.N.Bytes(),
		pkcs11.CKA_PUBLIC_EXPONENT:  big.NewInt(int64(privateKey.E)).Bytes(),
		pkcs11.CKA_PRIVATE_EXPONENT: privateKey.D.Bytes(),
		pkcs11.CKA_PRIME_1:          privateKey.Primes[0].Bytes(),
		pkcs11.CKA_PRIME_2:          privateKey.Primes[1].Bytes(),
		pkcs11.CKA_EXPONENT_1:       privateKey.Precomputed.Dp.Bytes(),
		pkcs11.CKA_EXPONENT_2:       privateKey.Precomputed.Dq.Bytes(),
		pkcs11.CKA_COEFFICIENT:      privateKey.Precomputed.Qinv.Bytes(),
	}
	privateKeyTemplate := attributeMap2Slice(mergeAttribute(defaultPrivateKeyTemplateMap, attrs))

	privHandle, err := c.ctx.CreateObject(session, privateKeyTemplate)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Import corresponding public key
	defaultPublicKeyTemplateMap := map[uint]any{
		pkcs11.CKA_CLASS:    pkcs11.CKO_PUBLIC_KEY,
		pkcs11.CKA_KEY_TYPE: pkcs11.CKK_RSA,
		pkcs11.CKA_LABEL:    label,
		pkcs11.CKA_ID:       keyID,
		pkcs11.CKA_TOKEN:    true,

		pkcs11.CKA_VERIFY:  true,
		pkcs11.CKA_ENCRYPT: true,
		pkcs11.CKA_WRAP:    false,

		pkcs11.CKA_MODULUS:         privateKey.N.Bytes(),
		pkcs11.CKA_PUBLIC_EXPONENT: big.NewInt(int64(privateKey.E)).Bytes(),
	}
	publicKeyTemplate := attributeMap2Slice(mergeAttribute(defaultPublicKeyTemplateMap, attrs))

	pubHandle, err := c.ctx.CreateObject(session, publicKeyTemplate)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	publicKey, err := c.extractRSAPublicKey(pubHandle)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		client: c,

		Handle:       privHandle,
		PublicHandle: pubHandle,
		Label:        label,
		ID:           keyID,
		KeyType:      KeyPairTypeRSA,
		KeySize:      privateKey.Size() * 8,
		PublicKey:    publicKey,
	}, nil
}

// ImportECDSAKeyPair imports an existing ECDSA private key into the PKCS#11 device.
// The imported key is marked as non-extractable and sensitive for security.
// Both the private and public key objects are created in the device.
func (c *Client) ImportECDSAKeyPair(privateKey *ecdsa.PrivateKey, attrs ...*Attribute) (*KeyPair, error) {
	if privateKey == nil {
		return nil, NewPKCS11Error(ErrInvalidInput, "private key cannot be nil", nil)
	}

	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	var curveOID []byte
	var keySize int

	switch privateKey.Curve {
	case elliptic.P256():
		curveOID = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
		keySize = 256
	case elliptic.P384():
		curveOID = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}
		keySize = 384
	default:
		return nil, NewPKCS11Error(ErrInvalidInput, "unsupported elliptic curve", nil)
	}

	// default attributes
	newId := xid.New()
	label := newId.String()
	keyID := newId.Bytes()

	// Import private key
	defaultPrivateKeyTemplateMap := map[uint]any{
		pkcs11.CKA_CLASS:    pkcs11.CKO_PRIVATE_KEY,
		pkcs11.CKA_KEY_TYPE: pkcs11.CKK_ECDSA,
		pkcs11.CKA_LABEL:    label,
		pkcs11.CKA_ID:       keyID,
		pkcs11.CKA_TOKEN:    true,

		pkcs11.CKA_SIGN:    true,
		pkcs11.CKA_DECRYPT: true,
		pkcs11.CKA_UNWRAP:  false,

		pkcs11.CKA_PRIVATE:     true,
		pkcs11.CKA_SENSITIVE:   true,
		pkcs11.CKA_EXTRACTABLE: false,

		pkcs11.CKA_EC_PARAMS: curveOID,
		pkcs11.CKA_VALUE:     privateKey.D.Bytes(),
	}
	privateKeyTemplate := attributeMap2Slice(mergeAttribute(defaultPrivateKeyTemplateMap, attrs))

	privHandle, err := c.ctx.CreateObject(session, privateKeyTemplate)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Create EC point for public key
	// Format: 0x04 + X coordinate + Y coordinate
	coordSize := (keySize + 7) / 8
	ecPoint := make([]byte, 1+2*coordSize)
	ecPoint[0] = 0x04

	xBytes := privateKey.X.Bytes()
	yBytes := privateKey.Y.Bytes()

	copy(ecPoint[1+coordSize-len(xBytes):1+coordSize], xBytes)
	copy(ecPoint[1+2*coordSize-len(yBytes):], yBytes)

	// Wrap EC point in OCTET STRING for PKCS#11
	ecPointWrapped := append([]byte{0x04, byte(len(ecPoint))}, ecPoint...)

	// Import corresponding public key
	defaultPublicKeyTemplateMap := map[uint]any{
		pkcs11.CKA_CLASS:    pkcs11.CKO_PUBLIC_KEY,
		pkcs11.CKA_KEY_TYPE: pkcs11.CKK_ECDSA,
		pkcs11.CKA_LABEL:    label,
		pkcs11.CKA_ID:       keyID,
		pkcs11.CKA_TOKEN:    true,

		pkcs11.CKA_VERIFY:  true,
		pkcs11.CKA_ENCRYPT: true,
		pkcs11.CKA_WRAP:    false,

		pkcs11.CKA_EC_PARAMS: curveOID,
		pkcs11.CKA_EC_POINT:  ecPointWrapped,
	}
	publicKeyTemplate := attributeMap2Slice(mergeAttribute(defaultPublicKeyTemplateMap, attrs))
	pubHandle, err := c.ctx.CreateObject(session, publicKeyTemplate)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	publicKey, err := c.extractECDSAPublicKey(pubHandle)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		client: c,

		Handle:       privHandle,
		PublicHandle: pubHandle,
		Label:        label,
		ID:           keyID,
		KeyType:      KeyPairTypeECDSA,
		KeySize:      keySize,
		PublicKey:    publicKey,
	}, nil
}

// ImportED25519KeyPair imports an existing ED25519 private key into the PKCS#11 device.
// The imported key is marked as non-extractable and sensitive for security.
// Both the private and public key objects are created in the device.
// Uses a fallback strategy to handle different PKCS#11 implementation requirements.
func (c *Client) ImportED25519KeyPair(privateKey ed25519.PrivateKey, attrs ...*Attribute) (*KeyPair, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, NewPKCS11Error(ErrInvalidInput, "invalid ED25519 private key size", nil)
	}

	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// ED25519 curve OID: 1.3.101.112 (RFC 8410)
	ed25519OID := []byte{0x06, 0x03, 0x2b, 0x65, 0x70}

	// ED25519 private key is the first 32 bytes (seed), public key is the last 32 bytes
	privateKeySeed := []byte(privateKey[:32])
	publicKeyBytes := []byte(privateKey[32:])

	// Format public key for CKA_EC_POINT - most HSMs expect OCTET STRING format
	// OCTET STRING: 0x04 + length (0x20 = 32) + 32-byte public key
	ecPointValue := append([]byte{0x04, 0x20}, publicKeyBytes...)

	// default attributes
	newId := xid.New()
	label := newId.String()
	keyID := newId.Bytes()

	defaultPrivateKeyTemplateMap := map[uint]any{
		pkcs11.CKA_CLASS:    pkcs11.CKO_PRIVATE_KEY,
		pkcs11.CKA_KEY_TYPE: CKK_EC_EDWARDS,
		pkcs11.CKA_LABEL:    label,
		pkcs11.CKA_ID:       keyID,
		pkcs11.CKA_TOKEN:    true,

		pkcs11.CKA_SIGN:    true,
		pkcs11.CKA_DECRYPT: true,
		pkcs11.CKA_UNWRAP:  false,

		pkcs11.CKA_PRIVATE:     true,
		pkcs11.CKA_SENSITIVE:   true,
		pkcs11.CKA_EXTRACTABLE: false,

		pkcs11.CKA_EC_PARAMS: ed25519OID,
		pkcs11.CKA_VALUE:     privateKeySeed,
	}
	privateKeyTemplate := attributeMap2Slice(mergeAttribute(defaultPrivateKeyTemplateMap, attrs))

	privHandle, err := c.ctx.CreateObject(session, privateKeyTemplate)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	defaultPublicKeyTemplateMap := map[uint]any{
		pkcs11.CKA_CLASS:    pkcs11.CKO_PUBLIC_KEY,
		pkcs11.CKA_KEY_TYPE: CKK_EC_EDWARDS,
		pkcs11.CKA_LABEL:    label,
		pkcs11.CKA_ID:       keyID,
		pkcs11.CKA_TOKEN:    true,

		pkcs11.CKA_VERIFY:  true,
		pkcs11.CKA_ENCRYPT: true,
		pkcs11.CKA_WRAP:    false,

		pkcs11.CKA_EC_PARAMS: ed25519OID,
		pkcs11.CKA_EC_POINT:  ecPointValue,
	}
	publicKeyTemplate := attributeMap2Slice(mergeAttribute(defaultPublicKeyTemplateMap, attrs))

	pubHandle, err := c.ctx.CreateObject(session, publicKeyTemplate)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	publicKey, err := c.extractED25519PublicKey(pubHandle)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		client: c,

		Handle:       privHandle,
		PublicHandle: pubHandle,
		Label:        label,
		ID:           keyID,
		KeyType:      KeyPairTypeED25519,
		KeySize:      255, // ED25519 uses 255-bit keys
		PublicKey:    publicKey,
	}, nil
}

// ImportKeyPair imports a private key into the PKCS#11 device.
// It automatically detects the key type (RSA, ECDSA, or ED25519) and calls the appropriate import function.
func (c *Client) ImportKeyPair(privateKey crypto.PrivateKey, attrs ...*Attribute) (*KeyPair, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return c.ImportRSAKeyPair(key, attrs...)
	case *ecdsa.PrivateKey:
		return c.ImportECDSAKeyPair(key, attrs...)
	case ed25519.PrivateKey:
		return c.ImportED25519KeyPair(key, attrs...)
	default:
		return nil, NewPKCS11Error(ErrUnknown, "unsupported private key type", nil)
	}
}

// DeleteKeyPairByID deletes a key pair from the PKCS#11 device by its unique ID.
// Both the private and public key objects are removed from the device.
// Returns an error if the key pair is not found or if the deletion fails.
func (c *Client) DeleteKeyPair(keyID []byte) error {
	err1 := c.deletePrivateKey(keyID)
	err2 := c.deletePublicKey(keyID)

	if err1 != nil || err2 != nil {
		return fmt.Errorf("failed to delete key pair: private key error: %v, public key error: %v", err1, err2)
	}

	return nil
}

func (c *Client) listPublicKeyHandles(attrs ...*Attribute) ([]pkcs11.ObjectHandle, error) {
	attrsQuery := append(attrs, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY))
	return c.listKeyHandles(attrsQuery...)
}

func (c *Client) listPrivateKeyHandles(attrs ...*Attribute) ([]pkcs11.ObjectHandle, error) {
	attrsQuery := append(attrs, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY))
	return c.listKeyHandles(attrsQuery...)
}

func (c *Client) listKeyHandles(attrs ...*Attribute) ([]pkcs11.ObjectHandle, error) {
	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	if err := c.ctx.FindObjectsInit(session, attrs); err != nil {
		return nil, ConvertPKCS11Error(err)
	}
	var handles []pkcs11.ObjectHandle
	for {
		hds, more, err := c.ctx.FindObjects(session, 10)
		if err != nil {
			c.ctx.FindObjectsFinal(session)
			return nil, ConvertPKCS11Error(err)
		}
		handles = append(handles, hds...)

		if !more {
			break
		}
	}
	if err := c.ctx.FindObjectsFinal(session); err != nil {
		return nil, ConvertPKCS11Error(err)
	}
	return handles, nil
}

func (c *Client) getPrivateKeyHandle(keyID []byte) (pkcs11.ObjectHandle, error) {
	attrs := []*Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}
	handles, err := c.listKeyHandles(attrs...)
	if err != nil {
		return 0, err
	}
	if len(handles) == 0 {
		return 0, NewPKCS11Error(ErrKeyNotFound, "private key not found", nil)
	}
	return handles[0], nil
}

func (c *Client) getPublicKeyHandle(keyID []byte) (pkcs11.ObjectHandle, error) {
	attrs := []*Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}
	handles, err := c.listKeyHandles(attrs...)
	if err != nil {
		return 0, err
	}
	if len(handles) == 0 {
		return 0, NewPKCS11Error(ErrKeyNotFound, "private key not found", nil)
	}
	return handles[0], nil
}

// getKeyPair retrieves key pair information from a PKCS#11 object handle.
// It extracts key attributes and constructs a KeyPair structure with the public key.
func (c *Client) getKeyPair(privHandle pkcs11.ObjectHandle) (*KeyPair, error) {
	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	attrsQuery := []*Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	}

	attrs, err := c.ctx.GetAttributeValue(session, privHandle, attrsQuery)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	label := string(attrs[0].Value)
	id := attrs[1].Value
	keyTypeValue := attrs[2].Value

	if len(keyTypeValue) == 0 {
		return nil, NewPKCS11Error(ErrUnknown, "unable to determine key type", nil)
	}

	pubHandle, err := c.getPublicKeyHandle(id)
	if err != nil {
		return nil, err
	}

	var keyType KeyPairType
	var publicKey crypto.PublicKey
	var keySize int
	switch keyTypeValue[0] {
	case byte(pkcs11.CKK_RSA):
		keyType = KeyPairTypeRSA
		publicKey, err = c.extractRSAPublicKey(pubHandle)
		if err != nil {
			return nil, err
		}
		if rsaPub, ok := publicKey.(*rsa.PublicKey); ok {
			keySize = rsaPub.Size() * 8
		}
	case byte(pkcs11.CKK_ECDSA):
		keyType = KeyPairTypeECDSA
		publicKey, err = c.extractECDSAPublicKey(pubHandle)
		if err != nil {
			return nil, err
		}
		if ecdsaPub, ok := publicKey.(*ecdsa.PublicKey); ok {
			keySize = ecdsaPub.Curve.Params().BitSize
		}
	case byte(CKK_EC_EDWARDS):
		keyType = KeyPairTypeED25519
		publicKey, err = c.extractED25519PublicKey(pubHandle)
		if err != nil {
			return nil, err
		}
		keySize = 255 // ED25519 uses 255-bit keys
	default:
		return nil, NewPKCS11Error(ErrUnknown, "unsupported key type", nil)
	}

	return &KeyPair{
		client: c,

		Handle:       privHandle,
		PublicHandle: pubHandle,
		Label:        label,
		ID:           id,
		KeyType:      keyType,
		KeySize:      keySize,
		PublicKey:    publicKey,
	}, nil
}

// extractRSAPublicKey extracts RSA public key material from a PKCS#11 public key object.
// It retrieves the modulus and public exponent to construct a Go RSA public key.
func (c *Client) extractRSAPublicKey(pubHandle pkcs11.ObjectHandle) (*rsa.PublicKey, error) {
	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	attrsQeury := []*Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}

	attrs, err := c.ctx.GetAttributeValue(session, pubHandle, attrsQeury)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	n := new(big.Int).SetBytes(attrs[0].Value)
	e := new(big.Int).SetBytes(attrs[1].Value)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// extractECDSAPublicKey extracts an ECDSA public key from a public key handle,
// automatically determining the curve from the EC_PARAMS attribute.
// Supports P-256 and P-384 curves.
func (c *Client) extractECDSAPublicKey(pubHandle pkcs11.ObjectHandle) (*ecdsa.PublicKey, error) {
	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	attrsQuery := []*Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}

	attrs, err := c.ctx.GetAttributeValue(session, pubHandle, attrsQuery)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	var curve elliptic.Curve
	curveOID := attrs[0].Value

	if len(curveOID) >= 10 &&
		curveOID[0] == 0x06 && curveOID[1] == 0x08 &&
		curveOID[8] == 0x01 && curveOID[9] == 0x07 {
		curve = elliptic.P256()
	} else if len(curveOID) >= 7 &&
		curveOID[0] == 0x06 && curveOID[1] == 0x05 &&
		curveOID[6] == 0x22 {
		curve = elliptic.P384()
	} else {
		return nil, NewPKCS11Error(ErrUnknown, "unsupported elliptic curve", nil)
	}

	ecPoint := attrs[1].Value
	if len(ecPoint) < 3 || ecPoint[0] != 0x04 {
		return nil, NewPKCS11Error(ErrUnknown, "invalid EC point format", nil)
	}

	pointLen := (len(ecPoint) - 3) / 2
	xBytes := ecPoint[3 : 3+pointLen]
	yBytes := ecPoint[3+pointLen:]

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// extractECDSAPublicKeyWithCurve extracts an ECDSA public key from a public key handle,
// using the provided curve parameter instead of auto-detecting from EC_PARAMS.
// This is used during key generation when the curve is already known.
func (c *Client) extractECDSAPublicKeyWithCurve(pubHandle pkcs11.ObjectHandle, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	attrsQuery := []*Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}

	attrs, err := c.ctx.GetAttributeValue(session, pubHandle, attrsQuery)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	ecPoint := attrs[0].Value
	if len(ecPoint) < 3 || ecPoint[0] != 0x04 {
		return nil, NewPKCS11Error(ErrUnknown, "invalid EC point format", nil)
	}

	pointLen := (len(ecPoint) - 3) / 2
	xBytes := ecPoint[3 : 3+pointLen]
	yBytes := ecPoint[3+pointLen:]

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// extractED25519PublicKey extracts an ED25519 public key from a public key handle.
// ED25519 public keys are 32 bytes in their raw form.
func (c *Client) extractED25519PublicKey(pubHandle pkcs11.ObjectHandle) (ed25519.PublicKey, error) {
	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	attrsQuery := []*Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}

	attrs, err := c.ctx.GetAttributeValue(session, pubHandle, attrsQuery)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	ecPoint := attrs[0].Value

	// ED25519 public keys should be 32 bytes
	// The EC_POINT might be wrapped in an OCTET STRING
	var publicKeyBytes []byte
	if len(ecPoint) == 32 {
		// Direct 32-byte key
		publicKeyBytes = ecPoint
	} else if len(ecPoint) == 34 && ecPoint[0] == 0x04 && ecPoint[1] == 0x20 {
		// OCTET STRING wrapped: 0x04 + 0x20 (32 bytes length) + 32 bytes key
		publicKeyBytes = ecPoint[2:]
	} else {
		return nil, NewPKCS11Error(ErrUnknown, "invalid ED25519 public key format", nil)
	}

	if len(publicKeyBytes) != 32 {
		return nil, NewPKCS11Error(ErrUnknown, fmt.Sprintf("invalid ED25519 public key length: expected 32, got %d", len(publicKeyBytes)), nil)
	}

	return ed25519.PublicKey(publicKeyBytes), nil
}

func (c *Client) deletePrivateKey(keyID []byte) error {
	privHandle, err := c.getPrivateKeyHandle(keyID)
	if err != nil {
		return err
	}

	session, err := c.GetSession()
	if err != nil {
		return ConvertPKCS11Error(err)
	}
	if err := c.ctx.DestroyObject(session, privHandle); err != nil {
		return ConvertPKCS11Error(err)
	}

	return nil
}

func (c *Client) deletePublicKey(keyID []byte) error {
	pubHandles, err := c.listPublicKeyHandles(pkcs11.NewAttribute(pkcs11.CKA_ID, keyID))
	if err != nil {
		return err
	}

	session, err := c.GetSession()
	if err != nil {
		return ConvertPKCS11Error(err)
	}
	if len(pubHandles) > 0 {
		if err := c.ctx.DestroyObject(session, pubHandles[0]); err != nil {
			return ConvertPKCS11Error(err)
		}
	}

	return nil

}
