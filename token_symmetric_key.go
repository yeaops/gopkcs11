package gopkcs11

import (
	"context"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
	"github.com/rs/xid"
)

// GenerateAESKey generates a new AES symmetric key in the PKCS#11 device.
// Supported key sizes are 128, 192, and 256 bits.
// The generated key is marked as non-extractable and sensitive for security.
func (t *Token) GenerateAESKey(ctx context.Context, keySize int, attrs ...*Attribute) (*SymmetricKey, error) {
	if keySize != 128 && keySize != 192 && keySize != 256 {
		return nil, errors.New("AES key size must be 128, 192, or 256 bits")
	}

	session, err := t.GetSession(ctx)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}
	defer session.Release()

	sessionHandle := session.GetHandle()

	// default attributes
	newId := xid.New()
	label := newId.String()
	keyID := newId.Bytes()

	// AES key generation template
	defaultTemplateMap := map[uint]any{
		pkcs11.CKA_CLASS:    pkcs11.CKO_SECRET_KEY,
		pkcs11.CKA_KEY_TYPE: pkcs11.CKK_AES,
		pkcs11.CKA_LABEL:    label,
		pkcs11.CKA_ID:       keyID,
		pkcs11.CKA_TOKEN:    true,

		pkcs11.CKA_ENCRYPT: true,
		pkcs11.CKA_DECRYPT: true,
		pkcs11.CKA_WRAP:    true,
		pkcs11.CKA_UNWRAP:  true,

		pkcs11.CKA_PRIVATE:     true,
		pkcs11.CKA_SENSITIVE:   true,
		pkcs11.CKA_EXTRACTABLE: false,

		pkcs11.CKA_VALUE_LEN: keySize / 8,
	}
	template := attributeMap2Slice(mergeAttribute(defaultTemplateMap, attrs))

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)
	handle, err := session.GetCtx().GenerateKey(sessionHandle, []*pkcs11.Mechanism{mechanism}, template)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return t.getSymmetricKey(ctx, handle)
}

// GenerateDESKey generates a new DES symmetric key (64 bits) in the PKCS#11 device.
// The generated key is marked as non-extractable and sensitive for security.
func (t *Token) GenerateDESKey(ctx context.Context, attrs ...*Attribute) (*SymmetricKey, error) {
	session, err := t.GetSession(ctx)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}
	defer session.Release()

	sessionHandle := session.GetHandle()

	// default attributes
	newId := xid.New()
	label := newId.String()
	keyID := newId.Bytes()

	// DES key generation template
	defaultTemplateMap := map[uint]any{
		pkcs11.CKA_CLASS:    pkcs11.CKO_SECRET_KEY,
		pkcs11.CKA_KEY_TYPE: pkcs11.CKK_DES,
		pkcs11.CKA_LABEL:    label,
		pkcs11.CKA_ID:       keyID,
		pkcs11.CKA_TOKEN:    true,

		pkcs11.CKA_ENCRYPT: true,
		pkcs11.CKA_DECRYPT: true,
		pkcs11.CKA_WRAP:    true,
		pkcs11.CKA_UNWRAP:  true,

		pkcs11.CKA_PRIVATE:     true,
		pkcs11.CKA_SENSITIVE:   true,
		pkcs11.CKA_EXTRACTABLE: false,
	}
	template := attributeMap2Slice(mergeAttribute(defaultTemplateMap, attrs))

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_DES_KEY_GEN, nil)
	handle, err := session.GetCtx().GenerateKey(sessionHandle, []*pkcs11.Mechanism{mechanism}, template)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return t.getSymmetricKey(ctx, handle)
}

// Generate3DESKey generates a new 3DES symmetric key (192 bits) in the PKCS#11 device.
// The generated key is marked as non-extractable and sensitive for security.
func (t *Token) Generate3DESKey(ctx context.Context, attrs ...*Attribute) (*SymmetricKey, error) {
	session, err := t.GetSession(ctx)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}
	defer session.Release()

	sessionHandle := session.GetHandle()

	// default attributes
	newId := xid.New()
	label := newId.String()
	keyID := newId.Bytes()

	// 3DES key generation template
	defaultTemplateMap := map[uint]any{
		pkcs11.CKA_CLASS:    pkcs11.CKO_SECRET_KEY,
		pkcs11.CKA_KEY_TYPE: pkcs11.CKK_DES3,
		pkcs11.CKA_LABEL:    label,
		pkcs11.CKA_ID:       keyID,
		pkcs11.CKA_TOKEN:    true,

		pkcs11.CKA_ENCRYPT: true,
		pkcs11.CKA_DECRYPT: true,
		pkcs11.CKA_WRAP:    true,
		pkcs11.CKA_UNWRAP:  true,

		pkcs11.CKA_PRIVATE:     true,
		pkcs11.CKA_SENSITIVE:   true,
		pkcs11.CKA_EXTRACTABLE: false,
	}
	template := attributeMap2Slice(mergeAttribute(defaultTemplateMap, attrs))

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_DES3_KEY_GEN, nil)
	handle, err := session.GetCtx().GenerateKey(sessionHandle, []*pkcs11.Mechanism{mechanism}, template)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return t.getSymmetricKey(ctx, handle)
}

// ImportAESKey imports existing AES key material into the PKCS#11 device.
// Supported key sizes are 16, 24, or 32 bytes (128, 192, or 256 bits).
// The imported key is marked as non-extractable and sensitive for security.
func (t *Token) ImportAESKey(ctx context.Context, keyMaterial []byte, attrs ...*Attribute) (*SymmetricKey, error) {
	if len(keyMaterial) != 16 && len(keyMaterial) != 24 && len(keyMaterial) != 32 {
		return nil, errors.New("AES key material must be 16, 24, or 32 bytes (128, 192, or 256 bits)")
	}

	session, err := t.GetSession(ctx)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}
	defer session.Release()

	sessionHandle := session.GetHandle()

	// default attributes
	newId := xid.New()
	label := newId.String()
	keyID := newId.Bytes()

	// AES key import template
	defaultTemplateMap := map[uint]any{
		pkcs11.CKA_CLASS:    pkcs11.CKO_SECRET_KEY,
		pkcs11.CKA_KEY_TYPE: pkcs11.CKK_AES,
		pkcs11.CKA_LABEL:    label,
		pkcs11.CKA_ID:       keyID,
		pkcs11.CKA_TOKEN:    true,

		pkcs11.CKA_ENCRYPT: true,
		pkcs11.CKA_DECRYPT: true,
		pkcs11.CKA_WRAP:    true,
		pkcs11.CKA_UNWRAP:  true,

		pkcs11.CKA_PRIVATE:     true,
		pkcs11.CKA_SENSITIVE:   true,
		pkcs11.CKA_EXTRACTABLE: false,

		pkcs11.CKA_VALUE: keyMaterial,
	}
	template := attributeMap2Slice(mergeAttribute(defaultTemplateMap, attrs))

	handle, err := session.GetCtx().CreateObject(sessionHandle, template)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return t.getSymmetricKey(ctx, handle)
}

// ImportDESKey imports existing DES key material into the PKCS#11 device.
// Key material must be exactly 8 bytes (64 bits).
// The imported key is marked as non-extractable and sensitive for security.
func (t *Token) ImportDESKey(ctx context.Context, keyMaterial []byte, attrs ...*Attribute) (*SymmetricKey, error) {
	if len(keyMaterial) != 8 {
		return nil, errors.New("DES key material must be exactly 8 bytes (64 bits)")
	}

	session, err := t.GetSession(ctx)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}
	defer session.Release()

	sessionHandle := session.GetHandle()

	// default attributes
	newId := xid.New()
	label := newId.String()
	keyID := newId.Bytes()

	// DES key import template
	defaultTemplateMap := map[uint]any{
		pkcs11.CKA_CLASS:    pkcs11.CKO_SECRET_KEY,
		pkcs11.CKA_KEY_TYPE: pkcs11.CKK_DES,
		pkcs11.CKA_LABEL:    label,
		pkcs11.CKA_ID:       keyID,
		pkcs11.CKA_TOKEN:    true,

		pkcs11.CKA_ENCRYPT: true,
		pkcs11.CKA_DECRYPT: true,
		pkcs11.CKA_WRAP:    true,
		pkcs11.CKA_UNWRAP:  true,

		pkcs11.CKA_PRIVATE:     true,
		pkcs11.CKA_SENSITIVE:   true,
		pkcs11.CKA_EXTRACTABLE: false,

		pkcs11.CKA_VALUE: keyMaterial,
	}
	template := attributeMap2Slice(mergeAttribute(defaultTemplateMap, attrs))

	handle, err := session.GetCtx().CreateObject(sessionHandle, template)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return &SymmetricKey{
		token: t,

		Handle:  handle,
		Label:   label,
		ID:      keyID,
		KeyType: SymmetricKeyTypeDES,
		KeySize: 64,
	}, nil
}

// Import3DESKey imports existing 3DES key material into the PKCS#11 device.
// Key material must be exactly 24 bytes (192 bits).
// The imported key is marked as non-extractable and sensitive for security.
func (t *Token) Import3DESKey(ctx context.Context, keyMaterial []byte, attrs ...*Attribute) (*SymmetricKey, error) {
	if len(keyMaterial) != 24 {
		return nil, errors.New("3DES key material must be exactly 24 bytes (192 bits)")
	}

	session, err := t.GetSession(ctx)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}
	defer session.Release()

	sessionHandle := session.GetHandle()

	// default attributes
	newId := xid.New()
	label := newId.String()
	keyID := newId.Bytes()

	// 3DES key import template
	defaultTemplateMap := map[uint]any{
		pkcs11.CKA_CLASS:    pkcs11.CKO_SECRET_KEY,
		pkcs11.CKA_KEY_TYPE: pkcs11.CKK_DES3,
		pkcs11.CKA_LABEL:    label,
		pkcs11.CKA_ID:       keyID,
		pkcs11.CKA_TOKEN:    true,

		pkcs11.CKA_ENCRYPT: true,
		pkcs11.CKA_DECRYPT: true,
		pkcs11.CKA_WRAP:    true,
		pkcs11.CKA_UNWRAP:  true,

		pkcs11.CKA_PRIVATE:     true,
		pkcs11.CKA_SENSITIVE:   true,
		pkcs11.CKA_EXTRACTABLE: false,

		pkcs11.CKA_VALUE: keyMaterial,
	}
	template := attributeMap2Slice(mergeAttribute(defaultTemplateMap, attrs))

	handle, err := session.GetCtx().CreateObject(sessionHandle, template)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return t.getSymmetricKey(ctx, handle)
}

func (t *Token) GetSymmetricKey(ctx context.Context, keyID []byte) (*SymmetricKey, error) {
	privHandle, err := t.getSymmetricKeyHandle(ctx, keyID)
	if err != nil {
		return nil, err
	}

	return t.getSymmetricKey(ctx, privHandle)
}

// ListSymmetricKeys returns all symmetric keys stored in the PKCS#11 device.
// Keys that cannot be processed (due to unsupported types, etc.) are silently skipped.
func (t *Token) ListSymmetricKeys(ctx context.Context, attrs ...*Attribute) ([]*SymmetricKey, error) {

	handles, err := t.listSymmetricKeyHandles(ctx, attrs...)
	if err != nil {
		return nil, err
	}

	keys := []*SymmetricKey{}
	for _, handle := range handles {
		key, err := t.getSymmetricKey(ctx, handle)
		// TODO: should logging
		if err != nil {
			continue
		}
		keys = append(keys, key)
	}

	return keys, nil
}

// DeleteSymmetricKey deletes a symmetric key from the PKCS#11 device.
// Returns an error if the deletion fails.
func (t *Token) DeleteSymmetricKey(ctx context.Context, keyID []byte) error {
	handle, err := t.getSymmetricKeyHandle(ctx, keyID)
	if err != nil {
		return err
	}

	session, err := t.GetSession(ctx)
	if err != nil {
		return ConvertPKCS11Error(err)
	}
	defer session.Release()

	sessionHandle := session.GetHandle()
	if err := session.GetCtx().DestroyObject(sessionHandle, handle); err != nil {
		return ConvertPKCS11Error(err)
	}

	return nil
}

func (t *Token) listSymmetricKeyHandles(ctx context.Context, attrs ...*Attribute) ([]pkcs11.ObjectHandle, error) {
	session, err := t.GetSession(ctx)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}
	defer session.Release()

	sessionHandle := session.GetHandle()

	templateMap := map[uint]any{
		pkcs11.CKA_CLASS: pkcs11.CKO_SECRET_KEY,
	}
	template := attributeMap2Slice(mergeAttribute(templateMap, attrs))

	if err := session.GetCtx().FindObjectsInit(sessionHandle, template); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	var handles []pkcs11.ObjectHandle
	for {
		gotHandles, more, err := session.GetCtx().FindObjects(sessionHandle, 10)
		if err != nil {
			session.GetCtx().FindObjectsFinal(sessionHandle)
			return nil, ConvertPKCS11Error(err)
		}
		handles = append(handles, gotHandles...)
		if !more {
			break
		}
	}

	if err := session.GetCtx().FindObjectsFinal(sessionHandle); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return handles, nil

}

func (t *Token) getSymmetricKeyHandle(ctx context.Context, keyID []byte) (pkcs11.ObjectHandle, error) {
	attrs := []*Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}
	handles, err := t.listKeyHandles(ctx, attrs...)
	if err != nil {
		return 0, err
	}
	if len(handles) == 0 {
		return 0, NewPKCS11Error(ErrKeyNotFound, "symmetric key not found", nil)
	}
	return handles[0], nil

}

// getSymmetricKey retrieves symmetric key information from a PKCS#11 object handle.
// It extracts the key attributes and constructs a SymmetricKey structure.
func (t *Token) getSymmetricKey(ctx context.Context, handle pkcs11.ObjectHandle) (*SymmetricKey, error) {
	session, err := t.GetSession(ctx)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}
	defer session.Release()

	sessionHandle := session.GetHandle()

	attrsQuery := []*Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	}

	attrs, err := session.GetCtx().GetAttributeValue(sessionHandle, handle, attrsQuery)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	label := string(attrs[0].Value)
	id := attrs[1].Value
	keyTypeValue := attrs[2].Value

	if len(keyTypeValue) == 0 {
		return nil, NewPKCS11Error(ErrUnknown, "unable to determine key type", nil)
	}

	var keyType SymmetricKeyType
	var keySize int
	pkcs11KeyType := uint(keyTypeValue[0])

	switch pkcs11KeyType {
	case pkcs11.CKK_AES:
		keyType = SymmetricKeyTypeAES

		attrsQuery := []*Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil),
		}

		attrs, err := session.GetCtx().GetAttributeValue(sessionHandle, handle, attrsQuery)
		if err != nil {
			return nil, ConvertPKCS11Error(err)
		}
		valueLenBytes := attrs[0].Value

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
		token: t,

		Handle:  handle,
		Label:   label,
		ID:      id,
		KeyType: keyType,
		KeySize: keySize,
	}, nil
}
