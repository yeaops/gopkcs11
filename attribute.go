package gopkcs11

import (
	"encoding/binary"
	"fmt"
	"time"
)

// Attribute represents a PKCS#11 attribute
type Attribute struct {
	Type  AttributeType
	Value []byte
}

// NewAttribute creates a new attribute with the given type and value
func NewAttribute(attrType AttributeType, value interface{}) *Attribute {
	attr := &Attribute{
		Type: attrType,
	}

	switch v := value.(type) {
	case bool:
		if v {
			attr.Value = []byte{1}
		} else {
			attr.Value = []byte{0}
		}
	case int:
		attr.Value = uintToBytes(uint(v))
	case uint:
		attr.Value = uintToBytes(v)
	case string:
		attr.Value = []byte(v)
	case []byte:
		attr.Value = v
	case time.Time:
		attr.Value = []byte(v.Format("20060102150405"))
	case nil:
		attr.Value = nil
	default:
		panic(fmt.Sprintf("unsupported attribute value type: %T", value))
	}

	return attr
}

// NewAttributeClass creates an attribute for a object class
func NewAttributeClass(objClass ObjectClass) *Attribute {
	return NewAttribute(CKA_CLASS, uint(objClass))
}

// NewAttributeKeyType creates an attribute for a key type
func NewAttributeKeyType(keyType KeyType) *Attribute {
	return NewAttribute(CKA_KEY_TYPE, uint(keyType))
}

// GetBool returns the attribute value as a boolean
func (a *Attribute) GetBool() (bool, error) {
	if len(a.Value) != 1 {
		return false, fmt.Errorf("invalid boolean length")
	}
	return a.Value[0] != 0, nil
}

// GetUint returns the attribute value as an unsigned integer
func (a *Attribute) GetUint() (uint, error) {
	if len(a.Value) > 8 {
		return 0, fmt.Errorf("integer too large")
	}

	var value uint
	for i := 0; i < len(a.Value); i++ {
		value = (value << 8) | uint(a.Value[i])
	}
	return value, nil
}

// GetString returns the attribute value as a string
func (a *Attribute) GetString() (string, error) {
	return string(a.Value), nil
}

// GetBytes returns the attribute value as a byte array
func (a *Attribute) GetBytes() ([]byte, error) {
	return a.Value, nil
}

// GetTime returns the attribute value as a time.Time
func (a *Attribute) GetTime() (time.Time, error) {
	if len(a.Value) != 14 {
		return time.Time{}, fmt.Errorf("invalid time format")
	}
	return time.Parse("20060102150405", string(a.Value))
}

// uintToBytes converts an uint to a byte array
func uintToBytes(value uint) []byte {
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, uint64(value))

	// Trim leading zeros
	for i := 0; i < len(bytes); i++ {
		if bytes[i] != 0 {
			return bytes[i:]
		}
	}
	return []byte{0}
}

// Common attribute convenience functions

// NewAttributeLabel creates a CKA_LABEL attribute
func NewAttributeLabel(label string) *Attribute {
	return NewAttribute(CKA_LABEL, label)
}

// NewAttributeID creates a CKA_ID attribute
func NewAttributeID(id []byte) *Attribute {
	return NewAttribute(CKA_ID, id)
}

// NewAttributeToken creates a CKA_TOKEN attribute
func NewAttributeToken(token bool) *Attribute {
	return NewAttribute(CKA_TOKEN, token)
}

// NewAttributePrivate creates a CKA_PRIVATE attribute
func NewAttributePrivate(private bool) *Attribute {
	return NewAttribute(CKA_PRIVATE, private)
}

// NewAttributeModifiable creates a CKA_MODIFIABLE attribute
func NewAttributeModifiable(modifiable bool) *Attribute {
	return NewAttribute(CKA_MODIFIABLE, modifiable)
}

// NewAttributeExtractable creates a CKA_EXTRACTABLE attribute
func NewAttributeExtractable(extractable bool) *Attribute {
	return NewAttribute(CKA_EXTRACTABLE, extractable)
}

// NewAttributeSensitive creates a CKA_SENSITIVE attribute
func NewAttributeSensitive(sensitive bool) *Attribute {
	return NewAttribute(CKA_SENSITIVE, sensitive)
}

// NewAttributeEncrypt creates a CKA_ENCRYPT attribute
func NewAttributeEncrypt(encrypt bool) *Attribute {
	return NewAttribute(CKA_ENCRYPT, encrypt)
}

// NewAttributeDecrypt creates a CKA_DECRYPT attribute
func NewAttributeDecrypt(decrypt bool) *Attribute {
	return NewAttribute(CKA_DECRYPT, decrypt)
}

// NewAttributeSign creates a CKA_SIGN attribute
func NewAttributeSign(sign bool) *Attribute {
	return NewAttribute(CKA_SIGN, sign)
}

// NewAttributeVerify creates a CKA_VERIFY attribute
func NewAttributeVerify(verify bool) *Attribute {
	return NewAttribute(CKA_VERIFY, verify)
}

// NewAttributeWrap creates a CKA_WRAP attribute
func NewAttributeWrap(wrap bool) *Attribute {
	return NewAttribute(CKA_WRAP, wrap)
}

// NewAttributeUnwrap creates a CKA_UNWRAP attribute
func NewAttributeUnwrap(unwrap bool) *Attribute {
	return NewAttribute(CKA_UNWRAP, unwrap)
}

// NewAttributeDerive creates a CKA_DERIVE attribute
func NewAttributeDerive(derive bool) *Attribute {
	return NewAttribute(CKA_DERIVE, derive)
}

// NewAttributeModulusBits creates a CKA_MODULUS_BITS attribute
func NewAttributeModulusBits(bits uint) *Attribute {
	return NewAttribute(CKA_MODULUS_BITS, bits)
}

// NewAttributeValueLen creates a CKA_VALUE_LEN attribute
func NewAttributeValueLen(length uint) *Attribute {
	return NewAttribute(CKA_VALUE_LEN, length)
}

// NewAttributeECParams creates a CKA_EC_PARAMS attribute for elliptic curve parameters
func NewAttributeECParams(params []byte) *Attribute {
	return NewAttribute(CKA_EC_PARAMS, params)
}

// NewAttributePublicExponent creates a CKA_PUBLIC_EXPONENT attribute
func NewAttributePublicExponent(exponent []byte) *Attribute {
	return NewAttribute(CKA_PUBLIC_EXPONENT, exponent)
}

// Standard EC curve parameters as byte arrays (DER encoded OIDs)
var (
	// NIST P-256 curve (secp256r1 / prime256v1)
	ECP256Params = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	// NIST P-384 curve (secp384r1)
	ECP384Params = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}
	// NIST P-521 curve (secp521r1)
	ECP521Params = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23}
)

// Common RSA public exponents
var (
	RSAPublicExponent3     = []byte{0x03}
	RSAPublicExponent65537 = []byte{0x01, 0x00, 0x01}
)
