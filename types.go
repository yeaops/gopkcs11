package gopkcs11

import "fmt"

// Info represents information about a PKCS#11 module
type Info struct {
	CryptokiVersion    Version
	ManufacturerID     string
	LibraryDescription string
	LibraryVersion     Version
}

// Version represents version information
type Version struct {
	Major uint
	Minor uint
}

// String returns a string representation of a version
func (v Version) String() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// AttributeType represents a PKCS#11 attribute type
type AttributeType uint

// Common attribute types
const (
	CKA_CLASS               AttributeType = 0x00000000
	CKA_TOKEN               AttributeType = 0x00000001
	CKA_PRIVATE             AttributeType = 0x00000002
	CKA_LABEL               AttributeType = 0x00000003
	CKA_APPLICATION         AttributeType = 0x00000010
	CKA_VALUE               AttributeType = 0x00000011
	CKA_OBJECT_ID           AttributeType = 0x00000012
	CKA_CERTIFICATE_TYPE    AttributeType = 0x00000080
	CKA_ISSUER              AttributeType = 0x00000081
	CKA_SERIAL_NUMBER       AttributeType = 0x00000082
	CKA_KEY_TYPE            AttributeType = 0x00000100
	CKA_SUBJECT             AttributeType = 0x00000101
	CKA_ID                  AttributeType = 0x00000102
	CKA_SENSITIVE           AttributeType = 0x00000103
	CKA_ENCRYPT             AttributeType = 0x00000104
	CKA_DECRYPT             AttributeType = 0x00000105
	CKA_WRAP                AttributeType = 0x00000106
	CKA_UNWRAP              AttributeType = 0x00000107
	CKA_SIGN                AttributeType = 0x00000108
	CKA_SIGN_RECOVER        AttributeType = 0x00000109
	CKA_VERIFY              AttributeType = 0x0000010A
	CKA_VERIFY_RECOVER      AttributeType = 0x0000010B
	CKA_DERIVE              AttributeType = 0x0000010C
	CKA_START_DATE          AttributeType = 0x00000110
	CKA_END_DATE            AttributeType = 0x00000111
	CKA_MODULUS             AttributeType = 0x00000120
	CKA_MODULUS_BITS        AttributeType = 0x00000121
	CKA_PUBLIC_EXPONENT     AttributeType = 0x00000122
	CKA_PRIVATE_EXPONENT    AttributeType = 0x00000123
	CKA_PRIME_1             AttributeType = 0x00000124
	CKA_PRIME_2             AttributeType = 0x00000125
	CKA_EXPONENT_1          AttributeType = 0x00000126
	CKA_EXPONENT_2          AttributeType = 0x00000127
	CKA_COEFFICIENT         AttributeType = 0x00000128
	CKA_PRIME               AttributeType = 0x00000130
	CKA_SUBPRIME            AttributeType = 0x00000131
	CKA_BASE                AttributeType = 0x00000132
	CKA_PRIME_BITS          AttributeType = 0x00000133
	CKA_SUBPRIME_BITS       AttributeType = 0x00000134
	CKA_VALUE_BITS          AttributeType = 0x00000160
	CKA_VALUE_LEN           AttributeType = 0x00000161
	CKA_EXTRACTABLE         AttributeType = 0x00000162
	CKA_LOCAL               AttributeType = 0x00000163
	CKA_NEVER_EXTRACTABLE   AttributeType = 0x00000164
	CKA_ALWAYS_SENSITIVE    AttributeType = 0x00000165
	CKA_MODIFIABLE          AttributeType = 0x00000170
	CKA_EC_PARAMS           AttributeType = 0x00000180
	CKA_EC_POINT            AttributeType = 0x00000181
	CKA_ALWAYS_AUTHENTICATE AttributeType = 0x00000202
)

// ObjectClass represents a PKCS#11 object class
type ObjectClass uint

// Object classes
const (
	CKO_DATA              ObjectClass = 0x00000000
	CKO_CERTIFICATE       ObjectClass = 0x00000001
	CKO_PUBLIC_KEY        ObjectClass = 0x00000002
	CKO_PRIVATE_KEY       ObjectClass = 0x00000003
	CKO_SECRET_KEY        ObjectClass = 0x00000004
	CKO_HW_FEATURE        ObjectClass = 0x00000005
	CKO_DOMAIN_PARAMETERS ObjectClass = 0x00000006
	CKO_MECHANISM         ObjectClass = 0x00000007
)

// KeyType represents a PKCS#11 key type
type KeyType uint

// Key types
const (
	CKK_RSA               KeyType = 0x00000000
	CKK_DSA               KeyType = 0x00000001
	CKK_DH                KeyType = 0x00000002
	CKK_EC                KeyType = 0x00000003
	CKK_X9_42_DH          KeyType = 0x00000004
	CKK_KEA               KeyType = 0x00000005
	CKK_GENERIC_SECRET    KeyType = 0x00000010
	CKK_RC2               KeyType = 0x00000011
	CKK_RC4               KeyType = 0x00000012
	CKK_DES               KeyType = 0x00000013
	CKK_DES2              KeyType = 0x00000014
	CKK_DES3              KeyType = 0x00000015
	CKK_AES               KeyType = 0x0000001F
)

// MechanismType represents a PKCS#11 mechanism type
type MechanismType uint

// Mechanism types
const (
	CKM_RSA_PKCS_KEY_PAIR_GEN  MechanismType = 0x00000000
	CKM_RSA_PKCS               MechanismType = 0x00000001
	CKM_RSA_9796               MechanismType = 0x00000002
	CKM_RSA_X_509              MechanismType = 0x00000003
	CKM_MD5_RSA_PKCS           MechanismType = 0x00000005
	CKM_SHA1_RSA_PKCS          MechanismType = 0x00000006
	CKM_SHA256_RSA_PKCS        MechanismType = 0x00000040
	CKM_SHA384_RSA_PKCS        MechanismType = 0x00000041
	CKM_SHA512_RSA_PKCS        MechanismType = 0x00000042
	CKM_DSA_KEY_PAIR_GEN       MechanismType = 0x00000010
	CKM_DSA                    MechanismType = 0x00000011
	CKM_DSA_SHA1               MechanismType = 0x00000012
	CKM_DH_PKCS_KEY_PAIR_GEN   MechanismType = 0x00000020
	CKM_DH_PKCS_DERIVE         MechanismType = 0x00000021
	CKM_EC_KEY_PAIR_GEN        MechanismType = 0x00001040
	CKM_ECDSA                  MechanismType = 0x00001041
	CKM_ECDSA_SHA1             MechanismType = 0x00001042
	CKM_ECDSA_SHA256           MechanismType = 0x00001043
	CKM_ECDH1_DERIVE           MechanismType = 0x00001050
	CKM_SHA_1                  MechanismType = 0x00000220
	CKM_SHA_1_HMAC             MechanismType = 0x00000221
	CKM_SHA256                 MechanismType = 0x00000250
	CKM_SHA256_HMAC            MechanismType = 0x00000251
	CKM_SHA384                 MechanismType = 0x00000260
	CKM_SHA384_HMAC            MechanismType = 0x00000261
	CKM_SHA512                 MechanismType = 0x00000270
	CKM_SHA512_HMAC            MechanismType = 0x00000271
	CKM_AES_KEY_GEN            MechanismType = 0x00001080
	CKM_AES_ECB                MechanismType = 0x00001081
	CKM_AES_CBC                MechanismType = 0x00001082
	CKM_AES_CBC_PAD            MechanismType = 0x00001085
	CKM_AES_GCM                MechanismType = 0x00001087
)

// UserType represents a PKCS#11 user type
type UserType uint

// User types
const (
	CKU_SO               UserType = 0
	CKU_USER             UserType = 1
	CKU_CONTEXT_SPECIFIC UserType = 2
)

// SessionFlags represents PKCS#11 session flags
type SessionFlags uint

// Session flags
const (
	CKF_RW_SESSION      SessionFlags = 0x00000002
	CKF_SERIAL_SESSION  SessionFlags = 0x00000004
)

// TokenFlags represents PKCS#11 token flags
type TokenFlags uint

// Token flags
const (
	CKF_RNG                TokenFlags = 0x00000001
	CKF_WRITE_PROTECTED    TokenFlags = 0x00000002
	CKF_LOGIN_REQUIRED     TokenFlags = 0x00000004
	CKF_USER_PIN_INITIALIZED TokenFlags = 0x00000008
	CKF_TOKEN_INITIALIZED  TokenFlags = 0x00000400
)

// SlotFlags represents PKCS#11 slot flags
type SlotFlags uint

// Slot flags
const (
	CKF_TOKEN_PRESENT     SlotFlags = 0x00000001
	CKF_REMOVABLE_DEVICE  SlotFlags = 0x00000002
	CKF_HW_SLOT           SlotFlags = 0x00000004
)

// Vendor defined range
const (
	CKM_VENDOR_DEFINED MechanismType = 0x80000000
	CKA_VENDOR_DEFINED AttributeType = 0x80000000
	CKO_VENDOR_DEFINED ObjectClass   = 0x80000000
)

// Error represents a PKCS#11 error
type Error struct {
	Code    uint
	Message string
}

func (e Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("PKCS#11 error 0x%08X: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("PKCS#11 error 0x%08X", e.Code)
}

// Error codes (comprehensive list)
const (
	CKR_OK                             uint = 0x00000000
	CKR_CANCEL                         uint = 0x00000001
	CKR_HOST_MEMORY                    uint = 0x00000002
	CKR_SLOT_ID_INVALID                uint = 0x00000003
	CKR_GENERAL_ERROR                  uint = 0x00000005
	CKR_FUNCTION_FAILED                uint = 0x00000006
	CKR_ARGUMENTS_BAD                  uint = 0x00000007
	CKR_ATTRIBUTE_READ_ONLY            uint = 0x00000010
	CKR_ATTRIBUTE_TYPE_INVALID         uint = 0x00000012
	CKR_ATTRIBUTE_VALUE_INVALID        uint = 0x00000013
	CKR_DATA_INVALID                   uint = 0x00000020
	CKR_DATA_LEN_RANGE                 uint = 0x00000021
	CKR_DEVICE_ERROR                   uint = 0x00000030
	CKR_DEVICE_MEMORY                  uint = 0x00000031
	CKR_DEVICE_REMOVED                 uint = 0x00000032
	CKR_FUNCTION_CANCELED              uint = 0x00000050
	CKR_FUNCTION_NOT_PARALLEL          uint = 0x00000051
	CKR_FUNCTION_NOT_SUPPORTED         uint = 0x00000054
	CKR_KEY_HANDLE_INVALID             uint = 0x00000060
	CKR_KEY_SIZE_RANGE                 uint = 0x00000062
	CKR_KEY_TYPE_INCONSISTENT          uint = 0x00000063
	CKR_MECHANISM_INVALID              uint = 0x00000070
	CKR_MECHANISM_PARAM_INVALID        uint = 0x00000071
	CKR_OBJECT_HANDLE_INVALID          uint = 0x00000082
	CKR_OPERATION_ACTIVE               uint = 0x00000090
	CKR_OPERATION_NOT_INITIALIZED      uint = 0x00000091
	CKR_PIN_INCORRECT                  uint = 0x000000A0
	CKR_PIN_INVALID                    uint = 0x000000A1
	CKR_PIN_LEN_RANGE                  uint = 0x000000A2
	CKR_PIN_LOCKED                     uint = 0x000000A4
	CKR_SESSION_CLOSED                 uint = 0x000000B0
	CKR_SESSION_COUNT                  uint = 0x000000B1
	CKR_SESSION_HANDLE_INVALID         uint = 0x000000B3
	CKR_SESSION_PARALLEL_NOT_SUPPORTED uint = 0x000000B4
	CKR_SESSION_READ_ONLY              uint = 0x000000B5
	CKR_SIGNATURE_INVALID              uint = 0x000000C0
	CKR_SIGNATURE_LEN_RANGE            uint = 0x000000C1
	CKR_TEMPLATE_INCOMPLETE            uint = 0x000000D0
	CKR_TEMPLATE_INCONSISTENT          uint = 0x000000D1
	CKR_TOKEN_NOT_PRESENT              uint = 0x000000E0
	CKR_TOKEN_NOT_RECOGNIZED           uint = 0x000000E1
	CKR_TOKEN_WRITE_PROTECTED          uint = 0x000000E2
	CKR_USER_ALREADY_LOGGED_IN         uint = 0x00000100
	CKR_USER_NOT_LOGGED_IN             uint = 0x00000101
	CKR_USER_PIN_NOT_INITIALIZED       uint = 0x00000102
)

// IsUserNotLoggedIn checks if an error is a user not logged in error
func IsUserNotLoggedIn(err error) bool {
	if e, ok := err.(Error); ok {
		return e.Code == CKR_USER_NOT_LOGGED_IN
	}
	return false
}

// IsTokenNotPresent checks if an error is a token not present error
func IsTokenNotPresent(err error) bool {
	if e, ok := err.(Error); ok {
		return e.Code == CKR_TOKEN_NOT_PRESENT
	}
	return false
}

// IsSessionHandleInvalid checks if an error is a session handle invalid error
func IsSessionHandleInvalid(err error) bool {
	if e, ok := err.(Error); ok {
		return e.Code == CKR_SESSION_HANDLE_INVALID
	}
	return false
}

// Common vendor errors
var (
	ErrVendorNotSupported = fmt.Errorf("vendor extension not supported")
)