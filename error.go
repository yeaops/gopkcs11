package gopkcs11

import (
	"fmt"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

// ErrorCode represents different categories of PKCS#11 errors for easier error handling.
type ErrorCode int

const (
	// ErrUnknown represents an unknown or unmapped PKCS#11 error
	ErrUnknown ErrorCode = iota
	// ErrNotInitialized indicates the PKCS#11 library is not initialized
	ErrNotInitialized
	// ErrSessionInvalid indicates the session handle is invalid
	ErrSessionInvalid
	// ErrKeyNotFound indicates a requested key could not be found
	ErrKeyNotFound
	// ErrOperationFailed indicates a cryptographic operation failed
	ErrOperationFailed
	// ErrInvalidInput indicates invalid input parameters or templates
	ErrInvalidInput
	// ErrAuthenticationFailed indicates PIN verification or login failed
	ErrAuthenticationFailed
	// ErrSlotNotFound indicates the specified slot is not available
	ErrSlotNotFound
	// ErrObjectNotFound indicates a PKCS#11 object could not be found
	ErrObjectNotFound
	// ErrSignatureFailed indicates a signature operation failed
	ErrSignatureFailed
	// ErrDecryptionFailed indicates a decryption operation failed
	ErrDecryptionFailed
)

// PKCS11Error represents a PKCS#11 specific error with additional context.
// It wraps the underlying PKCS#11 error code and provides a categorized error code for easier handling.
type PKCS11Error struct {
	// Code is the categorized error code for easier error handling
	Code ErrorCode
	// Message is a human-readable error message
	Message string
	// CKRCode is the raw PKCS#11 CKR error code
	CKRCode uint
	// Cause is the underlying error that caused this PKCS#11 error
	Cause error
}

func (e *PKCS11Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("PKCS#11 error [%d]: %s (CKR: 0x%08X) - %v", e.Code, e.Message, e.CKRCode, e.Cause)
	}
	return fmt.Sprintf("PKCS#11 error [%d]: %s (CKR: 0x%08X)", e.Code, e.Message, e.CKRCode)
}

func (e *PKCS11Error) Unwrap() error {
	return e.Cause
}

// NewPKCS11Error creates a new PKCS11Error with the specified parameters.
func NewPKCS11Error(code ErrorCode, message string, cause error) *PKCS11Error {
	return &PKCS11Error{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// ConvertPKCS11Error converts a raw PKCS#11 error into a PKCS11Error with categorized error codes.
// This function maps specific PKCS#11 CKR codes to more general error categories for easier handling.
func ConvertPKCS11Error(err error) error {
	if err == nil {
		return nil
	}

	ckrErr, ok := err.(pkcs11.Error)
	if !ok {
		return NewPKCS11Error(ErrUnknown, "unknown error", err)
	}

	var code ErrorCode
	var message string

	switch ckrErr {
	case pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED:
		code = ErrNotInitialized
		message = "PKCS#11 not initialized"
	case pkcs11.CKR_SESSION_HANDLE_INVALID:
		code = ErrSessionInvalid
		message = "invalid session handle"
	case pkcs11.CKR_OBJECT_HANDLE_INVALID:
		code = ErrObjectNotFound
		message = "invalid object handle"
	case pkcs11.CKR_TEMPLATE_INCOMPLETE:
		code = ErrInvalidInput
		message = "incomplete object template"
	case pkcs11.CKR_TEMPLATE_INCONSISTENT:
		code = ErrInvalidInput
		message = "inconsistent object template"
	case pkcs11.CKR_PIN_INCORRECT:
		code = ErrAuthenticationFailed
		message = "incorrect PIN"
	case pkcs11.CKR_PIN_LOCKED:
		code = ErrAuthenticationFailed
		message = "PIN locked"
	case pkcs11.CKR_USER_NOT_LOGGED_IN:
		code = ErrAuthenticationFailed
		message = "user not logged in"
	case pkcs11.CKR_SLOT_ID_INVALID:
		code = ErrSlotNotFound
		message = "invalid slot ID"
	case pkcs11.CKR_TOKEN_NOT_PRESENT:
		code = ErrSlotNotFound
		message = "token not present"
	case pkcs11.CKR_SIGNATURE_INVALID:
		code = ErrSignatureFailed
		message = "signature operation failed"
	case pkcs11.CKR_SIGNATURE_LEN_RANGE:
		code = ErrSignatureFailed
		message = "signature length out of range"
	case pkcs11.CKR_ENCRYPTED_DATA_INVALID:
		code = ErrDecryptionFailed
		message = "encrypted data invalid"
	case pkcs11.CKR_ENCRYPTED_DATA_LEN_RANGE:
		code = ErrDecryptionFailed
		message = "encrypted data length out of range"
	case pkcs11.CKR_OPERATION_NOT_INITIALIZED:
		code = ErrOperationFailed
		message = "operation not initialized"
	case pkcs11.CKR_OPERATION_ACTIVE:
		code = ErrOperationFailed
		message = "operation already active"
	default:
		code = ErrUnknown
		message = fmt.Sprintf("unknown PKCS#11 error: %s", ckrErr.Error())
	}

	return &PKCS11Error{
		Code:    code,
		Message: message,
		CKRCode: uint(ckrErr),
		Cause:   err,
	}
}

// IsPKCS11Error checks if an error is a PKCS11Error with the specified error code.
func IsPKCS11Error(err error, code ErrorCode) bool {
	if err == nil {
		return false
	}

	var pkcs11Err *PKCS11Error
	if errors.As(err, &pkcs11Err) {
		return pkcs11Err.Code == code
	}
	return false
}

// IsAuthenticationError checks if an error is related to authentication (PIN verification, login, etc.).
func IsAuthenticationError(err error) bool {
	return IsPKCS11Error(err, ErrAuthenticationFailed)
}

// IsKeyNotFoundError checks if an error indicates that a key or object was not found.
func IsKeyNotFoundError(err error) bool {
	return IsPKCS11Error(err, ErrKeyNotFound) || IsPKCS11Error(err, ErrObjectNotFound)
}

// IsSessionError checks if an error is related to session management (invalid session, not initialized, etc.).
func IsSessionError(err error) bool {
	return IsPKCS11Error(err, ErrSessionInvalid) || IsPKCS11Error(err, ErrNotInitialized)
}
