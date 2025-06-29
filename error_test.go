package gopkcs11

import (
	"errors"
	"testing"

	"github.com/miekg/pkcs11"
)

func TestNewPKCS11Error(t *testing.T) {
	cause := errors.New("underlying error")
	err := NewPKCS11Error(ErrKeyNotFound, "test message", cause)

	if err.Code != ErrKeyNotFound {
		t.Errorf("Expected code %d, got %d", ErrKeyNotFound, err.Code)
	}
	if err.Message != "test message" {
		t.Errorf("Expected message 'test message', got '%s'", err.Message)
	}
	if err.Cause != cause {
		t.Errorf("Expected cause to match")
	}
}

func TestPKCS11Error_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *PKCS11Error
		expected string
	}{
		{
			name: "error with cause",
			err: &PKCS11Error{
				Code:    ErrKeyNotFound,
				Message: "key not found",
				CKRCode: 123,
				Cause:   errors.New("underlying"),
			},
			expected: "PKCS#11 error [3]: key not found (CKR: 0x0000007B) - underlying",
		},
		{
			name: "error without cause",
			err: &PKCS11Error{
				Code:    ErrAuthenticationFailed,
				Message: "login failed",
				CKRCode: 456,
				Cause:   nil,
			},
			expected: "PKCS#11 error [6]: login failed (CKR: 0x000001C8)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestPKCS11Error_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := &PKCS11Error{
		Code:    ErrKeyNotFound,
		Message: "test",
		Cause:   cause,
	}

	unwrapped := err.Unwrap()
	if unwrapped != cause {
		t.Error("Unwrap should return the original cause")
	}

	// Test with nil cause
	errNoCause := &PKCS11Error{
		Code:    ErrKeyNotFound,
		Message: "test",
		Cause:   nil,
	}

	unwrappedNil := errNoCause.Unwrap()
	if unwrappedNil != nil {
		t.Error("Unwrap should return nil when cause is nil")
	}
}

func TestConvertPKCS11Error(t *testing.T) {
	tests := []struct {
		name         string
		input        error
		expectedCode ErrorCode
		expectedMsg  string
	}{
		{
			name:  "nil error",
			input: nil,
		},
		{
			name:         "CKR_CRYPTOKI_NOT_INITIALIZED",
			input:        pkcs11.Error(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED),
			expectedCode: ErrNotInitialized,
			expectedMsg:  "PKCS#11 not initialized",
		},
		{
			name:         "CKR_SESSION_HANDLE_INVALID",
			input:        pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID),
			expectedCode: ErrSessionInvalid,
			expectedMsg:  "invalid session handle",
		},
		{
			name:         "CKR_OBJECT_HANDLE_INVALID",
			input:        pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID),
			expectedCode: ErrObjectNotFound,
			expectedMsg:  "invalid object handle",
		},
		{
			name:         "CKR_TEMPLATE_INCOMPLETE",
			input:        pkcs11.Error(pkcs11.CKR_TEMPLATE_INCOMPLETE),
			expectedCode: ErrInvalidInput,
			expectedMsg:  "incomplete object template",
		},
		{
			name:         "CKR_TEMPLATE_INCONSISTENT",
			input:        pkcs11.Error(pkcs11.CKR_TEMPLATE_INCONSISTENT),
			expectedCode: ErrInvalidInput,
			expectedMsg:  "inconsistent object template",
		},
		{
			name:         "CKR_PIN_INCORRECT",
			input:        pkcs11.Error(pkcs11.CKR_PIN_INCORRECT),
			expectedCode: ErrAuthenticationFailed,
			expectedMsg:  "incorrect PIN",
		},
		{
			name:         "CKR_PIN_LOCKED",
			input:        pkcs11.Error(pkcs11.CKR_PIN_LOCKED),
			expectedCode: ErrAuthenticationFailed,
			expectedMsg:  "PIN locked",
		},
		{
			name:         "CKR_USER_NOT_LOGGED_IN",
			input:        pkcs11.Error(pkcs11.CKR_USER_NOT_LOGGED_IN),
			expectedCode: ErrAuthenticationFailed,
			expectedMsg:  "user not logged in",
		},
		{
			name:         "CKR_SLOT_ID_INVALID",
			input:        pkcs11.Error(pkcs11.CKR_SLOT_ID_INVALID),
			expectedCode: ErrSlotNotFound,
			expectedMsg:  "invalid slot ID",
		},
		{
			name:         "CKR_TOKEN_NOT_PRESENT",
			input:        pkcs11.Error(pkcs11.CKR_TOKEN_NOT_PRESENT),
			expectedCode: ErrSlotNotFound,
			expectedMsg:  "token not present",
		},
		{
			name:         "CKR_SIGNATURE_INVALID",
			input:        pkcs11.Error(pkcs11.CKR_SIGNATURE_INVALID),
			expectedCode: ErrSignatureFailed,
			expectedMsg:  "signature operation failed",
		},
		{
			name:         "CKR_SIGNATURE_LEN_RANGE",
			input:        pkcs11.Error(pkcs11.CKR_SIGNATURE_LEN_RANGE),
			expectedCode: ErrSignatureFailed,
			expectedMsg:  "signature length out of range",
		},
		{
			name:         "CKR_ENCRYPTED_DATA_INVALID",
			input:        pkcs11.Error(pkcs11.CKR_ENCRYPTED_DATA_INVALID),
			expectedCode: ErrDecryptionFailed,
			expectedMsg:  "encrypted data invalid",
		},
		{
			name:         "CKR_ENCRYPTED_DATA_LEN_RANGE",
			input:        pkcs11.Error(pkcs11.CKR_ENCRYPTED_DATA_LEN_RANGE),
			expectedCode: ErrDecryptionFailed,
			expectedMsg:  "encrypted data length out of range",
		},
		{
			name:         "CKR_OPERATION_NOT_INITIALIZED",
			input:        pkcs11.Error(pkcs11.CKR_OPERATION_NOT_INITIALIZED),
			expectedCode: ErrOperationFailed,
			expectedMsg:  "operation not initialized",
		},
		{
			name:         "CKR_OPERATION_ACTIVE",
			input:        pkcs11.Error(pkcs11.CKR_OPERATION_ACTIVE),
			expectedCode: ErrOperationFailed,
			expectedMsg:  "operation already active",
		},
		{
			name:         "unknown PKCS#11 error",
			input:        pkcs11.Error(9999),
			expectedCode: ErrUnknown,
			expectedMsg:  "unknown PKCS#11 error:",
		},
		{
			name:         "non-PKCS#11 error",
			input:        errors.New("generic error"),
			expectedCode: ErrUnknown,
			expectedMsg:  "unknown error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertPKCS11Error(tt.input)

			if tt.input == nil {
				if result != nil {
					t.Error("Expected nil result for nil input")
				}
				return
			}

			pkcs11Err, ok := result.(*PKCS11Error)
			if !ok {
				t.Fatalf("Expected *PKCS11Error, got %T", result)
			}

			if pkcs11Err.Code != tt.expectedCode {
				t.Errorf("Expected code %d, got %d", tt.expectedCode, pkcs11Err.Code)
			}

			if tt.expectedMsg != "" && !containsSubstring(pkcs11Err.Message, tt.expectedMsg) {
				t.Errorf("Expected message to contain '%s', got '%s'", tt.expectedMsg, pkcs11Err.Message)
			}

			if pkcs11Err.Cause != tt.input {
				t.Error("Expected cause to be the original error")
			}
		})
	}
}

func TestIsPKCS11Error(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		code     ErrorCode
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			code:     ErrKeyNotFound,
			expected: false,
		},
		{
			name:     "matching PKCS11Error",
			err:      NewPKCS11Error(ErrKeyNotFound, "test", nil),
			code:     ErrKeyNotFound,
			expected: true,
		},
		{
			name:     "non-matching PKCS11Error",
			err:      NewPKCS11Error(ErrKeyNotFound, "test", nil),
			code:     ErrAuthenticationFailed,
			expected: false,
		},
		{
			name:     "non-PKCS11Error",
			err:      errors.New("generic error"),
			code:     ErrKeyNotFound,
			expected: false,
		},
		{
			name:     "wrapped PKCS11Error",
			err:      errors.New("wrapped: " + NewPKCS11Error(ErrKeyNotFound, "test", nil).Error()),
			code:     ErrKeyNotFound,
			expected: false, // errors.As won't find it in a simple string wrap
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPKCS11Error(tt.err, tt.code)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsAuthenticationError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "authentication error",
			err:      NewPKCS11Error(ErrAuthenticationFailed, "test", nil),
			expected: true,
		},
		{
			name:     "non-authentication error",
			err:      NewPKCS11Error(ErrKeyNotFound, "test", nil),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAuthenticationError(tt.err)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsKeyNotFoundError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "key not found error",
			err:      NewPKCS11Error(ErrKeyNotFound, "test", nil),
			expected: true,
		},
		{
			name:     "object not found error",
			err:      NewPKCS11Error(ErrObjectNotFound, "test", nil),
			expected: true,
		},
		{
			name:     "other error",
			err:      NewPKCS11Error(ErrAuthenticationFailed, "test", nil),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsKeyNotFoundError(tt.err)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsSessionError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "session invalid error",
			err:      NewPKCS11Error(ErrSessionInvalid, "test", nil),
			expected: true,
		},
		{
			name:     "not initialized error",
			err:      NewPKCS11Error(ErrNotInitialized, "test", nil),
			expected: true,
		},
		{
			name:     "other error",
			err:      NewPKCS11Error(ErrKeyNotFound, "test", nil),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSessionError(tt.err)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}