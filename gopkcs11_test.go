package gopkcs11

import (
	"testing"
)

func TestVersion(t *testing.T) {
	version := Version{Major: 2, Minor: 40}
	expected := "2.40"
	if version.String() != expected {
		t.Errorf("Version.String() = %s, want %s", version.String(), expected)
	}
}

func TestNewAttribute(t *testing.T) {
	tests := []struct {
		name     string
		attrType AttributeType
		value    interface{}
		expected []byte
	}{
		{
			name:     "boolean true",
			attrType: CKA_TOKEN,
			value:    true,
			expected: []byte{1},
		},
		{
			name:     "boolean false",
			attrType: CKA_TOKEN,
			value:    false,
			expected: []byte{0},
		},
		{
			name:     "string",
			attrType: CKA_LABEL,
			value:    "test",
			expected: []byte("test"),
		},
		{
			name:     "uint",
			attrType: CKA_CLASS,
			value:    uint(1),
			expected: []byte{1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := NewAttribute(tt.attrType, tt.value)
			if attr.Type != tt.attrType {
				t.Errorf("NewAttribute() type = %v, want %v", attr.Type, tt.attrType)
			}
			if len(attr.Value) != len(tt.expected) {
				t.Errorf("NewAttribute() value length = %d, want %d", len(attr.Value), len(tt.expected))
			}
		})
	}
}

func TestNewMechanism(t *testing.T) {
	mech := NewMechanism(CKM_RSA_PKCS, nil)
	if mech.Type != CKM_RSA_PKCS {
		t.Errorf("NewMechanism() type = %v, want %v", mech.Type, CKM_RSA_PKCS)
	}
	if mech.Parameter != nil {
		t.Errorf("NewMechanism() parameter = %v, want nil", mech.Parameter)
	}
}

func TestNewMechanismRSAPKCS(t *testing.T) {
	mech := NewMechanismRSAPKCS()
	if mech.Type != CKM_RSA_PKCS {
		t.Errorf("NewMechanismRSAPKCS() type = %v, want %v", mech.Type, CKM_RSA_PKCS)
	}
}

func TestNewMechanismAESCBC(t *testing.T) {
	iv := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	mech := NewMechanismAESCBC(iv)
	if mech.Type != CKM_AES_CBC {
		t.Errorf("NewMechanismAESCBC() type = %v, want %v", mech.Type, CKM_AES_CBC)
	}
	if len(mech.Parameter) != len(iv) {
		t.Errorf("NewMechanismAESCBC() parameter length = %d, want %d", len(mech.Parameter), len(iv))
	}
}

func TestErrorHandling(t *testing.T) {
	err := Error{Code: CKR_PIN_INCORRECT, Message: "PIN incorrect"}
	expected := "PKCS#11 error 0x000000A0: PIN incorrect"
	if err.Error() != expected {
		t.Errorf("Error.Error() = %s, want %s", err.Error(), expected)
	}
}

func TestErrorChecking(t *testing.T) {
	err := Error{Code: CKR_USER_NOT_LOGGED_IN}
	if !IsUserNotLoggedIn(err) {
		t.Errorf("IsUserNotLoggedIn() = false, want true")
	}

	err = Error{Code: CKR_TOKEN_NOT_PRESENT}
	if !IsTokenNotPresent(err) {
		t.Errorf("IsTokenNotPresent() = false, want true")
	}

	err = Error{Code: CKR_SESSION_HANDLE_INVALID}
	if !IsSessionHandleInvalid(err) {
		t.Errorf("IsSessionHandleInvalid() = false, want true")
	}
}

func TestAttributeValueParsing(t *testing.T) {
	// Test boolean parsing
	attr := &Attribute{Type: CKA_TOKEN, Value: []byte{1}}
	val, err := attr.GetBool()
	if err != nil {
		t.Errorf("GetBool() error = %v", err)
	}
	if !val {
		t.Errorf("GetBool() = false, want true")
	}

	// Test string parsing
	attr = &Attribute{Type: CKA_LABEL, Value: []byte("test")}
	str, err := attr.GetString()
	if err != nil {
		t.Errorf("GetString() error = %v", err)
	}
	if str != "test" {
		t.Errorf("GetString() = %s, want test", str)
	}

	// Test byte parsing
	testBytes := []byte{1, 2, 3, 4}
	attr = &Attribute{Type: CKA_ID, Value: testBytes}
	bytes, err := attr.GetBytes()
	if err != nil {
		t.Errorf("GetBytes() error = %v", err)
	}
	if len(bytes) != len(testBytes) {
		t.Errorf("GetBytes() length = %d, want %d", len(bytes), len(testBytes))
	}
}

func TestUintToBytes(t *testing.T) {
	tests := []struct {
		value    uint
		expected []byte
	}{
		{0, []byte{0}},
		{1, []byte{1}},
		{255, []byte{255}},
		{256, []byte{1, 0}},
		{65535, []byte{255, 255}},
	}

	for _, tt := range tests {
		result := uintToBytes(tt.value)
		if len(result) != len(tt.expected) {
			t.Errorf("uintToBytes(%d) length = %d, want %d", tt.value, len(result), len(tt.expected))
		}
	}
}
