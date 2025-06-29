package gopkcs11

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/miekg/pkcs11"
)

// MockPKCS11Context implements a mock PKCS#11 context for testing
type MockPKCS11Context struct {
	initialized       bool
	slots             []uint
	sessions          map[pkcs11.SessionHandle]*MockSession
	objects           map[pkcs11.ObjectHandle]*MockObject
	nextSessionHandle pkcs11.SessionHandle
	nextObjectHandle  pkcs11.ObjectHandle
	errorMode         map[string]pkcs11.Error
}

type MockSession struct {
	handle       pkcs11.SessionHandle
	slotID       uint
	state        uint
	userLoggedIn bool
	operations   map[string]bool
}

type MockObject struct {
	handle     pkcs11.ObjectHandle
	attributes map[uint][]byte
	class      uint
	keyType    uint
	label      string
	id         []byte
	publicKey  interface{}
	privateKey interface{}
}

// NewMockPKCS11Context creates a new mock PKCS#11 context for testing
func NewMockPKCS11Context() *MockPKCS11Context {
	return &MockPKCS11Context{
		sessions:          make(map[pkcs11.SessionHandle]*MockSession),
		objects:           make(map[pkcs11.ObjectHandle]*MockObject),
		nextSessionHandle: 1,
		nextObjectHandle:  1000,
		errorMode:         make(map[string]pkcs11.Error),
		slots:             []uint{0, 1, 2},
	}
}

// SetErrorMode sets an error to be returned for specific operations
func (m *MockPKCS11Context) SetErrorMode(operation string, err pkcs11.Error) {
	m.errorMode[operation] = err
}

func (m *MockPKCS11Context) checkError(operation string) error {
	if err, exists := m.errorMode[operation]; exists {
		return err
	}
	return nil
}

func (m *MockPKCS11Context) Initialize() error {
	if err := m.checkError("Initialize"); err != nil {
		return err
	}
	if m.initialized {
		return pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED)
	}
	m.initialized = true
	return nil
}

func (m *MockPKCS11Context) Finalize() error {
	if err := m.checkError("Finalize"); err != nil {
		return err
	}
	if !m.initialized {
		return pkcs11.Error(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED)
	}
	m.initialized = false
	return nil
}

func (m *MockPKCS11Context) Destroy() {
	// No-op for mock
}

func (m *MockPKCS11Context) GetSlotList(tokenPresent bool) ([]uint, error) {
	if err := m.checkError("GetSlotList"); err != nil {
		return nil, err
	}
	if !m.initialized {
		return nil, pkcs11.Error(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED)
	}
	return append([]uint(nil), m.slots...), nil
}

func (m *MockPKCS11Context) OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error) {
	if err := m.checkError("OpenSession"); err != nil {
		return 0, err
	}
	if !m.initialized {
		return 0, pkcs11.Error(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	slotExists := false
	for _, slot := range m.slots {
		if slot == slotID {
			slotExists = true
			break
		}
	}
	if !slotExists {
		return 0, pkcs11.Error(pkcs11.CKR_SLOT_ID_INVALID)
	}

	handle := m.nextSessionHandle
	m.nextSessionHandle++

	session := &MockSession{
		handle:       handle,
		slotID:       slotID,
		state:        pkcs11.CKS_RO_PUBLIC_SESSION,
		userLoggedIn: false,
		operations:   make(map[string]bool),
	}

	if flags&pkcs11.CKF_RW_SESSION != 0 {
		session.state = pkcs11.CKS_RW_PUBLIC_SESSION
	}

	m.sessions[handle] = session
	return handle, nil
}

func (m *MockPKCS11Context) CloseSession(session pkcs11.SessionHandle) error {
	if err := m.checkError("CloseSession"); err != nil {
		return err
	}
	if _, exists := m.sessions[session]; !exists {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	delete(m.sessions, session)
	return nil
}

func (m *MockPKCS11Context) Login(session pkcs11.SessionHandle, userType uint, pin string) error {
	if err := m.checkError("Login"); err != nil {
		return err
	}
	sess, exists := m.sessions[session]
	if !exists {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	if userType != pkcs11.CKU_USER {
		return pkcs11.Error(pkcs11.CKR_USER_TYPE_INVALID)
	}
	if pin != "1234" && pin != "testpin" {
		return pkcs11.Error(pkcs11.CKR_PIN_INCORRECT)
	}
	sess.userLoggedIn = true
	return nil
}

func (m *MockPKCS11Context) Logout(session pkcs11.SessionHandle) error {
	if err := m.checkError("Logout"); err != nil {
		return err
	}
	sess, exists := m.sessions[session]
	if !exists {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	sess.userLoggedIn = false
	return nil
}

func (m *MockPKCS11Context) GetSessionInfo(session pkcs11.SessionHandle) (pkcs11.SessionInfo, error) {
	if err := m.checkError("GetSessionInfo"); err != nil {
		return pkcs11.SessionInfo{}, err
	}
	sess, exists := m.sessions[session]
	if !exists {
		return pkcs11.SessionInfo{}, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	return pkcs11.SessionInfo{
		SlotID:      sess.slotID,
		State:       sess.state,
		Flags:       pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION,
		DeviceError: 0,
	}, nil
}

func (m *MockPKCS11Context) GenerateKeyPair(session pkcs11.SessionHandle, mechanisms []*pkcs11.Mechanism, publicTemplate, privateTemplate []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	if err := m.checkError("GenerateKeyPair"); err != nil {
		return 0, 0, err
	}
	sess, exists := m.sessions[session]
	if !exists {
		return 0, 0, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	if !sess.userLoggedIn {
		return 0, 0, pkcs11.Error(pkcs11.CKR_USER_NOT_LOGGED_IN)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return 0, 0, pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
	}

	pubHandle := m.nextObjectHandle
	m.nextObjectHandle++
	privHandle := m.nextObjectHandle
	m.nextObjectHandle++

	var label string
	var id []byte
	for _, attr := range publicTemplate {
		if attr.Type == pkcs11.CKA_LABEL {
			label = string(attr.Value)
		} else if attr.Type == pkcs11.CKA_ID {
			id = attr.Value
		}
	}

	pubObj := &MockObject{
		handle:     pubHandle,
		attributes: make(map[uint][]byte),
		class:      pkcs11.CKO_PUBLIC_KEY,
		keyType:    pkcs11.CKK_RSA,
		label:      label,
		id:         id,
		publicKey:  &privateKey.PublicKey,
	}

	privObj := &MockObject{
		handle:     privHandle,
		attributes: make(map[uint][]byte),
		class:      pkcs11.CKO_PRIVATE_KEY,
		keyType:    pkcs11.CKK_RSA,
		label:      label,
		id:         id,
		privateKey: privateKey,
	}

	m.objects[pubHandle] = pubObj
	m.objects[privHandle] = privObj

	return pubHandle, privHandle, nil
}

func (m *MockPKCS11Context) FindObjectsInit(session pkcs11.SessionHandle, template []*pkcs11.Attribute) error {
	if err := m.checkError("FindObjectsInit"); err != nil {
		return err
	}
	sess, exists := m.sessions[session]
	if !exists {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	if sess.operations["find"] {
		return pkcs11.Error(pkcs11.CKR_OPERATION_ACTIVE)
	}
	sess.operations["find"] = true
	return nil
}

func (m *MockPKCS11Context) FindObjects(session pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	if err := m.checkError("FindObjects"); err != nil {
		return nil, false, err
	}
	sess, exists := m.sessions[session]
	if !exists {
		return nil, false, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	if !sess.operations["find"] {
		return nil, false, pkcs11.Error(pkcs11.CKR_OPERATION_NOT_INITIALIZED)
	}

	var handles []pkcs11.ObjectHandle
	count := 0
	for handle := range m.objects {
		if count >= max {
			break
		}
		handles = append(handles, handle)
		count++
	}
	return handles, count == max, nil
}

func (m *MockPKCS11Context) FindObjectsFinal(session pkcs11.SessionHandle) error {
	if err := m.checkError("FindObjectsFinal"); err != nil {
		return err
	}
	sess, exists := m.sessions[session]
	if !exists {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	if !sess.operations["find"] {
		return pkcs11.Error(pkcs11.CKR_OPERATION_NOT_INITIALIZED)
	}
	delete(sess.operations, "find")
	return nil
}

func (m *MockPKCS11Context) GetAttributeValue(session pkcs11.SessionHandle, object pkcs11.ObjectHandle, template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	if err := m.checkError("GetAttributeValue"); err != nil {
		return nil, err
	}
	_, exists := m.sessions[session]
	if !exists {
		return nil, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	obj, exists := m.objects[object]
	if !exists {
		return nil, pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	}

	var result []*pkcs11.Attribute
	for _, attr := range template {
		switch attr.Type {
		case pkcs11.CKA_CLASS:
			result = append(result, pkcs11.NewAttribute(pkcs11.CKA_CLASS, []byte{byte(obj.class)}))
		case pkcs11.CKA_KEY_TYPE:
			result = append(result, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, []byte{byte(obj.keyType)}))
		case pkcs11.CKA_LABEL:
			result = append(result, pkcs11.NewAttribute(pkcs11.CKA_LABEL, obj.label))
		case pkcs11.CKA_ID:
			result = append(result, pkcs11.NewAttribute(pkcs11.CKA_ID, obj.id))
		case pkcs11.CKA_MODULUS:
			if rsaKey, ok := obj.publicKey.(*rsa.PublicKey); ok {
				result = append(result, pkcs11.NewAttribute(pkcs11.CKA_MODULUS, rsaKey.N.Bytes()))
			}
		case pkcs11.CKA_PUBLIC_EXPONENT:
			result = append(result, pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}))
		default:
			result = append(result, pkcs11.NewAttribute(attr.Type, nil))
		}
	}
	return result, nil
}

func (m *MockPKCS11Context) SignInit(session pkcs11.SessionHandle, mechanisms []*pkcs11.Mechanism, key pkcs11.ObjectHandle) error {
	if err := m.checkError("SignInit"); err != nil {
		return err
	}
	sess, exists := m.sessions[session]
	if !exists {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	if !sess.userLoggedIn {
		return pkcs11.Error(pkcs11.CKR_USER_NOT_LOGGED_IN)
	}
	if _, exists := m.objects[key]; !exists {
		return pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	}
	if sess.operations["sign"] {
		return pkcs11.Error(pkcs11.CKR_OPERATION_ACTIVE)
	}
	sess.operations["sign"] = true
	return nil
}

func (m *MockPKCS11Context) Sign(session pkcs11.SessionHandle, data []byte) ([]byte, error) {
	if err := m.checkError("Sign"); err != nil {
		return nil, err
	}
	sess, exists := m.sessions[session]
	if !exists {
		return nil, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	if !sess.operations["sign"] {
		return nil, pkcs11.Error(pkcs11.CKR_OPERATION_NOT_INITIALIZED)
	}
	delete(sess.operations, "sign")

	signature := make([]byte, 256)
	for i := range signature {
		signature[i] = byte(i % 256)
	}
	return signature, nil
}

// NewMockTestConfig creates a test config specifically for mock testing
func NewMockTestConfig() *Config {
	slotID := uint(0)
	return &Config{
		LibraryPath: "/tmp/libpkcs11.so",
		SlotID:      &slotID,
		UserPIN:     "testpin",
	}
}