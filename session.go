package gopkcs11

import (
	"fmt"
	"sync"

	"github.com/yeaops/gopkcs11/internal/pkcs11"
)

// Session represents a PKCS#11 session with a token
type Session struct {
	handle      uint
	ctx         *Context
	slotID      uint
	flags       uint
	findInit    bool
	signInit    bool
	verifyInit  bool
	encryptInit bool
	decryptInit bool
	mu          sync.Mutex
}

// Close closes the session
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.ctx.module.CloseSession(s.handle)
	if err != nil {
		return err
	}

	// Remove from session pool
	s.ctx.sessionPoolLock.Lock()
	defer s.ctx.sessionPoolLock.Unlock()
	delete(s.ctx.sessionPool, s.handle)

	return nil
}

// Login logs a user into the token
func (s *Session) Login(userType UserType, pin string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.ctx.module.Login(s.handle, uint(userType), pin)
}

// Logout logs a user out from the token
func (s *Session) Logout() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.ctx.module.Logout(s.handle)
}

// FindObjects finds objects that match the template
func (s *Session) FindObjects(template []*Attribute) ([]Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Convert attributes
	attrs := make([]*pkcs11.Attribute, len(template))
	for i, attr := range template {
		attrs[i] = &pkcs11.Attribute{
			Type:  uint(attr.Type),
			Value: attr.Value,
		}
	}

	// Initialize find operation
	if err := s.ctx.module.FindObjectsInit(s.handle, attrs); err != nil {
		return nil, err
	}
	defer s.ctx.module.FindObjectsFinal(s.handle)
	s.findInit = true

	// Find objects
	handles, err := s.ctx.module.FindObjects(s.handle, 100)
	if err != nil {
		return nil, err
	}

	// Convert handles to objects
	objects := make([]Object, len(handles))
	for i, handle := range handles {
		objects[i] = newObject(s, handle)
	}

	return objects, nil
}

// GetAttributeValue gets the value of one or more object attributes
func (s *Session) GetAttributeValue(object Object, template []*Attribute) ([]*Attribute, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Convert attributes
	attrs := make([]*pkcs11.Attribute, len(template))
	for i, attr := range template {
		attrs[i] = &pkcs11.Attribute{
			Type:  uint(attr.Type),
			Value: nil,
		}
	}

	// Get attribute values
	retAttrs, err := s.ctx.module.GetAttributeValue(s.handle, object.Handle(), attrs)
	if err != nil {
		return nil, err
	}

	// Convert back to public attributes
	result := make([]*Attribute, len(retAttrs))
	for i, attr := range retAttrs {
		result[i] = &Attribute{
			Type:  AttributeType(attr.Type),
			Value: attr.Value,
		}
	}

	return result, nil
}

// GenerateKeyPair generates a public/private key pair
func (s *Session) GenerateKeyPair(mechanism *Mechanism, pubKeyTemplate, privKeyTemplate []*Attribute) (PublicKey, PrivateKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Convert mechanism
	mech := &pkcs11.Mechanism{
		Mechanism: uint(mechanism.Type),
		Parameter: mechanism.Parameter,
	}

	// Convert public key template
	pubAttrs := make([]*pkcs11.Attribute, len(pubKeyTemplate))
	for i, attr := range pubKeyTemplate {
		pubAttrs[i] = &pkcs11.Attribute{
			Type:  uint(attr.Type),
			Value: attr.Value,
		}
	}

	// Convert private key template
	privAttrs := make([]*pkcs11.Attribute, len(privKeyTemplate))
	for i, attr := range privKeyTemplate {
		privAttrs[i] = &pkcs11.Attribute{
			Type:  uint(attr.Type),
			Value: attr.Value,
		}
	}

	// Generate key pair
	pubHandle, privHandle, err := s.ctx.module.GenerateKeyPair(s.handle, mech, pubAttrs, privAttrs)
	if err != nil {
		return nil, nil, err
	}

	pubKey := &publicKey{
		object: newObject(s, pubHandle),
	}

	privKey := &privateKey{
		object: newObject(s, privHandle),
	}

	return pubKey, privKey, nil
}

// SignInit initializes a signature operation
func (s *Session) SignInit(mechanism *Mechanism, key PrivateKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Convert mechanism
	mech := &pkcs11.Mechanism{
		Mechanism: uint(mechanism.Type),
		Parameter: mechanism.Parameter,
	}

	err := s.ctx.module.SignInit(s.handle, mech, key.Handle())
	if err != nil {
		return err
	}

	s.signInit = true
	return nil
}

// Sign signs data
func (s *Session) Sign(data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.signInit {
		return nil, fmt.Errorf("sign operation not initialized")
	}
	defer func() { s.signInit = false }()

	return s.ctx.module.Sign(s.handle, data)
}

// GenerateRandom generates random data
func (s *Session) GenerateRandom(length int) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.ctx.module.GenerateRandom(s.handle, length)
}

// GetContext returns the context associated with this session
func (s *Session) GetContext() *Context {
	return s.ctx
}

// GetHandle returns the handle of this session
func (s *Session) GetHandle() uint {
	return s.handle
}

// GetSlotID returns the slot ID associated with this session
func (s *Session) GetSlotID() uint {
	return s.slotID
}

// IsRW returns whether this is a read/write session
func (s *Session) IsRW() bool {
	return (s.flags & uint(CKF_RW_SESSION)) != 0
}

// GenerateKey generates a symmetric key
func (s *Session) GenerateKey(mechanism *Mechanism, template []*Attribute) (SecretKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Convert mechanism
	mech := &pkcs11.Mechanism{
		Mechanism: uint(mechanism.Type),
		Parameter: mechanism.Parameter,
	}

	// Convert template
	attrs := make([]*pkcs11.Attribute, len(template))
	for i, attr := range template {
		attrs[i] = &pkcs11.Attribute{
			Type:  uint(attr.Type),
			Value: attr.Value,
		}
	}

	// Generate key
	handle, err := s.ctx.module.GenerateKey(s.handle, mech, attrs)
	if err != nil {
		return nil, err
	}

	key := &secretKey{
		object: newObject(s, handle),
	}

	return key, nil
}

// VerifyInit initializes a verification operation
func (s *Session) VerifyInit(mechanism *Mechanism, key PublicKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Convert mechanism
	mech := &pkcs11.Mechanism{
		Mechanism: uint(mechanism.Type),
		Parameter: mechanism.Parameter,
	}

	err := s.ctx.module.VerifyInit(s.handle, mech, key.Handle())
	if err != nil {
		return err
	}

	s.verifyInit = true
	return nil
}

// Verify verifies a signature
func (s *Session) Verify(data, signature []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.verifyInit {
		return fmt.Errorf("verify operation not initialized")
	}
	defer func() { s.verifyInit = false }()

	return s.ctx.module.Verify(s.handle, data, signature)
}

// EncryptInit initializes an encryption operation
func (s *Session) EncryptInit(mechanism *Mechanism, key Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Convert mechanism
	mech := &pkcs11.Mechanism{
		Mechanism: uint(mechanism.Type),
		Parameter: mechanism.Parameter,
	}

	err := s.ctx.module.EncryptInit(s.handle, mech, key.Handle())
	if err != nil {
		return err
	}

	s.encryptInit = true
	return nil
}

// Encrypt encrypts data
func (s *Session) Encrypt(data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.encryptInit {
		return nil, fmt.Errorf("encrypt operation not initialized")
	}
	defer func() { s.encryptInit = false }()

	return s.ctx.module.Encrypt(s.handle, data)
}

// DecryptInit initializes a decryption operation
func (s *Session) DecryptInit(mechanism *Mechanism, key Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Convert mechanism
	mech := &pkcs11.Mechanism{
		Mechanism: uint(mechanism.Type),
		Parameter: mechanism.Parameter,
	}

	err := s.ctx.module.DecryptInit(s.handle, mech, key.Handle())
	if err != nil {
		return err
	}

	s.decryptInit = true
	return nil
}

// Decrypt decrypts data
func (s *Session) Decrypt(ciphertext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.decryptInit {
		return nil, fmt.Errorf("decrypt operation not initialized")
	}
	defer func() { s.decryptInit = false }()

	return s.ctx.module.Decrypt(s.handle, ciphertext)
}

// SetAttributeValue sets attribute values on an object
func (s *Session) SetAttributeValue(object Object, template []*Attribute) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Convert attributes
	attrs := make([]*pkcs11.Attribute, len(template))
	for i, attr := range template {
		attrs[i] = &pkcs11.Attribute{
			Type:  uint(attr.Type),
			Value: attr.Value,
		}
	}

	return s.ctx.module.SetAttributeValue(s.handle, object.Handle(), attrs)
}

// newObject creates a new object
func newObject(session *Session, handle uint) Object {
	return &object{
		session: session,
		handle:  handle,
	}
}

// SessionInfo represents information about a session
type SessionInfo struct {
	SlotID      uint
	State       uint
	Flags       SessionFlags
	DeviceError uint
}

// SignData is a convenience function that combines SignInit and Sign
func (s *Session) SignData(mechanism *Mechanism, key PrivateKey, data []byte) ([]byte, error) {
	if err := s.SignInit(mechanism, key); err != nil {
		return nil, err
	}
	return s.Sign(data)
}

// VerifyData is a convenience function that combines VerifyInit and Verify
func (s *Session) VerifyData(mechanism *Mechanism, key PublicKey, data, signature []byte) error {
	if err := s.VerifyInit(mechanism, key); err != nil {
		return err
	}
	return s.Verify(data, signature)
}

// EncryptData is a convenience function that combines EncryptInit and Encrypt
func (s *Session) EncryptData(mechanism *Mechanism, key Key, data []byte) ([]byte, error) {
	if err := s.EncryptInit(mechanism, key); err != nil {
		return nil, err
	}
	return s.Encrypt(data)
}

// DecryptData is a convenience function that combines DecryptInit and Decrypt
func (s *Session) DecryptData(mechanism *Mechanism, key Key, ciphertext []byte) ([]byte, error) {
	if err := s.DecryptInit(mechanism, key); err != nil {
		return nil, err
	}
	return s.Decrypt(ciphertext)
}

// FindObjectsByTemplate is a convenience function to find objects with a simple attribute template
func (s *Session) FindObjectsByTemplate(class ObjectClass, label string, id []byte) ([]Object, error) {
	template := []*Attribute{
		NewAttributeClass(class),
	}
	
	if label != "" {
		template = append(template, NewAttribute(CKA_LABEL, []byte(label)))
	}
	
	if len(id) > 0 {
		template = append(template, NewAttribute(CKA_ID, id))
	}
	
	return s.FindObjects(template)
}

// FindKeyByLabel finds a key by its label
func (s *Session) FindKeyByLabel(label string) ([]Key, error) {
	objects, err := s.FindObjects([]*Attribute{
		NewAttribute(CKA_LABEL, []byte(label)),
	})
	if err != nil {
		return nil, err
	}
	
	var keys []Key
	for _, obj := range objects {
		class, err := obj.GetObjectClass()
		if err != nil {
			continue
		}
		
		switch class {
		case CKO_PUBLIC_KEY:
			keys = append(keys, &publicKey{object: obj})
		case CKO_PRIVATE_KEY:
			keys = append(keys, &privateKey{object: obj})
		case CKO_SECRET_KEY:
			keys = append(keys, &secretKey{object: obj})
		}
	}
	
	return keys, nil
}

// FindKeyPairByLabel finds a key pair by label
func (s *Session) FindKeyPairByLabel(label string) (PublicKey, PrivateKey, error) {
	keys, err := s.FindKeyByLabel(label)
	if err != nil {
		return nil, nil, err
	}
	
	var pubKey PublicKey
	var privKey PrivateKey
	
	for _, key := range keys {
		class, err := key.GetObjectClass()
		if err != nil {
			continue
		}
		
		switch class {
		case CKO_PUBLIC_KEY:
			pubKey = key.(PublicKey)
		case CKO_PRIVATE_KEY:
			privKey = key.(PrivateKey)
		}
	}
	
	if pubKey == nil || privKey == nil {
		return nil, nil, fmt.Errorf("incomplete key pair found")
	}
	
	return pubKey, privKey, nil
}

// GenerateRandomBytes generates random bytes of the specified length
func (s *Session) GenerateRandomBytes(length int) ([]byte, error) {
	return s.GenerateRandom(length)
}
