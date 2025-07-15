package gopkcs11

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

// Client represents a connection to a PKCS#11 device (HSM).
// It manages the PKCS#11 context, session, and authentication state.
// Client is thread-safe and can be used concurrently from multiple goroutines.
type Client struct {
	ctx       *pkcs11.Ctx
	config    *Config
	session   pkcs11.SessionHandle
	sessionMu sync.RWMutex
	loggedIn  bool
	lastUsed  time.Time
	closeOnce sync.Once
}

// NewClient creates a new PKCS#11 client with the provided configuration.
// It initializes the PKCS#11 library, opens a session, and authenticates with the device.
// The client must be closed using Close() when no longer needed.
func NewClient(config *Config) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, errors.Wrap(err, "invalid PKCS#11 configuration")
	}

	ctx := pkcs11.New(config.LibraryPath)
	if ctx == nil {
		return nil, errors.New("failed to create PKCS#11 context")
	}

	if err := ctx.Initialize(); err != nil {
		return nil, errors.Wrap(err, "failed to initialize PKCS#11")
	}

	client := &Client{
		ctx:    ctx,
		config: config,
	}

	if err := client.connect(); err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, errors.Wrap(err, "failed to connect to PKCS#11 device")
	}

	return client, nil
}

// connect establishes a connection to the PKCS#11 device by finding the configured slot,
// opening a session, and logging in with the user PIN. This is called internally by NewClient.
func (c *Client) connect() error {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()

	// Determine slot identification type
	slotType, err := c.config.GetSlotIdentificationType()
	if err != nil {
		return errors.Wrap(err, "invalid slot identification configuration")
	}

	// Find target slot based on identification type
	var targetSlot uint
	if slotType == SlotIdentificationByID {
		// For SlotID, try direct connection (optimization - no need to enumerate slots)
		targetSlot = *c.config.SlotID
	} else {
		// For other methods, get available slots and search
		slots, err := c.ctx.GetSlotList(true)
		if err != nil {
			return errors.Wrap(err, "failed to get slot list")
		}
		targetSlot, err = c.findSlot(slots, slotType)
		if err != nil {
			return errors.Wrap(err, "failed to find target slot")
		}
	}

	// Open session
	session, err := c.ctx.OpenSession(targetSlot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		// For SlotID, provide better error message with available slots
		if slotType == SlotIdentificationByID {
			if slots, slotsErr := c.ctx.GetSlotList(true); slotsErr == nil {
				return errors.Errorf("failed to open session on slot ID %d: %v (available slots: %v)", targetSlot, err, slots)
			}
		}
		return errors.Wrap(err, "failed to open session")
	}

	// Login
	if err := c.ctx.Login(session, pkcs11.CKU_USER, c.config.UserPIN); err != nil {
		c.ctx.CloseSession(session)
		return errors.Wrap(err, "failed to login as CKU_USER")
	}

	c.session = session
	c.loggedIn = true
	c.lastUsed = time.Now()

	return nil
}

// findSlot locates the target slot based on the configured identification method
// Note: SlotID uses direct connection optimization and doesn't call this method
func (c *Client) findSlot(slots []uint, slotType SlotIdentificationType) (uint, error) {
	switch slotType {
	case SlotIdentificationByID:
		// This case should not be reached due to optimization in connect()
		return c.findSlotByID(slots)
	case SlotIdentificationByIndex:
		return c.findSlotByIndex(slots)
	case SlotIdentificationByTokenLabel:
		return c.findSlotByTokenLabel(slots)
	case SlotIdentificationByTokenSerial:
		return c.findSlotByTokenSerial(slots)
	default:
		return 0, errors.Errorf("unsupported slot identification type: %v", slotType)
	}
}

// findSlotByID finds a slot by its slot ID
func (c *Client) findSlotByID(slots []uint) (uint, error) {
	targetSlotID := *c.config.SlotID
	for _, slot := range slots {
		if slot == targetSlotID {
			return slot, nil
		}
	}
	return 0, errors.Errorf("slot ID %d not found in available slots: %v", targetSlotID, slots)
}

// findSlotByIndex finds a slot by its index in the slot list
func (c *Client) findSlotByIndex(slots []uint) (uint, error) {
	targetSlotIndex := *c.config.SlotIndex
	if int(targetSlotIndex) >= len(slots) {
		return 0, errors.Errorf("slot index %d is out of range, only %d slots available", targetSlotIndex, len(slots))
	}
	return slots[targetSlotIndex], nil
}

// findSlotByTokenLabel finds a slot by its token label
func (c *Client) findSlotByTokenLabel(slots []uint) (uint, error) {
	for _, slot := range slots {
		tokenInfo, err := c.ctx.GetTokenInfo(slot)
		if err != nil {
			// Skip slots that can't be queried (might not have tokens)
			continue
		}

		// Compare token label (trim spaces as PKCS#11 labels are padded)
		tokenLabel := strings.TrimSpace(tokenInfo.Label)
		if tokenLabel == c.config.TokenLabel {
			return slot, nil
		}
	}
	return 0, errors.Errorf("token with label '%s' not found in any available slot", c.config.TokenLabel)
}

// findSlotByTokenSerial finds a slot by its token serial number
func (c *Client) findSlotByTokenSerial(slots []uint) (uint, error) {
	for _, slot := range slots {
		tokenInfo, err := c.ctx.GetTokenInfo(slot)
		if err != nil {
			// Skip slots that can't be queried (might not have tokens)
			continue
		}

		// Compare token serial number (trim spaces as PKCS#11 serials are padded)
		tokenSerial := strings.TrimSpace(tokenInfo.SerialNumber)
		if tokenSerial == c.config.TokenSerialNumber {
			return slot, nil
		}
	}
	return 0, errors.Errorf("token with serial number '%s' not found in any available slot", c.config.TokenSerialNumber)
}

// GetSession returns the current PKCS#11 session handle.
// It validates that the client is logged in and updates the last used timestamp.
// This method is thread-safe.
func (c *Client) GetSession() (pkcs11.SessionHandle, error) {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()

	if !c.loggedIn {
		return 0, errors.New("not logged in to PKCS#11 device")
	}

	c.lastUsed = time.Now()
	return c.session, nil
}

// GetContext returns the underlying PKCS#11 context.
// This can be used for advanced operations not covered by the high-level API.
func (c *Client) GetContext() *pkcs11.Ctx {
	return c.ctx
}

// IsConnected returns true if the client is currently logged in to the PKCS#11 device.
// This method is thread-safe.
func (c *Client) IsConnected() bool {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	return c.loggedIn
}

// Ping tests the connection to the PKCS#11 device by performing a simple session info query.
// It returns an error if the device is not accessible or the session is invalid.
func (c *Client) Ping(ctx context.Context) error {
	session, err := c.GetSession()
	if err != nil {
		return err
	}

	_, err = c.ctx.GetSessionInfo(session)
	if err != nil {
		return errors.Wrap(err, "PKCS#11 ping failed")
	}

	return nil
}

// Close properly shuts down the PKCS#11 client by logging out, closing the session,
// finalizing the context, and destroying the PKCS#11 context.
// This method is safe to call multiple times and is thread-safe.
func (c *Client) Close() error {
	var finalErr error

	c.closeOnce.Do(func() {
		c.sessionMu.Lock()
		defer c.sessionMu.Unlock()

		if c.loggedIn && c.session != 0 {
			if err := c.ctx.Logout(c.session); err != nil {
				finalErr = errors.Wrap(err, "failed to logout")
			}

			if err := c.ctx.CloseSession(c.session); err != nil {
				if finalErr == nil {
					finalErr = errors.Wrap(err, "failed to close session")
				}
			}

			c.loggedIn = false
			c.session = 0
		}

		if err := c.ctx.Finalize(); err != nil {
			if finalErr == nil {
				finalErr = errors.Wrap(err, "failed to finalize PKCS#11")
			}
		}

		c.ctx.Destroy()
	})

	return finalErr
}

func attributeMap2Slice(attrs map[uint]any) []*pkcs11.Attribute {
	attrSlice := make([]*pkcs11.Attribute, 0, len(attrs))
	for k, v := range attrs {
		attrSlice = append(attrSlice, pkcs11.NewAttribute(k, v))
	}
	return attrSlice
}

func mergeAttribute(attrs map[uint]any, merges []*pkcs11.Attribute) map[uint]any {

	for _, attr := range merges {
		attrs[attr.Type] = attr.Value
	}
	return attrs

}

// EncryptData encrypts data using the symmetric key with the specified PKCS#11 mechanism.
// Common mechanisms include CKM_AES_CBC, CKM_AES_GCM, CKM_DES_CBC, etc.
// The iv parameter is used for mechanisms that require an initialization vector.
func (c *Client) EncryptData(key *SymmetricKey, mechanism uint, iv []byte, data []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("symmetric key cannot be nil")
	}

	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Create mechanism with IV if provided
	var mech *pkcs11.Mechanism
	if len(iv) > 0 {
		mech = pkcs11.NewMechanism(mechanism, iv)
	} else {
		mech = pkcs11.NewMechanism(mechanism, nil)
	}

	// Initialize encryption
	if err := c.ctx.EncryptInit(session, []*pkcs11.Mechanism{mech}, key.Handle); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Perform encryption
	ciphertext, err := c.ctx.Encrypt(session, data)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return ciphertext, nil
}

// DecryptData decrypts data using the symmetric key with the specified PKCS#11 mechanism.
// The mechanism and iv parameters must match those used for encryption.
func (c *Client) DecryptData(key *SymmetricKey, mechanism uint, iv []byte, ciphertext []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("symmetric key cannot be nil")
	}

	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Create mechanism with IV if provided
	var mech *pkcs11.Mechanism
	if len(iv) > 0 {
		mech = pkcs11.NewMechanism(mechanism, iv)
	} else {
		mech = pkcs11.NewMechanism(mechanism, nil)
	}

	// Initialize decryption
	if err := c.ctx.DecryptInit(session, []*pkcs11.Mechanism{mech}, key.Handle); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Perform decryption
	plaintext, err := c.ctx.Decrypt(session, ciphertext)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return plaintext, nil
}

// WrapKey wraps a target key using a wrapping key with the specified PKCS#11 mechanism.
// This is used for secure key transport and storage.
// Common mechanisms include CKM_AES_KEY_WRAP, CKM_AES_CBC, etc.
func (c *Client) WrapKey(wrappingKey *SymmetricKey, targetKeyHandle pkcs11.ObjectHandle, mechanism uint, iv []byte) ([]byte, error) {
	if wrappingKey == nil {
		return nil, errors.New("wrapping key cannot be nil")
	}

	session, err := c.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Create mechanism with IV if provided
	var mech *pkcs11.Mechanism
	if len(iv) > 0 {
		mech = pkcs11.NewMechanism(mechanism, iv)
	} else {
		mech = pkcs11.NewMechanism(mechanism, nil)
	}

	// Wrap the key
	wrappedKey, err := c.ctx.WrapKey(session, []*pkcs11.Mechanism{mech}, wrappingKey.Handle, targetKeyHandle)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return wrappedKey, nil
}

// UnwrapKey unwraps a wrapped key using an unwrapping key with the specified PKCS#11 mechanism.
// The keyTemplate parameter specifies the attributes for the unwrapped key object.
// Returns the handle to the newly created unwrapped key.
func (c *Client) UnwrapKey(unwrappingKey *SymmetricKey, wrappedKey []byte, mechanism uint, iv []byte, keyTemplate []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	if unwrappingKey == nil {
		return 0, errors.New("unwrapping key cannot be nil")
	}

	session, err := c.GetSession()
	if err != nil {
		return 0, ConvertPKCS11Error(err)
	}

	// Create mechanism with IV if provided
	var mech *pkcs11.Mechanism
	if len(iv) > 0 {
		mech = pkcs11.NewMechanism(mechanism, iv)
	} else {
		mech = pkcs11.NewMechanism(mechanism, nil)
	}

	// Unwrap the key
	handle, err := c.ctx.UnwrapKey(session, []*pkcs11.Mechanism{mech}, unwrappingKey.Handle, wrappedKey, keyTemplate)
	if err != nil {
		return 0, ConvertPKCS11Error(err)
	}

	return handle, nil
}
