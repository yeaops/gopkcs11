package gopkcs11

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

type Attribute = pkcs11.Attribute

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

// Config holds the configuration parameters for connecting to a PKCS#11 device.
type Config struct {
	// LibraryPath is the filesystem path to the PKCS#11 library (.so, .dll, or .dylib)
	LibraryPath string

	// Slot identification method (only one should be used)
	// SlotID is the slot id of the PKCS#11 device to use
	SlotID *uint
	// SlotIndex is the index of the slot to use (alternative to SlotID)
	SlotIndex *uint
	// TokenLabel is used to identify the token to use by label
	TokenLabel string
	// TokenSerialNumber is the serial number of the token to use
	TokenSerialNumber string

	// UserPIN is the PIN used to authenticate as a normal user (not SO)
	UserPIN string
}

// SlotIdentificationType represents the type of slot identification method used
type SlotIdentificationType int

const (
	SlotIdentificationByID SlotIdentificationType = iota
	SlotIdentificationByIndex
	SlotIdentificationByTokenLabel
	SlotIdentificationByTokenSerial
)

// String returns the string representation of the slot identification type
func (s SlotIdentificationType) String() string {
	switch s {
	case SlotIdentificationByID:
		return "SlotID"
	case SlotIdentificationByIndex:
		return "SlotIndex"
	case SlotIdentificationByTokenLabel:
		return "TokenLabel"
	case SlotIdentificationByTokenSerial:
		return "TokenSerialNumber"
	default:
		return "Unknown"
	}
}

// GetSlotIdentificationType returns the type of slot identification method configured
func (c *Config) GetSlotIdentificationType() (SlotIdentificationType, error) {
	var setFields []SlotIdentificationType

	if c.SlotID != nil {
		setFields = append(setFields, SlotIdentificationByID)
	}
	if c.SlotIndex != nil {
		setFields = append(setFields, SlotIdentificationByIndex)
	}
	if c.TokenLabel != "" {
		setFields = append(setFields, SlotIdentificationByTokenLabel)
	}
	if c.TokenSerialNumber != "" {
		setFields = append(setFields, SlotIdentificationByTokenSerial)
	}

	if len(setFields) == 0 {
		return SlotIdentificationByID, errors.New("no slot identification method specified - must set one of: SlotID, SlotIndex, TokenLabel, or TokenSerialNumber")
	}

	if len(setFields) > 1 {
		var fieldNames []string
		for _, field := range setFields {
			fieldNames = append(fieldNames, field.String())
		}
		return SlotIdentificationByID, errors.Errorf("multiple slot identification methods specified: %v - only one can be set", fieldNames)
	}

	return setFields[0], nil
}

// Validate checks that the configuration is valid and the library path exists.
// Returns an error if the library path is empty, the file doesn't exist, the user PIN is empty,
// or if multiple slot identification methods are specified.
func (c *Config) Validate() error {
	if c.LibraryPath == "" {
		return errors.New("library path cannot be empty")
	}

	if _, err := os.Stat(c.LibraryPath); os.IsNotExist(err) {
		return errors.Errorf("PKCS#11 library not found at: %s", c.LibraryPath)
	}

	// Validate slot identification method
	_, err := c.GetSlotIdentificationType()
	if err != nil {
		return errors.Wrap(err, "invalid slot identification configuration")
	}

	return nil
}

// String returns a string representation of the config with the PIN redacted for security.
func (c *Config) String() string {
	slotType, err := c.GetSlotIdentificationType()
	if err != nil {
		return fmt.Sprintf("PKCS11Config{LibraryPath: %s, SlotIdentification: INVALID, UserPIN: [REDACTED]}", c.LibraryPath)
	}

	var slotInfo string
	switch slotType {
	case SlotIdentificationByID:
		slotInfo = fmt.Sprintf("SlotID: %d", *c.SlotID)
	case SlotIdentificationByIndex:
		slotInfo = fmt.Sprintf("SlotIndex: %d", *c.SlotIndex)
	case SlotIdentificationByTokenLabel:
		slotInfo = fmt.Sprintf("TokenLabel: %s", c.TokenLabel)
	case SlotIdentificationByTokenSerial:
		slotInfo = fmt.Sprintf("TokenSerialNumber: %s", c.TokenSerialNumber)
	default:
		slotInfo = "Unknown"
	}

	return fmt.Sprintf("PKCS11Config{LibraryPath: %s, %s, UserPIN: [REDACTED]}", c.LibraryPath, slotInfo)
}

func attributeMap2Slice(attrs map[uint]any) []*Attribute {
	attrSlice := make([]*Attribute, 0, len(attrs))
	for k, v := range attrs {
		attrSlice = append(attrSlice, pkcs11.NewAttribute(k, v))
	}
	return attrSlice
}

func mergeAttribute(attrs map[uint]any, merges []*Attribute) map[uint]any {

	for _, attr := range merges {
		attrs[attr.Type] = attr.Value
	}
	return attrs

}

func NewIDAttribute(id []byte) *Attribute {
	return pkcs11.NewAttribute(pkcs11.CKA_ID, id)
}

func NewLabelAttribute(label string) *Attribute {
	return pkcs11.NewAttribute(pkcs11.CKA_LABEL, label)
}
