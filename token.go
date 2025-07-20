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

// Token represents a connection to a PKCS#11 device (HSM).
// It manages the session pool for concurrent access with isolated sessions.
// Token is thread-safe and can be used concurrently from multiple goroutines.
type Token struct {
	Config         *Config
	ctx            *pkcs11.Ctx // shared PKCS#11 context for all sessions
	pool           *Pool
	managerSession pkcs11.SessionHandle
	mu             sync.RWMutex // protects token state
	closed         bool
	closeOnce      sync.Once
}

// NewToken creates a new PKCS#11 token with the provided configuration.
// It validates the configuration and initializes the session pool.
// The token must be closed using Close() when no longer needed.
func NewToken(config *Config) (*Token, error) {
	if err := config.Validate(); err != nil {
		return nil, errors.Wrap(err, "invalid PKCS#11 configuration")
	}

	token := &Token{
		Config: config,
	}

	if err := token.configure(); err != nil {
		return nil, errors.Wrap(err, "failed to configure PKCS#11 device")
	}

	return token, nil
}

// configure finds the target slot and initializes the session pool.
// This is called internally by NewToken.
func (t *Token) configure() error {
	// Create and initialize shared PKCS#11 context
	t.ctx = pkcs11.New(t.Config.LibraryPath)
	if t.ctx == nil {
		return errors.New("failed to create PKCS#11 context")
	}

	if err := t.ctx.Initialize(); err != nil {
		if !IsAlreadyInitializedError(ConvertPKCS11Error(err)) {
			t.ctx.Destroy()
			return errors.Wrap(err, "failed to initialize PKCS#11 context")
		}
	}

	// Determine slot identification type
	slotType, err := t.Config.GetSlotIdentificationType()
	if err != nil {
		t.ctx.Finalize()
		t.ctx.Destroy()
		return errors.Wrap(err, "invalid slot identification configuration")
	}

	// Find target slot based on identification type
	slot, err := t.findSlot(slotType)
	if err != nil || slot == nil {
		t.ctx.Finalize()
		t.ctx.Destroy()
		return errors.Wrap(err, "failed to find target slot")
	}

	// Create session pool with shared context
	pool, err := newPool(t.Config, t.ctx, *slot)
	if err != nil {
		t.ctx.Finalize()
		t.ctx.Destroy()
		return errors.Wrap(err, "failed to create context pool")
	}
	t.pool = pool

	// Create manager session
	managerSession, err := t.ctx.OpenSession(*slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.ctx.Finalize()
		t.ctx.Destroy()
		return errors.Wrap(err, "failed to open manager session")
	}

	if err := t.ctx.Login(managerSession, pkcs11.CKU_USER, t.Config.UserPIN); err != nil {
		t.ctx.CloseSession(managerSession)
		t.ctx.Finalize()
		t.ctx.Destroy()
		return errors.Wrap(err, "failed to login to manager session")
	}
	t.managerSession = managerSession

	return nil
}

// findSlot locates the target slot based on the configured identification method
// Note: SlotID uses direct connection optimization and doesn't call this method
func (t *Token) findSlot(slotType SlotIdentificationType) (*uint, error) {
	if slotType == SlotIdentificationByID {
		_, err := t.ctx.GetTokenInfo(*t.Config.SlotID)
		if err != nil {
			return nil, err
		}

		// For SlotID, try direct access (optimization - no need to enumerate slots)
		targetSlot := *t.Config.SlotID
		return &targetSlot, nil
	}

	slots, err := t.ctx.GetSlotList(true)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get slot list")
	}

	switch slotType {
	case SlotIdentificationByID:
		// This case should not be reached due to optimization in configure()
		return t.findSlotByID(slots)
	case SlotIdentificationByIndex:
		return t.findSlotByIndex(slots)
	case SlotIdentificationByTokenLabel:
		return t.findSlotByTokenLabel(slots, t.ctx)
	case SlotIdentificationByTokenSerial:
		return t.findSlotByTokenSerial(slots, t.ctx)
	default:
		return nil, errors.Errorf("unsupported slot identification type: %v", slotType)
	}
}

// findSlotByID finds a slot by its slot ID
func (t *Token) findSlotByID(slots []uint) (*uint, error) {
	targetSlotID := *t.Config.SlotID
	for _, slot := range slots {
		slot := slot
		if slot == targetSlotID {
			return &slot, nil
		}
	}
	return nil, errors.Errorf("slot ID %d not found in available slots: %v", targetSlotID, slots)
}

// findSlotByIndex finds a slot by its index in the slot list
func (t *Token) findSlotByIndex(slots []uint) (*uint, error) {
	targetSlotIndex := *t.Config.SlotIndex
	if int(targetSlotIndex) >= len(slots) {
		return nil, errors.Errorf("slot index %d is out of range, only %d slots available", targetSlotIndex, len(slots))
	}
	slot := slots[targetSlotIndex]
	return &slot, nil
}

// findSlotByTokenLabel finds a slot by its token label
func (t *Token) findSlotByTokenLabel(slots []uint, ctx *pkcs11.Ctx) (*uint, error) {
	for _, slot := range slots {
		slot := slot
		tokenInfo, err := ctx.GetTokenInfo(slot)
		if err != nil {
			// Skip slots that can't be queried (might not have tokens)
			continue
		}

		// Compare token label (trim spaces as PKCS#11 labels are padded)
		tokenLabel := strings.TrimSpace(tokenInfo.Label)
		if tokenLabel == t.Config.TokenLabel {
			return &slot, nil
		}
	}
	return nil, errors.Errorf("token with label '%s' not found in any available slot", t.Config.TokenLabel)
}

// findSlotByTokenSerial finds a slot by its token serial number
func (t *Token) findSlotByTokenSerial(slots []uint, ctx *pkcs11.Ctx) (*uint, error) {

	for _, slot := range slots {
		slot := slot
		tokenInfo, err := ctx.GetTokenInfo(slot)
		if err != nil {
			// Skip slots that can't be queried (might not have tokens)
			continue
		}

		// Compare token serial number (trim spaces as PKCS#11 serials are padded)
		tokenSerial := strings.TrimSpace(tokenInfo.SerialNumber)
		if tokenSerial == t.Config.TokenSerialNumber {
			return &slot, nil
		}
	}
	return nil, errors.Errorf("token with serial number '%s' not found in any available slot", t.Config.TokenSerialNumber)
}

// GetContext acquires a context from the context pool.
// It supports timeout control through the context parameter.
// The returned Context must be released back to the pool using Release().
// This method is thread-safe and supports true concurrent access.
func (t *Token) GetSession(ctx context.Context) (*Session, error) {
	if t.pool == nil {
		return nil, errors.New("context pool not initialized")
	}

	return t.pool.acquire(ctx)
}

func (t *Token) GetTokenInfo(ctx context.Context) (*pkcs11.TokenInfo, error) {
	session, err := t.GetSession(ctx)
	if err != nil {
		return nil, err
	}
	defer session.Release()

	tokenInfo, err := session.GetCtx().GetTokenInfo(t.pool.targetSlot)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get token info")
	}

	return &tokenInfo, nil
}

func (t *Token) GetSlotInfo(ctx context.Context) (*pkcs11.SlotInfo, error) {
	session, err := t.GetSession(ctx)
	if err != nil {
		return nil, err
	}
	defer session.Release()

	slotInfo, err := session.GetCtx().GetSlotInfo(t.pool.targetSlot)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get token info")
	}

	return &slotInfo, nil
}

func (t *Token) GetSlotID() uint {
	return t.pool.targetSlot
}

// Ping tests the connection to the PKCS#11 device by performing a simple session info query.
// It returns an error if the device is not accessible or the session is invalid.
func (t *Token) Ping(ctx context.Context) error {
	session, err := t.GetSession(ctx)
	if err != nil {
		return err
	}
	defer session.Release()

	_, err = session.GetCtx().GetSessionInfo(session.GetHandle())
	if err != nil {
		return errors.Wrap(err, "PKCS#11 ping failed")
	}

	return nil
}

// Close properly shuts down the PKCS#11 token by closing the context pool.
// All context cleanup is handled by the context pool itself.
// This method is safe to call multiple times and is thread-safe.
func (t *Token) Close() error {
	var finalErr error

	t.closeOnce.Do(func() {
		// Close context pool - this will clean up all sessions
		if t.pool != nil {
			if err := t.pool.close(); err != nil {
				finalErr = errors.Wrap(err, "failed to close context pool")
			}
		}

		// Clean up shared PKCS#11 context
		if t.ctx != nil {
			t.ctx.Finalize()
			t.ctx.Destroy()
		}
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

	// Session Pool configuration
	// MaxSessions is the maximum number of sessions in the pool (default: 1024)
	MaxSessions int
	// SessionAcquireTimeout is the timeout for acquiring a session from the pool
	// (default: 0 means blocking wait)
	SessionAcquireTimeout time.Duration
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

	// Validate session pool configuration
	if c.MaxSessions < 0 {
		return errors.New("MaxSessions cannot be negative")
	}
	if c.SessionAcquireTimeout < 0 {
		return errors.New("SessionAcquireTimeout cannot be negative")
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
