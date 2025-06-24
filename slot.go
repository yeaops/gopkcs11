package gopkcs11

// Slot represents a PKCS#11 slot
type Slot struct {
	ID  uint
	ctx *Context
}

// GetInfo returns information about the slot
func (s Slot) GetInfo() (*SlotInfo, error) {
	info, err := s.ctx.module.GetSlotInfo(s.ID)
	if err != nil {
		return nil, err
	}

	return &SlotInfo{
		SlotDescription: info.SlotDescription,
		ManufacturerID:  info.ManufacturerID,
		Flags:           SlotFlags(info.Flags),
		HardwareVersion: Version{
			Major: uint(info.HardwareVersion.Major),
			Minor: uint(info.HardwareVersion.Minor),
		},
		FirmwareVersion: Version{
			Major: uint(info.FirmwareVersion.Major),
			Minor: uint(info.FirmwareVersion.Minor),
		},
	}, nil
}

// GetTokenInfo returns information about the token in this slot
func (s Slot) GetTokenInfo() (*TokenInfo, error) {
	info, err := s.ctx.module.GetTokenInfo(s.ID)
	if err != nil {
		return nil, err
	}

	return &TokenInfo{
		Label:              info.Label,
		ManufacturerID:     info.ManufacturerID,
		Model:              info.Model,
		SerialNumber:       info.SerialNumber,
		Flags:              TokenFlags(info.Flags),
		MaxSessionCount:    info.MaxSessionCount,
		SessionCount:       info.SessionCount,
		MaxRWSessionCount:  info.MaxRWSessionCount,
		RWSessionCount:     info.RWSessionCount,
		MaxPinLen:          info.MaxPinLen,
		MinPinLen:          info.MinPinLen,
		TotalPublicMemory:  info.TotalPublicMemory,
		FreePublicMemory:   info.FreePublicMemory,
		TotalPrivateMemory: info.TotalPrivateMemory,
		FreePrivateMemory:  info.FreePrivateMemory,
		HardwareVersion: Version{
			Major: uint(info.HardwareVersion.Major),
			Minor: uint(info.HardwareVersion.Minor),
		},
		FirmwareVersion: Version{
			Major: uint(info.FirmwareVersion.Major),
			Minor: uint(info.FirmwareVersion.Minor),
		},
		UTCTime: info.UTCTime,
	}, nil
}

// HasToken returns true if this slot has a token
func (s Slot) HasToken() bool {
	info, err := s.GetInfo()
	if err != nil {
		return false
	}
	return (info.Flags & CKF_TOKEN_PRESENT) != 0
}

// OpenSession opens a session with the token in this slot
func (s Slot) OpenSession(flags SessionFlags) (*Session, error) {
	return s.ctx.OpenSession(s.ID, uint(flags))
}

// SlotInfo represents information about a slot
type SlotInfo struct {
	SlotDescription string
	ManufacturerID  string
	Flags           SlotFlags
	HardwareVersion Version
	FirmwareVersion Version
}

// TokenInfo represents information about a token
type TokenInfo struct {
	Label              string
	ManufacturerID     string
	Model              string
	SerialNumber       string
	Flags              TokenFlags
	MaxSessionCount    uint
	SessionCount       uint
	MaxRWSessionCount  uint
	RWSessionCount     uint
	MaxPinLen          uint
	MinPinLen          uint
	TotalPublicMemory  uint
	FreePublicMemory   uint
	TotalPrivateMemory uint
	FreePrivateMemory  uint
	HardwareVersion    Version
	FirmwareVersion    Version
	UTCTime            string
}

// IsInitialized returns true if the token is initialized
func (t TokenInfo) IsInitialized() bool {
	return (t.Flags & CKF_TOKEN_INITIALIZED) != 0
}

// IsLoginRequired returns true if login is required to access token objects
func (t TokenInfo) IsLoginRequired() bool {
	return (t.Flags & CKF_LOGIN_REQUIRED) != 0
}

// IsUserPinInitialized returns true if the user PIN is initialized
func (t TokenInfo) IsUserPinInitialized() bool {
	return (t.Flags & CKF_USER_PIN_INITIALIZED) != 0
}

// IsWriteProtected returns true if the token is write protected
func (t TokenInfo) IsWriteProtected() bool {
	return (t.Flags & CKF_WRITE_PROTECTED) != 0
}

// HasRNG returns true if the token has a random number generator
func (t TokenInfo) HasRNG() bool {
	return (t.Flags & CKF_RNG) != 0
}
