// Package pkcs11 provides a low-level wrapper for the PKCS#11 C API
package pkcs11
import (
	"fmt"
	"unsafe"
)

// Module represents a PKCS#11 module loaded from a shared library
type Module struct {
	LibHandle      unsafe.Pointer
	FunctionList   unsafe.Pointer
	Path           string
	VersionMajor   uint8
	VersionMinor   uint8
	ManufacturerID string
	Info           Info
}

// Info represents information about the PKCS#11 module
type Info struct {
	CryptokiVersion    Version
	ManufacturerID     string
	Flags              uint
	LibraryDescription string
	LibraryVersion     Version
}

// Version represents a PKCS#11 version
type Version struct {
	Major uint8
	Minor uint8
}

// SlotInfo represents information about a slot
type SlotInfo struct {
	SlotDescription string
	ManufacturerID  string
	Flags           uint
	HardwareVersion Version
	FirmwareVersion Version
}

// TokenInfo represents information about a token
type TokenInfo struct {
	Label              string
	ManufacturerID     string
	Model              string
	SerialNumber       string
	Flags              uint
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

// SessionInfo represents information about a session
type SessionInfo struct {
	SlotID      uint
	State       uint
	Flags       uint
	DeviceError uint
}

// Attribute represents a PKCS#11 attribute
type Attribute struct {
	Type  uint
	Value []byte
}

// Mechanism represents a PKCS#11 mechanism
type Mechanism struct {
	Mechanism uint
	Parameter []byte
}

// Error represents a PKCS#11 error
type Error struct {
	Code uint
}

func (e Error) Error() string {
	return fmt.Sprintf("PKCS#11 error: 0x%08x", e.Code)
}
