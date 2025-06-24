// Package gopkcs11 provides a Go interface to PKCS#11 cryptographic tokens
package gopkcs11

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/yeaops/gopkcs11/internal/pkcs11"
)

// Context represents a PKCS#11 library context
type Context struct {
	module           *pkcs11.Module
	sessionPool      map[uint]*Session
	sessionPoolLock  sync.RWMutex
	vendorExtensions map[string]interface{}
}

// New creates a new PKCS#11 context by loading the specified PKCS#11 module
func New(path string) (*Context, error) {
	module, err := pkcs11.LoadModule(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %v", err)
	}

	ctx := &Context{
		module:           module,
		sessionPool:      make(map[uint]*Session),
		vendorExtensions: make(map[string]interface{}),
	}

	// Initialize vendor extensions
	ctx.initVendorExtensions()

	return ctx, nil
}

// Config represents configuration options for a PKCS#11 context
type Config struct {
	Path         string `json:"path"`
	TokenLabel   string `json:"token_label"`
	Pin          string `json:"pin"`
	ForceV24Mode bool   `json:"force_v24_mode"`
	SlotID       uint   `json:"slot_id"`
	MaxSessions  int    `json:"max_sessions"`
}

// NewWithConfig creates a new PKCS#11 context with the specified configuration
func NewWithConfig(config *Config) (*Context, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if config.Path == "" {
		return nil, fmt.Errorf("path must be specified")
	}

	return New(config.Path)
}

// Finalize finalizes the PKCS#11 module and frees associated resources
func (ctx *Context) Finalize() error {
	if ctx.module == nil {
		return fmt.Errorf("module not loaded")
	}

	// Close all open sessions
	ctx.sessionPoolLock.Lock()
	defer ctx.sessionPoolLock.Unlock()
	for _, session := range ctx.sessionPool {
		session.Close() // Ignore errors
	}

	// Clear the session pool
	ctx.sessionPool = make(map[uint]*Session)

	// Finalize the module
	return ctx.module.Finalize()
}

// Version returns the version of the PKCS#11 module
func (ctx *Context) Version() (major, minor uint) {
	return uint(ctx.module.VersionMajor), uint(ctx.module.VersionMinor)
}

// CompileTimeVersion returns the PKCS#11 version this library was compiled with
func (ctx *Context) CompileTimeVersion() (major, minor int) {
	return pkcs11.GetCompileTimeVersion()
}

// HasUtimacoSupport returns true if Utimaco extensions are available
func (ctx *Context) HasUtimacoSupport() bool {
	return pkcs11.HasUtimacoExtensions()
}

// GetInfo returns information about the PKCS#11 module
func (ctx *Context) GetInfo() (*Info, error) {
	info := &Info{
		CryptokiVersion: Version{
			Major: uint(ctx.module.Info.CryptokiVersion.Major),
			Minor: uint(ctx.module.Info.CryptokiVersion.Minor),
		},
		ManufacturerID:     ctx.module.Info.ManufacturerID,
		LibraryDescription: ctx.module.Info.LibraryDescription,
		LibraryVersion: Version{
			Major: uint(ctx.module.Info.LibraryVersion.Major),
			Minor: uint(ctx.module.Info.LibraryVersion.Minor),
		},
	}

	return info, nil
}

// GetSlotList gets a list of slots in the system
func (ctx *Context) GetSlotList(tokenPresent bool) ([]Slot, error) {
	slotIDs, err := ctx.module.GetSlotList(tokenPresent)
	if err != nil {
		return nil, err
	}

	slots := make([]Slot, len(slotIDs))
	for i, id := range slotIDs {
		slots[i] = Slot{ID: id, ctx: ctx}
	}

	return slots, nil
}

// GetSlots returns a list of available slots
// Shorthand for GetSlotList(true)
func (ctx *Context) GetSlots(tokenPresent bool) []Slot {
	slots, err := ctx.GetSlotList(tokenPresent)
	if err != nil {
		return []Slot{}
	}
	return slots
}

// FindSlotByLabel finds a slot by token label
func (ctx *Context) FindSlotByLabel(label string) (Slot, error) {
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return Slot{}, err
	}

	for _, slot := range slots {
		info, err := slot.GetTokenInfo()
		if err != nil {
			continue
		}
		if info.Label == label {
			return slot, nil
		}
	}

	return Slot{}, fmt.Errorf("slot with label %s not found", label)
}

// OpenSession opens a session with a token
func (ctx *Context) OpenSession(slotID uint, flags uint) (*Session, error) {
	handle, err := ctx.module.OpenSession(slotID, flags)
	if err != nil {
		return nil, err
	}

	session := &Session{
		handle: handle,
		ctx:    ctx,
		slotID: slotID,
		flags:  flags,
	}

	// Add to session pool
	ctx.sessionPoolLock.Lock()
	defer ctx.sessionPoolLock.Unlock()
	ctx.sessionPool[handle] = session

	return session, nil
}

// CloseAllSessions closes all open sessions
func (ctx *Context) CloseAllSessions() error {
	ctx.sessionPoolLock.Lock()
	defer ctx.sessionPoolLock.Unlock()

	var lastErr error
	for _, session := range ctx.sessionPool {
		if err := session.Close(); err != nil {
			lastErr = err
		}
	}

	ctx.sessionPool = make(map[uint]*Session)
	return lastErr
}

// SupportsFeature checks if a specific feature is supported
func (ctx *Context) SupportsFeature(feature string) bool {
	// Feature detection based on library version and other information
	major, _ := ctx.Version()

	switch feature {
	case "multipleAuth":
		return major >= 3 // PKCS#11 v3.0 feature
	case "extendedParams":
		return major >= 3 // PKCS#11 v3.0 feature
	case "profileAttributes":
		return major >= 3 // PKCS#11 v3.0 feature
	default:
		return false
	}
}

// SupportedFeatures returns a list of supported features
func (ctx *Context) SupportedFeatures() []string {
	var features []string

	supportedFeatures := []string{
		"multipleAuth",
		"extendedParams",
		"profileAttributes",
	}

	for _, feature := range supportedFeatures {
		if ctx.SupportsFeature(feature) {
			features = append(features, feature)
		}
	}

	return features
}

// SupportsVendor checks if a specific vendor extension is supported
func (ctx *Context) SupportsVendor(vendor string) bool {
	_, ok := ctx.vendorExtensions[vendor]
	return ok
}

// initVendorExtensions initializes vendor extensions
func (ctx *Context) initVendorExtensions() {
	// Register all known vendor extensions
	for name, initFunc := range vendorExtensionInitializers {
		ext, err := initFunc(ctx.module.LibHandle)
		if err == nil {
			ctx.vendorExtensions[name] = ext
		}
	}
}

// Map of vendor extension initializers
var vendorExtensionInitializers = map[string]func(unsafe.Pointer) (interface{}, error){}

// registerVendorExtension registers a vendor extension initializer
func registerVendorExtension(name string, initializer func(unsafe.Pointer) (interface{}, error)) {
	vendorExtensionInitializers[name] = initializer
}
