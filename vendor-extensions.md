# Vendor-Specific HSM Extension Design

This document outlines the approach for supporting vendor-specific extensions to PKCS#11 in the gopkcs11 library.

## Extension Architecture

### Base Extension Interface

```go
// VendorExtension defines the interface all vendor extensions must implement
type VendorExtension interface {
    // Name returns the vendor extension name
    Name() string
    
    // Initialize initializes the vendor extension with the base PKCS11 module
    Initialize(module *PKCS11Module) error
    
    // GetSupportedMechanisms returns the list of vendor-specific mechanisms
    GetSupportedMechanisms() []MechanismType
    
    // GetSupportedAttributes returns the list of vendor-specific attributes
    GetSupportedAttributes() []AttributeType
    
    // GetSupportedFunctions returns the list of vendor-specific functions
    GetSupportedFunctions() []string
    
    // IsSupported checks if this vendor extension is supported by the loaded library
    IsSupported() bool
}
```

### Extension Registration System

```go
// ExtensionManager manages vendor extensions
type ExtensionManager struct {
    extensions map[string]VendorExtension
    module     *PKCS11Module
}

// NewExtensionManager creates a new extension manager
func NewExtensionManager(module *PKCS11Module) *ExtensionManager {
    return &ExtensionManager{
        extensions: make(map[string]VendorExtension),
        module:     module,
    }
}

// RegisterExtension registers a vendor extension
func (em *ExtensionManager) RegisterExtension(ext VendorExtension) error {
    name := ext.Name()
    if _, exists := em.extensions[name]; exists {
        return fmt.Errorf("extension %s already registered", name)
    }
    
    err := ext.Initialize(em.module)
    if err != nil {
        return fmt.Errorf("failed to initialize extension %s: %w", name, err)
    }
    
    em.extensions[name] = ext
    return nil
}

// GetExtension returns a vendor extension by name
func (em *ExtensionManager) GetExtension(name string) (VendorExtension, bool) {
    ext, ok := em.extensions[name]
    return ext, ok
}

// GetSupportedExtensions returns the list of supported extensions for the current library
func (em *ExtensionManager) GetSupportedExtensions() []string {
    var supported []string
    for name, ext := range em.extensions {
        if ext.IsSupported() {
            supported = append(supported, name)
        }
    }
    return supported
}
```

## Vendor-Specific Extensions

### Thales HSM Extension Example

```go
// ThalesExtension implements the VendorExtension interface for Thales HSM
type ThalesExtension struct {
    module    *PKCS11Module
    supported bool
    
    // Vendor-specific functions
    FunctionGenerateCryptogram func(SessionHandle, []byte, []byte) ([]byte, error)
    // ... other vendor-specific functions
}

// NewThalesExtension creates a new Thales extension
func NewThalesExtension() *ThalesExtension {
    return &ThalesExtension{}
}

// Name returns the extension name
func (e *ThalesExtension) Name() string {
    return "thales"
}

// Initialize initializes the extension
func (e *ThalesExtension) Initialize(module *PKCS11Module) error {
    e.module = module
    
    // Detect if this is a Thales HSM
    info := C.CK_INFO{}
    rv := C.C_GetInfo(&info)
    if rv != C.CKR_OK {
        return fmt.Errorf("C_GetInfo failed: %v", Error(rv))
    }
    
    // Check if this is a Thales HSM by examining the manufacturer ID
    manufacturerID := trimSpace(info.manufacturerID[:])
    if strings.Contains(strings.ToLower(manufacturerID), "thales") {
        e.supported = true
        // Initialize vendor-specific functions
        e.initFunctions()
    }
    
    return nil
}

// IsSupported returns if this extension is supported
func (e *ThalesExtension) IsSupported() bool {
    return e.supported
}

// GetSupportedMechanisms returns the list of vendor-specific mechanisms
func (e *ThalesExtension) GetSupportedMechanisms() []MechanismType {
    if !e.supported {
        return nil
    }
    
    return []MechanismType{
        MechanismType(0x80000001), // Thales custom mechanism 1
        MechanismType(0x80000002), // Thales custom mechanism 2
        // ... other mechanisms
    }
}

// GetSupportedAttributes returns the list of vendor-specific attributes
func (e *ThalesExtension) GetSupportedAttributes() []AttributeType {
    if !e.supported {
        return nil
    }
    
    return []AttributeType{
        AttributeType(0x80000001), // Thales custom attribute 1
        AttributeType(0x80000002), // Thales custom attribute 2
        // ... other attributes
    }
}

// GetSupportedFunctions returns the list of vendor-specific functions
func (e *ThalesExtension) GetSupportedFunctions() []string {
    if !e.supported {
        return nil
    }
    
    return []string{
        "GenerateCryptogram",
        // ... other functions
    }
}

// initFunctions initializes vendor-specific functions
func (e *ThalesExtension) initFunctions() {
    e.FunctionGenerateCryptogram = func(session SessionHandle, key []byte, data []byte) ([]byte, error) {
        // Implementation using vendor-specific PKCS#11 functions or mechanisms
        // ...
        return nil, nil
    }
    // ... initialize other functions
}
```

### Luna HSM Extension Example

```go
// LunaExtension implements the VendorExtension interface for Luna HSM
type LunaExtension struct {
    module    *PKCS11Module
    supported bool
    
    // Vendor-specific functions
    FunctionClusterActivate func(SessionHandle) error
    // ... other vendor-specific functions
}

// Similar implementation pattern as the Thales extension
// ...
```

### AWS CloudHSM Extension Example

```go
// AWSCloudHSMExtension implements the VendorExtension interface for AWS CloudHSM
type AWSCloudHSMExtension struct {
    module    *PKCS11Module
    supported bool
    
    // Vendor-specific functions
    FunctionGetServicesInfo func(SessionHandle) (string, error)
    // ... other vendor-specific functions
}

// Similar implementation pattern as the Thales extension
// ...
```

## Type Definitions for Vendor-Specific Extensions

### Vendor-Specific Attribute Types

```go
// Define attribute type ranges for vendor extensions
const (
    VendorAttributeBase = 0x80000000

    // Thales attribute range
    ThalesAttributeBase = VendorAttributeBase
    ThalesKeyMigration  = ThalesAttributeBase + 1
    ThalesCADestination = ThalesAttributeBase + 2
    
    // Luna attribute range
    LunaAttributeBase   = VendorAttributeBase + 0x1000
    LunaVPED            = LunaAttributeBase + 1
    LunaHSMInfo         = LunaAttributeBase + 2

    // AWS CloudHSM attribute range
    AWSAttributeBase    = VendorAttributeBase + 0x2000
    AWSMfaRequired      = AWSAttributeBase + 1
    AWSClusterInfo      = AWSAttributeBase + 2
)
```

### Vendor-Specific Mechanism Types

```go
// Define mechanism type ranges for vendor extensions
const (
    VendorMechanismBase = 0x80000000

    // Thales mechanism range
    ThalesMechanismBase = VendorMechanismBase
    ThalesEMV           = ThalesMechanismBase + 1
    ThalesIssuerScript  = ThalesMechanismBase + 2
    
    // Luna mechanism range
    LunaMechanismBase   = VendorMechanismBase + 0x1000
    LunaCloning         = LunaMechanismBase + 1
    LunaSharing         = LunaMechanismBase + 2

    // AWS CloudHSM mechanism range
    AWSMechanismBase    = VendorMechanismBase + 0x2000
    AWSMultipart        = AWSMechanismBase + 1
    AWSKdf              = AWSMechanismBase + 2
)
```

## Extension Usage Examples

### PKCS11Module Extension Integration

```go
// PKCS11Module integration
type PKCS11Module struct {
    // Core fields
    path           string
    handle         unsafe.Pointer
    versionInfo    *VersionInfo
    functionList   unsafe.Pointer
    
    // Extension manager
    extensions     *ExtensionManager
}

// Initialize with extensions
func (p *PKCS11Module) Initialize() error {
    // Basic initialization
    if err := p.initializeCore(); err != nil {
        return err
    }
    
    // Initialize extension manager
    p.extensions = NewExtensionManager(p)
    
    // Register known extensions
    if err := p.registerExtensions(); err != nil {
        return err
    }
    
    return nil
}

// Register known extensions
func (p *PKCS11Module) registerExtensions() error {
    // Register Thales extension
    if err := p.extensions.RegisterExtension(NewThalesExtension()); err != nil {
        return err
    }
    
    // Register Luna extension
    if err := p.extensions.RegisterExtension(NewLunaExtension()); err != nil {
        return err
    }
    
    // Register AWS CloudHSM extension
    if err := p.extensions.RegisterExtension(NewAWSCloudHSMExtension()); err != nil {
        return err
    }
    
    // Register other vendor extensions
    
    return nil
}

// GetExtension returns a vendor extension
func (p *PKCS11Module) GetExtension(name string) (VendorExtension, bool) {
    return p.extensions.GetExtension(name)
}

// GetSupportedExtensions returns the list of supported extensions
func (p *PKCS11Module) GetSupportedExtensions() []string {
    return p.extensions.GetSupportedExtensions()
}
```

### Using Vendor Extensions in Application Code

```go
// Initialize PKCS#11 module
p, err := gopkcs11.New("/path/to/hsm/lib.so")
if err != nil {
    log.Fatalf("Failed to initialize: %v", err)
}

// Open session
session, err := p.OpenSession(slot, gopkcs11.CKF_SERIAL_SESSION|gopkcs11.CKF_RW_SESSION)
if err != nil {
    log.Fatalf("Failed to open session: %v", err)
}

// Check if Thales extensions are supported
if extensions := p.GetSupportedExtensions(); contains(extensions, "thales") {
    // Get Thales extension
    thalesExt, _ := p.GetExtension("thales").(*gopkcs11.ThalesExtension)
    
    // Use vendor-specific function
    cryptogram, err := thalesExt.FunctionGenerateCryptogram(session, key, data)
    if err != nil {
        log.Fatalf("Failed to generate cryptogram: %v", err)
    }
    
    // Process cryptogram
    // ...
}
```

## Extension Documentation

Each vendor extension should include comprehensive documentation:

1. Supported HSM models and firmware versions
2. Vendor-specific attributes and their usage
3. Vendor-specific mechanisms and their parameters
4. Custom functions and their behavior
5. Error conditions and handling
6. Version compatibility notes

This documentation should be maintained both as code comments and in separate
vendor-specific documentation files under the vendor directory.