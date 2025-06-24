# PKCS#11 Version Compatibility Design

This document outlines the approach for supporting both PKCS#11 v2.4 and v3.0 standards in the gopkcs11 library.

## Version Detection

### Runtime Detection

```go
type PKCS11Module struct {
    path            string
    handle          unsafe.Pointer
    versionInfo     *VersionInfo
    functionList    unsafe.Pointer
    supportedFeatures FeatureMap
}

type VersionInfo struct {
    Major uint8
    Minor uint8
    IsV3  bool
}

// During initialization
func (p *PKCS11Module) detectVersion() error {
    // Call C_GetInfo to get library version information
    info := C.CK_INFO{}
    rv := C.C_GetInfo(&info)
    if rv != C.CKR_OK {
        return fmt.Errorf("C_GetInfo failed: %v", Error(rv))
    }
    
    p.versionInfo = &VersionInfo{
        Major: uint8(info.cryptokiVersion.major),
        Minor: uint8(info.cryptokiVersion.minor),
        IsV3: info.cryptokiVersion.major >= 3,
    }
    
    // Detect supported features
    p.detectFeatures()
    
    return nil
}
```

### Feature Detection

```go
type FeatureMap map[Feature]bool

const (
    FeatureMultipleAuthentication Feature = iota
    FeatureExtendedAttributes
    FeatureInteropMode
    FeatureProfileAttributes
    // Additional features
)

func (p *PKCS11Module) detectFeatures() {
    p.supportedFeatures = make(FeatureMap)
    
    // Detect v3.0 features if appropriate
    if p.versionInfo.IsV3 {
        // Try to use v3.0 specific functions
        p.detectV3Features()
    }
    
    // Check for common extended features
    // Some v2.4 implementations may support features that became standard in v3.0
    p.detectExtendedFeatures()
}
```

## Type Definitions

### Version-Specific Types

```go
// Base types common to both versions
type SessionHandle uint

// Version-specific type definitions
var (
    attributeTypeMap map[string]interface{}
    mechanismTypeMap map[string]interface{}
)

func init() {
    // Initialize with common types
    attributeTypeMap = make(map[string]interface{})
    mechanismTypeMap = make(map[string]interface{})
    
    // Add v2.4 standard types
    initV24Types()
    
    // Add v3.0 types separately
    initV30Types()
}

func initV24Types() {
    // Standard v2.4 attribute types
    attributeTypeMap["CKA_CLASS"] = uint(0)
    attributeTypeMap["CKA_TOKEN"] = uint(1)
    // ...
}

func initV30Types() {
    // Additional v3.0 attribute types 
    attributeTypeMap["CKA_INTEROP_MODE"] = uint(0x100)
    // ...
}
```

## Function Compatibility Layer

### Unified API with Version-Specific Implementation

```go
// Unified function that works across versions
func (p *PKCS11Module) GenerateKeyPair(session SessionHandle, mechanism *Mechanism, 
                                      publicAttrs, privateAttrs []*Attribute) (PublicKeyHandle, PrivateKeyHandle, error) {
    if p.versionInfo.IsV3 && p.supportedFeatures[FeatureExtendedAttributes] {
        return p.generateKeyPairV3(session, mechanism, publicAttrs, privateAttrs)
    }
    
    return p.generateKeyPairV24(session, mechanism, publicAttrs, privateAttrs)
}

func (p *PKCS11Module) generateKeyPairV24(session SessionHandle, mechanism *Mechanism, 
                                         publicAttrs, privateAttrs []*Attribute) (PublicKeyHandle, PrivateKeyHandle, error) {
    // v2.4 implementation
}

func (p *PKCS11Module) generateKeyPairV3(session SessionHandle, mechanism *Mechanism, 
                                        publicAttrs, privateAttrs []*Attribute) (PublicKeyHandle, PrivateKeyHandle, error) {
    // v3.0 implementation using extended features
}
```

## Configuration Options

```go
type Config struct {
    Path         string `json:"path"`
    TokenLabel   string `json:"token_label"`
    Pin          string `json:"pin"`
    
    // Version compatibility options
    ForceV24Mode bool   `json:"force_v24_mode"`  // Force use of v2.4 API even on v3.0
    DisableFeatures []Feature `json:"disable_features"` // Disable specific features
}
```

## Feature Detection Examples

### PKCS#11 v3.0 Specific Features

1. **Multiple Authentication**
   - Detection: Test C_LoginUser availability
   - Fallback: Use standard C_Login for v2.4

2. **Extended Attributes**
   - Detection: Try setting v3.0-specific attributes
   - Fallback: Use only v2.4 attributes 

3. **Interoperability Mode**
   - Detection: Query CKA_INTEROP_MODE attribute support
   - Fallback: No interop mode in v2.4

4. **Profile-Specific Attributes**
   - Detection: Check profile IDs availability
   - Fallback: No profiles in v2.4

## Usage Examples

### Version-Aware Code

```go
ctx, err := gopkcs11.New("/path/to/pkcs11lib.so")
if err != nil {
    log.Fatalf("Failed to initialize: %v", err)
}

// Use version-specific features when available
if ctx.SupportsFeature(gopkcs11.FeatureMultipleAuthentication) {
    // Use multiple authentication
    err = ctx.LoginUser(session, gopkcs11.UserType, "username", "password")
} else {
    // Fall back to standard login
    err = ctx.Login(session, gopkcs11.UserType, "password")
}
```

### Configuring Behavior for Specific Versions

```go
config := &gopkcs11.Config{
    Path: "/path/to/pkcs11lib.so",
    TokenLabel: "my-token",
    Pin: "token-pin",
    ForceV24Mode: true, // Force v2.4 compatibility mode
}

ctx, err := gopkcs11.NewWithConfig(config)
```