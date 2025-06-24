package pkcs11

/*
#cgo LDFLAGS: -ldl
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

// PKCS#11 basic types for CGO compatibility
typedef unsigned char   CK_BYTE;
typedef CK_BYTE         CK_CHAR;
typedef CK_BYTE         CK_UTF8CHAR;
typedef CK_BYTE         CK_BBOOL;
typedef unsigned long   CK_ULONG;
typedef long            CK_LONG;
typedef CK_ULONG        CK_FLAGS;
typedef CK_ULONG        CK_RV;
typedef CK_ULONG        CK_SESSION_HANDLE;
typedef CK_ULONG        CK_OBJECT_HANDLE;
typedef CK_ULONG        CK_SLOT_ID;
typedef CK_ULONG        CK_MECHANISM_TYPE;
typedef CK_ULONG        CK_USER_TYPE;
typedef CK_ULONG        CK_ATTRIBUTE_TYPE;

// Version structure
typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

// Info structure
typedef struct CK_INFO {
    CK_VERSION cryptokiVersion;
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_UTF8CHAR libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;

// Slot info structure
typedef struct CK_SLOT_INFO {
    CK_UTF8CHAR slotDescription[64];
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
} CK_SLOT_INFO;

// Token info structure
typedef struct CK_TOKEN_INFO {
    CK_UTF8CHAR label[32];
    CK_UTF8CHAR manufacturerID[32];
    CK_UTF8CHAR model[16];
    CK_CHAR serialNumber[16];
    CK_FLAGS flags;
    CK_ULONG maxSessionCount;
    CK_ULONG sessionCount;
    CK_ULONG maxRwSessionCount;
    CK_ULONG rwSessionCount;
    CK_ULONG maxPinLen;
    CK_ULONG minPinLen;
    CK_ULONG totalPublicMemory;
    CK_ULONG freePublicMemory;
    CK_ULONG totalPrivateMemory;
    CK_ULONG freePrivateMemory;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
    CK_CHAR utcTime[16];
} CK_TOKEN_INFO;

// Attribute structure
typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type_;
    void *pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

// Mechanism structure
typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    void *pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;

// Function pointer types
typedef CK_RV (*CK_C_Initialize)(void *);
typedef CK_RV (*CK_C_Finalize)(void *);
typedef CK_RV (*CK_C_GetInfo)(CK_INFO *);
typedef CK_RV (*CK_C_GetSlotList)(CK_BBOOL, CK_SLOT_ID *, CK_ULONG *);
typedef CK_RV (*CK_C_GetSlotInfo)(CK_SLOT_ID, CK_SLOT_INFO *);
typedef CK_RV (*CK_C_GetTokenInfo)(CK_SLOT_ID, CK_TOKEN_INFO *);
typedef CK_RV (*CK_C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void *, void *, CK_SESSION_HANDLE *);
typedef CK_RV (*CK_C_CloseSession)(CK_SESSION_HANDLE);
typedef CK_RV (*CK_C_Login)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR *, CK_ULONG);
typedef CK_RV (*CK_C_Logout)(CK_SESSION_HANDLE);
typedef CK_RV (*CK_C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE *, CK_ULONG);
typedef CK_RV (*CK_C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE *, CK_ULONG, CK_ULONG *);
typedef CK_RV (*CK_C_FindObjectsFinal)(CK_SESSION_HANDLE);
typedef CK_RV (*CK_C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE *, CK_ULONG);
typedef CK_RV (*CK_C_SetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE *, CK_ULONG);
typedef CK_RV (*CK_C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_ATTRIBUTE *, CK_ULONG, CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *, CK_OBJECT_HANDLE *);
typedef CK_RV (*CK_C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE);
typedef CK_RV (*CK_C_Sign)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
typedef CK_RV (*CK_C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE);
typedef CK_RV (*CK_C_Verify)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG);
typedef CK_RV (*CK_C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE);
typedef CK_RV (*CK_C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
typedef CK_RV (*CK_C_DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE);
typedef CK_RV (*CK_C_Decrypt)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
typedef CK_RV (*CK_C_GenerateKey)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *);
typedef CK_RV (*CK_C_GenerateRandom)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG);

// Function list structure
typedef struct CK_FUNCTION_LIST {
    CK_VERSION version;
    CK_C_Initialize C_Initialize;
    CK_C_Finalize C_Finalize;
    CK_C_GetInfo C_GetInfo;
    CK_C_GetSlotList C_GetSlotList;
    CK_C_GetSlotInfo C_GetSlotInfo;
    CK_C_GetTokenInfo C_GetTokenInfo;
    CK_C_OpenSession C_OpenSession;
    CK_C_CloseSession C_CloseSession;
    CK_C_Login C_Login;
    CK_C_Logout C_Logout;
    CK_C_FindObjectsInit C_FindObjectsInit;
    CK_C_FindObjects C_FindObjects;
    CK_C_FindObjectsFinal C_FindObjectsFinal;
    CK_C_GetAttributeValue C_GetAttributeValue;
    CK_C_SetAttributeValue C_SetAttributeValue;
    CK_C_GenerateKeyPair C_GenerateKeyPair;
    CK_C_SignInit C_SignInit;
    CK_C_Sign C_Sign;
    CK_C_VerifyInit C_VerifyInit;
    CK_C_Verify C_Verify;
    CK_C_EncryptInit C_EncryptInit;
    CK_C_Encrypt C_Encrypt;
    CK_C_DecryptInit C_DecryptInit;
    CK_C_Decrypt C_Decrypt;
    CK_C_GenerateKey C_GenerateKey;
    CK_C_GenerateRandom C_GenerateRandom;
} CK_FUNCTION_LIST;

typedef CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;
typedef CK_RV (*CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR *);

// PKCS#11 constants
#define CKR_OK                   0x00000000UL
#define CK_UNAVAILABLE_INFORMATION   ((CK_ULONG) -1)

// Version configuration
#ifndef PKCS11_V30
    #define GOPKCS11_VERSION_MAJOR 2
    #define GOPKCS11_VERSION_MINOR 40
#else
    #define GOPKCS11_VERSION_MAJOR 3
    #define GOPKCS11_VERSION_MINOR 0
#endif

// Utimaco support flag
#ifdef UTIMACO_HSM
    #define GOPKCS11_HAS_UTIMACO 1
#else
    #define GOPKCS11_HAS_UTIMACO 0
#endif

// Helper function to call the C_GetFunctionList function
static CK_RV call_C_GetFunctionList(void* func_ptr, CK_FUNCTION_LIST_PTR* ppFunctionList) {
    CK_C_GetFunctionList func = (CK_C_GetFunctionList)func_ptr;
    return func(ppFunctionList);
}

// Helper functions to call PKCS#11 functions through function pointers
static CK_RV call_C_Initialize(CK_FUNCTION_LIST_PTR p, void* pInitArgs) {
    return p->C_Initialize(pInitArgs);
}

static CK_RV call_C_Finalize(CK_FUNCTION_LIST_PTR p, void* pReserved) {
    return p->C_Finalize(pReserved);
}

static CK_RV call_C_GetInfo(CK_FUNCTION_LIST_PTR p, CK_INFO* pInfo) {
    return p->C_GetInfo(pInfo);
}

static CK_RV call_C_GetSlotList(CK_FUNCTION_LIST_PTR p, CK_BBOOL tokenPresent, CK_SLOT_ID* pSlotList, CK_ULONG* pulCount) {
    return p->C_GetSlotList(tokenPresent, pSlotList, pulCount);
}

static CK_RV call_C_GetSlotInfo(CK_FUNCTION_LIST_PTR p, CK_SLOT_ID slotID, CK_SLOT_INFO* pInfo) {
    return p->C_GetSlotInfo(slotID, pInfo);
}

static CK_RV call_C_GetTokenInfo(CK_FUNCTION_LIST_PTR p, CK_SLOT_ID slotID, CK_TOKEN_INFO* pInfo) {
    return p->C_GetTokenInfo(slotID, pInfo);
}

static CK_RV call_C_OpenSession(CK_FUNCTION_LIST_PTR p, CK_SLOT_ID slotID, CK_FLAGS flags, void* pApplication, void* Notify, CK_SESSION_HANDLE* phSession) {
    return p->C_OpenSession(slotID, flags, pApplication, Notify, phSession);
}

static CK_RV call_C_CloseSession(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession) {
    return p->C_CloseSession(hSession);
}

static CK_RV call_C_Login(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR* pPin, CK_ULONG ulPinLen) {
    return p->C_Login(hSession, userType, pPin, ulPinLen);
}

static CK_RV call_C_Logout(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession) {
    return p->C_Logout(hSession);
}

static CK_RV call_C_FindObjectsInit(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, CK_ATTRIBUTE* pTemplate, CK_ULONG ulCount) {
    return p->C_FindObjectsInit(hSession, pTemplate, ulCount);
}

static CK_RV call_C_FindObjects(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE* phObject, CK_ULONG ulMaxObjectCount, CK_ULONG* pulObjectCount) {
    return p->C_FindObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount);
}

static CK_RV call_C_FindObjectsFinal(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession) {
    return p->C_FindObjectsFinal(hSession);
}

static CK_RV call_C_GetAttributeValue(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE* pTemplate, CK_ULONG ulCount) {
    return p->C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
}

static CK_RV call_C_SetAttributeValue(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE* pTemplate, CK_ULONG ulCount) {
    return p->C_SetAttributeValue(hSession, hObject, pTemplate, ulCount);
}

static CK_RV call_C_GenerateKeyPair(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, CK_MECHANISM* pMechanism, CK_ATTRIBUTE* pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE* pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE* phPublicKey, CK_OBJECT_HANDLE* phPrivateKey) {
    return p->C_GenerateKeyPair(hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey);
}

static CK_RV call_C_SignInit(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, CK_MECHANISM* pMechanism, CK_OBJECT_HANDLE hKey) {
    return p->C_SignInit(hSession, pMechanism, hKey);
}

static CK_RV call_C_Sign(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, CK_BYTE* pData, CK_ULONG ulDataLen, CK_BYTE* pSignature, CK_ULONG* pulSignatureLen) {
    return p->C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}

static CK_RV call_C_VerifyInit(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, CK_MECHANISM* pMechanism, CK_OBJECT_HANDLE hKey) {
    return p->C_VerifyInit(hSession, pMechanism, hKey);
}

static CK_RV call_C_Verify(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, CK_BYTE* pData, CK_ULONG ulDataLen, CK_BYTE* pSignature, CK_ULONG ulSignatureLen) {
    return p->C_Verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
}

static CK_RV call_C_EncryptInit(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, CK_MECHANISM* pMechanism, CK_OBJECT_HANDLE hKey) {
    return p->C_EncryptInit(hSession, pMechanism, hKey);
}

static CK_RV call_C_Encrypt(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, CK_BYTE* pData, CK_ULONG ulDataLen, CK_BYTE* pEncryptedData, CK_ULONG* pulEncryptedDataLen) {
    return p->C_Encrypt(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
}

static CK_RV call_C_DecryptInit(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, CK_MECHANISM* pMechanism, CK_OBJECT_HANDLE hKey) {
    return p->C_DecryptInit(hSession, pMechanism, hKey);
}

static CK_RV call_C_Decrypt(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, CK_BYTE* pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE* pData, CK_ULONG* pulDataLen) {
    return p->C_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
}

static CK_RV call_C_GenerateKey(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, CK_MECHANISM* pMechanism, CK_ATTRIBUTE* pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE* phKey) {
    return p->C_GenerateKey(hSession, pMechanism, pTemplate, ulCount, phKey);
}

static CK_RV call_C_GenerateRandom(CK_FUNCTION_LIST_PTR p, CK_SESSION_HANDLE hSession, CK_BYTE* RandomData, CK_ULONG ulRandomLen) {
    return p->C_GenerateRandom(hSession, RandomData, ulRandomLen);
}

// Helper functions to get compile-time version information
static int get_pkcs11_version_major() {
    return GOPKCS11_VERSION_MAJOR;
}

static int get_pkcs11_version_minor() {
    return GOPKCS11_VERSION_MINOR;
}

// Check if Utimaco extensions are compiled in
static int has_utimaco_extensions() {
    return GOPKCS11_HAS_UTIMACO;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// GetCompileTimeVersion returns the PKCS#11 version this wrapper was compiled with
func GetCompileTimeVersion() (major, minor int) {
	return int(C.get_pkcs11_version_major()), int(C.get_pkcs11_version_minor())
}

// HasUtimacoExtensions returns true if Utimaco extensions were compiled in
func HasUtimacoExtensions() bool {
	return int(C.has_utimaco_extensions()) == 1
}

// LoadModule loads a PKCS#11 module from a shared library
func LoadModule(path string) (*Module, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	handle := C.dlopen(cpath, C.RTLD_NOW)
	if handle == nil {
		err := C.dlerror()
		if err == nil {
			return nil, fmt.Errorf("failed to load module %s", path)
		}
		return nil, fmt.Errorf("failed to load module %s: %s", path, C.GoString(err))
	}

	module := &Module{
		LibHandle: handle,
		Path:      path,
	}

	// Get the C_GetFunctionList function
	sym := C.CString("C_GetFunctionList")
	defer C.free(unsafe.Pointer(sym))
	getFuncList := C.dlsym(handle, sym)
	if getFuncList == nil {
		err := C.dlerror()
		if err == nil {
			return nil, fmt.Errorf("failed to find C_GetFunctionList in module %s", path)
		}
		return nil, fmt.Errorf("failed to find C_GetFunctionList in module %s: %s", path, C.GoString(err))
	}

	var p C.CK_FUNCTION_LIST_PTR
	rv := C.CK_RV(C.call_C_GetFunctionList(getFuncList, &p))
	if rv != C.CKR_OK {
		return nil, Error{Code: uint(rv)}
	}

	module.FunctionList = unsafe.Pointer(p)
	module.VersionMajor = uint8(p.version.major)
	module.VersionMinor = uint8(p.version.minor)

	// Initialize the module
	if err := module.Initialize(); err != nil {
		return nil, err
	}

	// Get module info
	var info C.CK_INFO
	rv = C.CK_RV(C.call_C_GetInfo(p, &info))
	if rv != C.CKR_OK {
		return nil, Error{Code: uint(rv)}
	}

	module.Info = Info{
		CryptokiVersion: Version{
			Major: uint8(info.cryptokiVersion.major),
			Minor: uint8(info.cryptokiVersion.minor),
		},
		ManufacturerID:     TrimSpace(string(C.GoBytes(unsafe.Pointer(&info.manufacturerID[0]), 32))),
		LibraryDescription: TrimSpace(string(C.GoBytes(unsafe.Pointer(&info.libraryDescription[0]), 32))),
		LibraryVersion: Version{
			Major: uint8(info.libraryVersion.major),
			Minor: uint8(info.libraryVersion.minor),
		},
	}

	return module, nil
}

// Initialize initializes the PKCS#11 module
func (m *Module) Initialize() error {
	if m.FunctionList == nil {
		return fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)
	rv := C.CK_RV(C.call_C_Initialize(p, nil))

	if rv != C.CKR_OK {
		return Error{Code: uint(rv)}
	}

	return nil
}

// Finalize finalizes the PKCS#11 module
func (m *Module) Finalize() error {
	if m.FunctionList == nil {
		return fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)
	rv := C.CK_RV(C.call_C_Finalize(p, nil))

	defer func() {
		if m.LibHandle != nil {
			C.dlclose(m.LibHandle)
			m.LibHandle = nil
			m.FunctionList = nil
		}
	}()

	if rv != C.CKR_OK {
		return Error{Code: uint(rv)}
	}

	return nil
}

// GetSlotList gets a list of slots in the system
func (m *Module) GetSlotList(tokenPresent bool) ([]uint, error) {
	if m.FunctionList == nil {
		return nil, fmt.Errorf("module not loaded")
	}

	var tp C.CK_BBOOL
	if tokenPresent {
		tp = C.CK_BBOOL(1)
	} else {
		tp = C.CK_BBOOL(0)
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)
	var count C.CK_ULONG
	rv := C.CK_RV(C.call_C_GetSlotList(p, tp, nil, &count))
	if rv != C.CKR_OK {
		return nil, Error{Code: uint(rv)}
	}

	if count == 0 {
		return []uint{}, nil
	}

	cSlots := make([]C.CK_SLOT_ID, count)
	rv = C.CK_RV(C.call_C_GetSlotList(p, tp, &cSlots[0], &count))
	if rv != C.CKR_OK {
		return nil, Error{Code: uint(rv)}
	}

	slots := make([]uint, count)
	for i := 0; i < int(count); i++ {
		slots[i] = uint(cSlots[i])
	}

	return slots, nil
}

// GetSlotInfo gets information about a slot
func (m *Module) GetSlotInfo(slotID uint) (*SlotInfo, error) {
	if m.FunctionList == nil {
		return nil, fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)
	var cInfo C.CK_SLOT_INFO
	rv := C.CK_RV(C.call_C_GetSlotInfo(p, C.CK_SLOT_ID(slotID), &cInfo))
	if rv != C.CKR_OK {
		return nil, Error{Code: uint(rv)}
	}

	info := &SlotInfo{
		SlotDescription: TrimSpace(TrimNull(C.GoBytes(unsafe.Pointer(&cInfo.slotDescription[0]), 64))),
		ManufacturerID:  TrimSpace(TrimNull(C.GoBytes(unsafe.Pointer(&cInfo.manufacturerID[0]), 32))),
		Flags:           uint(cInfo.flags),
		HardwareVersion: Version{
			Major: uint8(cInfo.hardwareVersion.major),
			Minor: uint8(cInfo.hardwareVersion.minor),
		},
		FirmwareVersion: Version{
			Major: uint8(cInfo.firmwareVersion.major),
			Minor: uint8(cInfo.firmwareVersion.minor),
		},
	}

	return info, nil
}

// GetTokenInfo gets information about a token in a slot
func (m *Module) GetTokenInfo(slotID uint) (*TokenInfo, error) {
	if m.FunctionList == nil {
		return nil, fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)
	var cInfo C.CK_TOKEN_INFO
	rv := C.CK_RV(C.call_C_GetTokenInfo(p, C.CK_SLOT_ID(slotID), &cInfo))
	if rv != C.CKR_OK {
		return nil, Error{Code: uint(rv)}
	}

	info := &TokenInfo{
		Label:              TrimSpace(TrimNull(C.GoBytes(unsafe.Pointer(&cInfo.label[0]), 32))),
		ManufacturerID:     TrimSpace(TrimNull(C.GoBytes(unsafe.Pointer(&cInfo.manufacturerID[0]), 32))),
		Model:              TrimSpace(TrimNull(C.GoBytes(unsafe.Pointer(&cInfo.model[0]), 16))),
		SerialNumber:       TrimSpace(TrimNull(C.GoBytes(unsafe.Pointer(&cInfo.serialNumber[0]), 16))),
		Flags:              uint(cInfo.flags),
		MaxSessionCount:    uint(cInfo.maxSessionCount),
		SessionCount:       uint(cInfo.sessionCount),
		MaxRWSessionCount:  uint(cInfo.maxRwSessionCount),
		RWSessionCount:     uint(cInfo.rwSessionCount),
		MaxPinLen:          uint(cInfo.maxPinLen),
		MinPinLen:          uint(cInfo.minPinLen),
		TotalPublicMemory:  uint(cInfo.totalPublicMemory),
		FreePublicMemory:   uint(cInfo.freePublicMemory),
		TotalPrivateMemory: uint(cInfo.totalPrivateMemory),
		FreePrivateMemory:  uint(cInfo.freePrivateMemory),
		HardwareVersion: Version{
			Major: uint8(cInfo.hardwareVersion.major),
			Minor: uint8(cInfo.hardwareVersion.minor),
		},
		FirmwareVersion: Version{
			Major: uint8(cInfo.firmwareVersion.major),
			Minor: uint8(cInfo.firmwareVersion.minor),
		},
		UTCTime: TrimSpace(TrimNull(C.GoBytes(unsafe.Pointer(&cInfo.utcTime[0]), 16))),
	}

	return info, nil
}

// OpenSession opens a session with a token
func (m *Module) OpenSession(slotID uint, flags uint) (uint, error) {
	if m.FunctionList == nil {
		return 0, fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)
	var session C.CK_SESSION_HANDLE
	rv := C.CK_RV(C.call_C_OpenSession(p, C.CK_SLOT_ID(slotID), C.CK_FLAGS(flags), nil, nil, &session))
	if rv != C.CKR_OK {
		return 0, Error{Code: uint(rv)}
	}

	return uint(session), nil
}

// CloseSession closes a session
func (m *Module) CloseSession(session uint) error {
	if m.FunctionList == nil {
		return fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)
	rv := C.CK_RV(C.call_C_CloseSession(p, C.CK_SESSION_HANDLE(session)))
	if rv != C.CKR_OK {
		return Error{Code: uint(rv)}
	}

	return nil
}

// Login logs a user into a token
func (m *Module) Login(session uint, userType uint, pin string) error {
	if m.FunctionList == nil {
		return fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)

	var cPin *C.CK_UTF8CHAR
	var pinLen C.CK_ULONG

	if pin != "" {
		cPin = (*C.CK_UTF8CHAR)(unsafe.Pointer(C.CString(pin)))
		defer C.free(unsafe.Pointer(cPin))
		pinLen = C.CK_ULONG(len(pin))
	}

	rv := C.CK_RV(C.call_C_Login(p, C.CK_SESSION_HANDLE(session), C.CK_USER_TYPE(userType), cPin, pinLen))
	if rv != C.CKR_OK {
		return Error{Code: uint(rv)}
	}

	return nil
}

// Logout logs a user out from a token
func (m *Module) Logout(session uint) error {
	if m.FunctionList == nil {
		return fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)
	rv := C.CK_RV(C.call_C_Logout(p, C.CK_SESSION_HANDLE(session)))
	if rv != C.CKR_OK {
		return Error{Code: uint(rv)}
	}

	return nil
}

// FindObjectsInit initializes a search for token and session objects
func (m *Module) FindObjectsInit(session uint, attrs []*Attribute) error {
	if m.FunctionList == nil {
		return fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)

	var cAttrs []C.CK_ATTRIBUTE
	for _, attr := range attrs {
		var cAttr C.CK_ATTRIBUTE
		cAttr.type_ = C.CK_ATTRIBUTE_TYPE(attr.Type)
		if len(attr.Value) > 0 {
			cAttr.pValue = C.CBytes(attr.Value)
			defer C.free(cAttr.pValue)
			cAttr.ulValueLen = C.CK_ULONG(len(attr.Value))
		} else {
			cAttr.pValue = nil
			cAttr.ulValueLen = 0
		}
		cAttrs = append(cAttrs, cAttr)
	}

	var cAttrsPtr *C.CK_ATTRIBUTE
	if len(cAttrs) > 0 {
		cAttrsPtr = &cAttrs[0]
	}

	rv := C.CK_RV(C.call_C_FindObjectsInit(p, C.CK_SESSION_HANDLE(session), cAttrsPtr, C.CK_ULONG(len(attrs))))
	if rv != C.CKR_OK {
		return Error{Code: uint(rv)}
	}

	return nil
}

// FindObjects continues a search for token and session objects
func (m *Module) FindObjects(session uint, max int) ([]uint, error) {
	if m.FunctionList == nil {
		return nil, fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)

	var objects []C.CK_OBJECT_HANDLE
	if max > 0 {
		objects = make([]C.CK_OBJECT_HANDLE, max)
	} else {
		objects = make([]C.CK_OBJECT_HANDLE, 1)
		max = 1
	}

	var count C.CK_ULONG
	rv := C.CK_RV(C.call_C_FindObjects(p, C.CK_SESSION_HANDLE(session), &objects[0], C.CK_ULONG(max), &count))
	if rv != C.CKR_OK {
		return nil, Error{Code: uint(rv)}
	}

	result := make([]uint, count)
	for i := 0; i < int(count); i++ {
		result[i] = uint(objects[i])
	}

	return result, nil
}

// FindObjectsFinal finishes a search for token and session objects
func (m *Module) FindObjectsFinal(session uint) error {
	if m.FunctionList == nil {
		return fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)
	rv := C.CK_RV(C.call_C_FindObjectsFinal(p, C.CK_SESSION_HANDLE(session)))
	if rv != C.CKR_OK {
		return Error{Code: uint(rv)}
	}

	return nil
}

// GetAttributeValue gets the value of one or more attributes of an object
func (m *Module) GetAttributeValue(session, object uint, attrs []*Attribute) ([]*Attribute, error) {
	if m.FunctionList == nil {
		return nil, fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)

	var cAttrs []C.CK_ATTRIBUTE
	for _, attr := range attrs {
		var cAttr C.CK_ATTRIBUTE
		cAttr.type_ = C.CK_ATTRIBUTE_TYPE(attr.Type)
		cAttr.pValue = nil
		cAttr.ulValueLen = 0
		cAttrs = append(cAttrs, cAttr)
	}

	// First call to get attribute sizes
	rv := C.CK_RV(C.call_C_GetAttributeValue(p, C.CK_SESSION_HANDLE(session), C.CK_OBJECT_HANDLE(object), &cAttrs[0], C.CK_ULONG(len(cAttrs))))
	if rv != C.CKR_OK {
		return nil, Error{Code: uint(rv)}
	}

	// Allocate memory for attribute values
	for i := range cAttrs {
		if cAttrs[i].ulValueLen != C.CK_UNAVAILABLE_INFORMATION {
			cAttrs[i].pValue = C.malloc(C.size_t(cAttrs[i].ulValueLen))
			defer C.free(cAttrs[i].pValue)
		}
	}

	// Second call to get attribute values
	rv = C.CK_RV(C.call_C_GetAttributeValue(p, C.CK_SESSION_HANDLE(session), C.CK_OBJECT_HANDLE(object), &cAttrs[0], C.CK_ULONG(len(cAttrs))))
	if rv != C.CKR_OK {
		return nil, Error{Code: uint(rv)}
	}

	// Convert C attributes to Go attributes
	result := make([]*Attribute, len(attrs))
	for i := range cAttrs {
		if cAttrs[i].ulValueLen != C.CK_UNAVAILABLE_INFORMATION {
			result[i] = &Attribute{
				Type:  uint(cAttrs[i].type_),
				Value: C.GoBytes(cAttrs[i].pValue, C.int(cAttrs[i].ulValueLen)),
			}
		} else {
			result[i] = &Attribute{
				Type:  uint(cAttrs[i].type_),
				Value: nil,
			}
		}
	}

	return result, nil
}

// GenerateKeyPair generates a public-key/private-key pair
func (m *Module) GenerateKeyPair(session uint, mechanism *Mechanism, pubKeyTemplate, privKeyTemplate []*Attribute) (pubKey, privKey uint, err error) {
	if m.FunctionList == nil {
		return 0, 0, fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)

	// Convert mechanism to C mechanism
	var mech C.CK_MECHANISM
	mech.mechanism = C.CK_MECHANISM_TYPE(mechanism.Mechanism)

	if len(mechanism.Parameter) > 0 {
		mech.pParameter = C.CBytes(mechanism.Parameter)
		defer C.free(mech.pParameter)
		mech.ulParameterLen = C.CK_ULONG(len(mechanism.Parameter))
	} else {
		mech.pParameter = nil
		mech.ulParameterLen = 0
	}

	// Convert public key template to C attributes
	var cPubAttrs []C.CK_ATTRIBUTE
	for _, attr := range pubKeyTemplate {
		var cAttr C.CK_ATTRIBUTE
		cAttr.type_ = C.CK_ATTRIBUTE_TYPE(attr.Type)

		if len(attr.Value) > 0 {
			cAttr.pValue = C.CBytes(attr.Value)
			defer C.free(cAttr.pValue)
			cAttr.ulValueLen = C.CK_ULONG(len(attr.Value))
		} else {
			cAttr.pValue = nil
			cAttr.ulValueLen = 0
		}

		cPubAttrs = append(cPubAttrs, cAttr)
	}

	// Convert private key template to C attributes
	var cPrivAttrs []C.CK_ATTRIBUTE
	for _, attr := range privKeyTemplate {
		var cAttr C.CK_ATTRIBUTE
		cAttr.type_ = C.CK_ATTRIBUTE_TYPE(attr.Type)

		if len(attr.Value) > 0 {
			cAttr.pValue = C.CBytes(attr.Value)
			defer C.free(cAttr.pValue)
			cAttr.ulValueLen = C.CK_ULONG(len(attr.Value))
		} else {
			cAttr.pValue = nil
			cAttr.ulValueLen = 0
		}

		cPrivAttrs = append(cPrivAttrs, cAttr)
	}

	var cPubKey, cPrivKey C.CK_OBJECT_HANDLE

	var cPubAttrsPtr *C.CK_ATTRIBUTE
	if len(cPubAttrs) > 0 {
		cPubAttrsPtr = &cPubAttrs[0]
	}

	var cPrivAttrsPtr *C.CK_ATTRIBUTE
	if len(cPrivAttrs) > 0 {
		cPrivAttrsPtr = &cPrivAttrs[0]
	}

	rv := C.CK_RV(C.call_C_GenerateKeyPair(
		p,
		C.CK_SESSION_HANDLE(session),
		&mech,
		cPubAttrsPtr, C.CK_ULONG(len(cPubAttrs)),
		cPrivAttrsPtr, C.CK_ULONG(len(cPrivAttrs)),
		&cPubKey,
		&cPrivKey,
	))

	if rv != C.CKR_OK {
		return 0, 0, Error{Code: uint(rv)}
	}

	return uint(cPubKey), uint(cPrivKey), nil
}

// SignInit initializes a signature operation
func (m *Module) SignInit(session uint, mechanism *Mechanism, key uint) error {
	if m.FunctionList == nil {
		return fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)

	// Convert mechanism to C mechanism
	var mech C.CK_MECHANISM
	mech.mechanism = C.CK_MECHANISM_TYPE(mechanism.Mechanism)

	if len(mechanism.Parameter) > 0 {
		mech.pParameter = C.CBytes(mechanism.Parameter)
		defer C.free(mech.pParameter)
		mech.ulParameterLen = C.CK_ULONG(len(mechanism.Parameter))
	} else {
		mech.pParameter = nil
		mech.ulParameterLen = 0
	}

	rv := C.CK_RV(C.call_C_SignInit(
		p,
		C.CK_SESSION_HANDLE(session),
		&mech,
		C.CK_OBJECT_HANDLE(key),
	))

	if rv != C.CKR_OK {
		return Error{Code: uint(rv)}
	}

	return nil
}

// Sign signs data
func (m *Module) Sign(session uint, data []byte) ([]byte, error) {
	if m.FunctionList == nil {
		return nil, fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)

	var signatureLen C.CK_ULONG

	// Get signature length
	rv := C.CK_RV(C.call_C_Sign(
		p,
		C.CK_SESSION_HANDLE(session),
		(*C.CK_BYTE)(C.CBytes(data)), C.CK_ULONG(len(data)),
		nil, &signatureLen,
	))

	if rv != C.CKR_OK {
		return nil, Error{Code: uint(rv)}
	}

	// Allocate memory for signature
	signature := make([]byte, signatureLen)

	// Get signature
	rv = C.CK_RV(C.call_C_Sign(
		p,
		C.CK_SESSION_HANDLE(session),
		(*C.CK_BYTE)(C.CBytes(data)), C.CK_ULONG(len(data)),
		(*C.CK_BYTE)(unsafe.Pointer(&signature[0])), &signatureLen,
	))

	if rv != C.CKR_OK {
		return nil, Error{Code: uint(rv)}
	}

	return signature[:signatureLen], nil
}

// GenerateRandom generates random data
func (m *Module) GenerateRandom(session uint, length int) ([]byte, error) {
	if m.FunctionList == nil {
		return nil, fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)

	random := make([]byte, length)

	rv := C.CK_RV(C.call_C_GenerateRandom(
		p,
		C.CK_SESSION_HANDLE(session),
		(*C.CK_BYTE)(unsafe.Pointer(&random[0])),
		C.CK_ULONG(length),
	))

	if rv != C.CKR_OK {
		return nil, Error{Code: uint(rv)}
	}

	return random, nil
}

// Function to convert Go byte to C.CK_BYTE
func goToCKByte(in byte) C.CK_BYTE {
	return C.CK_BYTE(in)
}

// Function to convert C.CK_BYTE to Go byte
func ckToGoByte(in C.CK_BYTE) byte {
	return byte(in)
}

// Function to convert Go bool to C.CK_BBOOL
func goToCKBool(in bool) C.CK_BBOOL {
	if in {
		return C.CK_BBOOL(1)
	}
	return C.CK_BBOOL(0)
}

// Function to convert C.CK_BBOOL to Go bool
func ckToGoBool(in C.CK_BBOOL) bool {
	if in == 0 {
		return false
	}
	return true
}

// SetAttributeValue sets the value of one or more object attributes
func (m *Module) SetAttributeValue(session, object uint, attrs []*Attribute) error {
	if m.FunctionList == nil {
		return fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)

	var cAttrs []C.CK_ATTRIBUTE
	for _, attr := range attrs {
		var cAttr C.CK_ATTRIBUTE
		cAttr.type_ = C.CK_ATTRIBUTE_TYPE(attr.Type)
		if len(attr.Value) > 0 {
			cAttr.pValue = C.CBytes(attr.Value)
			defer C.free(cAttr.pValue)
			cAttr.ulValueLen = C.CK_ULONG(len(attr.Value))
		} else {
			cAttr.pValue = nil
			cAttr.ulValueLen = 0
		}
		cAttrs = append(cAttrs, cAttr)
	}

	var cAttrsPtr *C.CK_ATTRIBUTE
	if len(cAttrs) > 0 {
		cAttrsPtr = &cAttrs[0]
	}

	rv := C.CK_RV(C.call_C_SetAttributeValue(p, C.CK_SESSION_HANDLE(session), C.CK_OBJECT_HANDLE(object), cAttrsPtr, C.CK_ULONG(len(attrs))))
	if rv != C.CKR_OK {
		return Error{Code: uint(rv)}
	}

	return nil
}

// GenerateKey generates a symmetric key
func (m *Module) GenerateKey(session uint, mechanism *Mechanism, template []*Attribute) (uint, error) {
	if m.FunctionList == nil {
		return 0, fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)

	// Convert mechanism to C mechanism
	var mech C.CK_MECHANISM
	mech.mechanism = C.CK_MECHANISM_TYPE(mechanism.Mechanism)

	if len(mechanism.Parameter) > 0 {
		mech.pParameter = C.CBytes(mechanism.Parameter)
		defer C.free(mech.pParameter)
		mech.ulParameterLen = C.CK_ULONG(len(mechanism.Parameter))
	} else {
		mech.pParameter = nil
		mech.ulParameterLen = 0
	}

	// Convert template to C attributes
	var cAttrs []C.CK_ATTRIBUTE
	for _, attr := range template {
		var cAttr C.CK_ATTRIBUTE
		cAttr.type_ = C.CK_ATTRIBUTE_TYPE(attr.Type)

		if len(attr.Value) > 0 {
			cAttr.pValue = C.CBytes(attr.Value)
			defer C.free(cAttr.pValue)
			cAttr.ulValueLen = C.CK_ULONG(len(attr.Value))
		} else {
			cAttr.pValue = nil
			cAttr.ulValueLen = 0
		}

		cAttrs = append(cAttrs, cAttr)
	}

	var cKey C.CK_OBJECT_HANDLE

	var cAttrsPtr *C.CK_ATTRIBUTE
	if len(cAttrs) > 0 {
		cAttrsPtr = &cAttrs[0]
	}

	rv := C.CK_RV(C.call_C_GenerateKey(
		p,
		C.CK_SESSION_HANDLE(session),
		&mech,
		cAttrsPtr, C.CK_ULONG(len(cAttrs)),
		&cKey,
	))

	if rv != C.CKR_OK {
		return 0, Error{Code: uint(rv)}
	}

	return uint(cKey), nil
}

// VerifyInit initializes a verification operation
func (m *Module) VerifyInit(session uint, mechanism *Mechanism, key uint) error {
	if m.FunctionList == nil {
		return fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)

	// Convert mechanism to C mechanism
	var mech C.CK_MECHANISM
	mech.mechanism = C.CK_MECHANISM_TYPE(mechanism.Mechanism)

	if len(mechanism.Parameter) > 0 {
		mech.pParameter = C.CBytes(mechanism.Parameter)
		defer C.free(mech.pParameter)
		mech.ulParameterLen = C.CK_ULONG(len(mechanism.Parameter))
	} else {
		mech.pParameter = nil
		mech.ulParameterLen = 0
	}

	rv := C.CK_RV(C.call_C_VerifyInit(
		p,
		C.CK_SESSION_HANDLE(session),
		&mech,
		C.CK_OBJECT_HANDLE(key),
	))

	if rv != C.CKR_OK {
		return Error{Code: uint(rv)}
	}

	return nil
}

// Verify verifies a signature
func (m *Module) Verify(session uint, data, signature []byte) error {
	if m.FunctionList == nil {
		return fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)

	rv := C.CK_RV(C.call_C_Verify(
		p,
		C.CK_SESSION_HANDLE(session),
		(*C.CK_BYTE)(C.CBytes(data)), C.CK_ULONG(len(data)),
		(*C.CK_BYTE)(C.CBytes(signature)), C.CK_ULONG(len(signature)),
	))

	if rv != C.CKR_OK {
		return Error{Code: uint(rv)}
	}

	return nil
}

// EncryptInit initializes an encryption operation
func (m *Module) EncryptInit(session uint, mechanism *Mechanism, key uint) error {
	if m.FunctionList == nil {
		return fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)

	// Convert mechanism to C mechanism
	var mech C.CK_MECHANISM
	mech.mechanism = C.CK_MECHANISM_TYPE(mechanism.Mechanism)

	if len(mechanism.Parameter) > 0 {
		mech.pParameter = C.CBytes(mechanism.Parameter)
		defer C.free(mech.pParameter)
		mech.ulParameterLen = C.CK_ULONG(len(mechanism.Parameter))
	} else {
		mech.pParameter = nil
		mech.ulParameterLen = 0
	}

	rv := C.CK_RV(C.call_C_EncryptInit(
		p,
		C.CK_SESSION_HANDLE(session),
		&mech,
		C.CK_OBJECT_HANDLE(key),
	))

	if rv != C.CKR_OK {
		return Error{Code: uint(rv)}
	}

	return nil
}

// Encrypt encrypts data
func (m *Module) Encrypt(session uint, data []byte) ([]byte, error) {
	if m.FunctionList == nil {
		return nil, fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)

	var ciphertextLen C.CK_ULONG

	// Get ciphertext length
	rv := C.CK_RV(C.call_C_Encrypt(
		p,
		C.CK_SESSION_HANDLE(session),
		(*C.CK_BYTE)(C.CBytes(data)), C.CK_ULONG(len(data)),
		nil, &ciphertextLen,
	))

	if rv != C.CKR_OK {
		return nil, Error{Code: uint(rv)}
	}

	// Allocate memory for ciphertext
	ciphertext := make([]byte, ciphertextLen)

	// Get ciphertext
	rv = C.CK_RV(C.call_C_Encrypt(
		p,
		C.CK_SESSION_HANDLE(session),
		(*C.CK_BYTE)(C.CBytes(data)), C.CK_ULONG(len(data)),
		(*C.CK_BYTE)(unsafe.Pointer(&ciphertext[0])), &ciphertextLen,
	))

	if rv != C.CKR_OK {
		return nil, Error{Code: uint(rv)}
	}

	return ciphertext[:ciphertextLen], nil
}

// DecryptInit initializes a decryption operation
func (m *Module) DecryptInit(session uint, mechanism *Mechanism, key uint) error {
	if m.FunctionList == nil {
		return fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)

	// Convert mechanism to C mechanism
	var mech C.CK_MECHANISM
	mech.mechanism = C.CK_MECHANISM_TYPE(mechanism.Mechanism)

	if len(mechanism.Parameter) > 0 {
		mech.pParameter = C.CBytes(mechanism.Parameter)
		defer C.free(mech.pParameter)
		mech.ulParameterLen = C.CK_ULONG(len(mechanism.Parameter))
	} else {
		mech.pParameter = nil
		mech.ulParameterLen = 0
	}

	rv := C.CK_RV(C.call_C_DecryptInit(
		p,
		C.CK_SESSION_HANDLE(session),
		&mech,
		C.CK_OBJECT_HANDLE(key),
	))

	if rv != C.CKR_OK {
		return Error{Code: uint(rv)}
	}

	return nil
}

// Decrypt decrypts data
func (m *Module) Decrypt(session uint, ciphertext []byte) ([]byte, error) {
	if m.FunctionList == nil {
		return nil, fmt.Errorf("module not loaded")
	}

	p := (*C.CK_FUNCTION_LIST)(m.FunctionList)

	var plaintextLen C.CK_ULONG

	// Get plaintext length
	rv := C.CK_RV(C.call_C_Decrypt(
		p,
		C.CK_SESSION_HANDLE(session),
		(*C.CK_BYTE)(C.CBytes(ciphertext)), C.CK_ULONG(len(ciphertext)),
		nil, &plaintextLen,
	))

	if rv != C.CKR_OK {
		return nil, Error{Code: uint(rv)}
	}

	// Allocate memory for plaintext
	plaintext := make([]byte, plaintextLen)

	// Get plaintext
	rv = C.CK_RV(C.call_C_Decrypt(
		p,
		C.CK_SESSION_HANDLE(session),
		(*C.CK_BYTE)(C.CBytes(ciphertext)), C.CK_ULONG(len(ciphertext)),
		(*C.CK_BYTE)(unsafe.Pointer(&plaintext[0])), &plaintextLen,
	))

	if rv != C.CKR_OK {
		return nil, Error{Code: uint(rv)}
	}

	return plaintext[:plaintextLen], nil
}
