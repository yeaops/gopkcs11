/*
 * Utimaco PKCS#11 Extensions Header
 * 
 * This is a placeholder for the actual Utimaco vendor-specific header.
 * In a real implementation, this would contain the vendor-specific
 * extensions, attributes, mechanisms, and functions supported by
 * Utimaco HSMs.
 */

#ifndef CS_PKCS11EXT_H
#define CS_PKCS11EXT_H

#include "pkcs11.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Utimaco Vendor Extensions */

/* 
 * Utimaco vendor-defined mechanism types
 */
#define CKM_CS_DH_PKCS_DERIVE_RAW          (CKM_VENDOR_DEFINED + 0x100)
#define CKM_CS_ECDSA_ECIES                 (CKM_VENDOR_DEFINED + 0x101)
#define CKM_CS_ECDH_ECIES                  (CKM_VENDOR_DEFINED + 0x102)
#define CKM_CS_ECIES                       (CKM_VENDOR_DEFINED + 0x103)
#define CKM_CS_ECDH_DERIVE_RAW             (CKM_VENDOR_DEFINED + 0x104)
#define CKM_CS_RSA_MULTI                   (CKM_VENDOR_DEFINED + 0x105)
#define CKM_CS_STATEFUL_AES_CBC            (CKM_VENDOR_DEFINED + 0x106)
#define CKM_CS_STATEFUL_AES_GCM            (CKM_VENDOR_DEFINED + 0x107)
#define CKM_CS_AES_DERIVE_MULTI            (CKM_VENDOR_DEFINED + 0x108)

/*
 * Utimaco vendor-defined attributes
 */
#define CKA_CS_COUNTER                    (CKA_VENDOR_DEFINED + 0x100)
#define CKA_CS_LIFECYCLE                  (CKA_VENDOR_DEFINED + 0x101)
#define CKA_CS_BACKUP_KEY                 (CKA_VENDOR_DEFINED + 0x102)
#define CKA_CS_KCV                        (CKA_VENDOR_DEFINED + 0x103)
#define CKA_CS_MECHANISM_TYPE             (CKA_VENDOR_DEFINED + 0x104)
#define CKA_CS_KEY_STATE                  (CKA_VENDOR_DEFINED + 0x105)
#define CKA_CS_KMAC                       (CKA_VENDOR_DEFINED + 0x106)
#define CKA_CS_KEY_USAGE_COUNT            (CKA_VENDOR_DEFINED + 0x107)

/* 
 * Utimaco vendor-defined object types 
 */
#define CKO_CS_SECURE_KEY_BACKUP          (CKO_VENDOR_DEFINED + 0x01)
#define CKO_CS_CUSTOM_DATA                (CKO_VENDOR_DEFINED + 0x02)

/*
 * Utimaco vendor-defined mechanism parameters
 */
typedef struct CK_CS_STATEFUL_MECHANISM_PARAMS {
    CK_BYTE_PTR  pIV;
    CK_ULONG     ulIVLen;
    CK_BYTE_PTR  pState;
    CK_ULONG     ulStateLen;
    CK_BYTE_PTR  pTag;
    CK_ULONG     ulTagLen;
} CK_CS_STATEFUL_MECHANISM_PARAMS;

typedef CK_CS_STATEFUL_MECHANISM_PARAMS CK_PTR CK_CS_STATEFUL_MECHANISM_PARAMS_PTR;

/*
 * Utimaco vendor-defined functions
 */

/* Backup key management functions */
CK_PKCS11_FUNCTION_INFO(C_CSCreateBackup)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hKey,
  CK_OBJECT_HANDLE  hBackupKey,
  CK_BYTE_PTR       pBackupData,
  CK_ULONG_PTR      pulBackupDataLen
);
#endif

CK_PKCS11_FUNCTION_INFO(C_CSImportFromBackup)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE    hSession,
  CK_OBJECT_HANDLE     hBackupKey,
  CK_BYTE_PTR          pBackupData,
  CK_ULONG             ulBackupDataLen,
  CK_ATTRIBUTE_PTR     pTemplate,
  CK_ULONG             ulTemplateLen,
  CK_OBJECT_HANDLE_PTR phKey
);
#endif

/* Stateful operation management */
CK_PKCS11_FUNCTION_INFO(C_CSGetOperationState)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pState,
  CK_ULONG_PTR      pulStateLen
);
#endif

CK_PKCS11_FUNCTION_INFO(C_CSSetOperationState)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pState,
  CK_ULONG          ulStateLen
);
#endif

/* Firmware and device management */
CK_PKCS11_FUNCTION_INFO(C_CSGetDeviceInfo)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID       slotID,
  CK_BYTE_PTR      pDeviceInfo,
  CK_ULONG_PTR     pulDeviceInfoLen
);
#endif

/* Function list */
typedef struct CK_CS_FUNCTION_LIST {
    /* Backup key management */
    CK_C_CSCreateBackup          C_CSCreateBackup;
    CK_C_CSImportFromBackup      C_CSImportFromBackup;
    
    /* Stateful operation management */
    CK_C_CSGetOperationState     C_CSGetOperationState;
    CK_C_CSSetOperationState     C_CSSetOperationState;
    
    /* Firmware and device management */
    CK_C_CSGetDeviceInfo         C_CSGetDeviceInfo;
} CK_CS_FUNCTION_LIST;

typedef CK_CS_FUNCTION_LIST CK_PTR CK_CS_FUNCTION_LIST_PTR;
typedef CK_CS_FUNCTION_LIST_PTR CK_PTR CK_CS_FUNCTION_LIST_PTR_PTR;

/* Get the vendor extension function list */
CK_PKCS11_FUNCTION_INFO(C_CSGetFunctionList)
#ifdef CK_NEED_ARG_LIST
(
  CK_CS_FUNCTION_LIST_PTR_PTR ppFunctionList
);
#endif

#ifdef __cplusplus
}
#endif

#endif /* CS_PKCS11EXT_H */