#ifndef __PKCS11T_CS__
#define __PKCS11T_CS__

#ifdef WIN32
#pragma pack(push, cryptoki, 1)
#endif

#ifndef CK_PTR
  #define CK_PTR *
#endif

/**
 *
 * vendor defined attributes
 *
 */
// data attributes 
#define CKA_UTI_CUSTOM_DATA                0x80D00001       // Public attribute containing key data


// config attributes for global configuration object 
#define CKA_UTIMACO_CFG_PATH               0x80C00001       // path to the configurationfile

// config attributes for global and slot based CryptoServer configuration objects
#define CKA_CFG_ALLOW_SLOTS                0x80A00001       // TRUE: CryptoServer slot configuration objects are allowed
#define CKA_CFG_CHECK_VALIDITY_PERIOD      0x80A00002       // TRUE: CKA_START_DATE and CKA_END_DATE are evaluated
#define CKA_CFG_AUTH_PLAIN_MASK            0x80A00003       // CryptoServer permission mask for cleartext import
#define CKA_CFG_WRAP_POLICY                0x80A00004       // TRUE: do not allow wrapping of strong keys with weaker keys
#define CKA_CFG_AUTH_KEYM_MASK             0x80A00005       // CryptoServer permission mask for keymanager role (e.g. 0x00000020)
#define CKA_CFG_SECURE_DERIVATION          0x80A00006       // TRUE: do not allow weak derivation mechanisms (CKM_CONCATENATE_BASE_AND_DATA etc)
#define CKA_CFG_SECURE_IMPORT              0x80A00007       // TRUE: enable several strict checks in C_WrapKey and C_UnwrapKey
#define CKA_CFG_SECURE_RSA_COMPONENTS      0x80A00008       // TRUE: do not allow very low public exponents and
                                                            //       require modulus and private exponent when creating RSA keys
#define CKA_CFG_P11R2_BACKWARDS_COMPATIBLE 0x80A00009       // TRUE: disable changes that might break existing integrations
#define CKA_CFG_ENFORCE_BLINDING           0x80A0000A       // TRUE: use blinding for RSA/ECC private key operations
#define CKA_CFG_SECURE_SLOT_BACKUP         0x80A0000B       // TRUE: use individual keys to encrypt each slot's backups
#define CKA_CFG_SLOT_BACKUP_PASS_HASH      0x80A0000C       // Passphrase to further individualize slot backup key
#define CKA_CFG_ENFORCE_EXT_KEYS           0x80A0000D       // TRUE: only allow creating new keys that are stored externally
#define CKA_CFG_ALLOW_WEAK_DES_KEYS        0x80A0000E       // TRUE: allow weak des keys (e.g. all zeros or duplicate components)

/**
 *
 * vendor defined object types
 *
 */

#define CKO_CONFIG                         0x80100001       // configuration object

/**
 *
 * vendor defined object handles
 *
 */

#define P11_CFG_LOCAL_HDL                  0x80000008       // handle of local configuration object
  
#define P11_CFG_GLOBAL_HDL                 0x80000001       // handle of global CryptoServer configuration object
#define P11_CFG_SLOT_HDL                   0x80000004       // handle of slot CryptoServer configuration object

/**
 *
 * vendor defined user login types
 *
 */ 
#define CKU_CS_GENERIC              0x83            // login type for CryptoServer user (generic login of all CryptoServer user)

/**
 *
 * vendor defined init prefix
 *
 */ 

#define CS_AUTH_MECH                "CKU_VENDOR:"   // prefix for initToken and initPin to detect that a Utimaco login mechanism should be used
 
/**
 *
 * vendor defined mechanisms
 *
 */

#define CKM_DES3_RETAIL_MAC            0x80000135    // Retail-MAC with 0-Padding

#define CKM_ECDSA_RIPEMD160            0x8000104A    // ECDSA with RIPEMD-160

#define CKM_DSA_RIPEMD160              0x8000204A    // DSA with RIPEMD-160

#define CKM_ECKA                       0x80001101    // Elliptic curves key agreement

#define CKM_RSA_PKCS_MULTI             0x80000001    // Multiple PKCS RSA signatures
#define CKM_RSA_X_509_MULTI            0x80000003    // Multiple raw RSA signatures
#define CKM_ECDSA_MULTI                0x80001401    // Multiple ECDSA signatures

#define CKM_ECDSA_ECIES                0x80001201    // Elliptic Curve Integrated Encryption Scheme
#define CKM_ECDSA_ECIES_XOR            0x80001202    // used by CKM_ECDSA_ECIES

#define CKM_DES_CBC_WRAP               0x80003001    // Enhanced DES key wrapping mechanism 
#define CKM_AES_CBC_WRAP               0x80003002    // Enhanced AES key wrapping mechanism 

#define CKM_ECDSA_SHA256_DCC           0x800D0001    // ECDSA according to GBCS (UK smartmetering)

#define CKM_CUSTOM_VDM                 0xC0000000    // Custom VDM mechanisms (start with this ID)

#define CKM_UTIMACO_SM2                0xC0010100    // SM2 algorithm without hashing (input is expected to be hashed before)
#define CKM_UTIMACO_SM2_SHA256         0xC0010140    // SM2 algorithm with SHA256 hash algorithm
#define CKM_UTIMACO_SM2_SHA384         0xC0010160    // SM2 algorithm with SHA384 hash algorithm
#define CKM_UTIMACO_SM2_SHA512         0xC0010170    // SM2 algorithm with SHA512 hash algorithm
#define CKM_UTIMACO_SM2_SHA3_256       0xC0010190    // SM2 algorithm with SHA3_256 hash algorithm
#define CKM_UTIMACO_SM2_SHA3_384       0xC00101A0    // SM2 algorithm with SHA3_384 hash algorithm
#define CKM_UTIMACO_SM2_SHA3_512       0xC00101B0    // SM2 algorithm with SHA3_512 hash algorithm
#define CKM_UTIMACO_SM2_SM3            0xC0010200    // SM2 algorithm with SM3 algorithm
#define CKM_UTIMACO_SM2_KEY_PAIR_GEN   0xC0010300    // SM2 key generation
#define CKM_UTIMACO_SM3                0xC0010400    // SM3 digest algorithm
#define CKM_UTIMACO_SM4_KEY_GEN        0xC0010500    // SM4 key generation
#define CKM_UTIMACO_SM4_ECB            0xC0010601    // SM4 cipher in ECB mode without padding
#define CKM_UTIMACO_SM4_ECB_PAD        0xC0010602    // SM4 cipher in ECB mode with PKCS7 padding
#define CKM_UTIMACO_SM4_CBC            0xC0010603    // SM4 cipher in CBC mode without padding
#define CKM_UTIMACO_SM4_CBC_PAD        0xC0010604    // SM4 cipher in CBC mode with PKCS7 padding
#define CKM_UTIMACO_SM4_CFB            0xC0010605    // SM4 cipher in CFB mode
#define CKM_UTIMACO_SM4_OFB            0xC0010606    // SM4 cipher in OFB mode
#define CKM_UTIMACO_SM4_CTR            0xC0010607    // SM4 cipher in CTR mode
#define CKM_UTIMACO_SM4_GCM            0xC0010608    // SM4 cipher in GCM mode
#define CKM_UTIMACO_SM4_CCM            0xC0010609    // SM4 cipher in CCM mode
#define CKM_UTIMACO_SM4_GMAC           0xC001060A    // SM4 GMAC signature with 12 byte IV

/**
 *
 * vendor defined structures
 *
 */
 
typedef struct CK_ECDSA_ECIES_PARAMS // used by CKM_ECDSA_ECIES
{
    unsigned long int  hashAlg;          // hash algorithm used e.g. CKM_SHA_1
    unsigned long int  cryptAlg;         // crypt algorithm used for crypt/decrypt e.g. CKM_AES_ECB
    unsigned long int  cryptOpt;         // keysize of crypt algo (0 for CKM_ECDSA_ECIES_XOR)
    unsigned long int  macAlg;           // mac algorithm used e.g. CKM_SHA_1_HMAC
    unsigned long int  macOpt;           // keysize of mac algo (always 0)
    unsigned char     *pSharedSecret1;   // optional shared secret 1 included in hash calculation   
    unsigned long int  ulSharetSecret1;  // length of shared secret 1
    unsigned char     *pSharedSecret2;   // optional shared secret 2 included in mac calculation
    unsigned long int  ulSharetSecret2;  // lentgh of shared secret 2
}
CK_ECDSA_ECIES_PARAMS;

typedef CK_ECDSA_ECIES_PARAMS CK_PTR CK_ECDSA_ECIES_PARAMS_PTR;

typedef struct CK_WRAP_PARAMS // used by CKM_DES_CBC_WRAP and CKM_AES_CBC_WRAP
{
    unsigned char *pIv;           // the starting IV         
    unsigned int   ulIvLen;       // length of the starting IV 
    unsigned char *pPrefix;       // prefix data
    unsigned int   ulPrefixLen;   // length of the prefix data
    unsigned char *pPostfix;      // postfix data
    unsigned int   ulPostfixLen;  // length of the postfix data
}
CK_WRAP_PARAMS; 

typedef CK_WRAP_PARAMS CK_PTR CK_WRAP_PARAMS_PTR;

#ifdef WIN32
#pragma pack(pop, cryptoki)
#endif

#endif // __PKCS11T_CS__
