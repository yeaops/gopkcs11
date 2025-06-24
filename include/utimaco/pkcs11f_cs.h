/**
 * CS_BackupObject()
 * 
 * backup an token object
 *
 * Note: the memory (ppBackupObj) is allocated in the API and must be freed by the user !!!
 *
 */
CK_PKCS11_FUNCTION_INFO(CS_BackupObject)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE     hSession,
  CK_OBJECT_HANDLE      hObject,
  CK_BYTE_PTR_PTR       ppBackupObj,
  CK_ULONG_PTR          pulBackupObj
);
#endif

/**
 * CS_BackupUser()
 * 
 * backup an user (SO or USER)
 * pUsername and ulUsernameLen are reserved for later use and should always set to NULL_PTR and 0
 *
 * Note: the memory (ppBackupUser) is allocated in the API and must be freed by the user !!!
 *
 */
CK_PKCS11_FUNCTION_INFO(CS_BackupUser)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE     hSession,
  CK_USER_TYPE          userType,
  CK_CHAR_PTR           pUsername,
  CK_ULONG              ulUsernameLen,
  CK_BYTE_PTR_PTR       ppBackupUser,
  CK_ULONG_PTR          pulBackupUserLen
);
#endif

/**
 * CS_RestoreObject()
 * 
 * restore a backup object created with CS_BackupObject
 * Note: old object will be replaced by the object from the backup
 *
 */
CK_PKCS11_FUNCTION_INFO(CS_RestoreObject)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE     hSession,
  CK_ULONG              flags,
  CK_BYTE_PTR           pBackupObj,
  CK_ULONG              ulBackupObjLen,
  CK_OBJECT_HANDLE_PTR  phObject
);
#endif

/**
 * CS_RestoreUser()
 * 
 * restore a backup user created with CS_BackupObject
 * Note: old user authentication (if available) must be deleted first
 *
 */
CK_PKCS11_FUNCTION_INFO(CS_RestoreUser)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE     hSession,
  CK_BYTE_PTR           pBackupUser,
  CK_ULONG              ulBackupUserLen
);
#endif

/**
 * CS_DeleteUser()
 * 
 * delete user referenced by userType (CKU_USER or CKU_SO)
 * (pUsername and ulUsernameLen are reserved for later use)
 * cryptoserver administrator (for delete SO) or SO (for USER)
 * must be logged in to execute
 *
 */
CK_PKCS11_FUNCTION_INFO(CS_DeleteUser)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE     hSession,
  CK_USER_TYPE          userType,
  CK_CHAR_PTR           pUsername,
  CK_ULONG              ulUsernameLen
);
#endif

/**
 * CS_GetFunctionListCS()
 * 
 * function pointers for Utimaco specific functions
 *
 */
CK_PKCS11_FUNCTION_INFO(CS_GetFunctionListCS)
#ifdef CK_NEED_ARG_LIST
(
  CK_FUNCTION_LIST_CS_PTR_PTR ppFunctionListCS
);
#endif

/**
 * CS_GetSessionInfo()
 * 
 *
 * \param[in] hSession session handle
 * \param[out] pInfo session info structure
 *
 */
CK_PKCS11_FUNCTION_INFO(CS_GetSessionInfo)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE      hSession,
  CK_SESSION_INFO_CS_PTR pInfo
);
#endif

/**
* CS_RecryptExternalKeys()
*
* Recrypt external keys using the current MBK.
* Only available keys within the session's PKCS#11 slot are considered.
* Note: no backup is made at this level; keys are effectively replaced.
*
* \param[in] hSession session handle
* \param[out] keyCount number of keys recrypted
*
*/
CK_PKCS11_FUNCTION_INFO(CS_RecryptExternalKeys)
#ifdef CK_NEED_ARG_LIST
(
  const CK_SESSION_HANDLE    hSession,
  CK_ULONG_PTR               keyCount
);
#endif

/* Signing and MACing */

/**
* CS_AgreeSecret()
*
* Calculates a shared secret from two ECDH or ECDSA keys as described in BSI TR 03116-1.
*
* \param[in] hSession session handle
* \param[in] pMechanism secret calculation mechanism
* \param[in] hPrivateKey handle of private key used for shared secret calculation
* \param[in] pPublicKey public key used for shared secret calculation
* \param[in] ulPublicKeyLen length public key used for shared secret calculation
* \param[out] pSharedSecret gets the shared secret
* \param[out] pulSharedSecretLen gets shared secret length
*/
CK_PKCS11_FUNCTION_INFO(CS_AgreeSecret)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hPrivateKey,
  CK_BYTE_PTR       pPublicKey,
  CK_ULONG          ulPublicKeyLen,
  CK_BYTE_PTR       pSharedSecret,
  CK_ULONG_PTR      pulSharedSecretLen
);
#endif
