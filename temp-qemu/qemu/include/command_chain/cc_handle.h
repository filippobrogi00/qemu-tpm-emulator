/**
 * @file cc_handle.h
 * @brief TPM 2.0 Handle Validation and Unmarshaling
 * 
 * This file implements validation and unmarshaling for TPM handles
 * according to TCG TPM 2.0 Library Specification Part 2 (Structures).
 */

 #ifndef CC_HANDLE_H
 #define CC_HANDLE_H
 
 #include <stdint.h>
 #include "../tpm/tpm2_base_types.h"
 #include "../tpm/tpm2_rc.h"
 #include "../tpm/tpm2_handles.h"
 
 /******************************
  * HANDLE VALIDATION MACROS
  ******************************/
 
 /* Extract handle type (MSO - Most Significant Octet) */
 #define GET_HANDLE_TYPE(handle) ((UINT8)((handle) >> 24))
 
 /* Check handle range */
 #define HANDLE_IN_RANGE(handle, first, last) \
     ((handle) >= (first) && (handle) <= (last))
 
 /******************************
  * HANDLE TYPE CHECKING
  ******************************/

 
 /**
  * @brief Check if handle is an NV Index handle
  * @param handle Handle to check
  * @return 1 if NV Index handle, 0 otherwise
  */
 static inline int IsNVIndexHandle(TPM_HANDLE handle) {
     return HANDLE_IN_RANGE(handle, NV_INDEX_FIRST, NV_INDEX_LAST);
 }
 
 /**
  * @brief Check if handle is a transient object handle
  * @param handle Handle to check
  * @return 1 if transient handle, 0 otherwise
  */
 static inline int IsTransientHandle(TPM_HANDLE handle) {
     return HANDLE_IN_RANGE(handle, TRANSIENT_FIRST, TRANSIENT_LAST);
 }
 
 /**
  * @brief Check if handle is a persistent object handle
  * @param handle Handle to check
  * @return 1 if persistent handle, 0 otherwise
  */
 static inline int IsPersistentHandle(TPM_HANDLE handle) {
     return HANDLE_IN_RANGE(handle, PERSISTENT_FIRST, PERSISTENT_LAST);
 }
 
 /**
  * @brief Check if handle is a permanent handle
  * @param handle Handle to check
  * @return 1 if permanent handle, 0 otherwise
  */
 static inline int IsPermanentHandle(TPM_HANDLE handle) {
     return HANDLE_IN_RANGE(handle, PERMANENT_FIRST, PERMANENT_LAST);
 }
 
 /**
  * @brief Check if handle is a session handle (HMAC or Policy)
  * @param handle Handle to check
  * @return 1 if session handle, 0 otherwise
  */
 static inline int IsSessionHandle(TPM_HANDLE handle) {
     return HANDLE_IN_RANGE(handle, HMAC_SESSION_FIRST, HMAC_SESSION_LAST) ||
            HANDLE_IN_RANGE(handle, POLICY_SESSION_FIRST, POLICY_SESSION_LAST);
 }
 
 /**
  * @brief Check if handle is an HMAC session handle
  * @param handle Handle to check
  * @return 1 if HMAC session handle, 0 otherwise
  */
 static inline int IsHMACSessionHandle(TPM_HANDLE handle) {
     return HANDLE_IN_RANGE(handle, HMAC_SESSION_FIRST, HMAC_SESSION_LAST);
 }
 
 /**
  * @brief Check if handle is a policy session handle
  * @param handle Handle to check
  * @return 1 if policy session handle, 0 otherwise
  */
 static inline int IsPolicySessionHandle(TPM_HANDLE handle) {
     return HANDLE_IN_RANGE(handle, POLICY_SESSION_FIRST, POLICY_SESSION_LAST);
 }
 
 /**
  * @brief Check if handle is an attached component handle
  * @param handle Handle to check
  * @return 1 if AC handle, 0 otherwise
  */
 static inline int IsACHandle(TPM_HANDLE handle) {
     return HANDLE_IN_RANGE(handle, AC_FIRST, AC_LAST);
 }
 
 /******************************
  * SPECIFIC HANDLE VALIDATION
  ******************************/
 
 /**
  * @brief Validate TPM_RH (permanent handle)
  * @param handle Handle to validate
  * @return TPM_RC_SUCCESS if valid, TPM_RC_VALUE otherwise
  */
 static inline TPM_RC ValidatePermanentHandle(TPM_HANDLE handle) {
     switch (handle) {
         case TPM_RH_OWNER:
         case TPM_RH_NULL:
         case TPM_RS_PW:
         case TPM_RH_LOCKOUT:
         case TPM_RH_ENDORSEMENT:
         case TPM_RH_PLATFORM:
         case TPM_RH_PLATFORM_NV:
         case TPM_RH_FW_OWNER:
         case TPM_RH_FW_ENDORSEMENT:
         case TPM_RH_FW_PLATFORM:
         case TPM_RH_FW_NULL:
             return TPM_RC_SUCCESS;
         default:
             /* Check if in authenticated timer range */
             if (HANDLE_IN_RANGE(handle, TPM_RH_ACT_0, TPM_RH_ACT_F)) {
                 return TPM_RC_SUCCESS;
             }
             /* Check if in vendor-specific auth range */
             if (HANDLE_IN_RANGE(handle, TPM_RH_AUTH_00, TPM_RH_AUTH_FF)) {
                 return TPM_RC_SUCCESS;
             }
             /* Check if in SVN-limited ranges */
             if (HANDLE_IN_RANGE(handle, SVN_OWNER_FIRST, SVN_OWNER_LAST) ||
                 HANDLE_IN_RANGE(handle, SVN_ENDORSEMENT_FIRST, SVN_ENDORSEMENT_LAST) ||
                 HANDLE_IN_RANGE(handle, SVN_PLATFORM_FIRST, SVN_PLATFORM_LAST) ||
                 HANDLE_IN_RANGE(handle, SVN_NULL_FIRST, SVN_NULL_LAST)) {
                 return TPM_RC_SUCCESS;
             }
             return TPM_RC_VALUE;
     }
 }
 
 /**
  * @brief Validate TPMI_DH_OBJECT (object handle)
  * @param handle Handle to validate
  * @param allowNull If 1, TPM_RH_NULL is allowed
  * @return TPM_RC_SUCCESS if valid, TPM_RC_VALUE otherwise
  */
 static inline TPM_RC ValidateObjectHandle(TPM_HANDLE handle, int allowNull) {
     /* Check if transient object */
     if (IsTransientHandle(handle)) {
         return TPM_RC_SUCCESS;
     }
     
     /* Check if persistent object */
     if (IsPersistentHandle(handle)) {
         return TPM_RC_SUCCESS;
     }
     
     /* Check if NULL is allowed */
     if (allowNull && handle == TPM_RH_NULL) {
         return TPM_RC_SUCCESS;
     }
     
     return TPM_RC_VALUE;
 }
 
 /**
  * @brief Validate TPMI_DH_PARENT (parent handle for key creation)
  * @param handle Handle to validate
  * @return TPM_RC_SUCCESS if valid, TPM_RC_VALUE otherwise
  */
 static inline TPM_RC ValidateParentHandle(TPM_HANDLE handle) {
     /* Transient objects can be parents */
     if (IsTransientHandle(handle)) {
         return TPM_RC_SUCCESS;
     }
     
     /* Persistent objects can be parents */
     if (IsPersistentHandle(handle)) {
         return TPM_RC_SUCCESS;
     }
     
     /* Primary seed handles */
     switch (handle) {
         case TPM_RH_OWNER:
         case TPM_RH_PLATFORM:
         case TPM_RH_ENDORSEMENT:
         case TPM_RH_NULL:
         case TPM_RH_FW_OWNER:
         case TPM_RH_FW_PLATFORM:
         case TPM_RH_FW_ENDORSEMENT:
         case TPM_RH_FW_NULL:
             return TPM_RC_SUCCESS;
         default:
             /* Check SVN-limited hierarchies */
             if (HANDLE_IN_RANGE(handle, SVN_OWNER_FIRST, SVN_OWNER_LAST) ||
                 HANDLE_IN_RANGE(handle, SVN_ENDORSEMENT_FIRST, SVN_ENDORSEMENT_LAST) ||
                 HANDLE_IN_RANGE(handle, SVN_PLATFORM_FIRST, SVN_PLATFORM_LAST) ||
                 HANDLE_IN_RANGE(handle, SVN_NULL_FIRST, SVN_NULL_LAST)) {
                 return TPM_RC_SUCCESS;
             }
             return TPM_RC_VALUE;
     }
 }
 
 /**
  * @brief Validate TPMI_DH_ENTITY (entity handle for authorization)
  * @param handle Handle to validate
  * @return TPM_RC_SUCCESS if valid, TPM_RC_VALUE otherwise
  */
 static inline TPM_RC ValidateEntityHandle(TPM_HANDLE handle) {
     /* Permanent handles */
     if (handle == TPM_RH_OWNER || 
         handle == TPM_RH_ENDORSEMENT ||
         handle == TPM_RH_PLATFORM ||
         handle == TPM_RH_LOCKOUT) {
         return TPM_RC_SUCCESS;
     }
     
     /* Objects */
     if (IsTransientHandle(handle) || IsPersistentHandle(handle)) {
         return TPM_RC_SUCCESS;
     }
     
     /* NV Indexes */
     if (IsNVIndexHandle(handle)) {
         return TPM_RC_SUCCESS;
     }
     
     /* Auth handles range */
     if (HANDLE_IN_RANGE(handle, 0x40000000, 0x400000FF)) {
         return TPM_RC_SUCCESS;
     }
     
     return TPM_RC_VALUE;
 }
 
 /**
  * @brief Validate TPMI_SH_AUTH_SESSION (authorization session handle)
  * @param handle Handle to validate
  * @return TPM_RC_SUCCESS if valid, TPM_RC_VALUE otherwise
  */
 static inline TPM_RC ValidateAuthSessionHandle(TPM_HANDLE handle) {
     /* HMAC sessions */
     if (IsHMACSessionHandle(handle)) {
         return TPM_RC_SUCCESS;
     }
     
     /* Policy sessions */
     if (IsPolicySessionHandle(handle)) {
         return TPM_RC_SUCCESS;
     }
     
     /* Password authorization */
     if (handle == TPM_RS_PW) {
         return TPM_RC_SUCCESS;
     }
     
     return TPM_RC_VALUE;
 }
 
 /**
  * @brief Validate TPMI_RH_HIERARCHY (hierarchy handle)
  * @param handle Handle to validate
  * @return TPM_RC_SUCCESS if valid, TPM_RC_VALUE otherwise
  */
 static inline TPM_RC ValidateHierarchyHandle(TPM_HANDLE handle) {
     switch (handle) {
         case TPM_RH_OWNER:
         case TPM_RH_PLATFORM:
         case TPM_RH_ENDORSEMENT:
         case TPM_RH_NULL:
         case TPM_RH_FW_OWNER:
         case TPM_RH_FW_PLATFORM:
         case TPM_RH_FW_ENDORSEMENT:
         case TPM_RH_FW_NULL:
             return TPM_RC_SUCCESS;
         default:
             /* Check SVN-limited hierarchies */
             if (HANDLE_IN_RANGE(handle, SVN_OWNER_FIRST, SVN_OWNER_LAST) ||
                 HANDLE_IN_RANGE(handle, SVN_ENDORSEMENT_FIRST, SVN_ENDORSEMENT_LAST) ||
                 HANDLE_IN_RANGE(handle, SVN_PLATFORM_FIRST, SVN_PLATFORM_LAST) ||
                 HANDLE_IN_RANGE(handle, SVN_NULL_FIRST, SVN_NULL_LAST)) {
                 return TPM_RC_SUCCESS;
             }
             return TPM_RC_VALUE;
     }
 }
 
 /**
  * @brief Validate TPMI_RH_NV_INDEX (NV Index handle)
  * @param handle Handle to validate
  * @return TPM_RC_SUCCESS if valid, TPM_RC_VALUE otherwise
  */
 static inline TPM_RC ValidateNVIndexHandle(TPM_HANDLE handle) {
     /* Regular NV Index */
     if (IsNVIndexHandle(handle)) {
         return TPM_RC_SUCCESS;
     }
     
     /* External NV Index */
     if (HANDLE_IN_RANGE(handle, EXTERNAL_NV_FIRST, EXTERNAL_NV_LAST)) {
         return TPM_RC_SUCCESS;
     }
     
     /* Permanent NV Index */
     if (HANDLE_IN_RANGE(handle, PERMANENT_NV_FIRST, PERMANENT_NV_LAST)) {
         return TPM_RC_SUCCESS;
     }
     
     return TPM_RC_VALUE;
 }
 
 /******************************
  * HANDLE UNMARSHALING
  ******************************/
 
 /**
  * @brief Unmarshal a generic handle from buffer
  * @param buffer Pointer to buffer
  * @param bufferSize Size of buffer
  * @param handle Pointer to store unmarshaled handle
  * @param bytesRead Pointer to store bytes consumed
  * @return TPM_RC_SUCCESS if successful, error code otherwise
  */
 static inline TPM_RC UnmarshalHandle(
     const UINT8 *buffer,
     UINT32 bufferSize,
     TPM_HANDLE *handle,
     UINT32 *bytesRead)
 {
     if (bufferSize < 4) {
         return TPM_RC_INSUFFICIENT;
     }
     
     /* Unmarshal handle (big-endian) */
     *handle = ((UINT32)buffer[0] << 24) |
               ((UINT32)buffer[1] << 16) |
               ((UINT32)buffer[2] << 8)  |
               (UINT32)buffer[3];
     
     *bytesRead = 4;
     return TPM_RC_SUCCESS;
 }
 
 /**
  * @brief Unmarshal and validate an object handle
  * @param buffer Pointer to buffer
  * @param bufferSize Size of buffer
  * @param handle Pointer to store unmarshaled handle
  * @param allowNull If 1, TPM_RH_NULL is allowed
  * @param bytesRead Pointer to store bytes consumed
  * @return TPM_RC_SUCCESS if valid, error code otherwise
  */
 static inline TPM_RC UnmarshalObjectHandle(
     const UINT8 *buffer,
     UINT32 bufferSize,
     TPM_HANDLE *handle,
     int allowNull,
     UINT32 *bytesRead)
 {
     TPM_RC rc;
     
     rc = UnmarshalHandle(buffer, bufferSize, handle, bytesRead);
     if (rc != TPM_RC_SUCCESS) {
         return rc;
     }
     
     return ValidateObjectHandle(*handle, allowNull);
 }
 
 
 /**
  * @brief Unmarshal and validate a hierarchy handle
  * @param buffer Pointer to buffer
  * @param bufferSize Size of buffer
  * @param handle Pointer to store unmarshaled handle
  * @param bytesRead Pointer to store bytes consumed
  * @return TPM_RC_SUCCESS if valid, error code otherwise
  */
 static inline TPM_RC UnmarshalHierarchyHandle(
     const UINT8 *buffer,
     UINT32 bufferSize,
     TPM_HANDLE *handle,
     UINT32 *bytesRead)
 {
     TPM_RC rc;
     
     rc = UnmarshalHandle(buffer, bufferSize, handle, bytesRead);
     if (rc != TPM_RC_SUCCESS) {
         return rc;
     }
     
     return ValidateHierarchyHandle(*handle);
 }
 
 /**
  * @brief Unmarshal and validate an NV Index handle
  * @param buffer Pointer to buffer
  * @param bufferSize Size of buffer
  * @param handle Pointer to store unmarshaled handle
  * @param bytesRead Pointer to store bytes consumed
  * @return TPM_RC_SUCCESS if valid, error code otherwise
  */
 static inline TPM_RC UnmarshalNVIndexHandle(
     const UINT8 *buffer,
     UINT32 bufferSize,
     TPM_HANDLE *handle,
     UINT32 *bytesRead)
 {
     TPM_RC rc;
     
     rc = UnmarshalHandle(buffer, bufferSize, handle, bytesRead);
     if (rc != TPM_RC_SUCCESS) {
         return rc;
     }
     
     return ValidateNVIndexHandle(*handle);
 }
 
 /**
  * @brief Unmarshal and validate a session handle
  * @param buffer Pointer to buffer
  * @param bufferSize Size of buffer
  * @param handle Pointer to store unmarshaled handle
  * @param bytesRead Pointer to store bytes consumed
  * @return TPM_RC_SUCCESS if valid, error code otherwise
  */
 static inline TPM_RC UnmarshalSessionHandle(
     const UINT8 *buffer,
     UINT32 bufferSize,
     TPM_HANDLE *handle,
     UINT32 *bytesRead)
 {
     TPM_RC rc;
     
     rc = UnmarshalHandle(buffer, bufferSize, handle, bytesRead);
     if (rc != TPM_RC_SUCCESS) {
         return rc;
     }
     
     return ValidateAuthSessionHandle(*handle);
 }
 
 /******************************
  * HANDLE MARSHALING
  ******************************/
 
 /**
  * @brief Marshal a handle to buffer
  * @param buffer Pointer to output buffer
  * @param bufferSize Size of output buffer
  * @param handle Handle to marshal
  * @param bytesWritten Pointer to store bytes written
  * @return TPM_RC_SUCCESS if successful, error code otherwise
  */
 static inline TPM_RC MarshalHandle(
     UINT8 *buffer,
     UINT32 bufferSize,
     TPM_HANDLE handle,
     UINT32 *bytesWritten)
 {
     if (bufferSize < 4) {
         return TPM_RC_INSUFFICIENT;
     }
     
     /* Marshal handle (big-endian) */
     buffer[0] = (UINT8)(handle >> 24);
     buffer[1] = (UINT8)(handle >> 16);
     buffer[2] = (UINT8)(handle >> 8);
     buffer[3] = (UINT8)(handle & 0xFF);
     
     *bytesWritten = 4;
     return TPM_RC_SUCCESS;
 }
 
 /******************************
  * UTILITY FUNCTIONS
  ******************************/
 
 /**
  * @brief Get handle type as string (for debugging)
  * @param handle Handle to describe
  * @return String describing handle type
  */
 static inline const char* GetHandleTypeString(TPM_HANDLE handle) {
     if (IsNVIndexHandle(handle)) return "NV_INDEX";
     if (IsHMACSessionHandle(handle)) return "HMAC_SESSION";
     if (IsPolicySessionHandle(handle)) return "POLICY_SESSION";
     if (IsTransientHandle(handle)) return "TRANSIENT";
     if (IsPersistentHandle(handle)) return "PERSISTENT";
     if (IsPermanentHandle(handle)) return "PERMANENT";
     if (IsACHandle(handle)) return "ATTACHED_COMPONENT";
     return "UNKNOWN";
 }
 
 /**
  * @brief Check if handle requires authorization
  * @param handle Handle to check
  * @return 1 if authorization required, 0 otherwise
  */
 static inline int HandleRequiresAuth(TPM_HANDLE handle) {
     /* Most handles require authorization except TPM_RH_NULL */
     if (handle == TPM_RH_NULL) {
         return 0;
     }
     
     /* Password session doesn't require additional auth */
     if (handle == TPM_RS_PW) {
         return 0;
     }
     
     return 1;
 }
 
 #endif /* CC_HANDLE_H */