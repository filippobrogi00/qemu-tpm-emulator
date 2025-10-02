#ifndef TPM_INTERFACE_TYPES_H
#define TPM_INTERFACE_TYPES_H

#include <stdint.h>

/******************************
 * Introduction
 ********************************/
/*
 * Clause 8.11 contains definitions for interface types. An interface type is type checked when it is
 * unmarshaled. These types are based on an underlying type that is indicated in the table title by the value in parentheses.
 * When an interface type is used, the base type is unmarshaled and then checked to see if it has one of the allowed values.
 */

/******************************
 * TPMI_YES_NO
 ********************************/
typedef uint8_t TPMI_YES_NO;
#define YES 1
#define NO  0
/* #TPM_RC_VALUE indicates invalid value */

/******************************
 * TPMI_DH_OBJECT
 ********************************/
typedef uint32_t TPMI_DH_OBJECT;
#define TPMI_DH_OBJECT_TRANSIENT_FIRST  0x80000000
#define TPMI_DH_OBJECT_TRANSIENT_LAST   0x80FFFFFF
#define TPMI_DH_OBJECT_PERSISTENT_FIRST 0x81000000
#define TPMI_DH_OBJECT_PERSISTENT_LAST  0x81FFFFFF
#define TPMI_DH_OBJECT_NULL             0x00000000
/* #TPM_RC_VALUE */

/******************************
 * TPMI_DH_PARENT
 ********************************/
typedef uint32_t TPMI_DH_PARENT;
#define TPMI_DH_PARENT_TRANSIENT_FIRST  0x80000000
#define TPMI_DH_PARENT_TRANSIENT_LAST   0x80FFFFFF
#define TPMI_DH_PARENT_PERSISTENT_FIRST 0x81000000
#define TPMI_DH_PARENT_PERSISTENT_LAST  0x81FFFFFF
#define TPMI_DH_PARENT_OWNER            0x40000001
#define TPMI_DH_PARENT_PLATFORM         0x4000000C
#define TPMI_DH_PARENT_ENDORSEMENT      0x4000000B
#define TPMI_DH_PARENT_NULL             0x40000007
#define TPMI_DH_PARENT_FW_OWNER         0x40000010
#define TPMI_DH_PARENT_FW_PLATFORM      0x40000011
#define TPMI_DH_PARENT_FW_ENDORSEMENT   0x40000012
#define TPMI_DH_PARENT_FW_NULL          0x40000013
/* SVN ranges omitted for brevity */
/* #TPM_RC_VALUE */

/******************************
 * TPMI_DH_PERSISTENT
 ********************************/
typedef uint32_t TPMI_DH_PERSISTENT;
#define TPMI_DH_PERSISTENT_FIRST 0x81000000
#define TPMI_DH_PERSISTENT_LAST  0x81FFFFFF
/* #TPM_RC_VALUE */

/******************************
 * TPMI_DH_ENTITY
 ********************************/
typedef uint32_t TPMI_DH_ENTITY;
#define TPMI_DH_ENTITY_OWNER            0x40000001
#define TPMI_DH_ENTITY_ENDORSEMENT      0x4000000B
#define TPMI_DH_ENTITY_PLATFORM         0x4000000C
#define TPMI_DH_ENTITY_LOCKOUT          0x4000000A
#define TPMI_DH_ENTITY_TRANSIENT_FIRST  0x80000000
#define TPMI_DH_ENTITY_TRANSIENT_LAST   0x80FFFFFF
#define TPMI_DH_ENTITY_PERSISTENT_FIRST 0x81000000
#define TPMI_DH_ENTITY_PERSISTENT_LAST  0x81FFFFFF
#define TPMI_DH_ENTITY_NV_FIRST         0x01000000
#define TPMI_DH_ENTITY_NV_LAST          0x01FFFFFF
#define TPMI_DH_ENTITY_PCR_FIRST        0x00000000
#define TPMI_DH_ENTITY_PCR_LAST         0x00000017
#define TPMI_DH_ENTITY_RH_AUTH_FIRST    0x40000000
#define TPMI_DH_ENTITY_RH_AUTH_LAST     0x400000FF
#define TPMI_DH_ENTITY_NULL             0x00000000
/* #TPM_RC_VALUE */

/******************************
 * TPMI_DH_PCR
 ********************************/
typedef uint32_t TPMI_DH_PCR;
#define TPMI_DH_PCR_FIRST 0x00000000
#define TPMI_DH_PCR_LAST  0x00000017
#define TPMI_DH_PCR_NULL  0x00000000
/* #TPM_RC_VALUE */

/******************************
 * TPMI_SH_AUTH_SESSION
 ********************************/
typedef uint32_t TPMI_SH_AUTH_SESSION;
#define TPMI_SH_AUTH_HMAC_FIRST   0x02000000
#define TPMI_SH_AUTH_HMAC_LAST    0x0200FFFF
#define TPMI_SH_AUTH_POLICY_FIRST 0x03000000
#define TPMI_SH_AUTH_POLICY_LAST  0x0300FFFF
#define TPMI_SH_AUTH_PW           0x40000009
/* #TPM_RC_VALUE */

/******************************
 * TPMI_SH_HMAC
 ********************************/
typedef uint32_t TPMI_SH_HMAC;
#define TPMI_SH_HMAC_FIRST 0x02000000
#define TPMI_SH_HMAC_LAST  0x0200FFFF
/* #TPM_RC_VALUE */

/******************************
 * TPMI_SH_POLICY
 ********************************/
typedef uint32_t TPMI_SH_POLICY;
#define TPMI_SH_POLICY_FIRST 0x03000000
#define TPMI_SH_POLICY_LAST  0x0300FFFF
/* #TPM_RC_VALUE */

/******************************
 * TPMI_DH_CONTEXT
 ********************************/
typedef uint32_t TPMI_DH_CONTEXT;
#define TPMI_DH_CONTEXT_HMAC_FIRST      0x02000000
#define TPMI_DH_CONTEXT_HMAC_LAST       0x0200FFFF
#define TPMI_DH_CONTEXT_POLICY_FIRST    0x03000000
#define TPMI_DH_CONTEXT_POLICY_LAST     0x0300FFFF
#define TPMI_DH_CONTEXT_TRANSIENT_FIRST 0x80000000
#define TPMI_DH_CONTEXT_TRANSIENT_LAST  0x80FFFFFF
/* #TPM_RC_VALUE */

/******************************
 * TPMI_DH_SAVED
 *******************************/
#define TPMI_DH_SAVED_HMAC_FIRST   0x02000000
#define TPMI_DH_SAVED_HMAC_LAST    0x0200FFFF
#define TPMI_DH_SAVED_POLICY_FIRST 0x03000000
#define TPMI_DH_SAVED_POLICY_LAST  0x0300FFFF
#define TPMI_DH_SAVED_TRANSIENT    0x80000000
#define TPMI_DH_SAVED_SEQUENCE     0x80000001
#define TPMI_DH_SAVED_STCLEAR      0x80000002
/* #TPM_RC_VALUE */

/******************************
 * TPMI_RH_HIERARCHY
 *******************************/
#define TPMI_RH_HIERARCHY_OWNER          0x40000001
#define TPMI_RH_HIERARCHY_PLATFORM       0x4000000C
#define TPMI_RH_HIERARCHY_ENDORSEMENT    0x4000000B
#define TPMI_RH_HIERARCHY_NULL           0x40000007
#define TPMI_RH_HIERARCHY_FW_OWNER       0x40000010
#define TPMI_RH_HIERARCHY_FW_PLATFORM    0x40000011
#define TPMI_RH_HIERARCHY_FW_ENDORSEMENT 0x40000012
#define TPMI_RH_HIERARCHY_FW_NULL        0x40000013
/* #TPM_RC_VALUE */

/******************************
 * TPMI_RH_ENABLES
 *******************************/
#define TPMI_RH_ENABLES_OWNER       0x40000001
#define TPMI_RH_ENABLES_PLATFORM    0x4000000C
#define TPMI_RH_ENABLES_ENDORSEMENT 0x4000000B
#define TPMI_RH_ENABLES_PLATFORM_NV 0x40000014
#define TPMI_RH_ENABLES_NULL        0x40000007
/* #TPM_RC_VALUE */

/******************************
 * TPMI_RH_HIERARCHY_AUTH
 *******************************/
#define TPMI_RH_HIERARCHY_AUTH_OWNER       0x40000001
#define TPMI_RH_HIERARCHY_AUTH_PLATFORM    0x4000000C
#define TPMI_RH_HIERARCHY_AUTH_ENDORSEMENT 0x4000000B
#define TPMI_RH_HIERARCHY_AUTH_LOCKOUT     0x4000000A
#define TPMI_RH_HIERARCHY_AUTH_NULL        0x40000007
/* #TPM_RC_VALUE */

/******************************
 * TPMI_RH_HIERARCHY_POLICY
 *******************************/
#define TPMI_RH_HIERARCHY_POLICY_OWNER       0x40000001
#define TPMI_RH_HIERARCHY_POLICY_PLATFORM    0x4000000C
#define TPMI_RH_HIERARCHY_POLICY_ENDORSEMENT 0x4000000B
#define TPMI_RH_HIERARCHY_POLICY_LOCKOUT     0x4000000A
#define TPMI_RH_HIERARCHY_POLICY_ACT_0       0x40000100 /* example start of ACT range */
#define TPMI_RH_HIERARCHY_POLICY_ACT_F       0x4000010F /* example end of ACT range */
/* #TPM_RC_VALUE */

/******************************
 * TPMI_RH_BASE_HIERARCHY
 *******************************/
#define TPMI_RH_BASE_HIERARCHY_OWNER       0x40000001
#define TPMI_RH_BASE_HIERARCHY_PLATFORM    0x4000000C
#define TPMI_RH_BASE_HIERARCHY_ENDORSEMENT 0x4000000B
/* #TPM_RC_VALUE */

/******************************
 * TPMI_RH_PLATFORM
 *******************************/
#define TPMI_RH_PLATFORM_ONLY 0x4000000C
/* #TPM_RC_VALUE */

/******************************
 * TPMI_RH_OWNER
 *******************************/
#define TPMI_RH_OWNER_ONLY 0x40000001
#define TPMI_RH_OWNER_NULL 0x40000007
/* #TPM_RC_VALUE */

/******************************
 * TPMI_RH_ENDORSEMENT
 *******************************/
#define TPMI_RH_ENDORSEMENT_ONLY 0x4000000B
#define TPMI_RH_ENDORSEMENT_NULL 0x40000007
/* #TPM_RC_VALUE */

/******************************
 * TPMI_RH_PROVISION
 *******************************/
#define TPMI_RH_PROVISION_OWNER    0x40000001
#define TPMI_RH_PROVISION_PLATFORM 0x4000000C
/* #TPM_RC_VALUE */

/******************************
 * TPMI_RH_CLEAR
 ******************************/
#define TPMI_RH_CLEAR_LOCKOUT  0x4000000A
#define TPMI_RH_CLEAR_PLATFORM 0x4000000C
/* #TPM_RC_VALUE */

/******************************
 * TPMI_RH_NV_AUTH
 ******************************/
#define TPMI_RH_NV_AUTH_PLATFORM 0x4000000C
#define TPMI_RH_NV_AUTH_OWNER    0x40000001
#define TPMI_RH_NV_AUTH_NV_FIRST 0x01000000
#define TPMI_RH_NV_AUTH_NV_LAST  0x01FFFFFF
/* #TPM_RC_VALUE */

/******************************
 * TPMI_RH_LOCKOUT
 ******************************/
#define TPMI_RH_LOCKOUT_ONLY 0x4000000A
/* #TPM_RC_VALUE */

/******************************
 * TPMI_RH_NV_INDEX
 ******************************/
#define TPMI_RH_NV_INDEX_NV_FIRST        0x01000000
#define TPMI_RH_NV_INDEX_NV_LAST         0x01FFFFFF
#define TPMI_RH_NV_INDEX_EXTERNAL_FIRST  0x02000000
#define TPMI_RH_NV_INDEX_EXTERNAL_LAST   0x02FFFFFF
#define TPMI_RH_NV_INDEX_PERMANENT_FIRST 0x03000000
#define TPMI_RH_NV_INDEX_PERMANENT_LAST  0x03FFFFFF
/* #TPM_RC_VALUE */

/******************************
 * TPMI_RH_NV_DEFINED_INDEX
 ******************************/
#define TPMI_RH_NV_DEFINED_INDEX_NV_FIRST       0x01000000
#define TPMI_RH_NV_DEFINED_INDEX_NV_LAST        0x01FFFFFF
#define TPMI_RH_NV_DEFINED_INDEX_EXTERNAL_FIRST 0x02000000
#define TPMI_RH_NV_DEFINED_INDEX_EXTERNAL_LAST  0x02FFFFFF
/* #TPM_RC_VALUE */

/******************************
 * TPMI_RH_NV_LEGACY_INDEX
 ******************************/
#define TPMI_RH_NV_LEGACY_INDEX_NV_FIRST 0x01000000
#define TPMI_RH_NV_LEGACY_INDEX_NV_LAST  0x01FFFFFF
/* #TPM_RC_VALUE */

/******************************
 * TPMI_RH_NV_EXP_INDEX
 ******************************/
#define TPMI_RH_NV_EXP_INDEX_EXTERNAL_FIRST 0x02000000
#define TPMI_RH_NV_EXP_INDEX_EXTERNAL_LAST  0x02FFFFFF
/* #TPM_RC_VALUE */

/******************************
 * TPMI_RH_AC
 ******************************/
#define TPMI_RH_AC_FIRST 0x03000000
#define TPMI_RH_AC_LAST  0x03FFFFFF
/* #TPM_RC_VALUE */

/******************************
 * TPMI_RH_ACT
 ******************************/
#define TPMI_RH_ACT_0 0x40000100
#define TPMI_RH_ACT_F 0x4000010F
/* #TPM_RC_VALUE */

/******************************
 * TPMI_ALG_HASH
 ******************************/
#define TPMI_ALG_HASH_NULL 0x0000
/* Additional hash algorithm IDs defined by TCG can be added with #ifdef/#endif guards */
/* #TPM_RC_HASH */

/******************************
 * TPMI_ALG_ASYM
 ******************************/
#define TPMI_ALG_ASYM_NULL 0x0000
/* Additional asymmetric algorithm IDs defined by TCG can be added with #ifdef/#endif guards */
/* #TPM_RC_ASYMMETRIC */

/******************************
 * TPMI_ALG_SYM
 ******************************/
#define TPMI_ALG_SYM_NULL 0x0000
#define TPMI_ALG_SYM_XOR  0x0001
/* Additional symmetric block cipher algorithm IDs defined by TCG can be added with #ifdef/#endif guards */
/* #TPM_RC_SYMMETRIC */

/******************************
 * TPMI_ALG_SYM_OBJECT
 ******************************/
#define TPMI_ALG_SYM_OBJECT_NULL 0x0000
/* Additional symmetric block ciphers usable in CFB for asymmetric objects can be added here */
/* #TPM_RC_SYMMETRIC */

/******************************
 * TPMI_ALG_SYM_MODE
 ******************************/
#define TPMI_ALG_SYM_MODE_NULL 0x0000
/* Additional symmetric block cipher modes and MAC modes defined by TCG can be added here */
/* #TPM_RC_MODE */

/******************************
 * TPMI_ALG_KDF
 ******************************/
#define TPMI_ALG_KDF_NULL 0x0000
/* Additional hash-based key/mask derivation functions defined by TCG can be added here */
/* #TPM_RC_KDF */

/******************************
 * TPMI_ALG_SIG_SCHEME
 ******************************/
#define TPMI_ALG_SIG_SCHEME_NULL 0x0000
#define TPMI_ALG_SIG_SCHEME_HMAC 0x0001
/* Additional asymmetric signing schemes defined by TCG can be added here */
/* #TPM_RC_SCHEME */

/******************************
 * TPMI_ECC_KEY_EXCHANGE
 ******************************/
#define TPMI_ECC_KEY_EXCHANGE_NULL 0x0000
/* Additional ECC key exchange schemes defined by TCG can be added here */
/* #TPM_RC_SCHEME */

/******************************
 * TPMI_ST_COMMAND_TAG
 ******************************/
#define TPMI_ST_COMMAND_TAG_NO_SESSIONS 0x8001
#define TPMI_ST_COMMAND_TAG_SESSIONS    0x8002
/* #TPM_RC_BAD_TAG */

/******************************
 * TPMI_ALG_MAC_SCHEME
 ******************************/
#define TPMI_ALG_MAC_SCHEME_NULL 0x0000
/* Additional symmetric MAC and hash algorithms defined by TCG can be added here */
/* #TPM_RC_SYMMETRIC */

/******************************
 * TPMI_ALG_CIPHER_MODE
 ******************************/
#define TPMI_ALG_CIPHER_MODE_NULL 0x0000
/* Additional symmetric block cipher modes defined by TCG can be added here */
/* #TPM_RC_MODE */

#endif /* TPM_INTERFACE_TYPES_H */
