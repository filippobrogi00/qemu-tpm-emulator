#ifndef TPM_PROPERTIES_H
#define TPM_PROPERTIES_H

#include <stdint.h>

/*
 * TPM_PT (UINT32)
 * Property tag constants for
 * TPM2_GetCapability(capability=TPM_CAP_TPM_PROPERTIES). Reference: TCG TPM 2.0
 * Library Spec, Part 2, Table 25
 */

typedef uint32_t TPM_PT;

/* ---- Base definitions ---- */
#define TPM_PT_NONE  ((TPM_PT)0x00000000)
#define TPM_PT_GROUP ((TPM_PT)0x00000100)

/* ---- Fixed properties group ---- */
#define TPM_PT_FIXED (TPM_PT_GROUP * 1)

/* Fixed property tags */
#define TPM_PT_FAMILY_INDICATOR \
    (TPM_PT_FIXED + 0)                     /* TPM Family (TPM_SPEC_FAMILY) */
#define TPM_PT_LEVEL    (TPM_PT_FIXED + 1) /* Spec level (usually 0) */
#define TPM_PT_REVISION (TPM_PT_FIXED + 2) /* Spec revision * 100 */
#define TPM_PT_DAY_OF_YEAR \
    (TPM_PT_FIXED + 3)                                /* Spec build date (day of year) */
#define TPM_PT_YEAR                (TPM_PT_FIXED + 4) /* Spec build year */
#define TPM_PT_MANUFACTURER        (TPM_PT_FIXED + 5) /* Vendor ID */
#define TPM_PT_VENDOR_STRING_1     (TPM_PT_FIXED + 6)
#define TPM_PT_VENDOR_STRING_2     (TPM_PT_FIXED + 7)
#define TPM_PT_VENDOR_STRING_3     (TPM_PT_FIXED + 8)
#define TPM_PT_VENDOR_STRING_4     (TPM_PT_FIXED + 9)
#define TPM_PT_VENDOR_TPM_TYPE     (TPM_PT_FIXED + 10)
#define TPM_PT_FIRMWARE_VERSION_1  (TPM_PT_FIXED + 11)
#define TPM_PT_FIRMWARE_VERSION_2  (TPM_PT_FIXED + 12)
#define TPM_PT_INPUT_BUFFER        (TPM_PT_FIXED + 13)
#define TPM_PT_HR_TRANSIENT_MIN    (TPM_PT_FIXED + 14)
#define TPM_PT_HR_PERSISTENT_MIN   (TPM_PT_FIXED + 15)
#define TPM_PT_HR_LOADED_MIN       (TPM_PT_FIXED + 16)
#define TPM_PT_ACTIVE_SESSIONS_MAX (TPM_PT_FIXED + 17)
#define TPM_PT_PCR_COUNT           (TPM_PT_FIXED + 18)
#define TPM_PT_PCR_SELECT_MIN      (TPM_PT_FIXED + 19)
#define TPM_PT_CONTEXT_GAP_MAX     (TPM_PT_FIXED + 20)
/* 21 reserved */
#define TPM_PT_NV_COUNTERS_MAX (TPM_PT_FIXED + 22)
#define TPM_PT_NV_INDEX_MAX    (TPM_PT_FIXED + 23)
#define TPM_PT_MEMORY          (TPM_PT_FIXED + 24) /* TPMA_MEMORY flags */
#define TPM_PT_CLOCK_UPDATE    (TPM_PT_FIXED + 25)
#define TPM_PT_CONTEXT_HASH \
    (TPM_PT_FIXED + 26) /* Alg for HMAC integrity on context save */
#define TPM_PT_CONTEXT_SYM \
    (TPM_PT_FIXED + 27) /* Alg for encryption of context save */
#define TPM_PT_CONTEXT_SYM_SIZE \
    (TPM_PT_FIXED + 28)                                /* Key size for context save encryption */
#define TPM_PT_ORDERLY_COUNT       (TPM_PT_FIXED + 29) /* NV update modulus */
#define TPM_PT_MAX_COMMAND_SIZE    (TPM_PT_FIXED + 30)
#define TPM_PT_MAX_RESPONSE_SIZE   (TPM_PT_FIXED + 31)
#define TPM_PT_MAX_DIGEST          (TPM_PT_FIXED + 32)
#define TPM_PT_MAX_OBJECT_CONTEXT  (TPM_PT_FIXED + 33)
#define TPM_PT_MAX_SESSION_CONTEXT (TPM_PT_FIXED + 34)
#define TPM_PT_PS_FAMILY_INDICATOR (TPM_PT_FIXED + 35)
#define TPM_PT_PS_LEVEL            (TPM_PT_FIXED + 36)
#define TPM_PT_PS_REVISION         (TPM_PT_FIXED + 37)
#define TPM_PT_PS_DAY_OF_YEAR      (TPM_PT_FIXED + 38)
#define TPM_PT_PS_YEAR             (TPM_PT_FIXED + 39)
#define TPM_PT_SPLIT_MAX           (TPM_PT_FIXED + 40)
#define TPM_PT_TOTAL_COMMANDS      (TPM_PT_FIXED + 41)
#define TPM_PT_LIBRARY_COMMANDS    (TPM_PT_FIXED + 42)
#define TPM_PT_VENDOR_COMMANDS     (TPM_PT_FIXED + 43)
#define TPM_PT_NV_BUFFER_MAX       (TPM_PT_FIXED + 44)
#define TPM_PT_MODES               (TPM_PT_FIXED + 45) /* TPMA_MODES */
#define TPM_PT_MAX_CAP_BUFFER      (TPM_PT_FIXED + 46)
#define TPM_PT_FIRMWARE_SVN        (TPM_PT_FIXED + 47)
#define TPM_PT_FIRMWARE_MAX_SVN    (TPM_PT_FIXED + 48)

/* ---- Variable properties group ---- */
#define TPM_PT_VAR (TPM_PT_GROUP * 2)

/* Variable property tags */
#define TPM_PT_PERMANENT           (TPM_PT_VAR + 0) /* TPMA_PERMANENT */
#define TPM_PT_STARTUP_CLEAR       (TPM_PT_VAR + 1) /* TPMA_STARTUP_CLEAR */
#define TPM_PT_HR_NV_INDEX         (TPM_PT_VAR + 2)
#define TPM_PT_HR_LOADED           (TPM_PT_VAR + 3)
#define TPM_PT_HR_LOADED_AVAIL     (TPM_PT_VAR + 4)
#define TPM_PT_HR_ACTIVE           (TPM_PT_VAR + 5)
#define TPM_PT_HR_ACTIVE_AVAIL     (TPM_PT_VAR + 6)
#define TPM_PT_HR_TRANSIENT_AVAIL  (TPM_PT_VAR + 7)
#define TPM_PT_HR_PERSISTENT       (TPM_PT_VAR + 8)
#define TPM_PT_HR_PERSISTENT_AVAIL (TPM_PT_VAR + 9)
#define TPM_PT_NV_COUNTERS         (TPM_PT_VAR + 10)
#define TPM_PT_NV_COUNTERS_AVAIL   (TPM_PT_VAR + 11)
#define TPM_PT_ALGORITHM_SET       (TPM_PT_VAR + 12)
#define TPM_PT_LOADED_CURVES       (TPM_PT_VAR + 13)
#define TPM_PT_LOCKOUT_COUNTER     (TPM_PT_VAR + 14)
#define TPM_PT_MAX_AUTH_FAIL       (TPM_PT_VAR + 15)
#define TPM_PT_LOCKOUT_INTERVAL    (TPM_PT_VAR + 16)
#define TPM_PT_LOCKOUT_RECOVERY    (TPM_PT_VAR + 17)
#define TPM_PT_NV_WRITE_RECOVERY   (TPM_PT_VAR + 18)
#define TPM_PT_AUDIT_COUNTER_0     (TPM_PT_VAR + 19)
#define TPM_PT_AUDIT_COUNTER_1     (TPM_PT_VAR + 20)

#endif // TPM_PROPERTIES_H
