#ifndef TPM_RC_H
#define TPM_RC_H

#include "TpmBaseTypes.h"

/* Format/Version/Warning bits */
#define RC_VER1 0x100 /* Format 0, TCG-defined */
#define RC_FMT1 0x080 /* Format 1 (handle/param/session) */
#define RC_WARN 0x900 /* Warning codes */

/* Additional defines for handle, parameter, session modifiers */
#define TPM_RC_H 0x000 /* add to handle-related error */
#define TPM_RC_P 0x040 /* add to parameter-related error */
#define TPM_RC_S 0x800 /* add to session-related error */

/* Parameter/handle/session indexing for RC_FMT1 */
#define TPM_RC_1      0x100
#define TPM_RC_2      0x200
#define TPM_RC_3      0x300
#define TPM_RC_4      0x400
#define TPM_RC_5      0x500
#define TPM_RC_6      0x600
#define TPM_RC_7      0x700
#define TPM_RC_8      0x800
#define TPM_RC_9      0x900
#define TPM_RC_A      0xA00
#define TPM_RC_B      0xB00
#define TPM_RC_C      0xC00
#define TPM_RC_D      0xD00
#define TPM_RC_E      0xE00
#define TPM_RC_F      0xF00
#define TPM_RC_N_MASK 0xF00 /* mask for handle/session/param index */

/* Format-0 response codes */
enum
{
    TPM_RC_SUCCESS           = 0x000,
    TPM_RC_BAD_TAG           = 0x01E,
    TPM_RC_INITIALIZE        = RC_VER1 + 0x000,
    TPM_RC_FAILURE           = RC_VER1 + 0x001,
    TPM_RC_SEQUENCE          = RC_VER1 + 0x003,
    TPM_RC_PRIVATE           = RC_VER1 + 0x00B,
    TPM_RC_HMAC              = RC_VER1 + 0x019,
    TPM_RC_DISABLED          = RC_VER1 + 0x020,
    TPM_RC_EXCLUSIVE         = RC_VER1 + 0x021,
    TPM_RC_AUTH_TYPE         = RC_VER1 + 0x024,
    TPM_RC_AUTH_MISSING      = RC_VER1 + 0x025,
    TPM_RC_POLICY            = RC_VER1 + 0x026,
    TPM_RC_PCR               = RC_VER1 + 0x027,
    TPM_RC_PCR_CHANGED       = RC_VER1 + 0x028,
    TPM_RC_UPGRADE           = RC_VER1 + 0x02D,
    TPM_RC_TOO_MANY_CONTEXTS = RC_VER1 + 0x02E,
    TPM_RC_AUTH_UNAVAILABLE  = RC_VER1 + 0x02F,
    TPM_RC_REBOOT            = RC_VER1 + 0x030,
    TPM_RC_UNBALANCED        = RC_VER1 + 0x031,
    TPM_RC_COMMAND_SIZE      = RC_VER1 + 0x042,
    TPM_RC_COMMAND_CODE      = RC_VER1 + 0x043,
    TPM_RC_AUTHSIZE          = RC_VER1 + 0x044,
    TPM_RC_AUTH_CONTEXT      = RC_VER1 + 0x045,
    TPM_RC_NV_RANGE          = RC_VER1 + 0x046,
    TPM_RC_NV_SIZE           = RC_VER1 + 0x047,
    TPM_RC_NV_LOCKED         = RC_VER1 + 0x048,
    TPM_RC_NV_AUTHORIZATION  = RC_VER1 + 0x049,
    TPM_RC_NV_UNINITIALIZED  = RC_VER1 + 0x04A,
    TPM_RC_NV_SPACE          = RC_VER1 + 0x04B,
    TPM_RC_NV_DEFINED        = RC_VER1 + 0x04C,
    TPM_RC_BAD_CONTEXT       = RC_VER1 + 0x050,
    TPM_RC_CPHASH            = RC_VER1 + 0x051,
    TPM_RC_PARENT            = RC_VER1 + 0x052,
    TPM_RC_NEEDS_TEST        = RC_VER1 + 0x053,
    TPM_RC_NO_RESULT         = RC_VER1 + 0x054,
    TPM_RC_SENSITIVE         = RC_VER1 + 0x055,
    RC_MAX_FM0               = RC_VER1 + 0x07F
};

/* Format-1 response codes (parameter, handle, session errors) */
enum
{
    TPM_RC_ASYMMETRIC    = RC_FMT1 + 0x001,
    TPM_RC_ATTRIBUTES    = RC_FMT1 + 0x002,
    TPM_RC_HASH          = RC_FMT1 + 0x003,
    TPM_RC_VALUE         = RC_FMT1 + 0x004,
    TPM_RC_HIERARCHY     = RC_FMT1 + 0x005,
    TPM_RC_KEY_SIZE      = RC_FMT1 + 0x007,
    TPM_RC_MGF           = RC_FMT1 + 0x008,
    TPM_RC_MODE          = RC_FMT1 + 0x009,
    TPM_RC_TYPE          = RC_FMT1 + 0x00A,
    TPM_RC_HANDLE        = RC_FMT1 + 0x00B,
    TPM_RC_KDF           = RC_FMT1 + 0x00C,
    TPM_RC_RANGE         = RC_FMT1 + 0x00D,
    TPM_RC_AUTH_FAIL     = RC_FMT1 + 0x00E,
    TPM_RC_NONCE         = RC_FMT1 + 0x00F,
    TPM_RC_PP            = RC_FMT1 + 0x010,
    TPM_RC_SCHEME        = RC_FMT1 + 0x012,
    TPM_RC_SIZE          = RC_FMT1 + 0x015,
    TPM_RC_SYMMETRIC     = RC_FMT1 + 0x016,
    TPM_RC_TAG           = RC_FMT1 + 0x017,
    TPM_RC_SELECTOR      = RC_FMT1 + 0x018,
    TPM_RC_INSUFFICIENT  = RC_FMT1 + 0x01A,
    TPM_RC_SIGNATURE     = RC_FMT1 + 0x01B,
    TPM_RC_KEY           = RC_FMT1 + 0x01C,
    TPM_RC_POLICY_FAIL   = RC_FMT1 + 0x01D,
    TPM_RC_INTEGRITY     = RC_FMT1 + 0x01F,
    TPM_RC_TICKET        = RC_FMT1 + 0x020,
    TPM_RC_RESERVED_BITS = RC_FMT1 + 0x021,
    TPM_RC_BAD_AUTH      = RC_FMT1 + 0x022,
    TPM_RC_EXPIRED       = RC_FMT1 + 0x023,
    TPM_RC_POLICY_CC     = RC_FMT1 + 0x024,
    TPM_RC_BINDING       = RC_FMT1 + 0x025,
    TPM_RC_CURVE         = RC_FMT1 + 0x026,
    TPM_RC_ECC_POINT     = RC_FMT1 + 0x027,
    TPM_RC_FW_LIMITED    = RC_FMT1 + 0x028,
    TPM_RC_SVN_LIMITED   = RC_FMT1 + 0x029
};

/* Warning codes */
enum
{
    TPM_RC_CONTEXT_GAP     = RC_WARN + 0x001,
    TPM_RC_OBJECT_MEMORY   = RC_WARN + 0x002,
    TPM_RC_SESSION_MEMORY  = RC_WARN + 0x003,
    TPM_RC_MEMORY          = RC_WARN + 0x004,
    TPM_RC_SESSION_HANDLES = RC_WARN + 0x005,
    TPM_RC_OBJECT_HANDLES  = RC_WARN + 0x006,
    TPM_RC_LOCALITY        = RC_WARN + 0x007,
    TPM_RC_YIELDED         = RC_WARN + 0x008,
    TPM_RC_CANCELED        = RC_WARN + 0x009,
    TPM_RC_TESTING         = RC_WARN + 0x00A,
    TPM_RC_REFERENCE_H0    = RC_WARN + 0x010,
    TPM_RC_REFERENCE_H1    = RC_WARN + 0x011,
    TPM_RC_REFERENCE_H2    = RC_WARN + 0x012,
    TPM_RC_REFERENCE_H3    = RC_WARN + 0x013,
    TPM_RC_REFERENCE_H4    = RC_WARN + 0x014,
    TPM_RC_REFERENCE_H5    = RC_WARN + 0x015,
    TPM_RC_REFERENCE_H6    = RC_WARN + 0x016,
    TPM_RC_REFERENCE_S0    = RC_WARN + 0x018,
    TPM_RC_REFERENCE_S1    = RC_WARN + 0x019,
    TPM_RC_REFERENCE_S2    = RC_WARN + 0x01A,
    TPM_RC_REFERENCE_S3    = RC_WARN + 0x01B,
    TPM_RC_REFERENCE_S4    = RC_WARN + 0x01C,
    TPM_RC_REFERENCE_S5    = RC_WARN + 0x01D,
    TPM_RC_REFERENCE_S6    = RC_WARN + 0x01E,
    TPM_RC_NV_RATE         = RC_WARN + 0x020,
    TPM_RC_LOCKOUT         = RC_WARN + 0x021,
    TPM_RC_RETRY           = RC_WARN + 0x022,
    TPM_RC_NV_UNAVAILABLE  = RC_WARN + 0x023,
    TPM_RC_NOT_USED        = RC_WARN + 0x07F
};

/* Additional defines for handle, parameter, session errors and indexing */
#define TPM_RC_H 0x000 /* add to handle-related error */
#define TPM_RC_P 0x040 /* add to parameter-related error */
#define TPM_RC_S 0x800 /* add to session-related error */

/* Parameter/handle/session indexing for RC_FMT1 */
#define TPM_RC_1 0x100 /* add to parameter-, handle-, or session-related error */
#define TPM_RC_2 0x200 /* add to parameter-, handle-, or session-related error */
#define TPM_RC_3 0x300 /* add to parameter-, handle-, or session-related error */
#define TPM_RC_4 0x400 /* add to parameter-, handle-, or session-related error */
#define TPM_RC_5 0x500 /* add to parameter-, handle-, or session-related error */
#define TPM_RC_6 0x600 /* add to parameter-, handle-, or session-related error */
#define TPM_RC_7 0x700 /* add to parameter-, handle-, or session-related error */
#define TPM_RC_8 0x800 /* add to parameter-related error */
#define TPM_RC_9 0x900 /* add to parameter-related error */
#define TPM_RC_A 0xA00 /* add to parameter-related error */
#define TPM_RC_B 0xB00 /* add to parameter-related error */
#define TPM_RC_C 0xC00 /* add to parameter-related error */
#define TPM_RC_D 0xD00 /* add to parameter-related error */
#define TPM_RC_E 0xE00 /* add to parameter-related error */
#define TPM_RC_F 0xF00 /* add to parameter-related error */

#endif /* TPM_RC_H */
