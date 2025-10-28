#include <stdint.h>

/*************************************************
 * TPM HANDLES FOR REFERENCING SHIELDED LOCATIONS
 *************************************************/

// Handle type
typedef uint32_t TPM_HANDLE; // Handles are 32-bit values used to reference shielded locations

// TPM_HT Constants
typedef uint8_t TPM_HT; // Handle type is determined by the MSO (most significant octet)

// TPM_HT values (MSO) and their description
#define TPM_HT_PCR            0x00 // PCR – Platform Configuration Registers
#define TPM_HT_NV_INDEX       0x01 // NV Index – assigned by the caller
#define TPM_HT_HMAC_SESSION   0x02 // HMAC Authorization Session – assigned by TPM
#define TPM_HT_LOADED_SESSION 0x02 // Loaded Authorization Session – used in TPM2_GetCapability
#define TPM_HT_POLICY_SESSION 0x03 // Policy Authorization Session – assigned by TPM
#define TPM_HT_SAVED_SESSION  0x03 // Saved Authorization Session – used in TPM2_GetCapability
#define TPM_HT_EXTERNAL_NV    0x11 // External NV Index – assigned by caller (rev 1.72)
#define TPM_HT_PERMANENT_NV   0x12 // Permanent NV Index – platform-specific (rev 1.73)
#define TPM_HT_PERMANENT      0x40 // Permanent Values – assigned by specification
#define TPM_HT_TRANSIENT      0x80 // Transient Objects – assigned when object is loaded
#define TPM_HT_PERSISTENT     0x81 // Persistent Objects – assigned when transient object made persistent
#define TPM_HT_AC             0x90 // Attached Component – handle for attached components

// --- Example Notes ---
// - Transient objects: each load gets a unique handle with MSO = TPM_HT_TRANSIENT
// - Persistent objects: must have MSO = TPM_HT_PERSISTENT and not duplicate existing persistent handle
// - Sessions: handle assigned on start, MSO = TPM_HT_SESSION, remains until closed/flushed

/***********************************************
 * ARCHITECTURALLY-DEFINED PERMANENT HANDLES
 ***********************************************/

typedef uint32_t TPM_RH; // Permanent handle type

// Reserved / Primary Seeds / Authorization / Policy / Session / Control
#define TPM_RH_FIRST       0x40000000 // R
#define TPM_RH_SRK         0x40000000 // R, not used
#define TPM_RH_OWNER       0x40000001 // K, A, P – Storage Primary Seed (SPS), ownerAuth, ownerPolicy
#define TPM_RH_REVOKE      0x40000002 // R, not used
#define TPM_RH_TRANSPORT   0x40000003 // R, not used
#define TPM_RH_OPERATOR    0x40000004 // R, not used
#define TPM_RH_ADMIN       0x40000005 // R, not used
#define TPM_RH_EK          0x40000006 // R, not used
#define TPM_RH_NULL        0x40000007 // K, A, P – NULL hierarchy, EmptyAuth, Empty Policy
#define TPM_RH_UNASSIGNED  0x40000008 // R – indicates uninitialized/unassigned handle
#define TPM_RS_PW          0x40000009 // S – password authorization session
#define TPM_RH_LOCKOUT     0x4000000A // A – dictionary attack lockout reset
#define TPM_RH_ENDORSEMENT 0x4000000B // K, A, P – Endorsement Primary Seed (EPS)
#define TPM_RH_PLATFORM    0x4000000C // K, A, P – Platform Primary Seed (PPS)
#define TPM_RH_PLATFORM_NV 0x4000000D // C – control for phEnableNV
//
// Vendor-specific authorization range
#define TPM_RH_AUTH_00 0x40000010 // A – start of vendor-specific auth handles
#define TPM_RH_AUTH_FF 0x4000010F // A – end of vendor-specific auth handles

// Authenticated timers
#define TPM_RH_ACT_0 0x40000110 // A, P – start of authenticated timer handles
#define TPM_RH_ACT_F 0x4000011F // A, P – end of authenticated timer handles

// Firmware-limited hierarchies
#define TPM_RH_FW_OWNER       0x40000140 // K – firmware-limited Owner
#define TPM_RH_FW_ENDORSEMENT 0x40000141 // K – firmware-limited Endorsement
#define TPM_RH_FW_PLATFORM    0x40000142 // K – firmware-limited Platform
#define TPM_RH_FW_NULL        0x40000143 // K – firmware-limited NULL

// SVN-limited hierarchies
#define TPM_RH_SVN_OWNER_BASE       0x40010000 // K – SVN-limited Owner, low 2 bytes = min SVN
#define TPM_RH_SVN_ENDORSEMENT_BASE 0x40020000 // K – SVN-limited Endorsement
#define TPM_RH_SVN_PLATFORM_BASE    0x40030000 // K – SVN-limited Platform
#define TPM_RH_SVN_NULL_BASE        0x40040000 // K – SVN-limited NULL

#define TPM_RH_LAST 0x4004FFFF // R – top of reserved handle area

/***********************************************
 * TPM HANDLE CONSTANTS
 ***********************************************/
typedef uint32_t TPM_HC; // Handle constant type

// Needed for handle validation
#define IMPLEMENTATION_PCR 24
#define MAX_ACTIVE_SESSIONS 64
#define MAX_LOADED_OBJECTS 32

// Masks and shifts
#define HR_HANDLE_MASK 0x00FFFFFF // Mask off the handle-specific part
#define HR_RANGE_MASK  0xFF000000 // Mask off the type/MSO part
#define HR_SHIFT       24         // Shift amount to place MSO in handle

// Handle Type MSO shifted into position
#define HR_PCR            (TPM_HT_PCR << HR_SHIFT)
#define HR_HMAC_SESSION   (TPM_HT_HMAC_SESSION << HR_SHIFT)
#define HR_POLICY_SESSION (TPM_HT_POLICY_SESSION << HR_SHIFT)
#define HR_TRANSIENT      (TPM_HT_TRANSIENT << HR_SHIFT)
#define HR_PERSISTENT     (TPM_HT_PERSISTENT << HR_SHIFT)
#define HR_NV_INDEX       (TPM_HT_NV_INDEX << HR_SHIFT)
#define HR_EXTERNAL_NV    (TPM_HT_EXTERNAL_NV << HR_SHIFT)
#define HR_PERMANENT_NV   (TPM_HT_PERMANENT_NV << HR_SHIFT)
#define HR_PERMANENT      (TPM_HT_PERMANENT << HR_SHIFT)
#define HR_AC             (TPM_HT_AC << HR_SHIFT)
#define HR_NV_AC          ((TPM_HT_NV_INDEX << HR_SHIFT) + 0xD00000) // AC aliased NV Index

// PCR range
#define PCR_FIRST (HR_PCR + 0)
#define PCR_LAST  (PCR_FIRST + IMPLEMENTATION_PCR - 1)

// HMAC session range
#define HMAC_SESSION_FIRST (HR_HMAC_SESSION + 0)
#define HMAC_SESSION_LAST  (HMAC_SESSION_FIRST + MAX_ACTIVE_SESSIONS - 1)

// Loaded session (used in TPM2_GetCapability)
#define LOADED_SESSION_FIRST HMAC_SESSION_FIRST
#define LOADED_SESSION_LAST  HMAC_SESSION_LAST

// Policy session range
#define POLICY_SESSION_FIRST (HR_POLICY_SESSION + 0)
#define POLICY_SESSION_LAST  (POLICY_SESSION_FIRST + MAX_ACTIVE_SESSIONS - 1)

// Active session range (used in GetCapability)
#define ACTIVE_SESSION_FIRST POLICY_SESSION_FIRST
#define ACTIVE_SESSION_LAST  POLICY_SESSION_LAST

// Transient object range
#define TRANSIENT_FIRST (HR_TRANSIENT + 0)
#define TRANSIENT_LAST  (TRANSIENT_FIRST + MAX_LOADED_OBJECTS - 1)

// Persistent object range
#define PERSISTENT_FIRST    (HR_PERSISTENT + 0)
#define PERSISTENT_LAST     (PERSISTENT_FIRST + 0x00FFFFFF)
#define PLATFORM_PERSISTENT (PERSISTENT_FIRST + 0x00800000)

// NV Index ranges
#define NV_INDEX_FIRST     (HR_NV_INDEX + 0)
#define NV_INDEX_LAST      (NV_INDEX_FIRST + 0x00FFFFFF)
#define EXTERNAL_NV_FIRST  (HR_EXTERNAL_NV + 0)
#define EXTERNAL_NV_LAST   (EXTERNAL_NV_FIRST + 0x00FFFFFF)
#define PERMANENT_NV_FIRST (HR_PERMANENT_NV + 0)
#define PERMANENT_NV_LAST  (PERMANENT_NV_FIRST + 0x00FFFFFF)

// Permanent handles
#define PERMANENT_FIRST TPM_RH_FIRST
#define PERMANENT_LAST  TPM_RH_LAST

// SVN-limited ranges
#define SVN_OWNER_FIRST       (TPM_RH_SVN_OWNER_BASE + 0x0000)
#define SVN_OWNER_LAST        (TPM_RH_SVN_OWNER_BASE + 0xFFFF)
#define SVN_ENDORSEMENT_FIRST (TPM_RH_SVN_ENDORSEMENT_BASE + 0x0000)
#define SVN_ENDORSEMENT_LAST  (TPM_RH_SVN_ENDORSEMENT_BASE + 0xFFFF)
#define SVN_PLATFORM_FIRST    (TPM_RH_SVN_PLATFORM_BASE + 0x0000)
#define SVN_PLATFORM_LAST     (TPM_RH_SVN_PLATFORM_BASE + 0xFFFF)
#define SVN_NULL_FIRST        (TPM_RH_SVN_NULL_BASE + 0x0000)
#define SVN_NULL_LAST         (TPM_RH_SVN_NULL_BASE + 0xFFFF)

// Attached Component (AC) range
#define AC_FIRST (HR_AC + 0)
#define AC_LAST  (HR_AC + 0x0000FFFF)

// NV AC range
#define NV_AC_FIRST (HR_NV_AC + 0)
#define NV_AC_LAST  (HR_NV_AC + 0x0000FFFF)
