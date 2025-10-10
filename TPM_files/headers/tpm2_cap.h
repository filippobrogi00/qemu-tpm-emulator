#ifndef TPM_CAPABILITY_H
#define TPM_CAPABILITY_H

#include <stdint.h>

/*
 * TPM_CAP (UINT32)
 * Capability values for TPM2_GetCapability() / TPM2_SetCapability()
 * Reference: TCG TPM 2.0 Library Spec, Part 2, Table 22–24
 */

typedef uint32_t TPM_CAP;

/* ---- Standard Capability Selectors ---- */
#define TPM_CAP_FIRST ((TPM_CAP)0x00000000)

#define TPM_CAP_ALGS           ((TPM_CAP)0x00000000) /* returns TPML_ALG_PROPERTY */
#define TPM_CAP_HANDLES        ((TPM_CAP)0x00000001) /* returns TPML_HANDLE */
#define TPM_CAP_COMMANDS       ((TPM_CAP)0x00000002) /* returns TPML_CCA */
#define TPM_CAP_PP_COMMANDS    ((TPM_CAP)0x00000003) /* returns TPML_CC */
#define TPM_CAP_AUDIT_COMMANDS ((TPM_CAP)0x00000004) /* returns TPML_CC */
#define TPM_CAP_PCRS           ((TPM_CAP)0x00000005) /* returns TPML_PCR_SELECTION */
#define TPM_CAP_TPM_PROPERTIES \
    ((TPM_CAP)0x00000006) /* returns TPML_TAGGED_TPM_PROPERTY */
#define TPM_CAP_PCR_PROPERTIES \
    ((TPM_CAP)0x00000007)                        /* returns TPML_TAGGED_PCR_PROPERTY */
#define TPM_CAP_ECC_CURVES ((TPM_CAP)0x00000008) /* returns TPML_ECC_CURVE */
#define TPM_CAP_AUTH_POLICIES \
    ((TPM_CAP)0x00000009)                 /* returns TPML_TAGGED_POLICY */
#define TPM_CAP_ACT ((TPM_CAP)0x0000000A) /* returns TPML_ACT_DATA */

#define TPM_CAP_LAST TPM_CAP_ACT

/* ---- Vendor-specific ---- */
#define TPM_CAP_VENDOR_PROPERTY \
    ((TPM_CAP)0x00000100) /* manufacturer specific */

/* ---- Settable Capabilities (>= 0x80000000) ----
 * The upper byte [31:24] encodes required authorization, per Table 24:
 * 0x80 → no auth
 * 0x81 → platform auth
 * 0x82 → owner auth
 * 0x83 → platform OR owner
 * 0x84 → endorsement
 * 0x85 → lockout
 */
#define TPM_CAP_SET_FIRST ((TPM_CAP)0x80000000)
#define TPM_CAP_SET_LAST  ((TPM_CAP)0x8FFFFFFF)

/* Example Macros for Auth-specific ranges */
#define TPM_CAP_NO_AUTH(x)       (((x) & 0xFF000000U) == 0x80000000U)
#define TPM_CAP_PLATFORM_AUTH(x) (((x) & 0xFF000000U) == 0x81000000U)
#define TPM_CAP_OWNER_AUTH(x)    (((x) & 0xFF000000U) == 0x82000000U)
/* … extend as needed … */

/* ---- Capability Field Layout (Figure 4) ----
 * Bit 31 : S (settable)
 * Bit 30-28 : Reserved
 * Bit 27-24 : A (authorization requirement)
 * Bit 23 : V (vendor indicator)
 * Bit 22-16 : W (vendor ID for vendor-specific settable)
 * Bit 15-0 : C (capability code)
 */

#endif // TPM_CAPABILITY_H
