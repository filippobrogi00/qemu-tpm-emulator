#ifndef TPM_PS_H
#define TPM_PS_H

#include <stdint.h>

/*
 * TPM_PS (UINT32)
 * Platform-specific constants used for TPM_PT_PS_FAMILY_INDICATOR.
 * Reference: TCG TPM 2.0 Library Spec, Part 2, Table 27
 */

typedef uint32_t TPM_PS;

#define TPM_PS_MAIN           ((TPM_PS)0x00000000) /* Not platform specific */
#define TPM_PS_PC             ((TPM_PS)0x00000001) /* PC Client */
#define TPM_PS_PDA            ((TPM_PS)0x00000002) /* PDA / mobile devices */
#define TPM_PS_CELL_PHONE     ((TPM_PS)0x00000003) /* Cell Phone */
#define TPM_PS_SERVER         ((TPM_PS)0x00000004) /* Server WG */
#define TPM_PS_PERIPHERAL     ((TPM_PS)0x00000005) /* Peripheral WG */
#define TPM_PS_TSS            ((TPM_PS)0x00000006) /* TSS WG (deprecated) */
#define TPM_PS_STORAGE        ((TPM_PS)0x00000007) /* Storage WG */
#define TPM_PS_AUTHENTICATION ((TPM_PS)0x00000008) /* Authentication WG */
#define TPM_PS_EMBEDDED       ((TPM_PS)0x00000009) /* Embedded WG */
#define TPM_PS_HARDCOPY       ((TPM_PS)0x0000000A) /* Hardcopy WG */
#define TPM_PS_INFRASTRUCTURE ((TPM_PS)0x0000000B) /* Infrastructure WG (deprecated) */
#define TPM_PS_VIRTUALIZATION ((TPM_PS)0x0000000C) /* Virtualization WG */
#define TPM_PS_TNC            ((TPM_PS)0x0000000D) /* Trusted Network Connect WG (deprecated) */
#define TPM_PS_MULTI_TENANT   ((TPM_PS)0x0000000E) /* Multi-tenant WG (deprecated) */
#define TPM_PS_TC             ((TPM_PS)0x0000000F) /* Technical Committee (deprecated) */

#endif // TPM_PS_H
