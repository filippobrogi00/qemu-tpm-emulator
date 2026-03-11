#ifndef TPM_STARTUP_H
#define TPM_STARTUP_H

#include <stdint.h>

/*
 * TPM_SU constants (UINT16)
 * Used in TPM2_Shutdown() and TPM2_Startup()
 * Specification: TCG TPM 2.0 Library Spec, Part 2, Table 20
 */

typedef uint16_t TPM_SU;

#define TPM_SU_CLEAR ((TPM_SU)0x0000) /* TPM Reset / Restart */
#define TPM_SU_STATE ((TPM_SU)0x0001) /* TPM Resume / Restart */

/*
 * Notes:
 * - 0x8000 – 0xFFFF are reserved for internal TPM use.
 * - In reference implementations, 0xFFFF is used as "unset startup state"
 *   but this is not a valid caller input.
 */

#endif // TPM_STARTUP_H
