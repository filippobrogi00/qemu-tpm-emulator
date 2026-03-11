#ifndef TPM_UNMARSHALING_ERRORS_H
#define TPM_UNMARSHALING_ERRORS_H

#include "tpm2_base_types.h" /* for UINT32 */

/************************
 *  UNMARSHALING ERRORS
 ************************/

// Returned when parsing ("unmarshaling") an input buffer fails.

/* Not enough octets in input buffer */
#define TPM_RC_INSUFFICIENT ((UINT32)0x009A)

/* Non-zero in reserved bits of TPMA_ field */
#define TPM_RC_RESERVED_BITS ((UINT32)0x009B)

/* Size parameter outside allowed range */
#define TPM_RC_SIZE ((UINT32)0x0095)

/* Parameter has invalid/unsupported value */
#define TPM_RC_VALUE ((UINT32)0x0096)

/* Structure tag invalid/unsupported */
#define TPM_RC_TAG ((UINT32)0x0097)

#endif /* TPM_UNMARSHALING_ERRORS_H */
