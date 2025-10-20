#include "qemu/osdep.h"
#include <stdbool.h>       // For bool type
#include "qemu/bswap.h"
#include "command_chain/cc_header.h"
#include "tpm/tpm2_device.h"

// --- ADDED HEADERS ---
#include "tpm/tpm2_rc.h"   // For TPM_RC_... constants
#include "tpm/tpm2_cc.h"   // For TPM_CC_... constants

// --- END ADDED ---


/**
 * @brief Checks if a command code is in the valid range.
 * (Based on cc_header.h)
 */
bool is_valid_cc_command(UINT32 commandCode)
{
    if ((commandCode >= TPM_CC_FIRST && commandCode <= TPM_CC_LAST) ||
        (commandCode >= CC_VEND && commandCode <= 0x2FFFFFFF)) {
        return true;
    }
    return false;
}

/*************************************
 * COMMAND HEADER VALIDATION
 *************************************/

/*
 * Unpacks a TPM command header from a raw input buffer.
 * Returns 0 on success, -1 on failure.
 */
int tpm_unpack_header (const uint8_t *buffer, size_t bufferSize, TPM_CMD_HEADER *header)
{
  if (!buffer || !header)
    return -1;

  // TPM command header is always 10 bytes
  if (bufferSize < 10)
    return -1;

  // TPM values are big-endian. Use QEMU's functions.
  header->tag = lduw_be_p(buffer);
  header->size = ldl_be_p(buffer + 2); 
  header->code = ldl_be_p(buffer + 6);

  // Optional: sanity check
  if (header->size != bufferSize)
    {
      // Mismatch between header length and buffer length
      return -1;
    }

  return 0;
}

/* Validates a TPM Command Header */
UINT32 TPM2_ValidateCommandHeader (const UINT8 *cmdBuf, size_t bufSize, TPM_CMD_HEADER *hdr)
{
  /* Validate input parameters */
  if (!cmdBuf || bufSize < 10)
    return TPM_RC_COMMAND_SIZE;

  /* Unpack buffer contents into TPM header */
  if (tpm_unpack_header (cmdBuf, bufSize, hdr) == -1)
    return TPM_RC_COMMAND_SIZE;

  // --- THIS IS THE FIX ---
  /* 1. Validate tag: Must use constants from cc_header.h */
  if (hdr->tag != TPM_ST_NO_SESSIONS && hdr->tag != TPM_ST_SESSIONS)
    return TPM_RC_BAD_TAG;
  // --- END OF FIX ---

  /* 2. Validate commandSize: Must match bufSize */
  if (hdr->size < 10 || hdr->size != bufSize) // Changed to !=
    return TPM_RC_COMMAND_SIZE;

  /* 3. Validate commandCode: Verify command is Implemented by TPM */
  if (!is_valid_cc_command (hdr->code))
    return TPM_RC_COMMAND_CODE;

  return TPM_RC_SUCCESS;
}

/*************************************
 * MODE CHECK
 *************************************/

/* Checks TPM Mode */
UINT32 TPM2_ValidateMode (TPM_CMD_HEADER *cmdHeader, TPM2State *TPM_State) // Pass by pointer
{
  /* Check Failure Mode */
  switch (TPM_State->tpm_mode) // Use -> operator
    {
    case TPM_MODE_FAILURE:
      if (!(
              (cmdHeader->code == TPM_CC_GetTestResult || cmdHeader->code == TPM_CC_GetCapability)
              // --- THIS IS THE FIX ---
              && cmdHeader->tag == TPM_ST_NO_SESSIONS))
              // --- END OF FIX ---
        return TPM_RC_FAILURE;
      break;

    case TPM_MODE_FIELD:
      if (!(cmdHeader->code == TPM_CC_FieldUpgradeData))
        return TPM_RC_UPGRADE;
      break;

    case TPM_MODE_NOINIT:
      if (!(cmdHeader->code == TPM_CC_Startup))
        return TPM_RC_INITIALIZE;
      break;
    
    case TPM_MODE_NORMAL:
        // No checks needed in normal mode
        break;
    }

  return TPM_RC_SUCCESS;
}