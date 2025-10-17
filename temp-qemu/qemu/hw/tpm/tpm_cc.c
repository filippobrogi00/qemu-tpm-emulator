#include "../../include/tpm/tpm2_base_types.h"
#include "../../include/tpm/tpm2_cc.h"
#include "../../include/tpm/tpm2_device.h"
#include "../../include/tpm/tpm2_handles.h"
#include "../../include/tpm/tpm2_interfaces.h"
#include "../../include/tpm/tpm2_rc.h"

/*************************************
 *  COMMAND HEADER VALIDATION
 *************************************/

/*
 * Unpacks a TPM command header from a raw input buffer.
 * Returns 0 on success, -1 on failure.
 */
int
tpm_unpack_header (const uint8_t *buffer, size_t bufferSize, TPM_CMD_HEADER *header)
{
  if (!buffer || !header)
    return -1;

  // TPM command header is always 10 bytes
  if (bufferSize < 10)
    return -1;

  // TPM values are big-endian
  header->tag         = read_be16 (buffer);
  header->commandSize = read_be32 (buffer + 2);
  header->commandCode = read_be32 (buffer + 6);

  // Optional: sanity check
  if (header->commandSize != bufferSize)
    {
      // Mismatch between header length and buffer length
      return -1;
    }

  return 0;
}

/* Validates a TPM Command Header */
UINT32
TPM2_ValidateCommandHeader (const UINT8 *cmdBuf, size_t bufSize, TPM_CMD_HEADER *hdr)
{
  /* Validate input parameters */
  if (!cmdBuf || bufSize < 10)
    return TPM_RC_COMMAND_SIZE;

  /* Unpack buffer contents into TPM header */
  if (tpm_unpack_header (cmdBuf, bufSize, hdr) == -1)
    return TPM_RC_COMMAND_SIZE;

  /* 1. Validate tag: Either TPMI_ST_COMMAND_TAG_(NO_)SESSIONS */
  if (hdr->tag != TPMI_ST_COMMAND_TAG_NO_SESSIONS && hdr->tag != TPMI_ST_COMMAND_TAG_SESSIONS)
    return TPM_RC_BAD_TAG;

  /* 2. Validate commandSize: Must not exceed bufSize */
  if (hdr->commandSize < 10 || hdr->commandSize > bufSize)
    return TPM_RC_COMMAND_SIZE;

  /* 3. Validate commandCode: Verify command is Implemented by TPM */
  if (!is_valid_cc_command (hdr->commandCode))
    return TPM_RC_COMMAND_CODE;

  return TPM_RC_SUCCESS;
}

/*************************************
 *  MODE CHECK
 *************************************/

/* Checks TPM Mode */
UINT32
TPM2_ValidateMode (TPM_CMD_HEADER cmdHeader, TPMState TPM_State)
{
  /* Check Failure Mode */
  switch (TPM_State.tpm_mode)
    {
    case TPM_MODE_FAILURE:
      if (!(
              (cmdHeader.commandCode == TPM_CC_GetTestResult || cmdHeader.commandCode == TPM_CC_GetCapability)
              && cmdHeader.tag == TPMI_ST_COMMAND_TAG_NO_SESSIONS))
        return TPM_RC_FAILURE;
      break;

    case TPM_MODE_FIELD:
      if (!(cmdHeader.commandCode == TPM_CC_FieldUpgradeData))
        return TPM_RC_UPGRADE;
      break;

    case TPM_MODE_NOINIT:
      if (!(cmdHeader.commandCode == TPM_CC_Startup))
        return TPM_RC_INITIALIZE;
      break;
    }

  return TPM_RC_SUCCESS;
}
