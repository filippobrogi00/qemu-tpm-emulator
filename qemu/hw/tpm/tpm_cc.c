#include "qemu/osdep.h"
#include <stdbool.h>       // For bool type
#include "qemu/bswap.h"
#include "qemu/log.h"
#include "tpm/command_chain/cc_header.h"
#include "tpm/tpm2_device.h"

#include "tpm/tpm2_rc.h"   // For TPM_RC_... constants
#include "tpm/tpm2_cc.h"   // For TPM_CC_... constants

#define TPM2_LOG(fmt, ...) qemu_log("%s: " fmt, __func__, ## __VA_ARGS__)

/**
 * @brief Checks if a command code is in the valid range
 */
bool is_valid_cc_command(UINT32 commandCode)
{
    if ((commandCode >= TPM_CC_FIRST && commandCode <= TPM_CC_LAST) ||
        (commandCode >= CC_VEND && commandCode <= 0x2FFFFFFF)) {
        return true;
    }
    TPM2_LOG("Validation failed: Unknown command code 0x%08X\n", commandCode);
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
  if (!buffer || !header) {
    TPM2_LOG("Unpack failed: NULL buffer or header\n");
    return -1;
  }

  // TPM command header is always 10 bytes
  if (bufferSize < 10) {
    TPM2_LOG("Unpack failed: Buffer size %zu is < 10\n", bufferSize);
    return -1;
  }

  // TPM values are big-endian. Use QEMU's functions.
  header->tag = lduw_be_p(buffer);
  header->size = ldl_be_p(buffer + 2); 
  header->code = ldl_be_p(buffer + 6);

  TPM2_LOG("Unpacked Header: Tag=0x%04X, Size=%u, Code=0x%08X\n", header->tag, header->size, header->code);

  return 0;
}

/* Validates a TPM Command Header */
UINT32 TPM2_ValidateCommandHeader (const UINT8 *cmdBuf, size_t bufSize, TPM_CMD_HEADER *hdr)
{
  TPM2_LOG("Validating command header (received bufSize=%zu)\n", bufSize);

  // Validate input parameters
  if (!cmdBuf || bufSize < 10) {
    TPM2_LOG("Validation failed: bufSize %zu < 10\n", bufSize);
    return TPM_RC_COMMAND_SIZE;
  } 

  // Unpack buffer contents into TPM header
  if (tpm_unpack_header (cmdBuf, bufSize, hdr) == -1)
    return TPM_RC_COMMAND_SIZE;

  // Validate tag
  if (hdr->tag != TPM_ST_NO_SESSIONS && hdr->tag != TPM_ST_SESSIONS) {
    TPM2_LOG("Validation failed: Bad tag 0x%04X\n", hdr->tag);
    return TPM_RC_BAD_TAG;
  }

  // Validate commandSize: Must match bufSize
  if (hdr->size < 10 || hdr->size != bufSize) {
    TPM2_LOG("Validation failed: Mismatched size field %u vs bufSize %zu\n", hdr->size, bufSize);
    return TPM_RC_COMMAND_SIZE;
  }

  // Validate commandCode: Verify command is Implemented by TPM
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
  TPM2_LOG("Validating mode (current mode=%d, command=0x%08X)\n", TPM_State->tpm_mode, cmdHeader->code);
  /* Check Failure Mode */
  switch (TPM_State->tpm_mode) // Use -> operator
    {
    case TPM_MODE_FAILURE:
      if (!((cmdHeader->code == TPM_CC_GetTestResult || cmdHeader->code == TPM_CC_GetCapability) && cmdHeader->tag == TPM_ST_NO_SESSIONS)) {
        TPM2_LOG("Mode validation failed: TPM in failure mode\n");
        return TPM_RC_FAILURE;
      }
      break;

    case TPM_MODE_FIELD:
      if (!(cmdHeader->code == TPM_CC_FieldUpgradeData)) {
        TPM2_LOG("Mode validation failed: TPM in field mode\n");
        return TPM_RC_UPGRADE;
      }
      break;

    case TPM_MODE_NOINIT:
      if (!(cmdHeader->code == TPM_CC_Startup)) {
        TPM2_LOG("Mode validation failed: TPM not initialized\n");
        return TPM_RC_INITIALIZE;
      } 
      break;
    
    case TPM_MODE_NORMAL:
        // No checks needed in normal mode
        break;
    }

  TPM2_LOG("Mode validation successful.\n");
  return TPM_RC_SUCCESS;
}