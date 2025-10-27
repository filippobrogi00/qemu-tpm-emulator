#include "cc_test.h"
#include "command_chain/cc_header.h"
#include "qemu/bswap.h"
#include "test.h"
#include "tpm/tpm2_base_types.h"
#include "tpm/tpm2_device.h"
#include "tpm_cc.h"
#include "tpm_rc.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Tests TPM2_ValidateCommandHeader() by validating:
 *  - Bad tag detection (invalid TPM_ST values)
 *  - Command size mismatch
 *  - Invalid command code range
 *
 * @param hdr Temporary header structure used for unpacking test buffers.
 */
void
TPM2_TEST_CC_ValidateCommandHeader (TPM_CMD_HEADER *hdr)
{
  UINT32 rc;
  UINT8  badtag[10];
  UINT8  badsize[10];
  UINT8  badcode[10];

  /* Test return value */
  // TEST_START ("TPM2_ValidateCommandHeader - valid command");
  //
  // rc = TPM2_ValidateCommandHeader (buf, 10, &hdr);
  // ASSERT (rc == TPM_RC_SUCCESS, "Valid header rejected");
  //
  // TEST_PASS ();

  /* Test command tag */
  TEST_START ("TPM2_ValidateCommandHeader - bad tag");

  stw_be_p (badtag, 0xDEAD); // Invalid tag
  stl_be_p (badtag + 2, 10);
  stl_be_p (badtag + 6, TPM_CC_GetTestResult);
  ASSERT (TPM2_ValidateCommandHeader (badtag, 10, hdr) == TPM_RC_BAD_TAG,
          "Failed to detect bag tag");
  TEST_PASS ();

  /* Test command size */
  TEST_START ("TPM2_ValidateCommandHeader - bad command size");
  stw_be_p (badsize, TPM_ST_NO_SESSIONS);
  stl_be_p (badsize + 2, 12); // <-- header says 12 bytes, buffer has only 10
  stl_be_p (badsize + 6, TPM_CC_GetTestResult);
  ASSERT (TPM2_ValidateCommandHeader (badsize, 10, hdr) == TPM_RC_COMMAND_SIZE,
          "Failed to detect mismatched command size");
  TEST_PASS ();

  /* Test command code */
  TEST_START ("TPM2_ValidateCommandHeader - bad command code");

  stw_be_p (badcode, TPM_ST_NO_SESSIONS);
  stl_be_p (badcode + 2, 10);
  stl_be_p (badcode + 6, 0x00000001); // Invalid code
  ASSERT (TPM2_ValidateCommandHeader (badcode, 10, hdr) == TPM_RC_COMMAND_CODE,
          "Failed to detect invalid command code");
  TEST_PASS ();
}

/**
 * @brief Tests TPM2_ValidateMode() by simulating TPM behavior in
 *        all operational modes (failure, field upgrade, uninitialized,
 *        and normal) and checking that allowed and forbidden commands
 *        produce correct TPM_RC_* return codes.
 */
void
TPM2_TEST_CC_ValidateMode ()
{
  TPM2State      tpm_state;
  TPM_CMD_HEADER cmd_header;

  /* Validate allowed command codes in failure mode */
  TEST_START ("TPM2_ValidateMode - failure mode allowed commands");

  tpm_state.tpm_mode = TPM_MODE_FAILURE;
  cmd_header.tag     = TPM_ST_NO_SESSIONS;
  cmd_header.code    = TPM_CC_GetTestResult;
  ASSERT (TPM2_ValidateMode (&cmd_header, &tpm_state) == TPM_RC_SUCCESS,
          "GetTestResult should pass in failure mode");

  cmd_header.code = TPM_CC_GetCapability;
  ASSERT (TPM2_ValidateMode (&cmd_header, &tpm_state) == TPM_RC_SUCCESS,
          "GetCapability should pass in failure mode");

  cmd_header.code = TPM_CC_Startup;
  ASSERT (TPM2_ValidateMode (&cmd_header, &tpm_state) == TPM_RC_FAILURE,
          "Startup should fail in failure mode");

  TEST_PASS ();

  /* Validate allowed command codes in FUM */
  TEST_START ("TPM2_ValidateMode - field upgrade mode");
  tpm_state.tpm_mode = TPM_MODE_FIELD;
  cmd_header.code    = TPM_CC_FieldUpgradeData;
  ASSERT (TPM2_ValidateMode (&cmd_header, &tpm_state) == TPM_RC_SUCCESS, "FieldUpgradeData rejected");
  cmd_header.code = TPM_CC_Startup;
  ASSERT (TPM2_ValidateMode (&cmd_header, &tpm_state) == TPM_RC_UPGRADE, "Invalid command not rejected");
  TEST_PASS ();

  /* Validate allowed command codes in "Uninitialized mode" */
  TEST_START ("TPM2_ValidateMode - uninitialized mode");
  tpm_state.tpm_mode = TPM_MODE_NOINIT;
  cmd_header.code    = TPM_CC_Startup;
  ASSERT (TPM2_ValidateMode (&cmd_header, &tpm_state) == TPM_RC_SUCCESS, "Startup rejected in noinit mode");
  cmd_header.code = TPM_CC_GetTestResult;
  ASSERT (TPM2_ValidateMode (&cmd_header, &tpm_state) == TPM_RC_INITIALIZE, "Non-startup accepted in noinit");
  TEST_PASS ();

  /* Validate allowed command codes in Normal mode */
  TEST_START ("TPM2_ValidateMode - normal mode");
  tpm_state.tpm_mode = TPM_MODE_NORMAL;
  cmd_header.code    = TPM_CC_GetCapability;
  ASSERT (TPM2_ValidateMode (&cmd_header, &tpm_state) == TPM_RC_SUCCESS, "Normal mode failed");
  TEST_PASS ();
}

/**
 * @brief Runs all TPM Command Chain tests in sequence.
 */
void
TPM2_TEST_CC ()
{
  printf ("\n=============================\n");
  printf (" TPM2 CC TEST SUITE STARTED\n");
  printf ("==============================\n\n");

  TPM_CMD_HEADER *hdr;
  TPM2_TEST_CC_ValidateCommandHeader (hdr);
  TPM2_TEST_CC_ValidateMode ();

  printf ("\n=============================\n");
  printf (" TPM2 CC TEST SUITE STARTED\n");
  printf ("=============================\n\n");
}
