#include "nv_test.h"
#include "test.h"
#include "tpm/TPM2_NV_STRUCTS.h"
#include "tpm/tpm2_nv.h"
#include "tpm/tpm2_nv_entry.h"
#include "tpm2_test_nv.h"
#include <glib.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Test NV attribute helper functions such as any_read_bit()
 *        and any_write_bit() for correct bit interpretation.
 */
void
TPM2_TEST_NV_Helpers (void)
{
  TPMA_NV attrs = { 0 };

  TEST_START ("TPM2_NV helpers - any_read_bit() / any_write_bit()");

  // Check empty attributes
  ASSERT (!any_read_bit (attrs), "Empty attributes should not have read bits");
  ASSERT (!any_write_bit (attrs), "Empty attributes should not have write bits");

  // Check ownerRead and ownerWrite bits
  attrs.ownerRead = 1;
  ASSERT (any_read_bit (attrs), "ownerRead bit not detected");
  attrs.ownerWrite = 1;
  ASSERT (any_write_bit (attrs), "ownerWrite bit not detected");

  TEST_PASS ();
}

/**
 * @brief Test the TPM2_NV_DefineSpace() function against various
 *        valid and invalid NV definitions to ensure proper return codes.
 */
void
TPM2_TEST_NV_DefineSpace (void)
{
  TPM2State state = { 0 };
  TPMA_NV   attrs = { 0 };

  TEST_START ("TPM2_NV_DefineSpace - basic validation");

  // Create fake TPM state
  state.nv_map       = g_hash_table_new (g_direct_hash, g_direct_equal);
  state.nv_bank_size = TPM2_NVSTORAGE_SIZE;

  // Common NV public structure
  attrs.ownerRead      = 1;
  attrs.ownerWrite     = 1;
  attrs.nvType         = TPM_NT_ORDINARY;
  attrs.platformCreate = 0;

  TPMS_NV_PUBLIC pub_inner = {
    .nvIndex    = 0x01000001,
    .nameAlg    = TPM_ALG_SHA256,
    .attributes = attrs,
    .dataSize   = 16
  };

  TPM2B_NV_PUBLIC   pub        = { .size = sizeof (pub_inner), .nvPublic = pub_inner };
  TPM2B_AUTH        auth       = { .size = 0 };
  TPMI_RH_PROVISION authHandle = { .platform = TPM_RH_OWNER };

  // Define first NV space successfully
  TPM_RC rc = tpm2_nv_define_space (&state, authHandle, &auth, &pub);
  ASSERT (rc == TPM_RC_SUCCESS, "Expected success for valid NV define");

  // Attempt to redefine same index -> should fail with TPM_RC_NV_DEFINED
  rc = tpm2_nv_define_space (&state, authHandle, &auth, &pub);
  ASSERT (rc == TPM_RC_NV_DEFINED, "Expected NV_DEFINED for duplicate index");

  TEST_PASS ();

  TEST_START ("TPM2_NV_DefineSpace - invalid attributes");

  // Invalid attributes (written bit set)
  attrs.written        = 1;
  pub_inner.attributes = attrs;
  pub.nvPublic         = pub_inner;
  rc                   = tpm2_nv_define_space (&state, authHandle, &auth, &pub);
  ASSERT (rc == TPM_RC_ATTRIBUTES, "Invalid attribute (written=1) not detected");

  TEST_PASS ();

  TEST_START ("TPM2_NV_DefineSpace - excessive data size");

  // Too large dataSize
  pub_inner.attributes.written = 0;
  pub_inner.dataSize           = TPM2_NVSTORAGE_SIZE + 100;
  pub.nvPublic                 = pub_inner;
  rc                           = tpm2_nv_define_space (&state, authHandle, &auth, &pub);
  ASSERT (rc == TPM_RC_SIZE, "Too-large NV size not detected");

  TEST_PASS ();

  g_hash_table_destroy (state.nv_map);
}

/**
 * @brief Runs all TPM 2.0 NV subsystem tests.
 */
void
TPM2_TEST_NV (void)
{
  printf ("\n=============================\n");
  printf (" TPM2 NV TEST SUITE STARTED\n");
  printf ("=============================\n\n");

  TPM2_TEST_NV_Helpers ();
  TPM2_TEST_NV_DefineSpace ();

  printf ("\n=============================\n");
  printf (" TPM2 NV TEST SUITE COMPLETED\n");
  printf ("=============================\n");
}
