#include "crypto_test.h"
#include "test.h"
#include "tpm/tpm2_crypto.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/**
 *  Tests TPM2_SHA256() against a known message "test"
 *        and its expected SHA-256 hash.
 */
void
TPM2_TEST_CRYPTO_SHA256 ()
{
  const uint8_t msg[] = "test";
  uint8_t       hash[32];

  TEST_START ("TPM2_SHA256 - known value for 'test'");

  // Expected SHA-256("test") =
  // 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  const uint8_t expected[32] = {
    0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65,
    0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15,
    0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c,
    0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08
  };

  // Hash known message
  TPM2_SHA256 (msg, strlen ((char *)msg), hash);

  // Compare computed hash with expected value
  ASSERT (memcmp (hash, expected, 32) == 0, "SHA-256 digest mismatch");
  TEST_PASS ();
}

/**
 *  Tests TPM2_KDFa() using random key material and
 *        verifies that non-zero output is generated.
 */
void
TPM2_TEST_CRYPTO_KDFa ()
{
  uint8_t key[16];
  uint8_t out[32];
  int     allzero = 1;

  TEST_START ("TPM2_KDFa - HMAC key derivation");

  // Get random key (seed) and check KDF function succeedes
  RAND_bytes (key, sizeof (key));
  ASSERT (TPM2_KDFa (EVP_sha256 (), key, sizeof (key), "TPM2KDF", 256, out),
          "KDFa failed");

  // Check it didn't produce 0 as result (invalid key)
  for (int i = 0; i < 32; ++i)
    if (out[i] != 0)
      {
        allzero = 0;
        break;
      }

  ASSERT (!allzero, "KDFa produced all zeros");
  TEST_PASS ();
}

/**
 *  Tests TPM2_AES_CFB_Crypt() by encrypting and then decrypting
 *        a sample message, verifying byte count and data integrity.
 */
void
TPM2_TEST_CRYPTO_AES_CFB_Crypt ()
{

  uint8_t aes_key[16];
  uint8_t iv[16];
  uint8_t plaintext[32] = "Test Message";
  uint8_t ciphertext[32];
  uint8_t decrypted[32];
  int     enc_len;
  int     dec_len;

  TEST_START ("TPM2_AES_CFB_Crypt - AES-128 CFB mode");

  // Generate random AES key and IV
  RAND_bytes (aes_key, sizeof (aes_key));
  RAND_bytes (iv, sizeof (iv));

  // Check number of written bytes by the function
  enc_len = TPM2_AES_CFB_Crypt (aes_key, sizeof (aes_key),
                                iv, plaintext, strlen ((char *)plaintext),
                                ciphertext, 1);
  ASSERT (enc_len > 0, "AES encrypt failed");

  // Decrypt the previously encrypted message and check lengths and message itself match
  dec_len = TPM2_AES_CFB_Crypt (aes_key, sizeof (aes_key),
                                iv, ciphertext, enc_len,
                                decrypted, 0);
  ASSERT (dec_len == enc_len, "AES decrypt size mismatch");
  ASSERT (memcmp (plaintext, decrypted, dec_len) == 0, "AES decrypt mismatch");
  TEST_PASS ();
}

/**
 * Tests TPM2_RSA_Sign() and verifies that the produced signature
 *        validates correctly using OpenSSL EVP interfaces.
 */
void
TPM2_TEST_CRYPTO_RSA_Sign ()
{
  char         *test_string = "Test string";
  uint8_t       digest[32];
  uint8_t       sig[256];
  size_t        siglen;
  EVP_PKEY_CTX *pctx = NULL;
  EVP_PKEY_CTX *vctx = NULL;
  EVP_PKEY     *pkey = NULL;

  TEST_START ("TPM2_RSA_Sign - RSA 2048-bit");

  // Create context
  pctx = EVP_PKEY_CTX_new_id (EVP_PKEY_RSA, NULL);

  ASSERT (pctx != NULL, "EVP_PKEY_CTX_new_id failed");
  ASSERT (EVP_PKEY_keygen_init (pctx) > 0, "keygen init failed");
  ASSERT (EVP_PKEY_CTX_set_rsa_keygen_bits (pctx, 2048) > 0, "set bits failed");
  ASSERT (EVP_PKEY_keygen (pctx, &pkey) > 0, "keygen failed");

  EVP_PKEY_CTX_free (pctx);

  // Compute digest to sign
  TPM2_SHA256 ((const uint8_t *)test_string, strlen (test_string), digest);

  // Compute signature length
  siglen = sizeof (sig);

  // Check RSA is generated correctly
  ASSERT (TPM2_RSA_Sign (pkey, digest, sizeof (digest),
                         sig, &siglen, EVP_sha256 ())
              == 1,
          "RSA signing failed");

  // Verify signature
  vctx = EVP_PKEY_CTX_new (pkey, NULL);
  ASSERT (vctx != NULL, "verify ctx failed");
  ASSERT (EVP_PKEY_verify_init (vctx) > 0, "verify init failed");
  ASSERT (EVP_PKEY_CTX_set_signature_md (vctx, EVP_sha256 ()) > 0,
          "verify md failed");

  // Check verify return code
  ASSERT (EVP_PKEY_verify (vctx, sig, siglen, digest, sizeof (digest));
          == 1, "RSA signature verification failed");

  EVP_PKEY_CTX_free (vctx);
  EVP_PKEY_free (pkey);

  TEST_PASS ();
}

/**
 * Runs all TPM 2.0 cryptographic function tests sequentially.
 */
void
TPM2_TEST_CRYPTO ()
{
  printf ("\n================================\n");
  printf (" TPM2 CRYPTO TEST SUITE STARTED\n");
  printf ("================================\n\n");

  TPM2_TEST_CRYPTO_SHA256 ();
  TPM2_TEST_CRYPTO_KDFa ();
  TPM2_TEST_CRYPTO_AES_CFB_Crypt ();
  TPM2_TEST_CRYPTO_RSA_Sign ();

  printf ("\n================================\n");
  printf (" TPM2 CRYPTO TEST SUITE COMPLETED\n");
  printf ("================================\n\n");
}
