#include "uart.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TPM2_BASE       0xF0000000
#define TPM2_CTRL_REG   (*(volatile uint32_t *)(TPM2_BASE + 0x00)) // same
#define TPM2_STATUS_REG (*(volatile uint32_t *)(TPM2_BASE + 0x04)) // swapped
#define TPM2_RANDOM_REG (*(volatile uint32_t *)(TPM2_BASE + 0x08)) // same
#define TPM2_CMD_REG    (*(volatile uint32_t *)(TPM2_BASE + 0x0C)) // swapped
#define TPM2_DATA_REG   (*(volatile uint32_t *)(TPM2_BASE + 0x10)) // same

#define TPM2_CMD_GEN_RANDOM 0x01
#define TPM2_CMD_GEN_RSA    0x02
#define TPM2_CMD_CLEAR      0x03

void
delay ()
{
  for (volatile int i = 0; i < 100000; i++)
    ;
}

int
main (void)
{
  UART_init ();
  char message[] = "[UART]TPM2 OK!\n";
  UART_printf (message);
  return 0;
}
//
//   // Trigger random number generation
//   TPM2_CMD_REG = TPM2_CMD_GEN_RANDOM;
//
//   delay (); // Wait for completion (no IRQ here)
//
//   // Read result
//   uint32_t rand_val = TPM2_RANDOM_REG;
//
//   UART_printf ("Random Value: %u\n", rand_val);
//
//   TPM2_CMD_REG = TPM2_CMD_GEN_RSA;
//
//   delay (500); // Wait for RSA key generation
//
//   uint32_t key_generated = TPM2_DATA_REG;
//   UART_printf ("RSA KEY GEN: %u\n", key_generated);
//
//   char text[100];
//   UART_printf ("Enter message to encrypt:\n>> ");
//   UART_gets (text, sizeof (text));
//   UART_printf ("\nEncrypting message...\n %s\n", text);
//
//   printf ("=== TPM Crypto Self-Contained Test ===\n");
//
//   // -----------------------------
//   // 1️⃣ SHA-256
//   // -----------------------------
//   const uint8_t msg[] = "abc";
//   uint8_t       hash[32];
//   if (!sha256 (msg, sizeof (msg) - 1, hash))
//     {
//       printf ("SHA-256 failed!\n");
//       return 1;
//     }
//   printf ("SHA-256(\"abc\") = ");
//   for (int i = 0; i < 32; i++)
//     printf ("%02x", hash[i]);
//   printf ("\n");
//
//   // -----------------------------
//   // 2️⃣ KDFa
//   // -----------------------------
//   uint8_t       kdfa_out[32];
//   const uint8_t kdfa_key[16] = { 0 };
//   const char   *label        = "TPM-Test";
//   if (!KDFa (EVP_sha256 (), kdfa_key, sizeof (kdfa_key), label, 256, kdfa_out))
//     {
//       printf ("KDFa failed!\n");
//       return 1;
//     }
//   printf ("KDFa output: ");
//   for (int i = 0; i < sizeof (kdfa_out); i++)
//     printf ("%02x", kdfa_out[i]);
//   printf ("\n");
//
//   // -----------------------------
//   // 3️⃣ AES-CFB encrypt/decrypt
//   // -----------------------------
//   uint8_t aes_key[16]   = { 0 };
//   uint8_t aes_iv[16]    = { 0 };
//   uint8_t plaintext[16] = "Hello TPM AES!";
//   uint8_t ciphertext[16];
//   uint8_t decrypted[16];
//
//   aes_cfb_crypt (aes_key, sizeof (aes_key), aes_iv, plaintext, sizeof (plaintext), ciphertext, 1);
//   aes_cfb_crypt (aes_key, sizeof (aes_key), aes_iv, ciphertext, sizeof (ciphertext), decrypted, 0);
//
//   printf ("AES-CFB round-trip: %s\n",
//           memcmp (plaintext, decrypted, sizeof (plaintext)) == 0 ? "PASS" : "FAIL");
//
//   // -----------------------------
//   // 4️⃣ RSA sign + verify
//   // -----------------------------
//   EVP_PKEY     *rsa_priv = NULL;
//   EVP_PKEY_CTX *rsa_ctx  = EVP_PKEY_CTX_new_id (EVP_PKEY_RSA, NULL);
//   if (!rsa_ctx)
//     return 1;
//   if (EVP_PKEY_keygen_init (rsa_ctx) <= 0)
//     return 1;
//   if (EVP_PKEY_CTX_set_rsa_keygen_bits (rsa_ctx, 2048) <= 0)
//     return 1;
//   if (EVP_PKEY_keygen (rsa_ctx, &rsa_priv) <= 0)
//     return 1;
//   EVP_PKEY_CTX_free (rsa_ctx);
//
//   EVP_PKEY *rsa_pub = EVP_PKEY_new ();
//   EVP_PKEY_set1_RSA (rsa_pub, EVP_PKEY_get1_RSA (rsa_priv));
//
//   size_t  siglen   = EVP_PKEY_size (rsa_priv);
//   uint8_t sig[512] = { 0 };
//   if (!rsa_sign_auto (rsa_priv, hash, sizeof (hash), sig, &siglen, EVP_sha256 ()))
//     {
//       printf ("RSA signing failed!\n");
//       return 1;
//     }
//
//   EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new (rsa_pub, NULL);
//   EVP_PKEY_verify_init (ctx);
//   EVP_PKEY_CTX_set_signature_md (ctx, EVP_sha256 ());
//   int rc = EVP_PKEY_verify (ctx, sig, siglen, hash, sizeof (hash));
//   printf ("RSA sign/verify: %s\n", rc == 1 ? "PASS" : "FAIL");
//   EVP_PKEY_CTX_free (ctx);
//   EVP_PKEY_free (rsa_pub);
//   EVP_PKEY_free (rsa_priv);
//
//   // -----------------------------
//   // 5️⃣ ECDSA sign + verify
//   // -----------------------------
//   EVP_PKEY     *ec_priv = NULL;
//   EVP_PKEY_CTX *ec_ctx  = EVP_PKEY_CTX_new_id (EVP_PKEY_EC, NULL);
//   if (!ec_ctx)
//     return 1;
//   if (EVP_PKEY_paramgen_init (ec_ctx) <= 0)
//     return 1;
//   if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid (ec_ctx, NID_X9_62_prime256v1) <= 0)
//     return 1;
//   EVP_PKEY *ec_params = NULL;
//   if (EVP_PKEY_paramgen (ec_ctx, &ec_params) <= 0)
//     return 1;
//   EVP_PKEY_CTX_free (ec_ctx);
//
//   EVP_PKEY_CTX *keygen_ctx = EVP_PKEY_CTX_new (ec_params, NULL);
//   if (!keygen_ctx)
//     return 1;
//   if (EVP_PKEY_keygen_init (keygen_ctx) <= 0)
//     return 1;
//   if (EVP_PKEY_keygen (keygen_ctx, &ec_priv) <= 0)
//     return 1;
//   EVP_PKEY_CTX_free (keygen_ctx);
//   EVP_PKEY_free (ec_params);
//
//   EVP_PKEY *ec_pub = EVP_PKEY_new ();
//   EVP_PKEY_set1_EC_KEY (ec_pub, EVP_PKEY_get1_EC_KEY (ec_priv));
//
//   size_t ecdsa_siglen = 0;
//   ecdsa_sign (ec_priv, hash, sizeof (hash), NULL, &ecdsa_siglen); // determine length
//   uint8_t *ecdsa_sig = malloc (ecdsa_siglen);
//   ecdsa_sign (ec_priv, hash, sizeof (hash), ecdsa_sig, &ecdsa_siglen);
//
//   ctx = EVP_PKEY_CTX_new (ec_pub, NULL);
//   EVP_PKEY_verify_init (ctx);
//   EVP_PKEY_CTX_set_signature_md (ctx, EVP_sha256 ());
//   rc = EVP_PKEY_verify (ctx, ecdsa_sig, ecdsa_siglen, hash, sizeof (hash));
//   printf ("ECDSA sign/verify: %s\n", rc == 1 ? "PASS" : "FAIL");
//   EVP_PKEY_CTX_free (ctx);
//
//   EVP_PKEY_free (ec_priv);
//   EVP_PKEY_free (ec_pub);
//   free (ecdsa_sig);
//
//   printf ("=== All tests completed ===\n");
//
//   // Optional: infinite loop with value (good for stepping in debugger)
//   while (1)
//     {
//       (void)rand_val;
//     }
//   return 0;
// }
