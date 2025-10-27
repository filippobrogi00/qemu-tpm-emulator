#include <openssl/evp.h> // EVP_MD OpenSSL type
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Compute SHA-256 digest using OpenSSL EVP interface.
 *
 * This function computes the SHA-256 hash of an input message buffer.
 *
 * @param data Pointer to input message.
 * @param len  Length of input message in bytes.
 * @param out  Pointer to 32-byte buffer to receive the resulting hash.
 *
 * @return 1 on success, 0 on failure.
 */
int
TPM2_SHA256 (const uint8_t *data, size_t len, uint8_t out[32])
{
  unsigned int outlen = 0;

  // Create new context
  EVP_MD_CTX *md = EVP_MD_CTX_new ();
  if (!md)
    return 0;

  // Set up created context to use digest type SHA256 from default engine
  if (EVP_DigestInit_ex (md, EVP_sha256 (), NULL) != 1)
    goto cleanup;

  // Hash "len" bytes located at "data" address into "md" context
  if (EVP_DigestUpdate (md, data, len) != 1)
    goto cleanup;

  // Place created digest from context "md" into output buffer "out",
  // and retrieve written bytes into "outlen" variable
  if (EVP_DigestFinal_ex (md, out, &outlen) != 1)
    goto cleanup;

  EVP_MD_CTX_free (md);
  return outlen == 32;

cleanup:
  EVP_MD_CTX_free (md);
  return 0;
}

/**
 * @brief TPM 2.0 KDFa key derivation function (HMAC counter-mode).
 *
 * Produces a variable-length key stream using HMAC-based counter mode.
 *
 * @param hash         Digest algorithm (e.g., EVP_sha256()).
 * @param hmacKey      Key for HMAC input.
 * @param hmacKeyLen   Length of HMAC key in bytes.
 * @param label        Contextual label string (NULL-terminated).
 * @param bits         Number of bits of output key material to generate.
 * @param out          Output buffer of (bits+7)/8 bytes.
 *
 * @return 1 on success, 0 on failure.
 */
int
TPM2_KDFa (const EVP_MD  *hash,
           const uint8_t *hmacKey, size_t hmacKeyLen,
           const char *label,
           uint32_t    bits,
           uint8_t    *out)
{
  uint32_t     counter         = 1;
  uint32_t     bytesToGenerate = (bits + 7) / 8;
  uint32_t     hashLen         = (uint32_t)EVP_MD_size (hash);
  uint32_t     generated       = 0;
  uint8_t      hmacBuf[EVP_MAX_MD_SIZE];
  unsigned int hmacLen = 0;

  while (generated < bytesToGenerate)
    {
      // Create new context
      HMAC_CTX *hmac = HMAC_CTX_new ();
      if (!hmac)
        return 0;

      // Initializes context structure "hmac" with "hash" function and "hmacKey" key (default provider)
      if (!HMAC_Init_ex (hmac, hmacKey, (int)hmacKeyLen, hash, NULL))
        {
          HMAC_CTX_free (hmac);
          return 0;
        }

      // Assign bytes of counter to big endian array
      uint8_t ctr_be[4];
      ctr_be[0] = (counter >> 24) & 0xFF;
      ctr_be[1] = (counter >> 16) & 0xFF;
      ctr_be[2] = (counter >> 8) & 0xFF;
      ctr_be[3] = (counter) & 0xFF;
      // Update hmac context hashing contents of ctr_be array
      HMAC_Update (hmac, ctr_be, 4);

      // If label is present, add it to the hashing
      if (label && label[0])
        {
          HMAC_Update (hmac, (const uint8_t *)label, strlen (label));
        }

      // Finally, add 0x00 hash constant at end of hash (TPM spec)
      uint8_t zero = 0x00;
      HMAC_Update (hmac, &zero, 1);

      // Now update hash with bytes of 32-bit input value
      uint8_t bits_be[4];
      bits_be[0] = (bits >> 24) & 0xFF;
      bits_be[1] = (bits >> 16) & 0xFF;
      bits_be[2] = (bits >> 8) & 0xFF;
      bits_be[3] = bits & 0xFF;
      HMAC_Update (hmac, bits_be, 4);

      // Now place the hash from "hmac" context into the "hmacBuf" buffer
      // with specified length
      HMAC_Final (hmac, hmacBuf, &hmacLen);
      HMAC_CTX_free (hmac);

      // Update remaining bytes to process
      uint32_t toCopy = (generated + hmacLen > bytesToGenerate) ? (bytesToGenerate - generated) : hmacLen;
      memcpy (out + generated, hmacBuf, toCopy);
      generated += toCopy;
      counter++;
    }

  // If bits is not a multiple of 8, we must clear extra bits in the last byte (spec detail).
  if (bits % 8)
    {
      uint8_t mask = (uint8_t)(0xFF << (8 - (bits % 8)));
      out[bytesToGenerate - 1] &= mask;
    }

  return 1;
}

/**
 * @brief AES encryption/decryption in CFB-128 mode.
 *
 * @param key    AES key buffer.
 * @param keylen AES key length in bytes (16, 24, or 32).
 * @param iv     Initialization vector (same size as block, 16 bytes).
 * @param in     Input plaintext or ciphertext.
 * @param inlen  Length of input in bytes.
 * @param out    Output buffer (same length as input).
 * @param enc    1 = encrypt, 0 = decrypt.
 *
 * @return Number of bytes written to @p out on success, 0 on failure.
 */
int
TPM2_AES_CFB_Crypt (const uint8_t *key, int keylen,
                    const uint8_t *iv, const uint8_t *in, size_t inlen,
                    uint8_t *out, int enc) // enc: 1=encrypt, 0=decrypt
{
  // Create context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  if (!ctx)
    return 0;

  // Get a cipher algorithm structure into "cipher"
  const EVP_CIPHER *cipher = NULL;
  switch (keylen)
    {
    case 16:
      cipher = EVP_aes_128_cfb128 ();
      break;
    case 24:
      cipher = EVP_aes_192_cfb128 ();
      break;
    case 32:
      cipher = EVP_aes_256_cfb128 ();
      break;
    default:
      goto cleanup;
    }

  // Prime the context with the cipher before adjusting the key length
  if (EVP_CipherInit_ex (ctx, cipher, NULL, NULL, NULL, enc) != 1)
    goto cleanup;

  // Set key length
  if (EVP_CIPHER_CTX_set_key_length (ctx, keylen) != 1)
    goto cleanup;

  // Now set key and IV
  if (EVP_CipherInit_ex (ctx, NULL, NULL, key, iv, enc) != 1)
    goto cleanup;

  int outlen = 0, tmplen = 0;
  if (EVP_CipherUpdate (ctx, out, &outlen, in, (int)inlen) != 1)
    goto cleanup;

  // Output cleaning
  EVP_CipherFinal_ex (ctx, out + outlen, &tmplen);

  EVP_CIPHER_CTX_free (ctx);
  return (outlen + tmplen);

cleanup:
  EVP_CIPHER_CTX_free (ctx);
  return 0;
}

/**
 * @brief RSA sign function.
 *
 * This function signs a message using an RSA key. It automatically selects
 * the padding mode:
 *  - PKCS#1 v1.5 (RSASSA) if the key is standard RSA.
 *  - PSS (RSAPSS) if the key type is RSAPSS.
 *
 * @param pkey     Pointer to EVP_PKEY RSA private key.
 * @param msg      Pointer to message digest to sign.
 * @param msglen   Length of message digest in bytes.
 * @param sig      Output buffer for signature.
 * @param siglen   Input: buffer size, Output: actual signature length.
 * @param md       Digest algorithm (e.g., EVP_sha256()).
 *
 * @return 1 on success, 0 on failure.
 */
int
TPM2_RSA_Sign (EVP_PKEY      *pkey,
               const uint8_t *msg, size_t msglen,
               uint8_t *sig, size_t *siglen,
               const EVP_MD *md)
{
  if (!pkey || !msg || !sig || !siglen || !md)
    return 0;

  int           ret = 0;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new (pkey, NULL);
  if (!ctx)
    return 0;

  // Initialize context
  if (EVP_PKEY_sign_init (ctx) <= 0)
    goto cleanup;

  // Set digest algorithm
  if (EVP_PKEY_CTX_set_signature_md (ctx, md) <= 0)
    goto cleanup;

  // Detect if the key is PSS capable
  int key_type = EVP_PKEY_base_id (pkey);
  if (key_type == EVP_PKEY_RSA_PSS)
    {
      if (EVP_PKEY_CTX_set_rsa_padding (ctx, RSA_PKCS1_PSS_PADDING) <= 0)
        goto cleanup;

      // Default salt length = hash size
      if (EVP_PKEY_CTX_set_rsa_pss_saltlen (ctx, -1) <= 0)
        goto cleanup;
    }
  else if (key_type == EVP_PKEY_RSA)
    {
      if (EVP_PKEY_CTX_set_rsa_padding (ctx, RSA_PKCS1_PADDING) <= 0)
        goto cleanup;
    }
  else
    {
      // Unsupported key type
      goto cleanup;
    }

  // Determine required signature length
  if (EVP_PKEY_sign (ctx, NULL, siglen, msg, msglen) <= 0)
    goto cleanup;

  // Perform signing
  if (EVP_PKEY_sign (ctx, sig, siglen, msg, msglen) <= 0)
    goto cleanup;

  ret = 1; // success

cleanup:
  EVP_PKEY_CTX_free (ctx);
  return ret;
}
