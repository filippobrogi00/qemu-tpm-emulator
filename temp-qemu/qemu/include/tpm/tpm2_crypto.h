#ifndef TPM_CRYPTO_H
#define TPM_CRYPTO_H

#include <openssl/evp.h> // EVP_MD OpenSSL type
#include <stdint.h>

int TPM2_SHA256 (const uint8_t *data, size_t len, uint8_t out[32]);

int TPM2_KDFa (const EVP_MD  *hash,
               const uint8_t *hmacKey, size_t hmacKeyLen,
               const char *label,
               uint32_t    bits,
               uint8_t    *out);

int TPM2_AES_CFB_Crypt (const uint8_t *key, int keylen,
                        const uint8_t *iv, const uint8_t *in, size_t inlen,
                        uint8_t *out, int enc);

int TPM2_RSA_Sign (EVP_PKEY      *pkey,
                   const uint8_t *msg, size_t msglen,
                   uint8_t *sig, size_t *siglen,
                   const EVP_MD *md);

#endif
