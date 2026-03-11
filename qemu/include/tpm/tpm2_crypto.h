#ifndef TPM_CRYPTO_H
#define TPM_CRYPTO_H
#include "qemu/osdep.h"
#include <openssl/evp.h> // EVP_MD OpenSSL type
#include <stdint.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/hmac.h> //missing include 
#include <string.h>
#include <stdio.h>
#include "tpm/tpm2_base_types.h"
#include "tpm/tpm2_algorithms.h"
#include "tpm/tpm2_rc.h"
#include "tpm/tpm2_device.h"
#include "tpm/tpm2_structures.h"
#include "tpm/tpm2_handles.h"


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


TPM_RC tpm2_CreatePrimary(TPM2State *s,
                          uint32_t primaryHandle,
                          const TPM2B_SENSITIVE_CREATE *inSensitive,
                          const TPM2B_PUBLIC *inPublic,
                          const TPM2B_DATA *outsideInfo,
                          const TPML_PCR_SELECTION *creationPCR,
                          TPM_HANDLE *objectHandle,
                          TPM2B_PUBLIC *outPublic,
                          TPM2B_NAME *name);


#endif
