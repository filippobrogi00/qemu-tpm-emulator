#ifndef TPM_ALG_ID_H
#define TPM_ALG_ID_H

#include "tpm2_base_types.h" /* for UINT16 */
#define TPM_ECC_NIST_P256 0x0003  /* per TPM 2.0 Part 2, Table 183 */ //ellittic curve crypto id

/*
 * TPM 2.0 Part 2: Structures
 * Definition of (UINT16) TPM_ALG_ID Constants
 *
 * These values identify algorithms, modes, and object types.
 * They appear in command parameters, capability structures,
 * and object attributes.
 */

typedef UINT16 TPM_ALG_ID;

enum
{
    TPM_ALG_ERROR          = 0x0000,
    TPM_ALG_RSA            = 0x0001,
    TPM_ALG_TDES           = 0x0003,
    TPM_ALG_SHA            = 0x0004,
    TPM_ALG_SHA1           = 0x0004, /* alias for SHA */
    TPM_ALG_HMAC           = 0x0005,
    TPM_ALG_AES            = 0x0006,
    TPM_ALG_MGF1           = 0x0007,
    TPM_ALG_KEYEDHASH      = 0x0008,
    TPM_ALG_XOR            = 0x000A,
    TPM_ALG_SHA256         = 0x000B,
    TPM_ALG_SHA384         = 0x000C,
    TPM_ALG_SHA512         = 0x000D,
    TPM_ALG_SHA256_192     = 0x000E,
    TPM_ALG_NULL           = 0x0010,
    TPM_ALG_SM3_256        = 0x0012,
    TPM_ALG_SM4            = 0x0013,
    TPM_ALG_RSASSA         = 0x0014,
    TPM_ALG_RSAES          = 0x0015,
    TPM_ALG_RSAPSS         = 0x0016,
    TPM_ALG_OAEP           = 0x0017,
    TPM_ALG_ECDSA          = 0x0018,
    TPM_ALG_ECDH           = 0x0019,
    TPM_ALG_ECDAA          = 0x001A,
    TPM_ALG_SM2            = 0x001B,
    TPM_ALG_ECSCHNORR      = 0x001C,
    TPM_ALG_ECMQV          = 0x001D,
    TPM_ALG_KDF1_SP800_56A = 0x0020,
    TPM_ALG_KDF2           = 0x0021,
    TPM_ALG_KDF1_SP800_108 = 0x0022,
    TPM_ALG_ECC            = 0x0023,
    TPM_ALG_SYMCIPHER      = 0x0025,
    TPM_ALG_CAMELLIA       = 0x0026,
    TPM_ALG_SHA3_256       = 0x0027,
    TPM_ALG_SHA3_384       = 0x0028,
    TPM_ALG_SHA3_512       = 0x0029,
    TPM_ALG_SHAKE128       = 0x002A,
    TPM_ALG_SHAKE256       = 0x002B,
    TPM_ALG_SHAKE256_192   = 0x002C,
    TPM_ALG_SHAKE256_256   = 0x002D,
    TPM_ALG_SHAKE256_512   = 0x002E,
    TPM_ALG_CMAC           = 0x003F,
    TPM_ALG_CTR            = 0x0040,
    TPM_ALG_OFB            = 0x0041,
    TPM_ALG_CBC            = 0x0042,
    TPM_ALG_CFB            = 0x0043,
    TPM_ALG_ECB            = 0x0044,
    TPM_ALG_CCM            = 0x0050,
    TPM_ALG_GCM            = 0x0051,
    TPM_ALG_KW             = 0x0052,
    TPM_ALG_KWP            = 0x0053,
    TPM_ALG_EAX            = 0x0054,
    TPM_ALG_EDDSA          = 0x0060,
    TPM_ALG_EDDSA_PH       = 0x0061,
    TPM_ALG_LMS            = 0x0070,
    TPM_ALG_XMSS           = 0x0071,
    TPM_ALG_KEYEDXOF       = 0x0080,
    TPM_ALG_KMACXOF128     = 0x0081,
    TPM_ALG_KMACXOF256     = 0x0082,
    TPM_ALG_KMAC128        = 0x0090,
    TPM_ALG_KMAC256        = 0x0091,

    /* Reserved ranges */
    TPM_ALG_RESERVED_FIRST = 0x00C1,
    TPM_ALG_RESERVED_LAST  = 0x00C6,
    TPM_ALG_VENDOR_FIRST   = 0x8000,
    TPM_ALG_VENDOR_LAST    = 0xFFFF
};

#endif /* TPM_ALG_ID_H */
