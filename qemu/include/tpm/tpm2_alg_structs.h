#ifndef TPM_ALG_STRUCTURES_H
#define TPM_ALG_STRUCTURES_H

#include <stdint.h>
#include "tpm2_algorithms.h"
#include "tpm2_structures.h"

/*
Clause 11.1 defines the parameters and structures for describing symmetric algorithms.
This file includes relevant structures and unions for symmetric keys, modes, details,
and keyed-hash schemes used in TPM 2.0.
*/

/******************************
 * BASIC TYPE ALIASES & CONSTANTS
 ******************************/
typedef uint16_t TPMI_AES_KEY_BITS; // Example for AES
#define AES_KEY_SIZES_BITS 128
#define RSA_KEY_SIZES_BITS 2048
#define TPM_RC_VALUE       0x000 // Chiedere a Mugna
#define MAX_SYM_KEY_BYTES  32
#define MAX_RSA_KEY_BYTES  256
#define MAX_ECC_KEY_BYTES  64
#define MAX_SYM_DATA       128
#define LABEL_MAX_BUFFER   32

#ifndef TPM_ALG_NULL
#define TPM_ALG_NULL 0x0010
#endif

/******************************
 * SYMMETRIC DEFINITIONS
 ******************************/
typedef union
{
    TPMI_AES_KEY_BITS aes;
    uint16_t          sym;
    uint16_t          xor;
    uint16_t          null;
} TPMU_SYM_KEY_BITS;

typedef union
{
    uint16_t aes;
    uint16_t sym;
    uint16_t xor;
    uint16_t null;
} TPMU_SYM_MODE;

typedef union
{
    uint16_t aes;
    uint16_t sym;
    uint16_t xor;
    uint16_t null;
} TPMU_SYM_DETAILS;

typedef struct
{
    uint16_t          algorithm; // TPMI_ALG_SYM
    TPMU_SYM_KEY_BITS keyBits;
    TPMU_SYM_MODE     mode;
} TPMT_SYM_DEF;

typedef struct
{
    uint16_t          algorithm; // TPMI_ALG_SYM_OBJECT
    TPMU_SYM_KEY_BITS keyBits;
    TPMU_SYM_MODE     mode;
} TPMT_SYM_DEF_OBJECT;

typedef struct
{
    TPMT_SYM_DEF_OBJECT sym;
} TPMS_SYMCIPHER_PARMS;

typedef struct
{
    uint16_t size;
    uint8_t  buffer[MAX_SYM_KEY_BYTES];
} TPM2B_SYM_KEY;

/******************************
 * DERIVATION AND SENSITIVE CREATION
 ******************************/
typedef struct
{
    uint16_t size;
    uint8_t  buffer[LABEL_MAX_BUFFER];
} TPM2B_LABEL;

typedef struct
{
    TPM2B_LABEL label;
    TPM2B_LABEL context;
} TPMS_DERIVE;

typedef struct
{
    uint16_t size;
    uint8_t  buffer[sizeof(TPMS_DERIVE)];
} TPM2B_DERIVE;

typedef union
{
    uint8_t     create[MAX_SYM_DATA];
    TPMS_DERIVE derive;
} TPMU_SENSITIVE_CREATE;

typedef struct
{
    uint16_t size;
    uint8_t  buffer[sizeof(TPMU_SENSITIVE_CREATE)];
} TPM2B_SENSITIVE_DATA;

typedef struct
{
    TPM2B_AUTH           userAuth;
    TPM2B_SENSITIVE_DATA data;
} TPMS_SENSITIVE_CREATE;

typedef struct
{
    uint16_t              size;
    TPMS_SENSITIVE_CREATE sensitive;
} TPM2B_SENSITIVE_CREATE;

/******************************
 * HASH & KEYED HASH SCHEMES
 ******************************/
typedef struct
{
    uint16_t hashAlg;
} TPMS_SCHEME_HASH;

typedef struct
{
    uint16_t hashAlg;
    uint16_t count;
} TPMS_SCHEME_ECDAA;

typedef uint16_t TPMI_ALG_KEYEDHASH_SCHEME;
#define TPM_ALG_HMAC 0x0005
#define TPM_ALG_XOR  0x000A

typedef TPMS_SCHEME_HASH TPMS_SCHEME_HMAC;

typedef struct
{
    uint16_t hashAlg;
    uint16_t kdf;
} TPMS_SCHEME_XOR;

typedef union
{
    TPMS_SCHEME_HMAC hmac;
    TPMS_SCHEME_XOR  xor;
    uint16_t         null;
} TPMU_SCHEME_KEYEDHASH;

typedef struct
{
    TPMI_ALG_KEYEDHASH_SCHEME scheme;
    TPMU_SCHEME_KEYEDHASH     details;
} TPMT_KEYEDHASH_SCHEME;

/******************************
 * KDF SCHEMES
 ******************************/
typedef TPMS_SCHEME_HASH TPMS_KDF_SCHEME_RSA;

typedef union
{
    TPMS_KDF_SCHEME_RSA rsa;
    TPMS_SCHEME_HASH    anyKdf;
    uint16_t            null;
} TPMU_KDF_SCHEME;

typedef struct
{
    uint16_t        scheme;
    TPMU_KDF_SCHEME details;
} TPMT_KDF_SCHEME;

/******************************
 * SIGNATURE SCHEMES
 ******************************/
typedef TPMS_SCHEME_HASH  TPMS_SIG_SCHEME_RSA;
typedef TPMS_SCHEME_HASH  TPMS_SIG_SCHEME_ECC;
typedef TPMS_SCHEME_ECDAA TPMS_SIG_SCHEME_ECC_ANON;

typedef union
{
    TPMS_SIG_SCHEME_RSA      rsa;
    TPMS_SIG_SCHEME_ECC      ecc;
    TPMS_SIG_SCHEME_ECC_ANON eccAnon;
    TPMS_SCHEME_HMAC         hmac;
    TPMS_SCHEME_HASH         any;
    uint16_t                 null;
} TPMU_SIG_SCHEME;

typedef struct
{
    uint16_t        scheme;
    TPMU_SIG_SCHEME details;
} TPMT_SIG_SCHEME;

/******************************
 * ASYMMETRIC SCHEMES
 ******************************/
typedef uint16_t TPMI_ALG_ASYM_SCHEME;
#define TPM_ALG_RSA_AM 0x0010
#define TPM_ALG_RSA_AX 0x0011
#define TPM_ALG_RSA_AE 0x0012

typedef struct TPMS_KEY_SCHEME_ECC TPMS_KEY_SCHEME_ECC; // forward declare

typedef union
{
    TPMS_KEY_SCHEME_ECC *eccKeyExchange;
    TPMS_SIG_SCHEME_RSA  rsaSig;
    TPMS_SIG_SCHEME_ECC  eccSig;
    TPMS_SCHEME_HASH     anySig;
    uint16_t             null;
} TPMU_ASYM_SCHEME;

typedef struct
{
    TPMI_ALG_ASYM_SCHEME scheme;
    TPMU_ASYM_SCHEME     details;
} TPMT_ASYM_SCHEME;

/******************************
 * RSA SCHEMES & KEYS
 ******************************/
typedef uint16_t TPMI_ALG_RSA_SCHEME;
typedef uint16_t TPMI_ALG_RSA_DECRYPT;
typedef uint16_t TPMI_RSA_KEY_BITS;

typedef struct
{
    TPMI_ALG_RSA_SCHEME scheme;
    TPMU_ASYM_SCHEME    details;
} TPMT_RSA_SCHEME;

typedef struct
{
    TPMI_ALG_RSA_DECRYPT scheme;
    TPMU_ASYM_SCHEME     details;
} TPMT_RSA_DECRYPT;

typedef struct
{
    uint16_t size;
    uint8_t  buffer[MAX_RSA_KEY_BYTES];
} TPM2B_PUBLIC_KEY_RSA;

typedef struct
{
    uint16_t size;
    uint8_t  buffer[MAX_RSA_KEY_BYTES / 2];
} TPM2B_PRIVATE_KEY_RSA;

/******************************
 * ECC SCHEMES & KEYS
 ******************************/
typedef struct
{
    uint16_t size;
    uint8_t  buffer[MAX_ECC_KEY_BYTES];
} TPM2B_ECC_PARAMETER;

typedef struct
{
    TPM2B_ECC_PARAMETER x;
    TPM2B_ECC_PARAMETER y;
} TPMS_ECC_POINT;

typedef struct
{
    uint16_t       size;
    TPMS_ECC_POINT point;
} TPM2B_ECC_POINT;

typedef uint16_t TPMI_ALG_ECC_SCHEME;
typedef uint16_t TPMI_ECC_CURVE;

typedef struct
{
    TPMI_ALG_ECC_SCHEME scheme;
    TPMU_ASYM_SCHEME    details;
} TPMT_ECC_SCHEME;

typedef struct
{
    TPMI_ECC_CURVE      curveID;
    uint16_t            keySize;
    TPMT_KDF_SCHEME    *kdf;
    TPMT_ECC_SCHEME    *sign;
    TPM2B_ECC_PARAMETER p;
    TPM2B_ECC_PARAMETER a;
    TPM2B_ECC_PARAMETER b;
    TPM2B_ECC_PARAMETER gX;
    TPM2B_ECC_PARAMETER gY;
    TPM2B_ECC_PARAMETER n;
    TPM2B_ECC_PARAMETER h;
} TPMS_ALGORITHM_DETAIL_ECC;

/******************************
 * SIGNATURES
 ******************************/
typedef struct
{
    TPMI_ALG_HASH        hash;
    TPM2B_PUBLIC_KEY_RSA sig;
} TPMS_SIGNATURE_RSA;

typedef struct
{
    TPMI_ALG_HASH       hash;
    TPM2B_ECC_PARAMETER signatureR;
    TPM2B_ECC_PARAMETER signatureS;
} TPMS_SIGNATURE_ECC;

typedef union
{
    TPMS_SIGNATURE_RSA rsa;
    TPMS_SIGNATURE_ECC ecc;
    TPMT_HA            hmac;
    TPMS_SCHEME_HASH   any;
    uint16_t           null;
} TPMU_SIGNATURE;

typedef TPM_ALG_ID TPMI_ALG_SIG_SCHEME;

typedef struct
{
    TPMI_ALG_SIG_SCHEME sigAlg;
    TPMU_SIGNATURE      signature;
} TPMT_SIGNATURE;

/******************************
 * ENCRYPTED SECRETS
 ******************************/
typedef union
{
    TPMS_ECC_POINT ecc;
    uint8_t        rsa[MAX_RSA_KEY_BYTES];
    uint8_t        symmetric[sizeof(TPM2B_DIGEST)];
    uint8_t        keyedHash[sizeof(TPM2B_DIGEST)];
} TPMU_ENCRYPTED_SECRET;

typedef struct
{
    uint16_t              size;
    TPMU_ENCRYPTED_SECRET secret;
} TPM2B_ENCRYPTED_SECRET;

#endif // TPM_ALG_STRUCTURES_H
