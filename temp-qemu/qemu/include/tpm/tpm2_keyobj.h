#ifndef TPM_OBJ_H
#define TPM_OBJ_H

#include "tpm2_base_types.h"
#include "tpm2_alg_structs.h"

/******************************
 * PUBLIC AREA STRUCTURES
 ******************************/
typedef UINT16 TPMI_ALG_PUBLIC; // TPM_ALG_ID type for public area

typedef struct
{
    TPMI_ALG_PUBLIC   type;
    TPMI_ALG_HASH     nameAlg;
    TPMA_OBJECT       objectAttributes;
    TPM2B_DIGEST      authPolicy;
    TPMU_PUBLIC_PARMS parameters;
    TPMU_PUBLIC_ID    unique;
} TPMT_PUBLIC;

typedef struct
{
    UINT16      size;
    TPMT_PUBLIC publicArea;
} TPM2B_PUBLIC;

typedef struct
{
    UINT16 size;
    BYTE   buffer[sizeof (TPMT_PUBLIC)]; // TPM2B_TEMPLATE buffer
} TPM2B_TEMPLATE;

/******************************
 * PUBLIC AREA TYPE-SPECIFIC PARAMETERS
 ******************************/
typedef struct
{
    TPMT_KEYEDHASH_SCHEME scheme;
} TPMS_KEYEDHASH_PARMS;

typedef struct
{
    TPMT_SYM_DEF_OBJECT symmetric;
    TPMT_ASYM_SCHEME    scheme;
} TPMS_ASYM_PARMS;

typedef struct
{
    TPMT_SYM_DEF_OBJECT symmetric;
    TPMT_RSA_SCHEME     scheme;
    TPMI_RSA_KEY_BITS   keyBits;
    UINT32              exponent;
} TPMS_RSA_PARMS;

typedef struct
{
    TPMT_SYM_DEF_OBJECT symmetric;
    TPMT_ECC_SCHEME     scheme;
    TPMI_ECC_CURVE      curveID;
    TPMT_KDF_SCHEME     kdf;
} TPMS_ECC_PARMS;

typedef union
{
    TPMS_KEYEDHASH_PARMS keyedHashDetail;
    TPMS_SYMCIPHER_PARMS symDetail;
    TPMS_RSA_PARMS       rsaDetail;
    TPMS_ECC_PARMS       eccDetail;
    TPMS_ASYM_PARMS      asymDetail;
} TPMU_PUBLIC_PARMS;

typedef union
{
    TPM2B_DIGEST         keyedHash;
    TPM2B_DIGEST         sym;
    TPM2B_PUBLIC_KEY_RSA rsa;
    TPMS_ECC_POINT       ecc;
    TPMS_DERIVE          derive; // for TPM2_CreateLoaded derivation
} TPMU_PUBLIC_ID;

typedef struct
{
    TPMI_ALG_PUBLIC   type;
    TPMU_PUBLIC_PARMS parameters;
} TPMT_PUBLIC_PARMS;

/******************************
 * PRIVATE AREA STRUCTURES
 ******************************/
typedef struct
{
    UINT16 size;
    BYTE   buffer[PRIVATE_VENDOR_SPECIFIC_BYTES];
} TPM2B_PRIVATE_VENDOR_SPECIFIC;

typedef union
{
    TPM2B_PRIVATE_KEY_RSA         rsa;
    TPM2B_ECC_PARAMETER           ecc;
    TPM2B_SENSITIVE_DATA          bits;
    TPM2B_SYM_KEY                 sym;
    TPM2B_PRIVATE_VENDOR_SPECIFIC any;
} TPMU_SENSITIVE_COMPOSITE;

typedef struct
{
    TPMI_ALG_PUBLIC          sensitiveType;
    TPM2B_AUTH               authValue;
    TPM2B_DIGEST             seedValue;
    TPMU_SENSITIVE_COMPOSITE sensitive;
} TPMT_SENSITIVE;

typedef struct
{
    UINT16         size;
    TPMT_SENSITIVE sensitiveArea;
} TPM2B_SENSITIVE;

typedef struct
{
    TPM2B_DIGEST    integrityOuter;
    TPM2B_DIGEST    integrityInner; // could also be TPM2B_IV
    TPM2B_SENSITIVE sensitive;
} _PRIVATE;

typedef struct
{
    UINT16 size;
    BYTE   buffer[sizeof (_PRIVATE)];
} TPM2B_PRIVATE;

/******************************
 * IDENTITY OBJECT
 ******************************/
typedef struct
{
    TPM2B_DIGEST integrityHMAC;
    TPM2B_DIGEST encIdentity;
} TPMS_ID_OBJECT;

typedef struct
{
    UINT16 size;
    BYTE   credential[sizeof (TPMS_ID_OBJECT)];
} TPM2B_ID_OBJECT;

#endif // TPM_OBJ_H
