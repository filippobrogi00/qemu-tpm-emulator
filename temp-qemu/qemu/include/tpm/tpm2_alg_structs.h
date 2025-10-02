#ifndef TPM_ALG_STRUCTURES_H
#define TPM_ALG_STRUCTURES_H

#include <stdint.h>

/******************************
 * INTRODUCTION
 ******************************/
/*
Clause 11.1 defines the parameters and structures for describing symmetric algorithms.
This file includes relevant structures and unions for symmetric keys, modes, details,
and keyed-hash schemes used in TPM 2.0.
*/

/******************************
 * TPMI_SYM_KEY_BITS
 ******************************/
/*
TPMI_!ALG.S_KEY_BITS defines supported key sizes for a symmetric algorithm.
Key sizes are expressed in bits.
*/
typedef uint16_t TPMI_AES_KEY_BITS; // Example for AES
#define AES_KEY_SIZES_BITS 128      // could also include 192, 256
#define TPM_RC_VALUE       0x000    // error code placeholder

/******************************
 * TPMU_SYM_KEY_BITS
 ******************************/
/*
Union for symmetric encryption key sizes.
*/
typedef union
{
    TPMI_AES_KEY_BITS aes;
    uint16_t          sym; // generic reference
    uint16_t xor ;         // overload for XOR
    uint16_t null;         // TPM_ALG_NULL
} TPMU_SYM_KEY_BITS;

/******************************
 * TPMU_SYM_MODE
 ******************************/
/*
Union of all symmetric modes.
*/
typedef union
{
    uint16_t aes;  // AES modes selector
    uint16_t sym;  // generic reference
    uint16_t xor ; // no mode
    uint16_t null; // no mode
} TPMU_SYM_MODE;

/******************************
 * TPMU_SYM_DETAILS
 ******************************/
/*
Additional parameters for symmetric ciphers.
Currently empty for supported algorithms.
*/
typedef union
{
    uint16_t aes; // placeholder for AES-specific params
    uint16_t sym;
    uint16_t xor ;
    uint16_t null;
} TPMU_SYM_DETAILS;

/******************************
 * TPMT_SYM_DEF
 ******************************/
/*
Selects symmetric algorithm and its parameters.
*/
typedef struct
{
    uint16_t          algorithm; // TPMI_ALG_SYM
    TPMU_SYM_KEY_BITS keyBits;
    TPMU_SYM_MODE     mode;
    // TPMU_SYM_DETAILS details;  // commented out for now
} TPMT_SYM_DEF;

/******************************
 * TPMT_SYM_DEF_OBJECT
 ******************************/
/*
Used in object parameters when a block cipher may be selected.
*/
typedef struct
{
    uint16_t          algorithm; // TPMI_ALG_SYM_OBJECT
    TPMU_SYM_KEY_BITS keyBits;
    TPMU_SYM_MODE     mode;
    // TPMU_SYM_DETAILS details;  // commented out for now
} TPMT_SYM_DEF_OBJECT;

/******************************
 * TPM2B_SYM_KEY
 ******************************/
/*
Buffer holding symmetric key in sensitive area.
*/
#define MAX_SYM_KEY_BYTES 32
typedef struct
{
    uint16_t size;
    uint8_t  buffer[MAX_SYM_KEY_BYTES];
} TPM2B_SYM_KEY;

/******************************
 * TPMS_SYMCIPHER_PARMS
 ******************************/
typedef struct
{
    TPMT_SYM_DEF_OBJECT sym;
} TPMS_SYMCIPHER_PARMS;

/******************************
 * TPM2B_LABEL
 ******************************/
#define LABEL_MAX_BUFFER 32
typedef struct
{
    uint16_t size;
    uint8_t  buffer[LABEL_MAX_BUFFER];
} TPM2B_LABEL;

/******************************
 * TPMS_DERIVE
 ******************************/
typedef struct
{
    TPM2B_LABEL label;
    TPM2B_LABEL context;
} TPMS_DERIVE;

/******************************
 * TPM2B_DERIVE
 ******************************/
typedef struct
{
    uint16_t size;
    uint8_t  buffer[sizeof (TPMS_DERIVE)];
} TPM2B_DERIVE;

/******************************
 * TPMU_SENSITIVE_CREATE
 ******************************/
#define MAX_SYM_DATA 128
typedef union
{
    uint8_t     create[MAX_SYM_DATA];
    TPMS_DERIVE derive;
} TPMU_SENSITIVE_CREATE;

/******************************
 * TPM2B_SENSITIVE_DATA
 ******************************/
typedef struct
{
    uint16_t size;
    uint8_t  buffer[sizeof (TPMU_SENSITIVE_CREATE)];
} TPM2B_SENSITIVE_DATA;

/******************************
 * TPMS_SENSITIVE_CREATE
 ******************************/
typedef struct
{
    TPM2B_AUTH           userAuth; // assume TPM2B_AUTH defined elsewhere
    TPM2B_SENSITIVE_DATA data;
} TPMS_SENSITIVE_CREATE;

/******************************
 * TPM2B_SENSITIVE_CREATE
 ******************************/
typedef struct
{
    uint16_t              size;
    TPMS_SENSITIVE_CREATE sensitive;
} TPM2B_SENSITIVE_CREATE;

/******************************
 * TPMS_SCHEME_HASH
 ******************************/
typedef struct
{
    uint16_t hashAlg; // TPMI_ALG_HASH
} TPMS_SCHEME_HASH;

/******************************
 * TPMS_SCHEME_ECDAA
 ******************************/
typedef struct
{
    uint16_t hashAlg; // TPMI_ALG_HASH
    uint16_t count;
} TPMS_SCHEME_ECDAA;

/******************************
 * TPMI_ALG_KEYEDHASH_SCHEME
 ******************************/
typedef uint16_t TPMI_ALG_KEYEDHASH_SCHEME;
#define TPM_ALG_HMAC 0x0005
#define TPM_ALG_XOR  0x000A
#define TPM_ALG_NULL 0x0010

/******************************
 * TPMS_SCHEME_HMAC
 ******************************/
typedef TPMS_SCHEME_HASH TPMS_SCHEME_HMAC;

/******************************
 * TPMS_SCHEME_XOR
 ******************************/
typedef struct
{
    uint16_t hashAlg;
    uint16_t kdf; // TPMI_ALG_KDF
} TPMS_SCHEME_XOR;

/******************************
 * TPMU_SCHEME_KEYEDHASH
 ******************************/
typedef union
{
    TPMS_SCHEME_HMAC hmac;
    TPMS_SCHEME_XOR xor ;
    uint16_t null;
} TPMU_SCHEME_KEYEDHASH;

/******************************
 * TPMT_KEYEDHASH_SCHEME
 ******************************/
typedef struct
{
    TPMI_ALG_KEYEDHASH_SCHEME scheme;
    TPMU_SCHEME_KEYEDHASH     details;
} TPMT_KEYEDHASH_SCHEME;

/******************************
 * SIGNING SCHEMES
 ******************************/
/* RSA signing schemes only need a hash */
typedef TPMS_SCHEME_HASH TPMS_SIG_SCHEME_RSA;

/* ECC signing schemes */
typedef TPMS_SCHEME_HASH  TPMS_SIG_SCHEME_ECC;
typedef TPMS_SCHEME_ECDAA TPMS_SIG_SCHEME_ECC_ANON;

/* Union of all signature schemes */
typedef union
{
    TPMS_SIG_SCHEME_RSA      rsa;
    TPMS_SIG_SCHEME_ECC      ecc;
    TPMS_SIG_SCHEME_ECC_ANON eccAnon;
    TPMS_SCHEME_HMAC         hmac;
    TPMS_SCHEME_HASH         any;
    uint16_t                 null; // TPM_ALG_NULL
} TPMU_SIG_SCHEME;

/* TPMT_SIG_SCHEME structure */
typedef struct
{
    uint16_t        scheme; // TPMI_ALG_SIG_SCHEME
    TPMU_SIG_SCHEME details;
} TPMT_SIG_SCHEME;

/******************************
 * ENCRYPTION SCHEMES
 ******************************/
/* RSA encryption schemes */
typedef TPMS_SCHEME_HASH TPMS_ENC_SCHEME_RSA;
typedef struct
{
    uint16_t         scheme; // TPMI_ALG_RSA_DECRYPT
    TPMU_ASYM_SCHEME details;
} TPMT_RSA_DECRYPT;

/* ECC key exchange schemes */
typedef TPMS_SCHEME_HASH TPMS_KEY_SCHEME_ECC;

/******************************
 * KEY DERIVATION SCHEMES
 ******************************/
typedef TPMS_SCHEME_HASH TPMS_KDF_SCHEME_RSA;
typedef union
{
    TPMS_KDF_SCHEME_RSA rsa;
    TPMS_SCHEME_HASH    anyKdf;
    uint16_t            null; // TPM_ALG_NULL
} TPMU_KDF_SCHEME;

typedef struct
{
    uint16_t        scheme; // TPMI_ALG_KDF
    TPMU_KDF_SCHEME details;
} TPMT_KDF_SCHEME;

/******************************
 * TPMI_ALG_ASYM_SCHEME
 ******************************/
typedef uint16_t TPMI_ALG_ASYM_SCHEME;
#define TPM_ALG_RSA_AM 0x0010 // key exchange
#define TPM_ALG_RSA_AX 0x0011 // signing including anonymous
#define TPM_ALG_RSA_AE 0x0012 // encryption
#define TPM_ALG_NULL   0x001F

/******************************
 * TPMU_ASYM_SCHEME
 ******************************/
typedef union
{
    TPMS_KEY_SCHEME_ECC eccKeyExchange; // ECC key exchange
    TPMS_SIG_SCHEME_RSA rsaSig;         // RSA signing
    TPMS_SIG_SCHEME_ECC eccSig;         // ECC signing
    TPMS_SCHEME_HASH    anySig;
    uint16_t            null;
} TPMU_ASYM_SCHEME;

/******************************
 * TPMT_ASYM_SCHEME
 ******************************/
typedef struct
{
    TPMI_ALG_ASYM_SCHEME scheme;
    TPMU_ASYM_SCHEME     details;
} TPMT_ASYM_SCHEME;

/******************************
 * RSA SCHEMES
 ******************************/
typedef uint16_t TPMI_ALG_RSA_SCHEME;
#define TPM_ALG_RSA_AE_AX 0x0020
#define TPM_ALG_RSA_NULL  TPM_ALG_NULL

typedef struct
{
    TPMI_ALG_RSA_SCHEME scheme;
    TPMU_ASYM_SCHEME    details;
} TPMT_RSA_SCHEME;

typedef uint16_t TPMI_ALG_RSA_DECRYPT;
#define TPM_ALG_RSA_DECRYPT 0x0030

typedef struct
{
    TPMI_ALG_RSA_DECRYPT scheme;
    TPMU_ASYM_SCHEME     details;
} TPMT_RSA_DECRYPT;

/* RSA key buffers */
#define MAX_RSA_KEY_BYTES 256
typedef struct
{
    uint16_t size;
    uint8_t  buffer[MAX_RSA_KEY_BYTES];
} TPM2B_PUBLIC_KEY_RSA;

typedef struct
{
    uint16_t size;
    uint8_t  buffer[MAX_RSA_KEY_BYTES / 2]; // private key half-size
} TPM2B_PRIVATE_KEY_RSA;

typedef uint16_t TPMI_RSA_KEY_BITS;
#define RSA_KEY_SIZES_BITS 2048

/******************************
 * ECC SCHEMES
 ******************************/
#define MAX_ECC_KEY_BYTES 64
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
#define TPM_ALG_ECC_AX   0x0040 // ECC signing
#define TPM_ALG_ECC_AM   0x0041 // key exchange
#define TPM_ALG_ECC_NULL TPM_ALG_NULL

typedef uint16_t TPMI_ECC_CURVE;
#define TPM_ECC_NONE 0x0000

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
    TPMI_ALG_HASH        hash; // hash algorithm used to digest the message; TPM_ALG_NULL not allowed
    TPM2B_PUBLIC_KEY_RSA sig;  // signature is the size of a public key
} TPMS_SIGNATURE_RSA;

typedef struct
{
    TPMI_ALG_HASH       hash; // hash algorithm used in the signature process; TPM_ALG_NULL not allowed
    TPM2B_ECC_PARAMETER signatureR;
    TPM2B_ECC_PARAMETER signatureS;
} TPMS_SIGNATURE_ECC;

/* Union of all signature types */
typedef union
{
    TPMS_SIGNATURE_RSA rsa;
    TPMS_SIGNATURE_ECC ecc;
    TPMT_HA            hmac; // HMAC signature, required to be supported
    TPMS_SCHEME_HASH   any;  // access the hash
    uint16_t           null; // TPM_ALG_NULL
} TPMU_SIGNATURE;

/* Algorithm-agile signature structure */
typedef struct
{
    TPMI_ALG_SIG_SCHEME sigAlg;    // selector of the algorithm used to construct the signature
    TPMU_SIGNATURE      signature; // actual signature information
} TPMT_SIGNATURE;

/******************************
 * KEY / SECRET EXCHANGE
 ******************************/
/* Union of all possible encrypted secrets */
typedef union
{
    TPMS_ECC_POINT ecc;                              // ephemeral public point for ECDH
    uint8_t        rsa[MAX_RSA_KEY_BYTES];           // OAEP-encrypted block for RSA
    uint8_t        symmetric[sizeof (TPM2B_DIGEST)]; // symmetrically encrypted value (CFB or XOR)
    uint8_t        keyedHash[sizeof (TPM2B_DIGEST)]; // keyedHash-based encrypted secret
} TPMU_ENCRYPTED_SECRET;

/* Sized buffer for encrypted secret */
typedef struct
{
    uint16_t              size;   // size of the secret value
    TPMU_ENCRYPTED_SECRET secret; // secret
} TPM2B_ENCRYPTED_SECRET;

#endif // TPM_ALG_STRUCTURES_H
