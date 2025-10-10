#ifndef TPM_STRUCTS_H
#define TPM_STRUCTS_H

#include <stdint.h>

/******************************
 * ALGORITHM DESCRIPTION
 ******************************/
typedef struct
{
    uint16_t alg;        // TPM_ALG_ID
    uint32_t attributes; // TPMA_ALGORITHM
} TPMS_ALGORITHM_DESCRIPTION;

/******************************
 * DIGESTS AND HASHES
 ******************************/
#define SHA1_DIGEST_SIZE   20
#define SHA256_DIGEST_SIZE 32
#define SHA384_DIGEST_SIZE 48
#define SHA512_DIGEST_SIZE 64
#define NULL_DIGEST_SIZE   0

typedef uint8_t  TPMI_YES_NO;   /* constrained to 0x00 (NO) or 0x01 (YES) */


typedef union
{
#ifdef TPM_ALG_SHA1
    uint8_t sha1[SHA1_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA256
    uint8_t sha256[SHA256_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA384
    uint8_t sha384[SHA384_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA512
    uint8_t sha512[SHA512_DIGEST_SIZE];
#endif
    uint8_t null[NULL_DIGEST_SIZE];
} TPMU_HA;

typedef uint16_t TPMI_ALG_HASH;
typedef struct
{
    TPMI_ALG_HASH hashAlg; // TPMI_ALG_HASH
    TPMU_HA  digest;
} TPMT_HA;



typedef struct TPMS_CLOCK_INFO {
    uint64_t     clock;
    uint32_t     resetCount;
    uint32_t     restartCount;
    TPMI_YES_NO  safe;      /* 0 or 1 */
    uint8_t      _pad[3];
} TPMS_CLOCK_INFO;


typedef struct TPMS_TIME_INFO {
    uint64_t        time;       /* implementation-defined time base (e.g., ms) */
    TPMS_CLOCK_INFO clockInfo;
} TPMS_TIME_INFO;


/******************************
 * SIZED BUFFERS
 ******************************/
typedef struct
{
    uint16_t size;
    uint8_t  buffer[SHA512_DIGEST_SIZE]; // max digest size
} TPM2B_DIGEST;

typedef struct
{
    uint16_t size;
    uint8_t  buffer[SHA512_DIGEST_SIZE]; // max size of object name
} TPM2B_DATA;

typedef TPM2B_DIGEST TPM2B_NONCE;
typedef TPM2B_DIGEST TPM2B_AUTH;
typedef TPM2B_DIGEST TPM2B_OPERAND;

typedef struct
{
    uint16_t size;
    uint8_t  buffer[1024]; // TPM2B_EVENT max size
} TPM2B_EVENT;

#define MAX_2B_BUFFER_SIZE 1024
typedef struct
{
    uint16_t size;
    uint8_t  buffer[MAX_2B_BUFFER_SIZE];
} TPM2B_MAX_BUFFER;

#define MAX_NV_BUFFER_SIZE 1024 // TPM-dependent
typedef struct
{
    uint16_t size;
    uint8_t  buffer[MAX_NV_BUFFER_SIZE];
} TPM2B_MAX_NV_BUFFER;

typedef struct
{
    uint16_t size;
    uint8_t  buffer[8]; // sizeof(UINT64)
} TPM2B_TIMEOUT;

#define MAX_SYM_BLOCK_SIZE 16 // example, TPM-dependent
typedef struct
{
    uint16_t size;
    uint8_t  buffer[MAX_SYM_BLOCK_SIZE];
} TPM2B_IV;

typedef struct
{
    uint16_t size;
    uint8_t  buffer[512]; // vendor property
} TPM2B_VENDOR_PROPERTY;

/******************************
 * NAMES
 ******************************/
typedef union
{
    TPMT_HA  digest; // when the Name is a digest
    uint32_t handle; // TPM_HANDLE when the Name is a handle
} TPMU_NAME;

typedef struct
{
    uint16_t size;
    uint8_t  name[]; // :sizeof(TPMU_NAME)
} TPM2B_NAME;

#define PCR_SELECT_MIN 3 // Example: min bytes for platform PCRs
#define PCR_SELECT_MAX 4 // Example: max bytes for implemented PCRs

typedef struct
{
    uint8_t sizeofSelect;              // number of bytes in pcrSelect
    uint8_t pcrSelect[PCR_SELECT_MAX]; // bit map of selected PCRs
} TPMS_PCR_SELECT;

typedef struct
{
    uint16_t hashAlg;                   // TPMI_ALG_HASH
    uint8_t  sizeofSelect;              // number of bytes in pcrSelect
    uint8_t  pcrSelect[PCR_SELECT_MAX]; // bit map of selected PCRs
} TPMS_PCR_SELECTION;

/******************************
 * TICKETS
 ******************************/
typedef struct
{
    uint16_t     tag;       // TPM_ST
    uint32_t     hierarchy; // TPMI_RH_HIERARCHY+
    TPM2B_DIGEST digest;    // HMAC over ticket data
} TPMT_TK_CREATION;

typedef struct
{
    uint16_t     tag;       // TPM_ST
    uint32_t     hierarchy; // TPMI_RH_HIERARCHY+
    TPM2B_DIGEST digest;    // HMAC over ticket data
} TPMT_TK_VERIFIED;

typedef struct
{
    uint16_t     tag;       // TPM_ST_AUTH_SIGNED or TPM_ST_AUTH_SECRET
    uint32_t     hierarchy; // TPMI_RH_HIERARCHY+
    TPM2B_DIGEST digest;    // HMAC over ticket data
} TPMT_TK_AUTH;

typedef struct
{
    uint16_t     tag;       // TPM_ST_HASHCHECK
    uint32_t     hierarchy; // TPMI_RH_HIERARCHY+
    TPM2B_DIGEST digest;    // HMAC over digest of data
} TPMT_TK_HASHCHECK;

/******************************
 * PROPERTY STRUCTURES
 ******************************/
typedef struct
{
    uint16_t alg;           // TPM_ALG_ID
    uint32_t algProperties; // TPMA_ALGORITHM
} TPMS_ALG_PROPERTY;

typedef struct
{
    uint32_t property; // TPM_PT
    uint32_t value;    // property value
} TPMS_TAGGED_PROPERTY;

typedef struct
{
    uint16_t tag;                       // TPM_PT_PCR
    uint8_t  sizeofSelect;              // size of pcrSelect array
    uint8_t  pcrSelect[PCR_SELECT_MAX]; // bit map of PCR
} TPMS_TAGGED_PCR_SELECT;

typedef struct
{
    uint32_t handle;     // TPM_HANDLE
    TPMT_HA  policyHash; // policy algorithm and hash
} TPMS_TAGGED_POLICY;

typedef struct
{
    uint32_t handle;     // TPM_HANDLE
    uint32_t timeout;    // current timeout of ACT
    uint32_t attributes; // TPMA_ACT
} TPMS_ACT_DATA;

/******************************
 * LISTS
 ******************************/
#define MAX_CAP_CC          64 // Example maximum command codes
#define MAX_ALG_LIST_SIZE   16 // Example maximum algorithm list
#define MAX_CAP_HANDLES     32 // Example maximum handles
#define HASH_COUNT          8  // Maximum number of banks/digests
#define MAX_CAP_ALGS        16
#define MAX_TPM_PROPERTIES  16
#define MAX_PCR_PROPERTIES  8
#define MAX_ECC_CURVES      16
#define MAX_TAGGED_POLICIES 16
#define MAX_ACT_DATA        8
#define MAX_VENDOR_PROPERTY 16

typedef struct
{
    uint32_t count;
    uint32_t commandCodes[MAX_CAP_CC]; // TPM_CC
} TPML_CC;

typedef struct
{
    uint32_t count;
    uint32_t commandAttributes[MAX_CAP_CC]; // TPMA_CC
} TPML_CCA;

typedef struct
{
    uint32_t count;
    uint16_t algorithms[MAX_ALG_LIST_SIZE]; // TPM_ALG_ID
} TPML_ALG;

typedef struct
{
    uint32_t count;
    uint32_t handle[MAX_CAP_HANDLES]; // TPM_HANDLE
} TPML_HANDLE;

typedef struct
{
    uint32_t     count; // minimum 2 for TPM2_PolicyOR()
    TPM2B_DIGEST digests[HASH_COUNT];
} TPML_DIGEST;

typedef struct
{
    uint32_t count;
    TPMT_HA  digests[HASH_COUNT];
} TPML_DIGEST_VALUES;

typedef struct
{
    uint32_t           count;
    TPMS_PCR_SELECTION pcrSelections[HASH_COUNT];
} TPML_PCR_SELECTION;

typedef struct
{
    uint32_t          count;
    TPMS_ALG_PROPERTY algProperties[MAX_CAP_ALGS];
} TPML_ALG_PROPERTY;

typedef struct
{
    uint32_t             count;
    TPMS_TAGGED_PROPERTY tpmProperty[MAX_TPM_PROPERTIES];
} TPML_TAGGED_TPM_PROPERTY;

typedef struct
{
    uint32_t               count;
    TPMS_TAGGED_PCR_SELECT pcrProperty[MAX_PCR_PROPERTIES];
} TPML_TAGGED_PCR_PROPERTY;

typedef struct
{
    uint32_t count;
    uint16_t eccCurves[MAX_ECC_CURVES]; // TPM_ECC_CURVE
} TPML_ECC_CURVE;

typedef struct
{
    uint32_t           count;
    TPMS_TAGGED_POLICY policies[MAX_TAGGED_POLICIES];
} TPML_TAGGED_POLICY;

typedef struct
{
    uint32_t      count;
    TPMS_ACT_DATA actData[MAX_ACT_DATA];
} TPML_ACT_DATA;

typedef struct
{
    uint32_t              count;
    TPM2B_VENDOR_PROPERTY vendorData[MAX_VENDOR_PROPERTY];
} TPML_VENDOR_PROPERTY;

/******************************
 * CAPABILITY STRUCTURES
 ******************************/
typedef union
{
    TPML_ALG_PROPERTY        algorithms;     // TPM_CAP_ALGS
    TPML_HANDLE              handles;        // TPM_CAP_HANDLES
    TPML_CCA                 command;        // TPM_CAP_COMMANDS
    TPML_CC                  ppCommands;     // TPM_CAP_PP_COMMANDS
    TPML_CC                  auditCommands;  // TPM_CAP_AUDIT_COMMANDS
    TPML_PCR_SELECTION       assignedPCR;    // TPM_CAP_PCRS
    TPML_TAGGED_TPM_PROPERTY tpmProperties;  // TPM_CAP_TPM_PROPERTIES
    TPML_TAGGED_PCR_PROPERTY pcrProperties;  // TPM_CAP_PCR_PROPERTIES
    TPML_ECC_CURVE           eccCurves;      // TPM_CAP_ECC_CURVES
    TPML_TAGGED_POLICY       authPolicies;   // TPM_CAP_AUTH_POLICIES
    TPML_ACT_DATA            actData;        // TPM_CAP_ACT
    TPML_VENDOR_PROPERTY     vendorProperty; // TPM_CAP_VENDOR_PROPERTY
} TPMU_CAPABILITIES;

typedef struct
{
    uint32_t          capability; // TPM_CAP
    TPMU_CAPABILITIES data;       // capability-specific data
} TPMS_CAPABILITY_DATA;

typedef struct
{
    uint32_t          setCapability; // TPM_CAP
    TPMU_CAPABILITIES data;          // data to set
} TPMS_SET_CAPABILITY_DATA;

typedef struct
{
    uint16_t                 size;
    TPMS_SET_CAPABILITY_DATA setCapabilityData;
} TPM2B_SET_CAPABILITY_DATA;

/******************************
 * TPM ATTESTATION STRUCTURES
 ******************************/
typedef struct
{
    TPMS_TIME_INFO time;
    uint64_t       firmwareVersion;
} TPMS_TIME_ATTEST_INFO;

typedef struct
{
    TPM2B_NAME name;
    TPM2B_NAME qualifiedName;
} TPMS_CERTIFY_INFO;

typedef struct
{
    TPML_PCR_SELECTION pcrSelect;
    TPM2B_DIGEST       pcrDigest;
} TPMS_QUOTE_INFO;

typedef struct
{
    uint64_t     auditCounter;
    uint16_t     digestAlg; // TPM_ALG_ID
    TPM2B_DIGEST auditDigest;
    TPM2B_DIGEST commandDigest;
} TPMS_COMMAND_AUDIT_INFO;

typedef struct
{
    uint8_t      exclusiveSession; // TPMI_YES_NO
    TPM2B_DIGEST sessionDigest;
} TPMS_SESSION_AUDIT_INFO;

typedef struct
{
    TPM2B_NAME   objectName;
    TPM2B_DIGEST creationHash;
} TPMS_CREATION_INFO;

typedef struct
{
    TPM2B_NAME          indexName;
    uint16_t            offset;
    TPM2B_MAX_NV_BUFFER nvContents;
} TPMS_NV_CERTIFY_INFO;

typedef struct
{
    TPM2B_NAME   indexName;
    TPM2B_DIGEST nvDigest;
} TPMS_NV_DIGEST_CERTIFY_INFO;

typedef union
{
    TPMS_CERTIFY_INFO           certify;      // TPM_ST_ATTEST_CERTIFY
    TPMS_CREATION_INFO          creation;     // TPM_ST_ATTEST_CREATION
    TPMS_QUOTE_INFO             quote;        // TPM_ST_ATTEST_QUOTE
    TPMS_COMMAND_AUDIT_INFO     commandAudit; // TPM_ST_ATTEST_COMMAND_AUDIT
    TPMS_SESSION_AUDIT_INFO     sessionAudit; // TPM_ST_ATTEST_SESSION_AUDIT
    TPMS_TIME_ATTEST_INFO       time;         // TPM_ST_ATTEST_TIME
    TPMS_NV_CERTIFY_INFO        nv;           // TPM_ST_ATTEST_NV
    TPMS_NV_DIGEST_CERTIFY_INFO nvDigest;     // TPM_ST_ATTEST_NV_DIGEST
} TPMU_ATTEST;

typedef struct
{
    uint32_t        magic; // TPM_GENERATED_VALUE
    uint16_t        type;  // TPMI_ST_ATTEST
    TPM2B_NAME      qualifiedSigner;
    TPM2B_DATA      extraData;
    TPMS_CLOCK_INFO clockInfo;
    uint64_t        firmwareVersion;
    TPMU_ATTEST     attested;
} TPMS_ATTEST;

typedef struct
{
    uint16_t size;
    uint8_t  attestationData[sizeof (TPMS_ATTEST)];
} TPM2B_ATTEST;

/******************************
 * AUTHORIZATION STRUCTURES
 ******************************/
typedef struct
{
    uint32_t    sessionHandle; // TPMI_SH_AUTH_SESSION+
    TPM2B_NONCE nonce;
    uint8_t     sessionAttributes; // TPMA_SESSION
    TPM2B_AUTH  hmac;
} TPMS_AUTH_COMMAND;

typedef struct
{
    TPM2B_NONCE nonce;
    uint8_t     sessionAttributes; // TPMA_SESSION
    TPM2B_AUTH  hmac;
} TPMS_AUTH_RESPONSE;

#endif // TPM_STRUCTS_H
