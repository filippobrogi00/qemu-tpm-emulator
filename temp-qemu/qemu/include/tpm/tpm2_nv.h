#ifndef TPM_NV_STRUCTURES_H
#define TPM_NV_STRUCTURES_H

#include <stdint.h>
#include "tpm2_structures.h"
#include "tpm2_interfaces.h"
#include "tpm2_device.h"
#include "qemu/log.h"

#define TPM2_LOG(fmt, ...) qemu_log("%s: " fmt, __func__, ##__VA_ARGS__)


struct NVEntry;                 // This is defined later on
typedef struct TPM2State TPM2State;  /* forward declaration */

/******************************
 * TPM_NV_INDEX
 ******************************/
typedef uint32_t TPM_NV_INDEX;

/******************************
 * TPM_NT
 ******************************/
#define TPM_NT_ORDINARY 0x0
#define TPM_NT_COUNTER  0x1
#define TPM_NT_BITS     0x2
#define TPM_NT_EXTEND   0x4
#define TPM_NT_PIN_FAIL 0x8
#define TPM_NT_PIN_PASS 0x9

/******************************
 * TPMS_NV_PIN_COUNTER_PARAMETERS
 ******************************/
typedef struct
{
    uint32_t pinCount;
    uint32_t pinLimit;
} TPMS_NV_PIN_COUNTER_PARAMETERS;

/******************************
 * TPMA_NV
 ******************************/
typedef struct
{
    uint32_t ppWrite : 1;
    uint32_t ownerWrite : 1;
    uint32_t authWrite : 1;
    uint32_t policyWrite : 1;
    uint32_t reserved1 : 3;
    uint32_t nvType : 4; // TPM_NT
    uint32_t policyDelete : 1;
    uint32_t writeLocked : 1;
    uint32_t writeAll : 1;
    uint32_t writeDefine : 1;
    uint32_t writeStClear : 1;
    uint32_t globalLock : 1;
    uint32_t ppRead : 1;
    uint32_t ownerRead : 1;
    uint32_t authRead : 1;
    uint32_t policyRead : 1;
    uint32_t reserved2 : 5;
    uint32_t noDA : 1;
    uint32_t orderly : 1;
    uint32_t clearStClear : 1;
    uint32_t readLocked : 1;
    uint32_t written : 1;
    uint32_t platformCreate : 1;
    uint32_t readStClear : 1;
} TPMA_NV;

/******************************
 * TPMA_NV_EXP
 ******************************/
typedef struct
{
    uint64_t low; // lower 32 bits as TPMA_NV
    uint64_t externalEncryption : 1;
    uint64_t externalIntegrity : 1;
    uint64_t externalAntiRollback : 1;
    uint64_t reserved : 28;
} TPMA_NV_EXP;

/******************************
 * TPMS_NV_PUBLIC
 ******************************/
typedef struct
{
    TPM_NV_INDEX nvIndex;
    uint16_t     nameAlg;
    TPMA_NV      attributes;
    uint8_t      authPolicy[64]; // TPM2B_DIGEST, implementation-defined size
    uint16_t     dataSize;
} TPMS_NV_PUBLIC;

/******************************
 * TPM2B_NV_PUBLIC
 ******************************/
typedef struct
{
    uint16_t       size;
    TPMS_NV_PUBLIC nvPublic;
} TPM2B_NV_PUBLIC;

/******************************
 * TPMS_NV_PUBLIC_EXP_ATTR
 ******************************/
typedef struct
{
    TPM_NV_INDEX nvIndex;
    uint16_t     nameAlg;
    TPMA_NV_EXP  attributes;
    uint8_t      authPolicy[64]; // TPM2B_DIGEST
    uint16_t     dataSize;
} TPMS_NV_PUBLIC_EXP_ATTR;

/******************************
 * TPMU_NV_PUBLIC_2
 ******************************/
typedef union
{
    TPMS_NV_PUBLIC          nvIndex;     // TPM_HT_NV_INDEX
    TPMS_NV_PUBLIC_EXP_ATTR externalNV;  // TPM_HT_EXTERNAL_NV
    TPMS_NV_PUBLIC          permanentNV; // TPM_HT_PERMANENT_NV
} TPMU_NV_PUBLIC_2;

/******************************
 * TPMT_NV_PUBLIC_2
 ******************************/
typedef struct
{
    uint8_t          handleType;
    TPMU_NV_PUBLIC_2 publicArea;
} TPMT_NV_PUBLIC_2;

/******************************
 * TPM2B_NV_PUBLIC_2
 ******************************/
typedef struct
{
    uint16_t         size;
    TPMT_NV_PUBLIC_2 nvPublic;
} TPM2B_NV_PUBLIC_2;

TPM_RC tpm2_nv_define_space(TPM2State *s,
    TPMI_RH_PROVISION authHandle,
    const TPM2B_AUTH *auth,         /* new index auth */
    const TPM2B_NV_PUBLIC *public);

void tpm2_nv_init(TPM2State *s);
void tpm2_nv_cleanup(TPM2State *s);

TPM_RC nv_write_crypt_to_bank(TPM2State *s,
                              struct NVEntry *e,
                              const uint8_t *plain,
                              uint16_t len,
                              uint16_t offset);

TPM_RC nv_read_decrypt_from_bank(TPM2State *s,
                                 struct NVEntry *e,
                                 uint8_t *out,
                                 uint16_t len,
                                 uint16_t offset);


#endif // TPM_NV_STRUCTURES_H
