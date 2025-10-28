#ifndef QEMU_TPM2_DEVICE_H
#define QEMU_TPM2_DEVICE_H

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include <openssl/rsa.h>
//#include "tpm2_nv.h"
#include "tpm2_nv_entry.h"
#include <glib.h>
#include "tpm2_keyobj.h"

/* Type name for QEMU object */
#define TYPE_TPM2 "tpm2"
#define TPM2_SEED_SIZE 32 //Seed size for eps,pps,sps

// #define TPM2(obj) OBJECT_CHECK(TPM2State, (obj), TYPE_TPM2)

/* MMIO Offsets */
#define TPM2_CTRL_REG   0x00
#define TPM2_STATUS_REG 0x04
#define TPM2_RANDOM_REG 0x08
#define TPM2_CMD_REG    0x0C
#define TPM2_DATA_REG   0x10

/* Command IDs */
#define TPM2_CMD_GEN_RANDOM 0x01
#define TPM2_CMD_GEN_RSA    0x02
#define TPM2_CMD_CLEAR      0x03

#define TPM2_NVSTORAGE_SIZE 6962 // This is the size of the NV storage in a real TPM 2.0


enum tpm_state {
    TPM_STATE_IDLE,
    TPM_STATE_READY,
    TPM_STATE_RECEIVING,
    TPM_STATE_PROCESSING,
    TPM_STATE_SENDING
};

enum tpm_operational_mode {
    TPM_MODE_NORMAL,
    TPM_MODE_FAILURE,
    TPM_MODE_FIELD,
    TPM_MODE_NOINIT
};

OBJECT_DECLARE_SIMPLE_TYPE (TPM2State, TPM2)

struct TPM2State
{
    SysBusDevice parent_obj;



    MemoryRegion mmio;
    qemu_irq     irq;

    //NV Storage Memory region

    MemoryRegion nv_bank_mem;
    uint8_t     *nv_bank_ptr;
    uint32_t     nv_bank_size;
    uint32_t     nv_alloc_offset;   // <- add this


    /* In-RAM index of entries (not serialized as-is; we pack to nv_bank_ptr) */
    GHashTable  *nv_map;     // key: GUINT_TO_POINTER(nvIndex) -> NvEntry*
    uint32_t     nv_count;
    bool         nv_dirty;   // “needs flush to bank” flag

    //ENd NV Storage Memory region

    uint32_t ctrl;
    uint32_t status;
    uint32_t key_generated;
    RSA     *rsa_key;
    uint8_t  random_data[32];

    uint8_t command_buffer[1024];
    uint8_t response_buffer[1024];
    uint32_t cmd_size;
    uint32_t resp_size;
    uint32_t resp_idx;
    enum tpm_state state;
    enum tpm_operational_mode tpm_mode;
    //Primay handle sensitive data
    uint8_t pps[32], sps[32], eps[32]; //Seeds
    uint8_t phProof[32], shProof[32], ehProof[32]; //Storage root proofs

    TPM2B_SENSITIVE primary_sensitive;  // last created sensitive area
    TPM2B_PUBLIC    primary_public;     // last created public area
    TPM2B_NAME      primary_name;       // last created Name

    uint32_t next_transient_handle;
    bool initialized;

};

#endif /* QEMU_TPM2_DEVICE_H */
