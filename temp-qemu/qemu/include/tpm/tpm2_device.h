#ifndef QEMU_TPM2_DEVICE_H
#define QEMU_TPM2_DEVICE_H

#include "hw/sysbus.h"
#include <openssl/rsa.h>

/* Type name for QEMU object */
#define TYPE_TPM2 "tpm2"
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

OBJECT_DECLARE_SIMPLE_TYPE (TPM2State, TPM2)

struct TPM2State
{
    SysBusDevice parent_obj;

    MemoryRegion mmio;
    qemu_irq     irq;

    uint32_t ctrl;
    uint32_t status;
    uint32_t key_generated;
    RSA     *rsa_key;
    uint8_t  random_data[32];
};

#endif /* QEMU_TPM2_DEVICE_H */
