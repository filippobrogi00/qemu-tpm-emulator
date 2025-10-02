#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "migration/vmstate.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "tpm/tpm2_device.h"
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define TPM2_LOG(fmt, ...) qemu_log("%s: " fmt, __func__, ## __VA_ARGS__)


static void tpm2_generate_random(TPM2State *s) {
    RAND_bytes(s->random_data, sizeof(s->random_data));
}




static void tpm2_generate_rsa_key(TPM2State *s) {
    if (s->rsa_key) {
        RSA_free(s->rsa_key);
    }
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    s->rsa_key = RSA_new();
    RSA_generate_key_ex(s->rsa_key, 2048, bn, NULL);
    BN_free(bn);
    s->key_generated = 1;
}

static uint64_t tpm2_mmio_read(void *opaque, hwaddr addr, unsigned size) {
    TPM2State *s = opaque;
    switch (addr) {
        case TPM2_CTRL_REG:
            return s->ctrl;
        case TPM2_STATUS_REG:
            return s->status;
        case TPM2_RANDOM_REG:
            return *(uint32_t *)(s->random_data);
        case TPM2_DATA_REG:
            return s->key_generated;
        default:
            TPM2_LOG("Invalid read address: 0x%" HWADDR_PRIx "\n", addr);
            return 0;
    }
}

static void tpm2_mmio_write(void *opaque, hwaddr addr, uint64_t value, unsigned size) {
    TPM2State *s = opaque;
    switch (addr) {
        case TPM2_CTRL_REG:
            s->ctrl = value;
            break;
        case TPM2_CMD_REG:
            switch (value) {
                case TPM2_CMD_GEN_RANDOM:
                    tpm2_generate_random(s);
                    s->status = 0;
                    break;
                case TPM2_CMD_GEN_RSA:
                    tpm2_generate_rsa_key(s);
                    s->status = 0;
                    break;
                case TPM2_CMD_CLEAR:
                    if (s->rsa_key) {
                        RSA_free(s->rsa_key);
                        s->rsa_key = NULL;
                    }
                    memset(s->random_data, 0, sizeof(s->random_data));
                    s->key_generated = 0;
                    s->status = 0;
                    break;
                default:
                    s->status = 1;
                    break;
            }
            break;
        default:
            TPM2_LOG("Invalid write address: 0x%" HWADDR_PRIx "\n", addr);
            break;
    }
}

static const MemoryRegionOps tpm2_mmio_ops = {
    .read = tpm2_mmio_read,
    .write = tpm2_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
};

static void tpm2_reset(DeviceState *dev) {
    TPM2State *s = TPM2(dev);
    s->ctrl = 0;
    s->status = 0;
    s->key_generated = 0;
    if (s->rsa_key) {
        RSA_free(s->rsa_key);
        s->rsa_key = NULL;
    }
    memset(s->random_data, 0, sizeof(s->random_data));
}

static const VMStateDescription vmstate_tpm2 = {
    .name = TYPE_TPM2,
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(ctrl, TPM2State),
        VMSTATE_UINT32(status, TPM2State),
        VMSTATE_UINT32(key_generated, TPM2State),
        VMSTATE_END_OF_LIST()
    }
};

static void tpm2_init(Object *obj) {
    TPM2State *s = TPM2(obj);
    sysbus_init_irq(SYS_BUS_DEVICE(obj), &s->irq);
    memory_region_init_io(&s->mmio, obj, &tpm2_mmio_ops, s, TYPE_TPM2, 0x20);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->mmio);

    Error *err = NULL;
    //Non-volatile storage initialization

      /* --- NV bank: private RAM --- */
    memory_region_init_ram(&s->nv_bank_mem, OBJECT(s), "tpm2.nvbank",
                           TPM2_NVSTORAGE_SIZE, &err);
    if (err) { error_propagate(errp, err); return; }

    s->nv_bank_ptr  = memory_region_get_ram_ptr(&s->nv_bank_mem);
    s->nv_bank_size = TPM2_NVSTORAGE_SIZE;
    memset(s->nv_bank_ptr, 0, s->nv_bank_size); //Todo: Check if this is a secure functio. I don't think so.
    TPM2_LOG("[DEBUG]NV bank initialized: %u bytes at %p\n", s->nv_bank_size, s->nv_bank_ptr);
    /* In-RAM map: owns NvEntry*; frees them on destroy */
    s->nv_map   = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                        NULL, (GDestroyNotify)g_free /* or nventry_free */);
    s->nv_count = 0;
    s->nv_dirty = false;
    TPM2_LOG("[DEBUG]NV map initialized\n");




}

static void tpm2_class_init(ObjectClass *klass, void *data) {
    DeviceClass *dc = DEVICE_CLASS(klass);
    device_class_set_legacy_reset(dc, tpm2_reset);
    dc->vmsd = &vmstate_tpm2;
    dc->desc = "TPM 2.0 custom device";  // <-- This must be set!
}

static const TypeInfo tpm2_info = {
    .name          = TYPE_TPM2,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(TPM2State),
    .instance_init = tpm2_init,
    .class_init    = tpm2_class_init,
};

static void tpm2_register_types(void) {
    fprintf(stderr, "[DEBUG] tpm2_register_types called\n");
    //sysbus_register_type(&tpm2_info);
    type_register_static(&tpm2_info);
}

type_init(tpm2_register_types)
