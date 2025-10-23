#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "migration/vmstate.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "tpm/tpm2_device.h"
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "tpm/tpm2_nv.h"
#include "tpm/tpm2_structures.h"
#include "tpm/tpm2_handles.h"
#include "tpm/tpm2_crypto.h"

#define TPM2_LOG(fmt, ...) qemu_log("%s: " fmt, __func__, ## __VA_ARGS__)


static void tpm2_generate_random(TPM2State *s) {
    RAND_bytes(s->random_data, sizeof(s->random_data));
}


static inline TPMI_RH_PROVISION tpm2_provision_owner(void) {
    return (TPMI_RH_PROVISION){TPM_RH_OWNER, TPM_RH_OWNER, TPM_RH_PLATFORM};
}

static void tpm2_test_definespace(TPM2State *s)
{
    TPM2B_AUTH auth = { .size = 4, .buffer = {'1','2','3','4'} };

    TPMS_NV_PUBLIC pub = {
        .nvIndex   = 0x1500016,
        .nameAlg   = 0x000B, /* TPM_ALG_SHA256 */
        .attributes = {
            .ownerRead   = 1,
            .ownerWrite  = 1,
            .authRead    = 1,
            .authWrite   = 1,
            .noDA        = 1,
            .nvType      = TPM_NT_ORDINARY
        },
        .dataSize   = 32
    };

    memset(pub.authPolicy, 0, sizeof(pub.authPolicy));

    TPM2B_NV_PUBLIC publicInfo = {
        .size = sizeof(pub),
        .nvPublic = pub
    };

    TPMI_RH_PROVISION authHandle = tpm2_provision_owner();

    TPM2_LOG("[INIT] Testing NV DefineSpace...\n");

    TPM_RC rc = tpm2_nv_define_space(
        s,
        authHandle,
        &auth,
        &publicInfo
    );

    if (rc == TPM_RC_SUCCESS) {
        TPM2_LOG("[INIT] NV DefineSpace success (count=%u)\n", s->nv_count);
    } else {
        TPM2_LOG("[INIT] NV DefineSpace failed! RC=0x%X\n", rc);
    }

    /* Optional: print existing NV entries */
    if (s->nv_map && s->nv_count > 0) {
        GHashTableIter it;
        gpointer k, v;
        g_hash_table_iter_init(&it, s->nv_map);
        while (g_hash_table_iter_next(&it, &k, &v)) {
            NVEntry *e = v;
            TPM2_LOG("[INIT] NV Index=0x%X DataSize=%u NameAlg=0x%X\n",
                     (uint32_t)GPOINTER_TO_UINT(k),
                     e->pub.dataSize,
                     e->pub.nameAlg);
        }
    }
}







TPM_RC tpm2_test_CreatePrimary(TPM2State *s)
{
    TPM2_LOG("---- [TPM TEST] CreatePrimary start ----\n");

    /* 1. Initialize seeds and proofs */
    for (int i = 0; i < 32; i++) {
        s->sps[i]     = 0x10 + i;
        s->shProof[i] = 0x20 + i;
        s->pps[i]     = 0x30 + i;
        s->phProof[i] = 0x40 + i;
        s->eps[i]     = 0x50 + i;
        s->ehProof[i] = 0x60 + i;
    }
    s->next_transient_handle = 1;
    s->initialized = true;

    /* 2. Prepare inSensitive */
    TPM2B_SENSITIVE_CREATE inSensitive;
    memset(&inSensitive, 0, sizeof(inSensitive));
    inSensitive.size = sizeof(inSensitive.sensitive);
    inSensitive.sensitive.userAuth.size = 6;
    memcpy(inSensitive.sensitive.userAuth.buffer, "passwd", 6);

    /* 3. Prepare inPublic (ECC P-256) */
    TPM2B_PUBLIC inPublic;
    memset(&inPublic, 0, sizeof(inPublic));
    inPublic.size = sizeof(inPublic.publicArea);
    inPublic.publicArea.type     = TPM_ALG_ECC;
    inPublic.publicArea.nameAlg  = TPM_ALG_SHA256;
    inPublic.publicArea.objectAttributes =
        0x00030072; // userWithAuth | sign | fixedTPM | fixedParent
    inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;

    /* 4. Output placeholders */
    TPM2B_PUBLIC outPublic;
    TPM2B_NAME name;
    memset(&outPublic, 0, sizeof(outPublic));
    memset(&name, 0, sizeof(name));
    TPM2_LOG("---- [TPM TEST] CreatePrimary start 2----\n");
    /* 5. Invoke CreatePrimary (objectHandle = NULL) */
    TPM_RC rc = tpm2_CreatePrimary(s,
                                   TPM_RH_OWNER,
                                   &inSensitive,
                                   &inPublic,
                                   NULL,   /* outsideInfo */
                                   NULL,   /* creationPCR */
                                   NULL,   /* objectHandle unused */
                                   &outPublic,
                                   &name);

    /* 6. Evaluate result */
    TPM2_LOG("tpm2_CreatePrimary() returned 0x%X\n", rc);
    if (rc != TPM_RC_SUCCESS) {
        TPM2_LOG("FAILED: rc=0x%X\n", rc);
        return rc;
    }

    TPM2_LOG("Primary key created successfully.\n");

    /* 7. Log key details */
    TPM2_LOG("Private key (d): ");
    for (int i = 0; i < s->primary_sensitive.sensitiveArea.sensitive.ecc.size; i++)
        qemu_log("%02X", s->primary_sensitive.sensitiveArea.sensitive.ecc.buffer[i]);
    qemu_log("\n");

    TPM2_LOG("Public X: ");
    for (int i = 0; i < outPublic.publicArea.unique.ecc.x.size; i++)
        qemu_log("%02X", outPublic.publicArea.unique.ecc.x.buffer[i]);
    qemu_log("\n");

    TPM2_LOG("Public Y: ");
    for (int i = 0; i < outPublic.publicArea.unique.ecc.y.size; i++)
        qemu_log("%02X", outPublic.publicArea.unique.ecc.y.buffer[i]);
    qemu_log("\n");

    TPM2_LOG("Name: ");
    for (int i = 0; i < name.size; i++)
        qemu_log("%02X", name.name[i]);
    qemu_log("\n");

    TPM2_LOG("---- [TPM TEST] CreatePrimary done ----\n\n");

    return TPM_RC_SUCCESS;
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


static void tpm2_realize(DeviceState *dev, Error **errp)
{
    TPM2State *s = TPM2(dev);
    Error *err = NULL;



    //Here it returns error: Cannot get MMIO region.
    
    /* IRQ + MMIO window (guest-visible) */
    sysbus_init_irq(SYS_BUS_DEVICE(dev), &s->irq);
    memory_region_init_io(&s->mmio, OBJECT(dev), &tpm2_mmio_ops, s, TYPE_TPM2, 0x20);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->mmio);

    /* --- NV bank: private RAM (internal, not mapped to system bus) --- */
    memory_region_init_ram(&s->nv_bank_mem, OBJECT(dev), "tpm2.nvbank",
                           TPM2_NVSTORAGE_SIZE, &err);
    if (err) { error_propagate(errp, err); return; }

    s->nv_bank_ptr  = memory_region_get_ram_ptr(&s->nv_bank_mem);
    s->nv_bank_size = TPM2_NVSTORAGE_SIZE;

    /* Zeroing a fresh buffer is fine with memset (secure wipe is a different topic) */
    memset(s->nv_bank_ptr, 0, s->nv_bank_size);
    TPM2_LOG("[DEBUG]NV bank initialized: %u bytes at %p\n", s->nv_bank_size, s->nv_bank_ptr);

    tpm2_nv_init(s);
    s->nv_alloc_offset = 0;


    TPM2_LOG("[DEBUG]NV map initialized, running definespace_test\n");
    tpm2_test_definespace(s);
    TPM2_LOG("[DEBUG]Running CreatePrimary\n");
    tpm2_test_CreatePrimary(s);

}







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
        //VMSTATE_MEMORY_REGION(nv_bank_mem, TPM2State),  //We need also to maintain non-volatile storage
        VMSTATE_END_OF_LIST()
    }
};

static void tpm2_init(Object *obj) {
    TPM2State *s = TPM2(obj);
    /*
    sysbus_init_irq(SYS_BUS_DEVICE(obj), &s->irq);
    memory_region_init_io(&s->mmio, obj, &tpm2_mmio_ops, s, TYPE_TPM2, 0x20);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->mmio);
    */
       // tpm2_nv_init(s);

    //tpm2_test_definespace(s);
}

static void tpm2_class_init(ObjectClass *klass, void *data) {
    DeviceClass *dc = DEVICE_CLASS(klass);
    device_class_set_legacy_reset(dc, tpm2_reset);
    dc->vmsd = &vmstate_tpm2;
    dc->desc = "TPM 2.0 custom device";  // <-- This must be set!
    dc->realize = tpm2_realize;
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
