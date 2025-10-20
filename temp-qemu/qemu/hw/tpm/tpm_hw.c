#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "migration/vmstate.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "tpm/tpm2_device.h"
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "command_chain/cc_header.h"
#include "tpm/tpm2_rc.h"
#include "tpm/tpm2_cc.h"

#include "tpm/tpm2_nv.h"

#define TPM2_LOG(fmt, ...) qemu_log("%s: " fmt, __func__, ## __VA_ARGS__)

static void tpm2_reset(DeviceState *dev);
static void tpm2_process_command(TPM2State *s);

static void tpm2_generate_random(TPM2State *s) {
    RAND_bytes(s->random_data, sizeof(s->random_data));
}

static uint32_t Unmarshal_UINT16_BE(const uint8_t *buffer, uint16_t *value)
{
    *value = ((uint16_t)buffer[0] << 8) | (uint16_t)buffer[1];
    return 2;
}

static uint32_t Unmarshal_UINT32_BE(const uint8_t *buffer, uint32_t *value)
{
    *value = ((uint32_t)buffer[0] << 24) |
             ((uint32_t)buffer[1] << 16) |
             ((uint32_t)buffer[2] << 8)  |
             (uint32_t)buffer[3];
    return 4;
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
    uint32_t val = 0;
    switch (addr) {
        case TPM2_CTRL_REG:
            return s->ctrl;
        case TPM2_STATUS_REG:
            return s->state;
        case TPM2_RANDOM_REG:
            //This register is no longer used for simple commands
            //return *(uint32_t *)(s->random_data);
        case TPM2_DATA_REG:
            //return s->key_generated;
            //Read from the response buffer (FIFO)
            if (s->state != TPM_STATE_SENDING) {
                TPM2_LOG("Read from DATA_REG in invalid state %d\n", s->state);
                return 0;
            }
            if (s->resp_idx >= s->resp_size) {
                TPM2_LOG("Response buffer underflow\n");
                return 0;
            }
            //Read 4 bytes at a time
            //val = *(uint32_t *)(s->response_buffer + s->resp_idx);
            val = ((uint32_t)s->response_buffer[s->resp_idx + 0] << 24) |
                  ((uint32_t)s->response_buffer[s->resp_idx + 1] << 16) |
                  ((uint32_t)s->response_buffer[s->resp_idx + 2] << 8)  |
                  ((uint32_t)s->response_buffer[s->resp_idx + 3]);
            s->resp_idx += 4;
            //If all data sent return to idle
            if (s->resp_idx >= s->resp_size) {
                s->state = TPM_STATE_IDLE;
                s->resp_idx = 0;
                s->resp_size = 0;
            }
            return val;
        default:
            TPM2_LOG("Invalid read address: 0x%" HWADDR_PRIx "\n", addr);
            return 0;
    }
}

static void tpm2_mmio_write(void *opaque, hwaddr addr, uint64_t value, unsigned size) {
    TPM2State *s = opaque;
    uint32_t val32 = (uint32_t)value; // We only handle 32-bit writes
    
    switch (addr) {
        case TPM2_CTRL_REG:
            if (value == 1) {
                s->state = TPM_STATE_RECEIVING;
                s->cmd_size = 0;    // Reset command buffer index
                s->resp_size = 0;
                s->resp_idx = 0;
                TPM2_LOG("State -> RECEIVING\n");
            } else if (value == 0) {
                tpm2_reset(DEVICE(s));
            }
            //s->ctrl = value;
            break;
        case TPM2_CMD_REG:
            if (value == 1) {
                if (s->state != TPM_STATE_RECEIVING) {
                    TPM2_LOG("Execute command in invalid state %d\n", s->state);
                    s->state = TPM_STATE_IDLE;
                    return;
                }

                s->state = TPM_STATE_PROCESSING;
                TPM2_LOG("State -> PROCESSING (Cmd size: %u)\n", s->cmd_size);

                tpm2_process_command(s);

                if (s->state == TPM_STATE_PROCESSING) {
                    TPM2_LOG("State -> SENDING (Resp size. %u)\n", s->resp_size);
                }
            }
            break;

            // switch (value) {
            //     case TPM2_CMD_GEN_RANDOM:
            //         tpm2_generate_random(s);
            //         s->status = 0;
            //         break;
            //     case TPM2_CMD_GEN_RSA:
            //         tpm2_generate_rsa_key(s);
            //         s->status = 0;
            //         break;
            //     case TPM2_CMD_CLEAR:
            //         if (s->rsa_key) {
            //             RSA_free(s->rsa_key);
            //             s->rsa_key = NULL;
            //         }
            //         memset(s->random_data, 0, sizeof(s->random_data));
            //         s->key_generated = 0;
            //         s->status = 0;
            //         break;
            //     default:
            //         s->status = 1;
            //         break;
            // }
            // break;
        
        case TPM2_DATA_REG:
            if (s->state != TPM_STATE_RECEIVING) {
                TPM2_LOG("Write to DATA_REG in invalid state %d\n", s->state);
                return;
            }
            if ((s->cmd_size + 4) > sizeof(s->command_buffer)) {
                TPM2_LOG("Command buffer overflow\n");
                s->state = TPM_STATE_IDLE;
                return;
            }

            //*(uint32_t *)(s->command_buffer + s->cmd_size) = (uint32_t)value;
            s->command_buffer[s->cmd_size + 0] = (val32 >> 24) & 0xFF;
            s->command_buffer[s->cmd_size + 1] = (val32 >> 16) & 0xFF;
            s->command_buffer[s->cmd_size + 2] = (val32 >> 8)  & 0xFF;
            s->command_buffer[s->cmd_size + 3] = (val32)       & 0xFF;
            s->cmd_size += 4;
            break;

        default:
            TPM2_LOG("Invalid write address: 0x%" HWADDR_PRIx "\n", addr);
            break;
    }
}

static void build_error_response(TPM2State *s, TPM_RC rc) {
    TPM_RSP_HEADER header;
    header.tag = TPM_ST_NO_SESSIONS;
    header.size = TPM_RSP_HEADER_SIZE;
    header.code = rc;

    UINT32 bytesWritten;
    MarshalResponseHeader(s->response_buffer, sizeof(s->response_buffer), &header, &bytesWritten);

    s->resp_size = header.size;
    s->resp_idx = 0;
    s->state = TPM_STATE_SENDING; //Ready to send the error

}

static void tpm2_process_command(TPM2State *s) {
    TPM_CMD_HEADER header;
    UINT32 rc;

    rc = TPM2_ValidateCommandHeader(s->command_buffer, s->cmd_size, &header);

    if (rc != TPM_RC_SUCCESS) {
        TPM2_LOG("TPM2_ValidateCommandHeader failed: 0x%X\n", rc);
        build_error_response(s, rc);
        return;
    }

    // TPM_RC rc = UnmarshalCommandHeader(s->command_buffer, s->cmd_size, &header, &bytesRead);
    // if (rc != TPM_RC_SUCCESS) {
    //     TPM2_LOG("Invalid command header: 0x%X\n", rc);
    //     build_error_response(s, rc);
    //     return;
    // }
    // if (header.size != s->cmd_size) {
    //     TPM2_LOG("Command size mismatch. Header: %u, Received %u\n", header.size, s->cmd_size);
    //     build_error_response(s, TPM_RC_COMMAND_SIZE);
    //     return;
    // }

    switch (header.code) {
        case TPM_CC_GetRandom:
        {
            TPM2_LOG("Handling TPM_CC_GetRandom\n");
            tpm2_generate_random(s);

            TPM_RSP_HEADER rsp_header;
            rsp_header.tag = TPM_ST_NO_SESSIONS;
            rsp_header.code = TPM_RC_SUCCESS;
            rsp_header.size = 10 + 2 + sizeof(s->random_data); //header + size + random data

            UINT32 offset = 0;
            MarshalResponseHeader(s->response_buffer, sizeof(s->response_buffer), &rsp_header, &offset);

            s->response_buffer[offset++] = (sizeof(s->random_data) >> 8) & 0xFF;
            s->response_buffer[offset++] = sizeof(s->random_data) & 0xFF;

            memcpy(s->response_buffer + offset, s->random_data, sizeof(s->random_data));
            offset += sizeof(s->random_data);

            s->resp_size = offset;
            s->resp_idx = 0;
            s->state = TPM_STATE_SENDING;
            break;
        }

        case TPM_CC_CreatePrimary:
        {
            TPM2_LOG("Handling TPM_CC_CreatePrimary\n");
            // TODO: Unmarshal parameters from s->command_buffer
            // (e.g., inPublic, inSensitive)

            // 1. Execute your existing RSA key generation function
            tpm2_generate_rsa_key(s);
            if (!s->key_generated) {
                build_error_response(s, TPM_RC_FAILURE);
                break;
            }

            // 2. Build the response (this is complex)
            // For now, let's just send a success code
            TPM2_LOG("RSA key generated.\n");

            // --- Build a simple "Success" response ---
            TPM_RSP_HEADER rsp_header;
            rsp_header.tag = TPM_ST_NO_SESSIONS;
            rsp_header.code = TPM_RC_SUCCESS;
            
            // This is a placeholder. A real response is huge.
            // We'll just send a 10-byte success header for now.
            rsp_header.size = 10; 

            UINT32 offset = 0;
            MarshalResponseHeader(s->response_buffer, sizeof(s->response_buffer), &rsp_header, &offset);
            
            // TODO: Marshal the real response body:
            // - Marshal handle
            // - Marshal outPublic
            // - Marshal creationData
            // - Marshal creationHash
            // - Marshal creationTicket
            // - Marshal outPrivate
            // And update rsp_header.size *before* marshaling it

            s->resp_size = offset;
            s->resp_idx = 0;
            s->state = TPM_STATE_SENDING;
            break;
        }

        case TPM_CC_NV_DefineSpace:
        {
            TPM2_LOG("Handling TPM_CC_NV_DefineSpace\n");
            TPM_RC rc;
            uint32_t offset = TPM_CMD_HEADER_SIZE;

            // 1. Unmarshal parameters from the 32-byte command
            TPMI_RH_PROVISION authHandle;
            TPM2B_AUTH auth = {0};
            TPM2B_NV_PUBLIC public = {0};

            // Unmarshal authHandle (4 bytes)
            offset += Unmarshal_UINT32_BE(s->command_buffer + offset, &authHandle);

            // Unmarshal auth.size (2 bytes)
            offset += Unmarshal_UINT16_BE(s->command_buffer + offset, &auth.size);
            // (Skipping auth.buffer as size is 0 for this command)

            // Unmarshal public.size (2 bytes)
            offset += Unmarshal_UINT16_BE(s->command_buffer + offset, &public.size);
            if (public.size != 14) {
                build_error_response(s, TPM_RC_SIZE);
                break;
            }

            // Unmarshal public.nvPublic (14 bytes)
            offset += Unmarshal_UINT32_BE(s->command_buffer + offset, &public.nvPublic.nvIndex);
            offset += Unmarshal_UINT16_BE(s->command_buffer + offset, &public.nvPublic.nameAlg);
            offset += Unmarshal_UINT32_BE(s->command_buffer + offset, (uint32_t*)&public.nvPublic.attributes);
            offset += Unmarshal_UINT16_BE(s->command_buffer + offset, &public.nvPublic.authPolicySize);
            // (Skipping authPolicy as size is 0)
            offset += Unmarshal_UINT16_BE(s->command_buffer + offset, &public.nvPublic.dataSize);

            // 2. Call the backend function
            rc = tpm2_nv_define_space(s, authHandle, &auth, &public);

            // 3. Build the response
            build_error_response(s, rc); // Just sends a 10-byte header
            break;
        }

        default:
            TPM2_LOG("Unsupported command code: 0x%X\n", header.code);
            build_error_response(s, TPM_RC_COMMAND_CODE);
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
    s->state = TPM_STATE_IDLE;
    s->cmd_size = 0;
    s->resp_size = 0;
    s->resp_idx = 0;
    memset(s->command_buffer, 0, sizeof(s->command_buffer));
    memset(s->response_buffer, 0, sizeof(s->response_buffer));

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
