#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "migration/vmstate.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "tpm/tpm2_device.h"
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "tpm/command_chain/cc_header.h"
#include "tpm/command_chain/cc_unmarshal.h"
#include "tpm/command_chain/cc_marshal.h"
#include "tpm/tpm2_rc.h"
#include "tpm/tpm2_cc.h"
#include "tpm/tpm2_nv.h"

#define TPM2_LOG(fmt, ...) qemu_log("%s: " fmt, __func__, ## __VA_ARGS__)

static void tpm2_reset(DeviceState *dev);
static void tpm2_process_command(TPM2State *s);
static void build_error_response(TPM2State *s, TPM_RC rc);

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
    uint32_t val = 0;
    switch (addr) {
        case TPM2_CTRL_REG:
            return s->ctrl;
        
        case TPM2_STATUS_REG:
            return s->state;
        
        case TPM2_DATA_REG:
            //Read from the response buffer (FIFO)
            if (s->state != TPM_STATE_SENDING) {
                TPM2_LOG("Read from DATA_REG in invalid state %d\n", s->state);
                return 0;
            }
            if (s->resp_idx >= s->resp_size) {
                TPM2_LOG("Response buffer underflow\n");
                return 0;
            }

            //Read 4 bytes in big-endian format
            val = ((uint32_t)s->response_buffer[s->resp_idx + 0] << 24) |
                  ((uint32_t)s->response_buffer[s->resp_idx + 1] << 16) |
                  ((uint32_t)s->response_buffer[s->resp_idx + 2] << 8)  |
                  ((uint32_t)s->response_buffer[s->resp_idx + 3]);
            s->resp_idx += 4;

            //If all data sent, return to idle
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

                
                // Extract actual command size from header (bytes 2-5)
                uint32_t actual_size = ((uint32_t)s->command_buffer[2] << 24) |
                                      ((uint32_t)s->command_buffer[3] << 16) |
                                      ((uint32_t)s->command_buffer[4] << 8)  |
                                      ((uint32_t)s->command_buffer[5]);

                // Validate that we received enough data
                if (actual_size > s->cmd_size) {
                    TPM2_LOG("Command size mismatch: header=%u, received=%u\n", 
                            actual_size, s->cmd_size);
                    s->state = TPM_STATE_IDLE;
                    build_error_response(s, TPM_RC_COMMAND_SIZE);
                    return;
                }
                
                // Truncate cmd_size to actual command size (ignore padding)
                s->cmd_size = actual_size;

                s->state = TPM_STATE_PROCESSING;
                TPM2_LOG("State -> PROCESSING (Cmd size: %u)\n", s->cmd_size);

                tpm2_process_command(s);

                if (s->state == TPM_STATE_PROCESSING) {
                    TPM2_LOG("State -> SENDING (Resp size. %u)\n", s->resp_size);
                }
            }
            break;
        
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

            // Store in big-endian format
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

/**
 * @brief Build and send error response with proper header
 */
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

/**
 * @brief Build successful response with proper header
 */
static void build_success_response(TPM2State *s, UINT32 bodySize) {
    TPM_RSP_HEADER header;
    header.tag = TPM_ST_NO_SESSIONS;
    header.size = TPM_RSP_HEADER_SIZE + bodySize;
    header.code = TPM_RC_SUCCESS;

    UINT32 bytesWritten;
    // Marshal header at the beginning, body is already there
    MarshalResponseHeader(s->response_buffer, sizeof(s->response_buffer), &header, &bytesWritten);

    UINT32 actual_size = header.size;
    UINT32 padded_size = (actual_size + 3) & ~3; // Round up to multiple of 4
    
    // Zero out padding bytes
    for (UINT32 i = actual_size; i < padded_size; i++) {
        s->response_buffer[i] = 0;
    }
    
    s->resp_size = padded_size;  // Use padded size for transmission
    s->resp_idx = 0;
    s->state = TPM_STATE_SENDING;

    TPM2_LOG("Response: actual=%u, padded=%u\n", actual_size, padded_size);
}

/**
 * @brief Process TPM2_GetRandom command
 */
static void handle_GetRandom(TPM2State *s, const UINT8 *cmdBody, UINT32 bodySize) {
    TPM_RC rc;
    UINT16 bytesRequested;
    UINT32 bytesRead, bytesWritten;
    
    // Unmarshal parameters
    rc = Unmarshal_GetRandom(cmdBody, bodySize, &bytesRequested, &bytesRead);
    if (rc != TPM_RC_SUCCESS) {
        TPM2_LOG("Failed to unmarshal GetRandom: 0x%X\n", rc);
        build_error_response(s, rc);
        return;
    }
    
    // Validate request
    if (bytesRequested > sizeof(s->random_data)) {
        TPM2_LOG("Requested too many bytes: %u\n", bytesRequested);
        build_error_response(s, TPM_RC_SIZE);
        return;
    }
    
    TPM2_LOG("GetRandom: requesting %u bytes\n", bytesRequested);
    
    // Generate random data
    tpm2_generate_random(s);
    
    // Marshal response body (after header space)
    rc = Marshal_GetRandom_Response(
        s->response_buffer + TPM_RSP_HEADER_SIZE,
        sizeof(s->response_buffer) - TPM_RSP_HEADER_SIZE,
        s->random_data,
        bytesRequested,
        &bytesWritten);
    
    if (rc != TPM_RC_SUCCESS) {
        TPM2_LOG("Failed to marshal GetRandom response: 0x%X\n", rc);
        build_error_response(s, rc);
        return;
    }
    
    build_success_response(s, bytesWritten);
}

/**
 * @brief Process TPM2_CreatePrimary command
 */
static void handle_CreatePrimary(TPM2State *s, const UINT8 *cmdBody, UINT32 bodySize) {
    TPM_RC rc;
    CreatePrimary_Params params;
    CreatePrimary_Response response;
    UINT32 bytesRead, bytesWritten;
    
    // Unmarshal parameters
    rc = Unmarshal_CreatePrimary(cmdBody, bodySize, &params, &bytesRead);
    if (rc != TPM_RC_SUCCESS) {
        TPM2_LOG("Failed to unmarshal CreatePrimary: 0x%X\n", rc);
        build_error_response(s, rc);
        return;
    }
    
    TPM2_LOG("CreatePrimary: authHandle=0x%X\n", params.primaryHandle);
    
    // Generate RSA key
    tpm2_generate_rsa_key(s);
    if (!s->key_generated) {
        TPM2_LOG("Failed to generate RSA key\n");
        build_error_response(s, TPM_RC_FAILURE);
        return;
    }
    
    // Build response structure
    // For simplicity, we create a minimal response
    // In production, we'd populate all fields properly
    response.objectHandle = 0x80000001; // Transient handle
    
    // Minimal outPublic (just enough to be valid)
    response.outPublicSize = 14; // Minimal size
    memset(response.outPublic, 0, sizeof(response.outPublic));
    
    // Empty creation data
    response.creationDataSize = 0;
    
    // Empty creation hash
    response.creationHashSize = 0;
    
    // Creation ticket
    response.creationTicketTag = TPM_ST_CREATION;
    response.creationTicketHierarchy = params.primaryHandle;
    response.creationTicketDigestSize = 0;
    
    // Empty name for now
    response.nameSize = 0;
    
    // Marshal response body
    rc = Marshal_CreatePrimary_Response(
        s->response_buffer + TPM_RSP_HEADER_SIZE,
        sizeof(s->response_buffer) - TPM_RSP_HEADER_SIZE,
        &response,
        &bytesWritten);
    
    if (rc != TPM_RC_SUCCESS) {
        TPM2_LOG("Failed to marshal CreatePrimary response: 0x%X\n", rc);
        build_error_response(s, rc);
        return;
    }
    
    build_success_response(s, bytesWritten);
}

/**
 * @brief Process TPM2_NV_DefineSpace command
 */
static void handle_NV_DefineSpace(TPM2State *s, const UINT8 *cmdBody, UINT32 bodySize) {
    TPM_RC rc;
    NV_DefineSpace_Params params;
    UINT32 bytesRead;
    
    // Unmarshal parameters
    rc = Unmarshal_NV_DefineSpace(cmdBody, bodySize, &params, &bytesRead);
    if (rc != TPM_RC_SUCCESS) {
        TPM2_LOG("Failed to unmarshal NV_DefineSpace: 0x%X\n", rc);
        build_error_response(s, rc);
        return;
    }
    
    TPM2_LOG("NV_DefineSpace: authHandle=0x%X, nvIndex=0x%X, dataSize=%u\n",
             params.authHandle, params.nvIndex, params.dataSize);
    
    // Convert to legacy structures for backend
    TPM2B_AUTH auth;
    auth.size = params.authSize;
    memcpy(auth.buffer, params.auth, params.authSize);
    
    TPM2B_NV_PUBLIC public;
    public.size = params.publicSize;
    public.nvPublic.nvIndex = params.nvIndex;
    public.nvPublic.nameAlg = params.nameAlg;
    memcpy(&public.nvPublic.attributes, &params.attributes, sizeof(TPMA_NV));
    public.nvPublic.authPolicySize = params.authPolicySize;
    memcpy(public.nvPublic.authPolicy, params.authPolicy, params.authPolicySize);
    public.nvPublic.dataSize = params.dataSize;
    
    // Call backend function
    rc = tpm2_nv_define_space(s, params.authHandle, &auth, &public);
    
    if (rc != TPM_RC_SUCCESS) {
        TPM2_LOG("tpm2_nv_define_space failed: 0x%X\n", rc);
        build_error_response(s, rc);
        return;
    }
    
    // NV_DefineSpace has no response body
    build_success_response(s, 0);
}

/**
 * @brief Main command processing function
 */
static void tpm2_process_command(TPM2State *s) {
    TPM_CMD_HEADER header;
    UINT32 rc;

    // Validate and parse header
    rc = TPM2_ValidateCommandHeader(s->command_buffer, s->cmd_size, &header);
    if (rc != TPM_RC_SUCCESS) {
        TPM2_LOG("TPM2_ValidateCommandHeader failed: 0x%X\n", rc);
        build_error_response(s, rc);
        return;
    }

    // Validate TPM mode
    rc = TPM2_ValidateMode(&header,s);
    if (rc != TPM_RC_SUCCESS) {
        TPM2_LOG("TPM2_ValidateMode failed: 0x%X\n", rc);
        build_error_response(s, rc);
        return;
    }

    // Point to command body (after header)
    const UINT8 *cmdBody = s->command_buffer + TPM_CMD_HEADER_SIZE;
    UINT32 bodySize = s->cmd_size - TPM_CMD_HEADER_SIZE;

    switch (header.code) {
        case TPM_CC_GetRandom:
            TPM2_LOG("Handling TPM_CC_GetRandom\n");
            handle_GetRandom(s, cmdBody, bodySize);
            break;

        case TPM_CC_CreatePrimary:
            TPM2_LOG("Handling TPM_CC_CreatePrimary\n");
            handle_CreatePrimary(s, cmdBody, bodySize);
            break;

        case TPM_CC_NV_DefineSpace:
            TPM2_LOG("Handling TPM_CC_NV_DefineSpace\n");
            handle_NV_DefineSpace(s, cmdBody, bodySize);
            build_error_response(s, rc);
            break;

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
    type_register_static(&tpm2_info);
}

type_init(tpm2_register_types)
