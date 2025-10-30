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

#include "tpm/command_chain/cc_header.h"
#include "tpm/command_chain/cc_unmarshal.h"
#include "tpm/command_chain/cc_marshal.h"
#include "tpm/tpm2_rc.h"
#include "tpm/tpm2_cc.h"

#define TPM2_LOG(fmt, ...) qemu_log("%s: " fmt, __func__, ## __VA_ARGS__)

static void tpm2_reset(DeviceState *dev);
static void tpm2_process_command(TPM2State *s);
static void build_error_response(TPM2State *s, TPM_RC rc);

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
    TPM2_LOG("ownerWrite = %u\n", pub.attributes.ownerWrite);
    TPM2_LOG("authWrite  = %u\n", pub.attributes.authWrite);
    

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

    return TPM_RC_SUCCESS;
}



// static void tpm2_test_nv_encrypt_decrypt(TPM2State *s)
// {
//     TPM2_LOG("---- [TPM TEST] NV Encrypt/Decrypt start ----\n");

//     /* 1. Ensure NV entry exists (use one created by DefineSpace) */
//     uint32_t index = 0x1500016;
//     NVEntry *e = g_hash_table_lookup(s->nv_map, GUINT_TO_POINTER(index));
//     if (!e) {
//         TPM2_LOG("[TEST] NV index 0x%08X not found\n", index);
//         return;
//     }

//     const char *msg = "TPM NV TEST DATA";
//     uint8_t ciphertext[64] = {0};
//     uint8_t decrypted[64]  = {0};

//     TPM2_LOG("[TEST] Plaintext: %s\n", msg);

//     /* 2. Encrypt plaintext into NV bank */
//     TPM_RC rc = TPM2_NV_Write(s, e, (const uint8_t *)msg, strlen(msg), 0);
//     TPM2_LOG("[TEST] nv_write_crypt_to_bank rc=0x%X\n", rc);

//     /* 3. Dump encrypted bytes */
//     TPM2_LOG("[TEST] Ciphertext (in NV bank): ");
//     for (int i = 0; i < strlen(msg); i++)
//         qemu_log("%02X ", e->data[i]);
//     qemu_log("\n");

//     /* 4. Read and decrypt back */
//     rc = nv_read_decrypt_from_bank(s, e, decrypted, strlen(msg), 0);
//     TPM2_LOG("[TEST] nv_read_decrypt_from_bank rc=0x%X\n", rc);

//     decrypted[strlen(msg)] = '\0';
//     TPM2_LOG("[TEST] Decrypted: %s\n", decrypted);

//     /* 5. Compare */
//     if (memcmp(msg, decrypted, strlen(msg)) == 0)
//         TPM2_LOG("[TEST] ✅ Encryption/Decryption OK\n");
//     else
//         TPM2_LOG("[TEST] ❌ Mismatch!\n");

//     TPM2_LOG("---- [TPM TEST] NV Encrypt/Decrypt end ----\n");
// }














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
// static void handle_CreatePrimary(TPM2State *s, const UINT8 *cmdBody, UINT32 bodySize) {
//     TPM_RC rc;
//     CreatePrimary_Params params;
//     CreatePrimary_Response response;
//     UINT32 bytesRead, bytesWritten;
    
//     // Unmarshal parameters
//     rc = Unmarshal_CreatePrimary(cmdBody, bodySize, &params, &bytesRead);
//     if (rc != TPM_RC_SUCCESS) {
//         TPM2_LOG("Failed to unmarshal CreatePrimary: 0x%X\n", rc);
//         build_error_response(s, rc);
//         return;
//     }
    
//     TPM2_LOG("CreatePrimary: authHandle=0x%X\n", params.primaryHandle);
    
//     // Generate RSA key
//     tpm2_generate_rsa_key(s);
//     if (!s->key_generated) {
//         TPM2_LOG("Failed to generate RSA key\n");
//         build_error_response(s, TPM_RC_FAILURE);
//         return;
//     }
    
//     // Build response structure
//     // For simplicity, we create a minimal response
//     // In production, we'd populate all fields properly
//     response.objectHandle = 0x80000001; // Transient handle
    
//     // Minimal outPublic (just enough to be valid)
//     response.outPublicSize = 14; // Minimal size
//     memset(response.outPublic, 0, sizeof(response.outPublic));
    
//     // Empty creation data
//     response.creationDataSize = 0;
    
//     // Empty creation hash
//     response.creationHashSize = 0;
    
//     // Creation ticket
//     response.creationTicketTag = TPM_ST_CREATION;
//     response.creationTicketHierarchy = params.primaryHandle;
//     response.creationTicketDigestSize = 0;
    
//     // Empty name for now
//     response.nameSize = 0;
    
//     // Marshal response body
//     rc = Marshal_CreatePrimary_Response(
//         s->response_buffer + TPM_RSP_HEADER_SIZE,
//         sizeof(s->response_buffer) - TPM_RSP_HEADER_SIZE,
//         &response,
//         &bytesWritten);
    
//     if (rc != TPM_RC_SUCCESS) {
//         TPM2_LOG("Failed to marshal CreatePrimary response: 0x%X\n", rc);
//         build_error_response(s, rc);
//         return;
//     }
    
//     build_success_response(s, bytesWritten);
// }

/**
 * @brief Process TPM2_CreatePrimary command (FIXED VERSION)
 * 
 * This version properly calls tpm2_CreatePrimary and marshals the real response
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
    
    // Build TPM2B structures from unmarshaled params
    TPM2B_SENSITIVE_CREATE inSensitive;
    memset(&inSensitive, 0, sizeof(inSensitive));
    inSensitive.size = sizeof(inSensitive.sensitive);
    inSensitive.sensitive.userAuth.size = params.userAuthSize;
    if (params.userAuthSize > 0) {
        memcpy(inSensitive.sensitive.userAuth.buffer, params.userAuth, params.userAuthSize);
    }
    inSensitive.sensitive.data.size = params.dataSize;
    if (params.dataSize > 0) {
        memcpy(inSensitive.sensitive.data.buffer, params.data, params.dataSize);
    }
    
    // For inPublic, we need to reconstruct it from the buffer
    // This is a simplified version - in production you'd fully unmarshal TPMT_PUBLIC
    TPM2B_PUBLIC inPublic;
    memset(&inPublic, 0, sizeof(inPublic));
    
    // Parse basic fields from the inPublic buffer
    const UINT8 *pubBuf = cmdBody + bytesRead - params.inPublicSize;
    UINT32 pubOffset = 0;
    
    // Type (2 bytes)
    inPublic.publicArea.type = ((UINT16)pubBuf[pubOffset] << 8) | pubBuf[pubOffset + 1];
    pubOffset += 2;
    
    // NameAlg (2 bytes)
    inPublic.publicArea.nameAlg = ((UINT16)pubBuf[pubOffset] << 8) | pubBuf[pubOffset + 1];
    pubOffset += 2;
    
    // ObjectAttributes (4 bytes)
    inPublic.publicArea.objectAttributes = 
        ((UINT32)pubBuf[pubOffset] << 24) |
        ((UINT32)pubBuf[pubOffset + 1] << 16) |
        ((UINT32)pubBuf[pubOffset + 2] << 8) |
        pubBuf[pubOffset + 3];
    pubOffset += 4;
    
    // AuthPolicy size (2 bytes)
    UINT16 authPolicySize = ((UINT16)pubBuf[pubOffset] << 8) | pubBuf[pubOffset + 1];
    pubOffset += 2;
    
    // Skip authPolicy bytes
    pubOffset += authPolicySize;
    
    // For ECC, parse the curve ID
    if (inPublic.publicArea.type == TPM_ALG_ECC) {
        // Skip symmetric (2 bytes) and scheme (2 bytes)
        pubOffset += 4;
        
        // CurveID (2 bytes)
        inPublic.publicArea.parameters.eccDetail.curveID = 
            ((UINT16)pubBuf[pubOffset] << 8) | pubBuf[pubOffset + 1];
    }
    
    inPublic.size = sizeof(inPublic.publicArea);
    
    // Output placeholders
    TPM2B_PUBLIC outPublic;
    TPM2B_NAME name;
    memset(&outPublic, 0, sizeof(outPublic));
    memset(&name, 0, sizeof(name));
    
    // Allocate transient handle
    TPM_HANDLE objectHandle = 0x80000000 | s->next_transient_handle;
    s->next_transient_handle++;
    
    // Call the actual CreatePrimary implementation
    rc = tpm2_CreatePrimary(s,
                           params.primaryHandle,
                           &inSensitive,
                           &inPublic,
                           NULL,   /* outsideInfo */
                           NULL,   /* creationPCR */
                           &objectHandle,   /* pass handle */
                           &outPublic,
                           &name);
    
    if (rc != TPM_RC_SUCCESS) {
        TPM2_LOG("tpm2_CreatePrimary failed: 0x%X\n", rc);
        build_error_response(s, rc);
        return;
    }
    
    TPM2_LOG("Primary key created successfully with handle 0x%08X\n", objectHandle);
    
    // Build response structure
    memset(&response, 0, sizeof(response));
    response.objectHandle = objectHandle;
    
    // Marshal outPublic into response buffer
    // For simplicity, marshal the entire TPMT_PUBLIC structure
    UINT8 tempBuf[512];
    UINT32 pubSize = 0;
    
    // Type (2 bytes)
    tempBuf[pubSize++] = (outPublic.publicArea.type >> 8) & 0xFF;
    tempBuf[pubSize++] = outPublic.publicArea.type & 0xFF;
    
    // NameAlg (2 bytes)
    tempBuf[pubSize++] = (outPublic.publicArea.nameAlg >> 8) & 0xFF;
    tempBuf[pubSize++] = outPublic.publicArea.nameAlg & 0xFF;
    
    // ObjectAttributes (4 bytes)
    tempBuf[pubSize++] = (outPublic.publicArea.objectAttributes >> 24) & 0xFF;
    tempBuf[pubSize++] = (outPublic.publicArea.objectAttributes >> 16) & 0xFF;
    tempBuf[pubSize++] = (outPublic.publicArea.objectAttributes >> 8) & 0xFF;
    tempBuf[pubSize++] = outPublic.publicArea.objectAttributes & 0xFF;
    
    // AuthPolicy (empty)
    tempBuf[pubSize++] = 0x00;
    tempBuf[pubSize++] = 0x00;
    
    // For ECC, add parameters
    if (outPublic.publicArea.type == TPM_ALG_ECC) {
        // Symmetric (TPM_ALG_NULL)
        tempBuf[pubSize++] = 0x00;
        tempBuf[pubSize++] = 0x10;
        
        // Scheme (TPM_ALG_NULL)
        tempBuf[pubSize++] = 0x00;
        tempBuf[pubSize++] = 0x10;
        
        // CurveID
        tempBuf[pubSize++] = (outPublic.publicArea.parameters.eccDetail.curveID >> 8) & 0xFF;
        tempBuf[pubSize++] = outPublic.publicArea.parameters.eccDetail.curveID & 0xFF;
        
        // KDF (TPM_ALG_NULL)
        tempBuf[pubSize++] = 0x00;
        tempBuf[pubSize++] = 0x10;
        
        // X coordinate (size + data)
        tempBuf[pubSize++] = (outPublic.publicArea.unique.ecc.x.size >> 8) & 0xFF;
        tempBuf[pubSize++] = outPublic.publicArea.unique.ecc.x.size & 0xFF;
        memcpy(tempBuf + pubSize, outPublic.publicArea.unique.ecc.x.buffer,
               outPublic.publicArea.unique.ecc.x.size);
        pubSize += outPublic.publicArea.unique.ecc.x.size;
        
        // Y coordinate (size + data)
        tempBuf[pubSize++] = (outPublic.publicArea.unique.ecc.y.size >> 8) & 0xFF;
        tempBuf[pubSize++] = outPublic.publicArea.unique.ecc.y.size & 0xFF;
        memcpy(tempBuf + pubSize, outPublic.publicArea.unique.ecc.y.buffer,
               outPublic.publicArea.unique.ecc.y.size);
        pubSize += outPublic.publicArea.unique.ecc.y.size;
    }
    
    response.outPublicSize = pubSize;
    memcpy(response.outPublic, tempBuf, pubSize);
    
    // Empty creation data
    response.creationDataSize = 0;
    
    // Empty creation hash
    response.creationHashSize = 0;
    
    // Creation ticket
    response.creationTicketTag = TPM_ST_CREATION;
    response.creationTicketHierarchy = params.primaryHandle;
    response.creationTicketDigestSize = 0;
    
    // Name
    response.nameSize = name.size;
    memcpy(response.name, name.name, name.size);
    
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
 * @brief Process TPM2_NV_DefineSpace command (FIXED VERSION)
 */
static void handle_NV_DefineSpace(TPM2State *s, const UINT8 *cmdBody, UINT32 bodySize) {
    TPM_RC rc;
    NV_DefineSpace_Params params;
    UINT32 bytesRead;
    
    // 1. Unmarshal parameters
    rc = Unmarshal_NV_DefineSpace(cmdBody, bodySize, &params, &bytesRead);
    if (rc != TPM_RC_SUCCESS) {
        TPM2_LOG("Failed to unmarshal NV_DefineSpace: 0x%X\n", rc);
        build_error_response(s, rc);
        return;
    }
    
    // 2. Log the *unmarshaled* (and hopefully not corrupt) values
    TPM2_LOG("NV_DefineSpace: authHandle=0x%X, nvIndex=0x%X, dataSize=%u\n",
             params.authHandle, params.nvIndex, params.dataSize);

    // 3. Declare backend variables
    TPMI_RH_PROVISION provHandle;
    TPM2B_AUTH auth;
    TPM2B_NV_PUBLIC public;

    // 4. Handle check
    // We use the raw value 0x4000000C because the macro TPM_RH_PLATFORM
    // seems to be different in this QEMU build environment.
    if (params.authHandle == 0x4000000C) { // TPM_RH_PLATFORM
        provHandle = (TPMI_RH_PROVISION){ TPM_RH_PLATFORM, TPM_RH_PLATFORM, TPM_RH_PLATFORM };
    } else if (params.authHandle == 0x40000001) { // TPM_RH_OWNER (Guessing value)
        provHandle = (TPMI_RH_PROVISION){ TPM_RH_OWNER, TPM_RH_OWNER, TPM_RH_OWNER };
    } else {
        TPM2_LOG("NV_DefineSpace: Invalid authHandle 0x%X\n", params.authHandle);
        build_error_response(s, TPM_RC_HANDLE); // 0x8B
        return;
    }

    // 5. Access params struct *only after* UB is gone.
    // This removes the secondary source of UB the compiler was seeing.
    auth.size = params.authSize;
    memcpy(auth.buffer, params.auth, params.authSize);
    
    public.size = sizeof(public.nvPublic);
    public.nvPublic.nvIndex = params.nvIndex;
    public.nvPublic.nameAlg = params.nameAlg;
    memcpy(&public.nvPublic.attributes, &params.attributes, sizeof(TPMA_NV));
    public.nvPublic.authPolicySize = params.authPolicySize;
    memcpy(public.nvPublic.authPolicy, params.authPolicy, params.authPolicySize);
    public.nvPublic.dataSize = params.dataSize;

    // 6. Call backend function
    rc = tpm2_nv_define_space(s, provHandle, &auth, &public);
    
    if (rc != TPM_RC_SUCCESS) {
        TPM2_LOG("tpm2_nv_define_space failed: 0x%X\n", rc);
        build_error_response(s, rc);
        return;
    }
    
    TPM2_LOG("NV_DefineSpace succeeded\n");
    
    // NV_DefineSpace has no response body
    build_success_response(s, 0);
}

static void handle_NV_Write(TPM2State *s, const UINT8 *cmdBody, UINT32 bodySize) {
    TPM_RC rc;
    NV_Write_Params params;
    UINT32 bytesRead;
    
    // Unmarshal parameters
    rc = Unmarshal_NV_Write(cmdBody, bodySize, &params, &bytesRead);
    if (rc != TPM_RC_SUCCESS) {
        TPM2_LOG("Failed to unmarshal NV_Write: 0x%X\n", rc);
        build_error_response(s, rc);
        return;
    }
    
    TPM2_LOG("NV_Write: authHandle=0x%X, nvIndex=0x%X, size=%u, offset=%u\n",
             params.authHandle, params.nvIndex, params.data.size, params.offset);
    

    // Lookup NV entry
    NVEntry *e = g_hash_table_lookup(s->nv_map, GUINT_TO_POINTER(params.nvIndex));
    if (!e) {
        TPM2_LOG("NV_Write: Index 0x%08X not found\n", params.nvIndex);
        build_error_response(s, TPM_RC_HANDLE);
        return;
    }

    // Validate write is within bounds
    if ((uint32_t)params.offset + params.data.size > e->pub.dataSize) {
        TPM2_LOG("NV_Write: Write exceeds index size\n");
        build_error_response(s, TPM_RC_NV_RANGE);
        return;
    }

    TPMI_RH_PROVISION provHandle;
    if (params.authHandle == 0x4000000C) { // TPM_RH_PLATFORM
        provHandle = (TPMI_RH_PROVISION){ TPM_RH_PLATFORM, TPM_RH_PLATFORM, TPM_RH_PLATFORM };
    } else if (params.authHandle == 0x40000001) { // TPM_RH_OWNER (Guessing value)
        provHandle = (TPMI_RH_PROVISION){ TPM_RH_OWNER, TPM_RH_OWNER, TPM_RH_OWNER };
    } else {
        TPM2_LOG("NV_DefineSpace: Invalid authHandle 0x%X\n", params.authHandle);
        build_error_response(s, TPM_RC_HANDLE); // 0x8B
        return;
    }

    // Perform encrypted write to NV bank
    rc = TPM2_NV_Write(s, provHandle, params.nvIndex, &params.data, params.offset);
    if (rc != TPM_RC_SUCCESS) {
        TPM2_LOG("nv_write_crypt_to_bank failed: 0x%X\n", rc);
        build_error_response(s, rc);
        return;
    }
    
    // Mark as written
    e->written = true;
    s->nv_dirty = true;
    
    // NV_Write has no response body (just success header)
    build_success_response(s, 0);
}

static void handle_NV_Read(TPM2State *s, const UINT8 *cmdBody, UINT32 bodySize) {
    TPM_RC rc;
    NV_Read_Params params;
    NV_Read_Response response;
    UINT32 bytesRead, bytesWritten;
    
    // Unmarshal parameters
    rc = Unmarshal_NV_Read(cmdBody, bodySize, &params, &bytesRead);
    if (rc != TPM_RC_SUCCESS) {
        TPM2_LOG("Failed to unmarshal NV_Read: 0x%X\n", rc);
        build_error_response(s, rc);
        return;
    }
    
    TPM2_LOG("NV_Read: authHandle=0x%X, nvIndex=0x%X, size=%u, offset=%u\n",
             params.authHandle, params.nvIndex, params.sizeToRead, params.offset);
    
    // Lookup NV entry
    NVEntry *e = g_hash_table_lookup(s->nv_map, GUINT_TO_POINTER(params.nvIndex));
    if (!e) {
        TPM2_LOG("NV_Read: Index 0x%08X not found\n", params.nvIndex);
        build_error_response(s, TPM_RC_HANDLE);
        return;
    }
    
    // Check if written
    if (!e->written) {
        TPM2_LOG("NV_Read: Index not written\n");
        build_error_response(s, TPM_RC_NV_UNINITIALIZED);
        return;
    }
    
    // Validate read is within bounds
    if ((uint32_t)params.offset + params.sizeToRead > e->pub.dataSize) {
        TPM2_LOG("NV_Read: Read exceeds index size\n");
        build_error_response(s, TPM_RC_NV_RANGE);
        return;
    }
    
    // Check if index is readable
    if (e->readLocked) {
        TPM2_LOG("NV_Read: Index is read-locked\n");
        build_error_response(s, TPM_RC_NV_LOCKED);
        return;
    }
    
    // Perform decrypted read from NV bank
    memset(&response, 0, sizeof(response));
    response.data.size = params.sizeToRead;
    
    rc = nv_read_decrypt_from_bank(s, e, response.data.buffer, params.sizeToRead, params.offset);
    if (rc != TPM_RC_SUCCESS) {
        TPM2_LOG("nv_read_decrypt_from_bank failed: 0x%X\n", rc);
        build_error_response(s, rc);
        return;
    }
    
    // Marshal response body (after header space)
    rc = Marshal_NV_Read_Response(
        s->response_buffer + TPM_RSP_HEADER_SIZE,
        sizeof(s->response_buffer) - TPM_RSP_HEADER_SIZE,
        &response,
        &bytesWritten);
    
    if (rc != TPM_RC_SUCCESS) {
        TPM2_LOG("Failed to marshal NV_Read response: 0x%X\n", rc);
        build_error_response(s, rc);
        return;
    }

    TPM2_LOG("[NV_READ] decypted plaintext: ");
        for (UINT16 i = 0; i < params.sizeToRead; i++) {
        char c = response.data.buffer[i];
        qemu_log("%c", (c >= 32 && c <= 126) ? c : '.');
}
    qemu_log("\n");
    
    build_success_response(s, bytesWritten);
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
            break;
        case TPM_CC_NV_Write:
            TPM2_LOG("Handling TPM_CC_NV_Write\n");
            handle_NV_Write(s, cmdBody, bodySize);
            break;

        case TPM_CC_NV_Read:
            TPM2_LOG("Handling TPM_CC_NV_Read\n");
            handle_NV_Read(s, cmdBody, bodySize);
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
    // TPM2_LOG("[DEBUG]Running nv_encrypt_decrypt_test\n");
    // tpm2_test_nv_encrypt_decrypt(s);


}







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
    type_register_static(&tpm2_info);
}

type_init(tpm2_register_types)
