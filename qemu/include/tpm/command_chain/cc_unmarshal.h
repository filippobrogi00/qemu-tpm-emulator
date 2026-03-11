#ifndef CC_UNMARSHAL_H
#define CC_UNMARSHAL_H

#include <stdint.h>
#include <string.h>
#include "../tpm2_base_types.h"
#include "../tpm2_rc.h"
#include "../tpm2_interfaces.h"
#include "../tpm2_handles.h"
// qemu_log should be available as this file is included by tpm_hw.c
// which already includes qemu/log.h

/******************************
 * BASIC UNMARSHALING FUNCTIONS
 ******************************/

/**
 * @brief Unmarshal UINT8 from buffer
 */
static inline TPM_RC Unmarshal_UINT8(
    const UINT8 *buffer,
    UINT32 bufferSize,
    UINT8 *value,
    UINT32 *bytesRead)
{
    if (!buffer || !value || !bytesRead) {
        return TPM_RC_FAILURE;
    }
    
    if (bufferSize < 1) {
        return TPM_RC_INSUFFICIENT;
    }
    
    *value = buffer[0];
    *bytesRead = 1;
    // qemu_log("Unmarshal_UINT8: value=0x%02X\n", *value); // Optional: very verbose
    return TPM_RC_SUCCESS;
}

/**
 * @brief Unmarshal UINT16 from buffer (big-endian)
 */
static inline TPM_RC Unmarshal_UINT16(
    const UINT8 *buffer,
    UINT32 bufferSize,
    UINT16 *value,
    UINT32 *bytesRead)
{
    if (!buffer || !value || !bytesRead) {
        return TPM_RC_FAILURE;
    }
    
    if (bufferSize < 2) {
        return TPM_RC_INSUFFICIENT;
    }
    
    *value = ((UINT16)buffer[0] << 8) | (UINT16)buffer[1];
    *bytesRead = 2;
    qemu_log("[UNMARSHAL] UINT16: 0x%04X\n", *value);
    return TPM_RC_SUCCESS;
}

/**
 * @brief Unmarshal UINT32 from buffer (big-endian)
 */
static inline TPM_RC Unmarshal_UINT32(
    const UINT8 *buffer,
    UINT32 bufferSize,
    UINT32 *value,
    UINT32 *bytesRead)
{
    if (!buffer || !value || !bytesRead) {
        return TPM_RC_FAILURE;
    }
    
    if (bufferSize < 4) {
        return TPM_RC_INSUFFICIENT;
    }
    
    *value = ((UINT32)buffer[0] << 24) |
             ((UINT32)buffer[1] << 16) |
             ((UINT32)buffer[2] << 8)  |
             (UINT32)buffer[3];
    *bytesRead = 4;
    qemu_log("[UNMARSHAL] UINT32: 0x%08X\n", *value);
    return TPM_RC_SUCCESS;
}

/**
 * @brief Unmarshal UINT64 from buffer (big-endian)
 */
static inline TPM_RC Unmarshal_UINT64(
    const UINT8 *buffer,
    UINT32 bufferSize,
    UINT64 *value,
    UINT32 *bytesRead)
{
    if (!buffer || !value || !bytesRead) {
        return TPM_RC_FAILURE;
    }
    
    if (bufferSize < 8) {
        return TPM_RC_INSUFFICIENT;
    }
    
    *value = ((UINT64)buffer[0] << 56) |
             ((UINT64)buffer[1] << 48) |
             ((UINT64)buffer[2] << 40) |
             ((UINT64)buffer[3] << 32) |
             ((UINT64)buffer[4] << 24) |
             ((UINT64)buffer[5] << 16) |
             ((UINT64)buffer[6] << 8)  |
             (UINT64)buffer[7];
    *bytesRead = 8;
    qemu_log("[UNMARSHAL] UINT64: 0x%016lX\n", (unsigned long)*value);
    return TPM_RC_SUCCESS;
}

/**
 * @brief Unmarshal TPM2B structure (size-prefixed buffer)
 */
static inline TPM_RC Unmarshal_TPM2B(
    const UINT8 *buffer,
    UINT32 bufferSize,
    UINT16 maxSize,
    UINT8 *dataBuffer,
    UINT16 *dataSize,
    UINT32 *bytesRead)
{
    if (!buffer || !dataSize || !bytesRead) {
        return TPM_RC_FAILURE;
    }
    
    TPM_RC rc;
    UINT32 offset = 0;
    UINT32 consumed;
    
    // Unmarshal size
    rc = Unmarshal_UINT16(buffer + offset, bufferSize - offset, dataSize, &consumed);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
    offset += consumed;
    
    qemu_log("[UNMARSHAL] TPM2B: size=%u (max=%u)\n", *dataSize, maxSize);
    
    // Validate size
    if (*dataSize > maxSize) {
        qemu_log("[UNMARSHAL] TPM2B: Error TPM_RC_SIZE\n");
        return TPM_RC_SIZE;
    }
    
    if (bufferSize - offset < *dataSize) {
        qemu_log("[UNMARSHAL] TPM2B: Error TPM_RC_INSUFFICIENT\n");
        return TPM_RC_INSUFFICIENT;
    }
    
    // Copy data (only if dataBuffer is provided)
    if (dataBuffer && *dataSize > 0) {
        memcpy(dataBuffer, buffer + offset, *dataSize);
    }
    offset += *dataSize;
    
    *bytesRead = offset;
    return TPM_RC_SUCCESS;
}

/******************************
 * COMMAND-SPECIFIC UNMARSHALING
 ******************************/

/**
 * @brief Unmarshal TPM2_GetRandom command parameters
 */
static inline TPM_RC Unmarshal_GetRandom(
    const UINT8 *buffer,
    UINT32 bufferSize,
    UINT16 *bytesRequested,
    UINT32 *bytesRead)
{
    return Unmarshal_UINT16(buffer, bufferSize, bytesRequested, bytesRead);
}

/**
 * @brief Unmarshal TPM2_CreatePrimary command parameters
 */
typedef struct {
    UINT32 primaryHandle;        // authHandle (4 bytes)
    UINT32 authorizationSize;    // If sessions present (4 bytes)
    UINT16 inSensitiveSize;      // inSensitive size (2 bytes)
    UINT16 userAuthSize;         // userAuth size (2 bytes)
    UINT8  userAuth[64];         // userAuth buffer
    UINT16 dataSize;             // data size (2 bytes)
    UINT8  data[256];            // data buffer
    UINT16 inPublicSize;         // inPublic size (2 bytes)
    // ... rest of public area fields
} CreatePrimary_Params;

static inline TPM_RC Unmarshal_CreatePrimary(
    const UINT8 *buffer,
    UINT32 bufferSize,
    CreatePrimary_Params *params,
    UINT32 *bytesRead)
{
    if (!buffer || !params || !bytesRead) {
        return TPM_RC_FAILURE;
    }
    
    TPM_RC rc;
    UINT32 offset = 0;
    UINT32 consumed;
    
    // Unmarshal authHandle
    rc = Unmarshal_UINT32(buffer + offset, bufferSize - offset, 
                          &params->primaryHandle, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    // Unmarshal inSensitive (TPM2B)
    rc = Unmarshal_UINT16(buffer + offset, bufferSize - offset,
                          &params->inSensitiveSize, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    // Unmarshal userAuth within inSensitive
    if (params->inSensitiveSize > 0) {
        rc = Unmarshal_TPM2B(buffer + offset, bufferSize - offset,
                            sizeof(params->userAuth), params->userAuth,
                            &params->userAuthSize, &consumed);
        if (rc != TPM_RC_SUCCESS) return rc;
        offset += consumed;
        
        // Unmarshal data within inSensitive
        rc = Unmarshal_TPM2B(buffer + offset, bufferSize - offset,
                            sizeof(params->data), params->data,
                            &params->dataSize, &consumed);
        if (rc != TPM_RC_SUCCESS) return rc;
        offset += consumed;
    }
    
    // Unmarshal inPublic size
    rc = Unmarshal_UINT16(buffer + offset, bufferSize - offset,
                          &params->inPublicSize, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    // For now, skip detailed inPublic unmarshaling
    // In production, you'd unmarshal all TPMT_PUBLIC fields
    if (bufferSize - offset < params->inPublicSize) {
        return TPM_RC_INSUFFICIENT;
    }
    offset += params->inPublicSize;
    
    *bytesRead = offset;
    return TPM_RC_SUCCESS;
}

/**
 * @brief Unmarshal TPM2_NV_DefineSpace command parameters
 */
typedef struct {
    UINT32 authHandle;// TPMI_RH_PROVISION
    UINT16 authSize;             // TPM2B_AUTH size
    UINT8  auth[64];             // TPM2B_AUTH buffer
    UINT16 publicSize;           // TPM2B_NV_PUBLIC size
    UINT32 nvIndex;              // TPMS_NV_PUBLIC.nvIndex
    UINT16 nameAlg;              // TPMS_NV_PUBLIC.nameAlg
    UINT32 attributes;           // TPMS_NV_PUBLIC.attributes (TPMA_NV)
    UINT16 authPolicySize;       // authPolicy size
    UINT8  authPolicy[64];       // authPolicy buffer
    UINT16 dataSize;             // TPMS_NV_PUBLIC.dataSize
} NV_DefineSpace_Params;

static inline TPM_RC Unmarshal_NV_DefineSpace(
    const UINT8 *buffer,
    UINT32 bufferSize,
    NV_DefineSpace_Params *params,
    UINT32 *bytesRead)
{
    if (!buffer || !params || !bytesRead) {
        return TPM_RC_FAILURE;
    }
    
    TPM_RC rc;
    UINT32 offset = 0;
    UINT32 consumed;
    
    qemu_log("[UNMARSHAL] --- Begin TPM2_NV_DefineSpace ---\n");
    
    // authHandle
    rc = Unmarshal_UINT32(buffer + offset, bufferSize - offset,
                          &params->authHandle, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    // auth (TPM2B_AUTH)
    rc = Unmarshal_TPM2B(buffer + offset, bufferSize - offset,
                        sizeof(params->auth), params->auth,
                        &params->authSize, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    // publicArea size
    rc = Unmarshal_UINT16(buffer + offset, bufferSize - offset,
                          &params->publicSize, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    // nvIndex
    rc = Unmarshal_UINT32(buffer + offset, bufferSize - offset,
                          &params->nvIndex, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    // nameAlg
    rc = Unmarshal_UINT16(buffer + offset, bufferSize - offset,
                          &params->nameAlg, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    // attributes
    rc = Unmarshal_UINT32(buffer + offset, bufferSize - offset,
                          &params->attributes, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    // authPolicy (TPM2B)
    rc = Unmarshal_TPM2B(buffer + offset, bufferSize - offset,
                        sizeof(params->authPolicy), params->authPolicy,
                        &params->authPolicySize, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    // dataSize
    rc = Unmarshal_UINT16(buffer + offset, bufferSize - offset,
                          &params->dataSize, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    *bytesRead = offset;
    qemu_log("[UNMARSHAL] --- End TPM2_NV_DefineSpace (read %u bytes) ---\n", *bytesRead);
    return TPM_RC_SUCCESS;
}

typedef struct {
    TPM_HANDLE authHandle;
    TPM_NV_INDEX nvIndex;
    TPM2B_MAX_NV_BUFFER data;
    UINT16 offset;
} NV_Write_Params;

typedef struct {
    TPM_HANDLE authHandle;
    TPM_NV_INDEX nvIndex;
    UINT16 sizeToRead;
    UINT16 offset;
} NV_Read_Params;

typedef struct {
    TPM2B_MAX_NV_BUFFER data;
} NV_Read_Response;

// Helper to unmarshal TPM2B_MAX_NV_BUFFER
static inline TPM_RC Unmarshal_TPM2B_MAX_NV_BUFFER(
    const UINT8 *buffer, UINT32 bufferSize,
    TPM2B_MAX_NV_BUFFER *target, UINT32 *bytesRead)
{
    if (!buffer || !target || !bytesRead) {
        return TPM_RC_FAILURE;
    }
    
    TPM_RC rc;
    UINT32 offset = 0;
    UINT32 consumed;

    rc = Unmarshal_UINT16(buffer + offset, bufferSize - offset, &target->size, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    qemu_log("[UNMARSHAL] TPM2B_MAX_NV_BUFFER: size=%u\n", target->size);

    if (target->size > MAX_NV_BUFFER_SIZE) return TPM_RC_SIZE;
    if (bufferSize - offset < target->size) return TPM_RC_INSUFFICIENT;

    memcpy(target->buffer, buffer + offset, target->size);
    offset += target->size;

    *bytesRead = offset;
    return TPM_RC_SUCCESS;
}

static inline TPM_RC Unmarshal_NV_Write(
    const UINT8 *buffer, UINT32 bufferSize,
    NV_Write_Params *params, UINT32 *bytesRead)
{
    if (!buffer || !params || !bytesRead) {
        return TPM_RC_FAILURE;
    }
    
    TPM_RC rc;
    UINT32 offset = 0;
    UINT32 consumed;
    
    qemu_log("[UNMARSHAL] --- Begin TPM2_NV_Write ---\n");

    rc = Unmarshal_UINT32(buffer + offset, bufferSize - offset, &params->authHandle, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;

    rc = Unmarshal_UINT32(buffer + offset, bufferSize - offset, &params->nvIndex, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;

    // Skip Auth Session Area (assuming size=0)
    UINT16 authSize;
    rc = Unmarshal_UINT16(buffer + offset, bufferSize - offset, &authSize, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    qemu_log("[UNMARSHAL] NV_Write: authSize=%u\n", authSize);
    if (authSize != 0) return TPM_RC_VALUE; // We don't support auth sessions here

    // Unmarshal data
    rc = Unmarshal_TPM2B_MAX_NV_BUFFER(buffer + offset, bufferSize - offset, &params->data, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;

    // Unmarshal offset
    rc = Unmarshal_UINT16(buffer + offset, bufferSize - offset, &params->offset, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;

    *bytesRead = offset;
    qemu_log("[UNMARSHAL] --- End TPM2_NV_Write (read %u bytes) ---\n", *bytesRead);
    return TPM_RC_SUCCESS;
}

static inline TPM_RC Unmarshal_NV_Read(
    const UINT8 *buffer, UINT32 bufferSize,
    NV_Read_Params *params, UINT32 *bytesRead)
{
    if (!buffer || !params || !bytesRead) {
        return TPM_RC_FAILURE;
    }
    
    TPM_RC rc;
    UINT32 offset = 0;
    UINT32 consumed;
    
    qemu_log("[UNMARSHAL] --- Begin TPM2_NV_Read ---\n");

    rc = Unmarshal_UINT32(buffer + offset, bufferSize - offset, &params->authHandle, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;

    rc = Unmarshal_UINT32(buffer + offset, bufferSize - offset, &params->nvIndex, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;

    // Skip Auth Session Area (assuming size=0)
    UINT16 authSize;
    rc = Unmarshal_UINT16(buffer + offset, bufferSize - offset, &authSize, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    qemu_log("[UNMARSHAL] NV_Read: authSize=%u\n", authSize);
    if (authSize != 0) return TPM_RC_VALUE;

    // Unmarshal sizeToRead
    rc = Unmarshal_UINT16(buffer + offset, bufferSize - offset, &params->sizeToRead, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;

    // Unmarshal offset
    rc = Unmarshal_UINT16(buffer + offset, bufferSize - offset, &params->offset, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;

    *bytesRead = offset;
    qemu_log("[UNMARSHAL] --- End TPM2_NV_Read (read %u bytes) ---\n", *bytesRead);
    return TPM_RC_SUCCESS;
}

#endif /* CC_UNMARSHAL_H */