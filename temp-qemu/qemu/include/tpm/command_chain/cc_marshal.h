#ifndef CC_MARSHAL_H
#define CC_MARSHAL_H

#include <stdint.h>
#include <string.h>
#include "../tpm2_base_types.h"
#include "../tpm2_rc.h"
#include "../tpm2_interfaces.h"

/******************************
 * RESPONSE HEADER MARSHALING
 ******************************/

/**
 * @brief Marshal TPM response header
 */
static inline TPM_RC MarshalResponseHeader(
    UINT8 *buffer,
    UINT32 bufferSize,
    const TPM_RSP_HEADER *header,
    UINT32 *bytesWritten)
{
    if (!buffer || !header || !bytesWritten) {
        return TPM_RC_FAILURE;
    }
    
    if (bufferSize < TPM_RSP_HEADER_SIZE) {
        return TPM_RC_INSUFFICIENT;
    }
    
    // Marshal tag (2 bytes, big-endian)
    buffer[0] = (header->tag >> 8) & 0xFF;
    buffer[1] = header->tag & 0xFF;
    
    // Marshal size (4 bytes, big-endian)
    buffer[2] = (header->size >> 24) & 0xFF;
    buffer[3] = (header->size >> 16) & 0xFF;
    buffer[4] = (header->size >> 8) & 0xFF;
    buffer[5] = header->size & 0xFF;
    
    // Marshal response code (4 bytes, big-endian)
    buffer[6] = (header->code >> 24) & 0xFF;
    buffer[7] = (header->code >> 16) & 0xFF;
    buffer[8] = (header->code >> 8) & 0xFF;
    buffer[9] = header->code & 0xFF;
    
    *bytesWritten = TPM_RSP_HEADER_SIZE;
    return TPM_RC_SUCCESS;
}

/******************************
 * BASIC MARSHALING FUNCTIONS
 ******************************/

/**
 * @brief Marshal UINT8 to buffer
 */
static inline TPM_RC Marshal_UINT8(
    UINT8 *buffer,
    UINT32 bufferSize,
    UINT8 value,
    UINT32 *bytesWritten)
{
    if (!buffer || !bytesWritten) {
        return TPM_RC_FAILURE;
    }
    
    if (bufferSize < 1) {
        return TPM_RC_INSUFFICIENT;
    }
    
    buffer[0] = value;
    *bytesWritten = 1;
    return TPM_RC_SUCCESS;
}

/**
 * @brief Marshal UINT16 to buffer (big-endian)
 */
static inline TPM_RC Marshal_UINT16(
    UINT8 *buffer,
    UINT32 bufferSize,
    UINT16 value,
    UINT32 *bytesWritten)
{
    if (!buffer || !bytesWritten) {
        return TPM_RC_FAILURE;
    }
    
    if (bufferSize < 2) {
        return TPM_RC_INSUFFICIENT;
    }
    
    buffer[0] = (UINT8)(value >> 8);
    buffer[1] = (UINT8)(value & 0xFF);
    *bytesWritten = 2;
    return TPM_RC_SUCCESS;
}

/**
 * @brief Marshal UINT32 to buffer (big-endian)
 */
static inline TPM_RC Marshal_UINT32(
    UINT8 *buffer,
    UINT32 bufferSize,
    UINT32 value,
    UINT32 *bytesWritten)
{
    if (!buffer || !bytesWritten) {
        return TPM_RC_FAILURE;
    }
    
    if (bufferSize < 4) {
        return TPM_RC_INSUFFICIENT;
    }
    
    buffer[0] = (UINT8)(value >> 24);
    buffer[1] = (UINT8)(value >> 16);
    buffer[2] = (UINT8)(value >> 8);
    buffer[3] = (UINT8)(value & 0xFF);
    *bytesWritten = 4;
    return TPM_RC_SUCCESS;
}

/**
 * @brief Marshal UINT64 to buffer (big-endian)
 */
static inline TPM_RC Marshal_UINT64(
    UINT8 *buffer,
    UINT32 bufferSize,
    UINT64 value,
    UINT32 *bytesWritten)
{
    if (!buffer || !bytesWritten) {
        return TPM_RC_FAILURE;
    }
    
    if (bufferSize < 8) {
        return TPM_RC_INSUFFICIENT;
    }
    
    buffer[0] = (UINT8)(value >> 56);
    buffer[1] = (UINT8)(value >> 48);
    buffer[2] = (UINT8)(value >> 40);
    buffer[3] = (UINT8)(value >> 32);
    buffer[4] = (UINT8)(value >> 24);
    buffer[5] = (UINT8)(value >> 16);
    buffer[6] = (UINT8)(value >> 8);
    buffer[7] = (UINT8)(value & 0xFF);
    *bytesWritten = 8;
    return TPM_RC_SUCCESS;
}

/**
 * @brief Marshal TPM2B structure (size-prefixed buffer)
 */
static inline TPM_RC Marshal_TPM2B(
    UINT8 *buffer,
    UINT32 bufferSize,
    const UINT8 *dataBuffer,
    UINT16 dataSize,
    UINT32 *bytesWritten)
{
    if (!buffer || !bytesWritten) {
        return TPM_RC_FAILURE;
    }
    
    TPM_RC rc;
    UINT32 offset = 0;
    UINT32 consumed;
    
    // Marshal size
    rc = Marshal_UINT16(buffer + offset, bufferSize - offset, dataSize, &consumed);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
    offset += consumed;
    
    // Check buffer space
    if (bufferSize - offset < dataSize) {
        return TPM_RC_INSUFFICIENT;
    }
    
    // Copy data
    if (dataBuffer && dataSize > 0) {
        memcpy(buffer + offset, dataBuffer, dataSize);
    }
    offset += dataSize;
    
    *bytesWritten = offset;
    return TPM_RC_SUCCESS;
}

/******************************
 * RESPONSE-SPECIFIC MARSHALING
 ******************************/

/**
 * @brief Marshal TPM2_GetRandom response
 */
static inline TPM_RC Marshal_GetRandom_Response(
    UINT8 *buffer,
    UINT32 bufferSize,
    const UINT8 *randomBytes,
    UINT16 randomSize,
    UINT32 *bytesWritten)
{
    // Response format: TPM2B_DIGEST randomBytes
    return Marshal_TPM2B(buffer, bufferSize, randomBytes, randomSize, bytesWritten);
}

/**
 * @brief Marshal TPM2_CreatePrimary response
 */
typedef struct {
    UINT32 objectHandle;         // New object handle
    UINT16 outPublicSize;        // TPM2B_PUBLIC size
    UINT8  outPublic[512];       // TPM2B_PUBLIC data
    UINT16 creationDataSize;     // TPM2B_CREATION_DATA size
    UINT8  creationData[256];    // TPM2B_CREATION_DATA
    UINT16 creationHashSize;     // TPM2B_DIGEST size
    UINT8  creationHash[64];     // TPM2B_DIGEST
    UINT16 creationTicketTag;    // TPMT_TK_CREATION.tag
    UINT32 creationTicketHierarchy;
    UINT16 creationTicketDigestSize;
    UINT8  creationTicketDigest[64];
    UINT16 nameSize;             // TPM2B_NAME size
    UINT8  name[64];             // TPM2B_NAME
} CreatePrimary_Response;

static inline TPM_RC Marshal_CreatePrimary_Response(
    UINT8 *buffer,
    UINT32 bufferSize,
    const CreatePrimary_Response *response,
    UINT32 *bytesWritten)
{
    if (!buffer || !response || !bytesWritten) {
        return TPM_RC_FAILURE;
    }
    
    TPM_RC rc;
    UINT32 offset = 0;
    UINT32 consumed;
    
    // Marshal objectHandle
    rc = Marshal_UINT32(buffer + offset, bufferSize - offset,
                       response->objectHandle, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    // Marshal outPublic (TPM2B)
    rc = Marshal_TPM2B(buffer + offset, bufferSize - offset,
                      response->outPublic, response->outPublicSize, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    // Marshal creationData (TPM2B)
    rc = Marshal_TPM2B(buffer + offset, bufferSize - offset,
                      response->creationData, response->creationDataSize, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    // Marshal creationHash (TPM2B)
    rc = Marshal_TPM2B(buffer + offset, bufferSize - offset,
                      response->creationHash, response->creationHashSize, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    // Marshal creationTicket
    rc = Marshal_UINT16(buffer + offset, bufferSize - offset,
                       response->creationTicketTag, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    rc = Marshal_UINT32(buffer + offset, bufferSize - offset,
                       response->creationTicketHierarchy, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    rc = Marshal_TPM2B(buffer + offset, bufferSize - offset,
                      response->creationTicketDigest,
                      response->creationTicketDigestSize, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    // Marshal name (TPM2B)
    rc = Marshal_TPM2B(buffer + offset, bufferSize - offset,
                      response->name, response->nameSize, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;
    
    *bytesWritten = offset;
    return TPM_RC_SUCCESS;
}

/**
 * @brief Marshal TPM2_NV_DefineSpace response (empty body, just header)
 */
static inline TPM_RC Marshal_NV_DefineSpace_Response(
    UINT8 *buffer,
    UINT32 bufferSize,
    UINT32 *bytesWritten)
{
    (void)buffer;
    (void)bufferSize;
    
    // NV_DefineSpace has no response body (just the header with RC)
    *bytesWritten = 0;
    return TPM_RC_SUCCESS;
}

// Helper to marshal TPM2B_MAX_NV_BUFFER
static inline TPM_RC Marshal_TPM2B_MAX_NV_BUFFER(
    UINT8 *buffer, UINT32 bufferSize,
    const TPM2B_MAX_NV_BUFFER *source, UINT32 *bytesWritten)
{
    if (!buffer || !source || !bytesWritten) {
        return TPM_RC_FAILURE;
    }
    
    TPM_RC rc;
    UINT32 offset = 0;
    UINT32 consumed;

    rc = Marshal_UINT16(buffer + offset, bufferSize - offset, source->size, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;

    if (source->size > MAX_NV_BUFFER_SIZE) return TPM_RC_SIZE;
    if (bufferSize - offset < source->size) return TPM_RC_INSUFFICIENT;

    memcpy(buffer + offset, source->buffer, source->size);
    offset += source->size;

    *bytesWritten = offset;
    return TPM_RC_SUCCESS;
}


static inline TPM_RC Marshal_NV_Read_Response(
    UINT8 *buffer, UINT32 bufferSize,
    const NV_Read_Response *response, UINT32 *bytesWritten)
{
    if (!buffer || !response || !bytesWritten) {
        return TPM_RC_FAILURE;
    }
    
    TPM_RC rc;
    UINT32 offset = 0;
    UINT32 consumed;

    // Marshal data
    rc = Marshal_TPM2B_MAX_NV_BUFFER(buffer + offset, bufferSize - offset, &response->data, &consumed);
    if (rc != TPM_RC_SUCCESS) return rc;
    offset += consumed;

    *bytesWritten = offset;
    return TPM_RC_SUCCESS;
}


#endif /* CC_MARSHAL_H */