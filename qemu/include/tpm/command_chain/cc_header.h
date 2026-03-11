#ifndef CC_HEADER_H
#define CC_HEADER_H

#include <stdint.h>
#include <stddef.h>
#include "../tpm2_base_types.h"
#include "../tpm2_rc.h"
#include "../tpm2_cc.h"
#include "../tpm2_device.h"

/******************************
 * CONSTANTS
 ******************************/

/* Minimum and maximum command sizes */
#define TPM_CMD_HEADER_SIZE      10U    /* tag(2) + size(4) + code(4) */
#define TPM_MIN_COMMAND_SIZE     10U    /* Minimum: just the header */
#define TPM_MAX_COMMAND_SIZE     4096U  /* Platform-dependent maximum */

/* Response code size */
#define TPM_RSP_HEADER_SIZE      10U    /* tag(2) + size(4) + code(4) */
#define TPM_MIN_RESPONSE_SIZE    10U    /* Minimum: just the header */
#define TPM_MAX_RESPONSE_SIZE    4096U  /* Platform-dependent maximum */

/******************************
 * DATA STRUCTURES
 ******************************/

/* Structure Tags for Commands and Responses */
typedef enum {
    TPM_ST_NULL              = 0x8000,  /* No structure present */
    TPM_ST_NO_SESSIONS       = 0x8001,  /* Command/Response with no sessions */
    TPM_ST_SESSIONS          = 0x8002,  /* Command/Response with sessions */
    TPM_ST_ATTEST_NV         = 0x8014,  /* TPM2B_ATTEST tag for NV */
    TPM_ST_ATTEST_COMMAND_AUDIT = 0x8015,
    TPM_ST_ATTEST_SESSION_AUDIT = 0x8016,
    TPM_ST_ATTEST_CERTIFY    = 0x8017,
    TPM_ST_ATTEST_QUOTE      = 0x8018,
    TPM_ST_ATTEST_TIME       = 0x8019,
    TPM_ST_ATTEST_CREATION   = 0x801A,
    TPM_ST_ATTEST_NV_DIGEST  = 0x801C,
    TPM_ST_CREATION          = 0x8021,  /* Tag for TPMS_CREATION_DATA */
    TPM_ST_VERIFIED          = 0x8022,  /* Tag for TPMT_TK_VERIFIED */
    TPM_ST_AUTH_SECRET       = 0x8023,  /* Tag for TPMT_TK_AUTH with secret */
    TPM_ST_HASHCHECK         = 0x8024,  /* Tag for TPMT_TK_HASHCHECK */
    TPM_ST_AUTH_SIGNED       = 0x8025,  /* Tag for TPMT_TK_AUTH with signature */
    TPM_ST_FU_MANIFEST       = 0x8029   /* Tag for firmware update manifest */
} TPMI_ST_COMMAND_TAG;

/* Marshaling/Unmarshaling error type */
typedef UINT32 TPM_RC_MARSH;

/* TPM Command Header */
typedef struct {
    UINT16 tag;         /* TPM_ST_NO_SESSIONS or TPM_ST_SESSIONS */
    UINT32 size;        /* Total command size in bytes */
    UINT32 code;        /* TPM_CC command code */
} TPM_CMD_HEADER;

/* TPM Response Header */
typedef struct {
    UINT16 tag;         /* TPM_ST_NO_SESSIONS or TPM_ST_SESSIONS */
    UINT32 size;        /* Total response size in bytes */
    UINT32 code;        /* TPM_RC response code */
} TPM_RSP_HEADER;

/******************************
 * FUNCTIONS
 ******************************/

/**
 * @brief Unmarshal and validate command tag
 * @param tag The tag value to validate
 * @return TPM_RC_SUCCESS if valid, TPM_RC_BAD_TAG otherwise
 */
static inline TPM_RC_MARSH UnmarshalCommandTag(UINT16 tag) {
    /* Valid command tags are TPM_ST_NO_SESSIONS and TPM_ST_SESSIONS */
    if (tag != TPM_ST_NO_SESSIONS && tag != TPM_ST_SESSIONS) {
        return TPM_RC_BAD_TAG;
    }
    return TPM_RC_SUCCESS;
}

/**
 * @brief Unmarshal and validate response tag
 * @param tag The tag value to validate
 * @return TPM_RC_SUCCESS if valid, TPM_RC_BAD_TAG otherwise
 */
static inline TPM_RC_MARSH UnmarshalResponseTag(UINT16 tag) {
    /* Valid response tags are TPM_ST_NO_SESSIONS and TPM_ST_SESSIONS */
    if (tag != TPM_ST_NO_SESSIONS && tag != TPM_ST_SESSIONS) {
        return TPM_RC_BAD_TAG;
    }
    return TPM_RC_SUCCESS;
}

/**
 * @brief Validate command size
 * @param commandSize The size field from command header
 * @return TPM_RC_SUCCESS if valid, TPM_RC_COMMAND_SIZE otherwise
 */
static inline TPM_RC_MARSH UnmarshalCommandSize(UINT32 commandSize) {
    /* Command size must be at least header size and not exceed maximum */
    if (commandSize < TPM_MIN_COMMAND_SIZE || 
        commandSize > TPM_MAX_COMMAND_SIZE) {
        return TPM_RC_COMMAND_SIZE;
    }
    return TPM_RC_SUCCESS;
}

/**
 * @brief Validate response size
 * @param responseSize The size field from response header
 * @return TPM_RC_SUCCESS if valid, TPM_RC_SIZE otherwise
 */
static inline TPM_RC_MARSH UnmarshalResponseSize(UINT32 responseSize) {
    /* Response size must be at least header size and not exceed maximum */
    if (responseSize < TPM_MIN_RESPONSE_SIZE || 
        responseSize > TPM_MAX_RESPONSE_SIZE) {
        return TPM_RC_SIZE;
    }
    return TPM_RC_SUCCESS;
}

/**
 * @brief Validate command code
 * @param commandCode The command code to validate
 * @return TPM_RC_SUCCESS if valid, TPM_RC_COMMAND_CODE otherwise
 */
static inline TPM_RC_MARSH UnmarshalCommandCode(UINT32 commandCode) {
    /* Check if command code is in valid range */
    /* TPM_CC_FIRST = 0x0000011F, TPM_CC_LAST = 0x0000019F */
    /* Vendor commands: 0x20000000 - 0x2FFFFFFF */
    
    if ((commandCode >= TPM_CC_FIRST && commandCode <= TPM_CC_LAST) ||
        (commandCode >= CC_VEND && commandCode <= 0x2FFFFFFF)) {
        return TPM_RC_SUCCESS;
    }
    
    return TPM_RC_COMMAND_CODE;
}

/**
 * @brief Unmarshal complete command header
 * @param buffer Pointer to buffer containing command
 * @param bufferSize Size of buffer
 * @param header Pointer to header structure to fill
 * @param bytesRead Pointer to store number of bytes consumed
 * @return TPM_RC_SUCCESS if valid, error code otherwise
 */
static inline TPM_RC_MARSH UnmarshalCommandHeader(
    const UINT8 *buffer,
    UINT32 bufferSize,
    TPM_CMD_HEADER *header,
    UINT32 *bytesRead)
{
    TPM_RC_MARSH rc;
    const UINT8 *ptr = buffer;
    
    /* Check minimum buffer size */
    if (bufferSize < TPM_CMD_HEADER_SIZE) {
        return TPM_RC_INSUFFICIENT;
    }
    
    /* Unmarshal tag (big-endian) */
    header->tag = ((UINT16)ptr[0] << 8) | (UINT16)ptr[1];
    ptr += 2;
    
    /* Validate tag */
    rc = UnmarshalCommandTag(header->tag);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
    
    /* Unmarshal size (big-endian) */
    header->size = ((UINT32)ptr[0] << 24) | 
                ((UINT32)ptr[1] << 16) |
                ((UINT32)ptr[2] << 8)  | 
                (UINT32)ptr[3];
    ptr += 4;
    
    /* Validate size */
    rc = UnmarshalCommandSize(header->size);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
     
    /* Check if size matches buffer size */
    if (header->size > bufferSize) {
        return TPM_RC_COMMAND_SIZE;
    }
    
    /* Unmarshal command code (big-endian) */
    header->code = ((UINT32)ptr[0] << 24) | 
                ((UINT32)ptr[1] << 16) |
                ((UINT32)ptr[2] << 8)  | 
                (UINT32)ptr[3];
    ptr += 4;
    
    /* Validate command code */
    rc = UnmarshalCommandCode(header->code);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
    
    *bytesRead = (UINT32)(ptr - buffer);
    return TPM_RC_SUCCESS;
}

/**
 * @brief Unmarshal complete response header
 * @param buffer Pointer to buffer containing response
 * @param bufferSize Size of buffer
 * @param header Pointer to header structure to fill
 * @param bytesRead Pointer to store number of bytes consumed
 * @return TPM_RC_SUCCESS if valid, error code otherwise
 */
static inline TPM_RC_MARSH UnmarshalResponseHeader(
    const UINT8 *buffer,
    UINT32 bufferSize,
    TPM_RSP_HEADER *header,
    UINT32 *bytesRead)
{
    TPM_RC_MARSH rc;
    const UINT8 *ptr = buffer;
    
    /* Check minimum buffer size */
    if (bufferSize < TPM_RSP_HEADER_SIZE) {
        return TPM_RC_INSUFFICIENT;
    }
    
    /* Unmarshal tag (big-endian) */
    header->tag = ((UINT16)ptr[0] << 8) | (UINT16)ptr[1];
    ptr += 2;
    
    /* Validate tag */
    rc = UnmarshalResponseTag(header->tag);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
    
    /* Unmarshal size (big-endian) */
    header->size = ((UINT32)ptr[0] << 24) | 
                ((UINT32)ptr[1] << 16) |
                ((UINT32)ptr[2] << 8)  | 
                (UINT32)ptr[3];
    ptr += 4;
    
    /* Validate size */
    rc = UnmarshalResponseSize(header->size);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
    
    /* Check if size matches buffer size */
    if (header->size > bufferSize) {
        return TPM_RC_SIZE;
    }
    
    /* Unmarshal response code (big-endian) */
    header->code = ((UINT32)ptr[0] << 24) | 
                ((UINT32)ptr[1] << 16) |
                ((UINT32)ptr[2] << 8)  | 
                (UINT32)ptr[3];
    ptr += 4;
    
    /* Response code validation is done by caller */
    
    *bytesRead = (UINT32)(ptr - buffer);
    return TPM_RC_SUCCESS;
}

/******************************
 * MARSHALING FUNCTIONS
 ******************************/

/**
 * @brief Marshal command header to buffer
 * @param buffer Pointer to output buffer
 * @param bufferSize Size of output buffer
 * @param header Pointer to header structure to marshal
 * @param bytesWritten Pointer to store number of bytes written
 * @return TPM_RC_SUCCESS if successful, error code otherwise
 */
static inline TPM_RC_MARSH MarshalCommandHeader(
    UINT8 *buffer,
    UINT32 bufferSize,
    const TPM_CMD_HEADER *header,
    UINT32 *bytesWritten)
{
    UINT8 *ptr = buffer;
    
    /* Check buffer size */
    if (bufferSize < TPM_CMD_HEADER_SIZE) {
        return TPM_RC_INSUFFICIENT;
    }
    
    /* Validate header fields */
    if (UnmarshalCommandTag(header->tag) != TPM_RC_SUCCESS) {
        return TPM_RC_BAD_TAG;
    }
    
    if (UnmarshalCommandSize(header->size) != TPM_RC_SUCCESS) {
        return TPM_RC_COMMAND_SIZE;
    }
    
    if (UnmarshalCommandCode(header->code) != TPM_RC_SUCCESS) {
        return TPM_RC_COMMAND_CODE;
    }
    
    /* Marshal tag (big-endian) */
    ptr[0] = (UINT8)(header->tag >> 8);
    ptr[1] = (UINT8)(header->tag & 0xFF);
    ptr += 2;
    
    /* Marshal size (big-endian) */
    ptr[0] = (UINT8)(header->size >> 24);
    ptr[1] = (UINT8)(header->size >> 16);
    ptr[2] = (UINT8)(header->size >> 8);
    ptr[3] = (UINT8)(header->size & 0xFF);
    ptr += 4;
    
    /* Marshal command code (big-endian) */
    ptr[0] = (UINT8)(header->code >> 24);
    ptr[1] = (UINT8)(header->code >> 16);
    ptr[2] = (UINT8)(header->code >> 8);
    ptr[3] = (UINT8)(header->code & 0xFF);
    ptr += 4;
    
    *bytesWritten = (UINT32)(ptr - buffer);
    return TPM_RC_SUCCESS;
}

/**
 * @brief Marshal response header to buffer
 * @param buffer Pointer to output buffer
 * @param bufferSize Size of output buffer
 * @param header Pointer to header structure to marshal
 * @param bytesWritten Pointer to store number of bytes written
 * @return TPM_RC_SUCCESS if successful, error code otherwise
 */
// static inline TPM_RC_MARSH MarshalResponseHeader(
//     UINT8 *buffer,
//     UINT32 bufferSize,
//     const TPM_RSP_HEADER *header,
//     UINT32 *bytesWritten)
// {
//     UINT8 *ptr = buffer;
    
//     /* Check buffer size */
//     if (bufferSize < TPM_RSP_HEADER_SIZE) {
//         return TPM_RC_INSUFFICIENT;
//     }
    
//     /* Validate header fields */
//     if (UnmarshalResponseTag(header->tag) != TPM_RC_SUCCESS) {
//         return TPM_RC_BAD_TAG;
//     }
    
//     if (UnmarshalResponseSize(header->size) != TPM_RC_SUCCESS) {
//         return TPM_RC_SIZE;
//     }
    
//     /* Marshal tag (big-endian) */
//     ptr[0] = (UINT8)(header->tag >> 8);
//     ptr[1] = (UINT8)(header->tag & 0xFF);
//     ptr += 2;
    
//     /* Marshal size (big-endian) */
//     ptr[0] = (UINT8)(header->size >> 24);
//     ptr[1] = (UINT8)(header->size >> 16);
//     ptr[2] = (UINT8)(header->size >> 8);
//     ptr[3] = (UINT8)(header->size & 0xFF);
//     ptr += 4;
    
//     /* Marshal response code (big-endian) */
//     ptr[0] = (UINT8)(header->code >> 24);
//     ptr[1] = (UINT8)(header->code >> 16);
//     ptr[2] = (UINT8)(header->code >> 8);
//     ptr[3] = (UINT8)(header->code & 0xFF);
//     ptr += 4;
    
//     *bytesWritten = (UINT32)(ptr - buffer);
//     return TPM_RC_SUCCESS;
// }

/******************************
 * UTILITY FUNCTIONS
 ******************************/

/**
 * @brief Check if tag indicates sessions are present
 * @param tag Structure tag
 * @return 1 if sessions present, 0 otherwise
 */
static inline int HasSessions(UINT16 tag) {
    return (tag == TPM_ST_SESSIONS) ? 1 : 0;
}

/**
 * @brief Get expected response tag for command tag
 * @param commandTag Command structure tag
 * @return Corresponding response tag
 */
static inline UINT16 GetResponseTag(UINT16 commandTag) {
    /* Response uses same tag as command */
    return commandTag;
}

/**
 * @brief Print command header (for debugging)
 * @param header Pointer to command header
 */
static inline void PrintCommandHeader(const TPM_CMD_HEADER *header) {
    /* This would require printf or similar - implement as needed */
    /* Example:
    printf("Command Header:\n");
    printf("  Tag:  0x%04X (%s)\n", header->tag, 
        header->tag == TPM_ST_SESSIONS ? "SESSIONS" : "NO_SESSIONS");
    printf("  Size: %u bytes\n", header->size);
    printf("  Code: 0x%08X\n", header->code);
    */
}

bool is_valid_cc_command(UINT32 commandCode);

int tpm_unpack_header (const uint8_t *buffer, size_t bufferSize, TPM_CMD_HEADER *header);

/*
 * Validates a TPM Command Header.
 * Returns TPM_RC_SUCCESS on success, or a TPM_RC_* error code on failure.
 */
UINT32 TPM2_ValidateCommandHeader (const UINT8 *cmdBuf, size_t bufSize, TPM_CMD_HEADER *hdr);

/*
 * Validates the TPM's operating mode based on the provided command header.
 * Returns TPM_RC_SUCCESS or a mode-specific TPM_RC_* error code.
 */
UINT32 TPM2_ValidateMode (TPM_CMD_HEADER *cmdHeader, TPM2State *TPM_State);

#endif /* CC_HEADER_H */