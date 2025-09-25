#ifndef TPM2_NV_STRUCTS_H
#define TPM2_NV_STRUCTS_H

#include <stdint.h>

//
// Basic TPM 2.0 types
//
typedef uint32_t TPMI_NV_INDEX;    // NV Index handle
typedef uint16_t UINT16;           // 16-bit unsigned integer
typedef uint32_t TPMA_NV;          // NV Index attributes
typedef uint16_t TPMI_ALG_HASH;    // Hash algorithm identifier
typedef uint8_t  BYTE;             // 8-bit byte

#define MAX_NV_INDEX_SIZE 1024      // Platform-defined max NV Index size
#define TPM2B_DIGEST_SIZE 32        // Size of policy digest for most algorithms

//
// Authorization structure
//
typedef struct {
    UINT16 size;                    // Length of authValue
    BYTE buffer[64];                // Authorization value (password)
} TPM2B_AUTH;

//
// Public metadata for an NV Index
//
typedef struct {
    TPMI_NV_INDEX nvIndex;          // NV Index handle
    TPMI_ALG_HASH nameAlg;          // Hash algorithm for name / authPolicy
    TPMA_NV       attributes;       // NV Index attributes (TPMA_NV flags)
    BYTE          authPolicy[TPM2B_DIGEST_SIZE]; // Optional policy digest
    UINT16        dataSize;         // Size of NV storage in bytes
} TPMS_NV_PUBLIC;

//
// Optional structure for PIN counter NV Index types
//
typedef struct {
    UINT32 pinCount;                // Current count of successful/failed attempts
    UINT32 pinLimit;                // Lockout threshold
} TPMS_NV_PIN_COUNTER_PARAMETERS;

//
// NV Index in-memory representation (for QEMU)
// This structure combines the handle, public metadata, authorization, and storage.
// Used for simulating persistent NV memory.
//
typedef struct {
    TPMS_NV_PUBLIC nvPublic;        // NV Index public metadata
    TPM2B_AUTH     auth;            // Authorization value
    BYTE           *nvData;         // Pointer to storage bytes
    UINT8          written;         // TPMA_NV_WRITTEN flag (0 = never written)
    char           filename[256];   // Optional file for persistent NV storage
} TPM2_NV_INDEX_OBJECT;

#endif // TPM2_NV_STRUCTS_H
