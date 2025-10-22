#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <glib.h>

#include "qemu/osdep.h"
#include "qemu/log.h"
/* TPM headers */
#include "tpm/tpm2_device.h"
#include "tpm/tpm2_nv.h"
#include "tpm/tpm2_nv_entry.h"
#include "tpm/tpm2_rc.h"
#include "tpm/tpm2_structures.h"
#include "tpm/tpm2_interfaces.h" 
#include "tpm/tpm2_handles.h"
//#include "headers/tpm2_device.h"

/* ---------------------------------------------------------------------
 * Constants required for compilation
 * -------------------------------------------------------------------*/
#ifndef TPM2_MAX_NV_INDEXES
#define TPM2_MAX_NV_INDEXES 16
#endif

#ifndef TPM2_NVSTORAGE_SIZE
#define TPM2_NVSTORAGE_SIZE 6962
#endif

#ifndef MAX_NV_BUFFER_SIZE
#define MAX_NV_BUFFER_SIZE 1024
#endif

#ifndef TPMI_RH_NV_INDEX_NV_FIRST
#define TPMI_RH_NV_INDEX_NV_FIRST 0x01000000
#endif

#ifndef TPMI_RH_NV_INDEX_PERMANENT_LAST
#define TPMI_RH_NV_INDEX_PERMANENT_LAST 0x03FFFFFF
#endif


/* ---------------------------------------------------------------------
 * Minimal TPM feature stubs for standalone build
 * -------------------------------------------------------------------*/
static inline bool impl_supports_counter(TPM2State *s) { (void)s; return true; }
static inline bool impl_supports_setbits(TPM2State *s) { (void)s; return true; }
static inline bool impl_supports_undefine_policy_delete(TPM2State *s) { (void)s; return true; }

/* NV entry allocation & persistence stubs */

static NVEntry *nv_entry_alloc(TPM2State *s,
                               TPM_NV_INDEX index,
                               uint16_t dataSize,
                               uint16_t nameAlg,
                               TPMA_NV attrs,
                               const void *auth)
{
    if (!s || !s->nv_bank_ptr) {
        TPM2_LOG("nv_entry_alloc: NV bank not initialized\n");
        return NULL;
    }

    /* Check space in NV bank */
    if (s->nv_alloc_offset + dataSize > s->nv_bank_size) {
        TPM2_LOG("nv_entry_alloc: NV bank full (need=%u bytes)\n", dataSize);
        return NULL;
    }

    NVEntry *e = g_malloc0(sizeof(NVEntry));

    e->pub.nvIndex    = index;
    e->pub.nameAlg    = nameAlg;
    e->pub.attributes = attrs;
    e->pub.dataSize   = dataSize;
    memset(e->pub.authPolicy, 0, sizeof(e->pub.authPolicy));

    /* Assign a slice of the NV bank */
    e->data    = s->nv_bank_ptr + s->nv_alloc_offset;
    e->dataLen = dataSize;
    memset(e->data, 0, e->dataLen);

    /* Advance allocation cursor */
    s->nv_alloc_offset += dataSize;

    e->written      = false;
    e->readLocked   = false;
    e->writeLocked  = false;

    TPM2_LOG("nv_entry_alloc: index=0x%08X offset=%zu size=%u\n",
             index, s->nv_alloc_offset - dataSize, dataSize);

    return e;
}


/* Free an NVEntry and its associated data */
static inline void nv_entry_free(NVEntry *e)
{
    if (!e)
        return;
    if (e->data)
        e->data = NULL;  // owned by NV bank

    g_free(e);
}

static inline bool tpm2_nv_flush_dirty(TPM2State *s)
{
    (void)s;
    return true;
}

/* ---------------------------------------------------------------------
 * TPM2_NV_DefineSpace Response Struct (per spec §31.3.2.4)
 * -------------------------------------------------------------------*/
typedef struct {
    uint16_t tag;         /* 0x8001 = TPM_ST_NO_SESSIONS */
    UINT32 responseSize;
    TPM_RC responseCode;
} TPM2_NV_DefineSpace_Resp;

/* ---------------------------------------------------------------------
 * NV attribute helpers
 * -------------------------------------------------------------------*/
static inline UINT8 nv_index_type(TPMA_NV attrs)
{
    return (UINT8)(attrs.nvType);
}

static inline bool any_read_bit(TPMA_NV a)
{
    return (a.ppRead || a.ownerRead || a.authRead || a.policyRead);
}

static inline bool any_write_bit(TPMA_NV a)
{
    return (a.ppWrite || a.ownerWrite || a.authWrite || a.policyWrite);
}

/* ---------------------------------------------------------------------
 * TPM2_NV_DefineSpace implementation (Part 3 §31.3)
 * -------------------------------------------------------------------*/
TPM_RC tpm2_nv_define_space(TPM2State *s,
                            TPMI_RH_PROVISION authHandle,
                            const TPM2B_AUTH *auth,         /* new index auth */
                            const TPM2B_NV_PUBLIC *public)
{
    const TPMS_NV_PUBLIC *nv = &public->nvPublic;
    const TPM_NV_INDEX index = nv->nvIndex;
    const uint16_t nameAlg = nv->nameAlg;
    const TPMA_NV attrs = nv->attributes;
    const UINT16 dataSize = nv->dataSize;
    const UINT8 nvt = nv_index_type(attrs);

    /* 1) Validate index range */
    /*if (nv->nvIndex < TPMI_RH_NV_INDEX_NV_FIRST ||
        authHandle > TPMI_RH_NV_INDEX_PERMANENT_LAST)
        return TPM_RC_VALUE;

    /* 2) Validate data size */
    if (nv->nvIndex == 0 || dataSize > TPM2_NVSTORAGE_SIZE)
        return TPM_RC_SIZE;

    /* 3) Already defined? */
    if (g_hash_table_contains(s->nv_map, GINT_TO_POINTER(index)))
        return TPM_RC_NV_DEFINED;

    /* 4) Check available NV slots */
    if (s->nv_count >= TPM2_MAX_NV_INDEXES)
        return TPM_RC_NV_SPACE;

    /* 5) Invalid or reserved bits */
    if (attrs.written || attrs.readLocked || attrs.writeLocked)
        return TPM_RC_ATTRIBUTES;

    /* 6) Reserved nvType values (beyond TPM_NT_PIN_PASS) */
    if (nvt > TPM_NT_PIN_PASS)
        return TPM_RC_ATTRIBUTES;

    /* 7) Must have at least one READ and one WRITE bit set */
    if (!any_read_bit(attrs))
        return TPM_RC_ATTRIBUTES;
    if (!any_write_bit(attrs))
        return TPM_RC_ATTRIBUTES;

    /* 8) PLATFORMCREATE rules */
    const bool platformAuth = (authHandle.platform == TPM_RH_PLATFORM);
    if (platformAuth) {
        if (!attrs.platformCreate)
            return TPM_RC_ATTRIBUTES;
    } else {
        if (attrs.platformCreate)
            return TPM_RC_ATTRIBUTES;
    }

    /* 9) POLICY_DELETE requires platform authorization */
    if (attrs.policyDelete && !platformAuth)
        return TPM_RC_ATTRIBUTES;

    /* 10) Type-specific attribute rules (EXTEND removed) */
    switch (nvt) {
    case TPM_NT_COUNTER:
        if (!impl_supports_counter(s))
            return TPM_RC_ATTRIBUTES;
        if (attrs.clearStClear)
            return TPM_RC_ATTRIBUTES;
        if (dataSize != 8)
            return TPM_RC_SIZE;
        break;

    case TPM_NT_BITS:
        if (!impl_supports_setbits(s))
            return TPM_RC_ATTRIBUTES;
        if (dataSize != 8)
            return TPM_RC_SIZE;
        break;

    case TPM_NT_PIN_FAIL:
        if (!attrs.noDA)
            return TPM_RC_ATTRIBUTES;
        if (dataSize != 8)
            return TPM_RC_SIZE;
        if (attrs.authWrite)
            return TPM_RC_ATTRIBUTES;
        if (!(attrs.ppWrite || attrs.ownerWrite || attrs.policyWrite))
            return TPM_RC_ATTRIBUTES;
        break;

    case TPM_NT_PIN_PASS:
        if (dataSize != 8)
            return TPM_RC_SIZE;
        if (attrs.authWrite)
            return TPM_RC_ATTRIBUTES;
        if (!(attrs.ppWrite || attrs.ownerWrite || attrs.policyWrite))
            return TPM_RC_ATTRIBUTES;
        break;

    default:
        /* ordinary index */
        break;
    }

    /* 11) Ordinary index WRITEALL constraint */
    const bool is_ordinary = (nvt == TPM_NT_ORDINARY) || (nvt == 0);
    if (is_ordinary) {
        if (dataSize > s->nv_bank_size)
            return TPM_RC_SIZE;
        if (attrs.writeAll && (dataSize > MAX_NV_BUFFER_SIZE))
            return TPM_RC_SIZE;
    }

    /* 12) POLICY_DELETE requires support */
    if (attrs.policyDelete && !impl_supports_undefine_policy_delete(s))
        return TPM_RC_ATTRIBUTES;

    /* 13) Create new NV entry */
    NVEntry *e = nv_entry_alloc(s,index, dataSize, nameAlg, attrs, auth);
    if (!e)
        return TPM_RC_MEMORY;

    /* 14) Insert and mark dirty */
    g_hash_table_insert(s->nv_map, GINT_TO_POINTER(index), e);
    s->nv_count++;
    s->nv_dirty = true;

    /* 15) Persist immediately */
    TPM_RC rc = TPM_RC_SUCCESS;
    if (!tpm2_nv_flush_dirty(s))
        rc = TPM_RC_NV_SPACE;

    /* 16) Build TPM response structure (per spec) */
    TPM2_NV_DefineSpace_Resp resp = {
        .tag = 0x8001,             /* TPM_ST_NO_SESSIONS */
        .responseSize = sizeof(TPM2_NV_DefineSpace_Resp),
        .responseCode = rc
    };

    /* In real TPM this would be marshaled into response buffer */
    printf("[TPM2_NV_DefineSpace] tag=0x%04X size=%u rc=0x%X\n",
           resp.tag, resp.responseSize, resp.responseCode);

    return rc; //change this to response buffer in real implementation
}

/* --------------------------------------------------------------------- */
void tpm2_nv_init(TPM2State *s)
{
    if (!s) {
        TPM2_LOG("Error: TPM2State pointer is NULL\n");
        return;
    }

    if (s->nv_map) {
        TPM2_LOG("NV subsystem already initialized\n");
        return;
    }

    /* Allocate GLib hash table to map NV indices → NVEntry* */
    s->nv_map = g_hash_table_new_full(
        g_direct_hash,           /* key hash */
        g_direct_equal,          /* key equality */
        NULL,                    /* no key destructor */
        (GDestroyNotify)nv_entry_free /* free NVEntry on removal */
    );

    if (!s->nv_map) {
        TPM2_LOG("Failed to allocate NV map (out of memory)\n");
        return;
    }

    s->nv_count = 0;
    s->nv_dirty = false;
    s->nv_bank_size = TPM2_NVSTORAGE_SIZE;
    s->nv_alloc_offset = 0;   // Start of the NV bank


    TPM2_LOG("NV subsystem initialized (bank size=%u)\n", s->nv_bank_size);
}

/*
 * Cleanup all NV entries and free resources.
 * Safe to call multiple times.
 */
void tpm2_nv_cleanup(TPM2State *s)
{
    if (!s) {
        TPM2_LOG("Error: TPM2State pointer is NULL\n");
        return;
    }

    if (s->nv_map) {
        g_hash_table_remove_all(s->nv_map);
        g_hash_table_destroy(s->nv_map);
        s->nv_map = NULL;
        TPM2_LOG("NV subsystem cleaned up\n");
    }

    s->nv_count = 0;
    s->nv_dirty = false;
}


static TPM_RC nv_write_crypt_to_bank(TPM2State *s, NVEntry *e,
                                      const uint8_t *plain, uint16_t len, uint16_t offset)
{
    if (!e || !plain) return TPM_RC_FAILURE;
    if (offset + len > e->pub.dataSize) return TPM_RC_SIZE;

    /* Optional: re-roll IV on each write for stronger forward secrecy */
    uint8_t *iv_ptr = nv_bank_at(s, e->data_off - 16); //This is the iv pointer in the bank. We need to maintain it
    //in memory so that when decrypting. it returns the correct data.
    if (RAND_bytes(e->iv, 16) != 1) {
        TPM2_LOG("[NV] RAND_bytes(IV) failed on write\n");
        return TPM_RC_FAILURE;
    }
    
    memcpy(iv_ptr, e->iv, 16);

    /* Encrypt in place from plaintext into bank ciphertext region */
    uint8_t *ct = e->data + offset; //this is the crypted cypterhtext point from NV bank
    int outlen = TPM2_AES_CFB_Crypt(s->master_key, s->master_key_len,
                                    iv_ptr, plain, len, ct, 1);
    if (outlen <= 0) {
        TPM2_LOG("[NV] Encrypt failed on write\n");
        return TPM_RC_FAILURE;
    }
    e->written = true;
    return TPM_RC_SUCCESS;
}





