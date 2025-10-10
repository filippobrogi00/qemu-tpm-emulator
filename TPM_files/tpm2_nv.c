#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <glib.h>

/* TPM headers */
#include "headers/tpm2_algorithms.h"
#include "headers/tpm2_alg_structs.h"
#include "headers/tpm2_base_types.h"
#include "headers/tpm2_handles.h"
#include "headers/tpm2_nv.h"
#include "headers/tpm2_rc.h"
#include "headers/tpm2_structures.h"
#include "headers/tpm2_nv_entry.h"
#include "headers/tpm2_interfaces.h"   /* <-- add this line */

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


typedef struct TPM2State {

    /* ---- Stub fields replacing QEMU device internals ---- */
    void *parent_obj;         /* placeholder for SysBusDevice */
    void *mmio;               /* placeholder for MemoryRegion */
    void *irq;                /* placeholder for qemu_irq */

    /* ---- NV Storage memory region ---- */
    void     *nv_bank_mem;    /* placeholder for MemoryRegion */
    uint8_t  *nv_bank_ptr;    /* simulated NV memory buffer */
    uint32_t  nv_bank_size;   /* NV storage size (bytes) */

    /* In-RAM NV index map */
    GHashTable *nv_map;       /* key: GUINT_TO_POINTER(nvIndex) -> NvEntry* */
    uint32_t    nv_count;     /* number of NV entries */
    bool        nv_dirty;     /* “needs flush to bank” flag */

    /* ---- TPM control state ---- */
    uint32_t ctrl;
    uint32_t status;
    uint32_t key_generated;

    /* ---- Simplified RSA placeholder ---- */
    void *rsa_key;            /* RSA* in QEMU version; unused here */

    /* ---- Random data buffer ---- */
    uint8_t random_data[32];

} TPM2State;

/* ---------------------------------------------------------------------
 * Minimal TPM feature stubs for standalone build
 * -------------------------------------------------------------------*/
static inline bool impl_supports_counter(TPM2State *s) { (void)s; return true; }
static inline bool impl_supports_setbits(TPM2State *s) { (void)s; return true; }
static inline bool impl_supports_undefine_policy_delete(TPM2State *s) { (void)s; return true; }

/* NV entry allocation & persistence stubs */
static inline NVEntry *nv_entry_alloc(TPM_NV_INDEX index, uint16_t dataSize,
                                      uint16_t nameAlg, TPMA_NV attrs,
                                      const void *auth)
{
    (void)index; (void)nameAlg; (void)attrs; (void)auth;
    NVEntry *e = g_malloc0(sizeof(NVEntry));
    e->data = g_malloc0(dataSize);
    e->dataLen = dataSize;
    e->written = false; /* per spec: starts uninitialized */
    return e;
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
    NVEntry *e = nv_entry_alloc(index, dataSize, nameAlg, attrs, auth);
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

    return rc;
}





#ifdef TEST_MAIN
int main(void)
{
    /* --- Initialize simulated TPM state --- */
    TPM2State s = {0};
    s.nv_map = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    s.nv_bank_size = 4096;

    /* --- Common NV attributes --- */
    TPMA_NV attrs = {0};
    attrs.platformCreate = 1;
    attrs.ppRead  = 1;
    attrs.ppWrite = 1;

    TPM2B_AUTH auth = {0};
    auth.size = 4;
    memcpy(auth.buffer, "abcd", 4);

    /* --- Helper for creating NV publics --- */
    TPM2B_NV_PUBLIC pub = {0};
    pub.nvPublic.nameAlg   = 0x000B;  /* SHA-256 */
    pub.nvPublic.attributes = attrs;
    pub.nvPublic.dataSize   = 8;

    /* --- 1) Define a valid NV space --- */
    pub.nvPublic.nvIndex = 0x01000001;
    TPM_RC rc = tpm2_nv_define_space(&s, (uint32_t)TPM_RH_PLATFORM, &auth, &pub);
    printf("Test 1: Define first NV index -> RC=0x%X\n", rc);

    /* --- 2) Attempt to redefine the same index (should fail) --- */
    rc = tpm2_nv_define_space(&s, TPM_RH_PLATFORM, &auth, &pub);
    printf("Test 2: Redefine same index -> RC=0x%X (expect TPM_RC_NV_DEFINED)\n", rc);

    /* --- 3) Define a few more indices to reach max slots --- */
    for (int i = 2; i <= TPM2_MAX_NV_INDEXES + 1; ++i) {
        pub.nvPublic.nvIndex = 0x01000000 + i;
        rc = tpm2_nv_define_space(&s, (uint32_t)TPM_RH_PLATFORM, &auth, &pub);
        printf("Test 3.%d: Define index 0x%08X -> RC=0x%X\n",
               i, pub.nvPublic.nvIndex, rc);
    }

    /* --- 4) Try oversize data (should return TPM_RC_SIZE) --- */
    pub.nvPublic.nvIndex = 0x0100A001;
    pub.nvPublic.dataSize = s.nv_bank_size + 1;
    rc = tpm2_nv_define_space(&s, TPM_RH_PLATFORM, &auth, &pub);
    printf("Test 4: Oversized NV space -> RC=0x%X (expect TPM_RC_SIZE)\n", rc);

    /* --- 5) Show NV map summary --- */
    printf("Total NV entries defined: %u\n", s.nv_count);

    /* --- Cleanup --- */
    g_hash_table_destroy(s.nv_map);
    return 0;
}
#endif