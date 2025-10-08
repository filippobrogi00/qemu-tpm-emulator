#include "tpm/tpm2_nv.h"
#include "tpm/tpm2_handles.h"
#include "tpm/tpm2_device.h"
#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/units.h"
#include "hw/sysbus.h"
#include <string.h>


/* Response for TPM2_NV_DefineSpace */
typedef struct {
    TPM_ST tag;
    UINT32 responseSize;
    TPM_RC responseCode;
} TPM2_NV_DefineSpace_Resp;


static inline UINT8 nv_index_type(TPMA_NV attrs) {
    return (UINT8)(attrs & 0x0F);   /* TPMA_NV_TPM_NT field per spec */
}

//This needs to chweck if any of the read/write bits are set.
//For defining space, at least one read and one write bit must be set.
static inline bool any_read_bit(TPMA_NV a) {
    return ( (a & TPMA_NV_PPREAD) ||
             (a & TPMA_NV_OWNERREAD) ||
             (a & TPMA_NV_AUTHREAD) ||
             (a & TPMA_NV_POLICYREAD) );
}
static inline bool any_write_bit(TPMA_NV a) {
    return ( (a & TPMA_NV_PPWRITE) ||
             (a & TPMA_NV_OWNERWRITE) ||
             (a & TPMA_NV_AUTHWRITE) ||
             (a & TPMA_NV_POLICYWRITE) );
}



TPM_RC tpm2_nv_define_space(TPM2State *s,
                            TPMI_RH_PROVISION authHandle,
                            const TPM2B_AUTH     *auth,         /* new index auth */
                            const TPM2B_NV_PUBLIC *public 
                              ){


     //Missing authorization hierearchy handle                           
    const TPM_NV_PUBLIC *nv = &public->nvPublic;
    const TPM_NV_INDEX   index = nv->nvIndex;
    const TPMI_ALG_HASH  nameAlg = nv->nameAlg;
    const TPMA_NV        attrs = nv->attributes;
    const UINT16         dataSize = nv->dataSize;
    const UINT8          nvt = nv_index_type(attrs);

    if(public->nvIndex < TPMI_RH_NV_INDEX_NV_FIRST || authHandle > TPMI_RH_NV_INDEX_PERMANENT_LAST){
        return TPM_RC_VALUE;
    }


    if(public->nvIndex == 0 || nvSize > TPM2_NVSTORAGE_SIZE){
        return TPM_RC_SIZE;
    }
    
    if(g_hash_table_contains(s->nv_map, GINT_TO_POINTER(index))) {
        return TPM_RC_NV_DEFINED;
    }

    if(s->nv_count >= TPM2_MAX_NV_INDEXES){
        return TPM_RC_NV_SPACE;
    }

     

    /* 2) Reserved / invalid attributes (spec requires certain bits CLEAR at creation) */
    if ((attrs & TPMA_NV_WRITTEN) || (attrs & TPMA_NV_READLOCKED) || (attrs & TPMA_NV_WRITELOCKED)) {
        return TPM_RC_ATTRIBUTES;
    }

    /* 3) At least one READ bit and at least one WRITE bit must be set */
    //if (!any_read_bit(attrs))  return TPM_RC_ATTRIBUTES;
    //if (!any_write_bit(attrs)) return TPM_RC_ATTRIBUTES;

    /* 4) PLATFORMCREATE must match the authorizing hierarchy */
    const bool platformAuth = (authHandle == TPM_RH_PLATFORM);
    if (platformAuth) {
        if (!(attrs & TPMA_NV_PLATFORMCREATE)) return TPM_RC_ATTRIBUTES;
    } else { /* owner auth */
        if (attrs & TPMA_NV_PLATFORMCREATE)   return TPM_RC_ATTRIBUTES;
    }

    /* 5) POLICY_DELETE requires platform authorization */
    if ((attrs & TPMA_NV_POLICY_DELETE) && !platformAuth) {
        return TPM_RC_ATTRIBUTES;
    }



    /* 6) Type-specific rules */
    switch (nvt) {
    case TPM_NT_COUNTER:
        if (!impl_supports_counter(s)) return TPM_RC_ATTRIBUTES;
        if (attrs & TPMA_NV_CLEAR_STCLEAR)     return TPM_RC_ATTRIBUTES;
        if (dataSize != 8)                     return TPM_RC_SIZE;
        break;
    case TPM_NT_BITS:
        if (!impl_supports_setbits(s))         return TPM_RC_ATTRIBUTES;
        if (dataSize != 8)                     return TPM_RC_SIZE;
        break;
    case TPM_NT_EXTEND: {
        if (!impl_supports_extend(s))          return TPM_RC_ATTRIBUTES;
        uint16_t dsz = tpm2_digest_size(nameAlg);
        if (!dsz)                               return TPM_RC_HASH;
        if (dataSize != dsz)                    return TPM_RC_SIZE;
        break;
    }
    case TPM_NT_PIN_FAIL:
        if (!(attrs & TPMA_NV_NO_DA))          return TPM_RC_ATTRIBUTES;
        if (dataSize != 8)                     return TPM_RC_SIZE;
        if (attrs & TPMA_NV_AUTHWRITE)         return TPM_RC_ATTRIBUTES;
        if (!((attrs & TPMA_NV_PPWRITE) || (attrs & TPMA_NV_OWNERWRITE) || (attrs & TPMA_NV_POLICYWRITE)))
            return TPM_RC_ATTRIBUTES;
        break;
    case TPM_NT_PIN_PASS:
        if (dataSize != 8)                     return TPM_RC_SIZE;
        if (attrs & TPMA_NV_AUTHWRITE)         return TPM_RC_ATTRIBUTES;
        if (!((attrs & TPMA_NV_PPWRITE) || (attrs & TPMA_NV_OWNERWRITE) || (attrs & TPMA_NV_POLICYWRITE)))
            return TPM_RC_ATTRIBUTES;
        break;
    default:
        /* ordinary index; further limits checked below */
        break;
    }

    /* 7) Ordinary index size / WRITEALL vs MAX_NV_BUFFER_SIZE */
    const bool is_ordinary = (nvt == TPM_NT_ORDINARY) || (nvt == 0);
    if (is_ordinary) {
        if (dataSize > s->nv_bank_size)        return TPM_RC_SIZE;
        if ((attrs & TPMA_NV_WRITEALL) && (dataSize > MAX_NV_BUFFER_SIZE))
            return TPM_RC_SIZE;
    }

    /* 8) If UndefineSpaceSpecial not supported, forbid POLICY_DELETE */
    if ((attrs & TPMA_NV_POLICY_DELETE) && !impl_supports_undefine_policy_delete(s)) {
        return TPM_RC_ATTRIBUTES;
    }

    /* 9) auth->size <= digest size(nameAlg) */
    {
        uint16_t dsz = tpm2_digest_size(nameAlg);
        if (!dsz)                               return TPM_RC_HASH;
        if (auth->size > dsz)                   return TPM_RC_SIZE;
    }

    /* 10) Optional: check backing resource capacity, else TPM_RC_NV_SPACE */
    /* if (!tpm2_nv_can_serialize(s, estimated_size)) return TPM_RC_NV_SPACE; */

    /* 11) Create NV entry with WRITTEN=0 (uninitialized) */
    NvEntry *e = nv_entry_alloc(index, dataSize, nameAlg, attrs, auth);
    if (!e)                                     return TPM_RC_MEMORY; /* or TPM_RC_NV_SPACE */

    /* 12) Insert into map and mark dirty for persistence */
    g_hash_table_insert(s->nv_map, GINT_TO_POINTER(index), e);
    s->nv_count++;
    s->nv_dirty = true;

    /* 13) Persist now (recommended) */
    if (!tpm2_nv_flush_dirty(s)) {
        /* Optionally rollback on failure and return TPM_RC_NV_SPACE */
        // g_hash_table_remove(s->nv_map, GINT_TO_POINTER(index));
        // s->nv_count--;
        // return TPM_RC_NV_SPACE;
    }

    return TPM_RC_SUCCESS;


                                
}







