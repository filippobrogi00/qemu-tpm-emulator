#ifndef TPM2_NV_ENTRY_H
#define TPM2_NV_ENTRY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
//#include "tpm2_structures.h"
/* Pull these from your TPM Part 2 header you already have */
#include "tpm2_nv.h"   /* TPMS_NV_PUBLIC, TPMA_NV, TPM_NT_*, etc. */
#include "tpm2_rc.h"
/* Max sizes: keep modest and configurable */
#ifndef NVENTRY_MAX_AUTH
#define NVENTRY_MAX_AUTH 64 /* <= digest size of nameAlg per spec */
#endif




/* One NV entry instance (TPM_HT_NV_INDEX flavor).
   - Public area is TPMS_NV_PUBLIC 
   - Name is computed from marshaled public area using nameAlg (Part 3 ReadPublic notes)
   - Data buffer holds the index’s bytes (size==public.dataSize).
   - written/readLocked/writeLocked are mirrors of TPMA_NV state that can be transient. */
typedef struct NVEntry {
    TPMS_NV_PUBLIC pub;          /* nvIndex, nameAlg, attributes, authPolicy, dataSize */
    uint8_t        authValue[NVENTRY_MAX_AUTH];
    uint16_t       authValueLen; /* <= hash size of nameAlg; enforced at DefineSpace. :contentReference[oaicite:0]{index=0} */

    /* cached Name of the index (size derived from nameAlg) */
    uint8_t  name[64];
    uint16_t nameLen;

    /* backing data */
    uint8_t *data;               /* host pointer to encrypted area: s->nv_bank_ptr + data_off */
    uint16_t dataLen;            /* equals pub.dataSize */

    /* per-entry IV for AES-CFB or AES-GCM */
    uint8_t *iv_ptr;              /* 16 bytes for AES block size */
    
    /* mirrors of dynamic bits */
    bool written;                /* TPMA_NV_WRITTEN (set after first init/write)  */
    bool readLocked;             /* TPMA_NV_READLOCKED – clears on Startup(CLEAR) */
    bool writeLocked;            /* TPMA_NV_WRITELOCKED semantics per spec */

    /* simple integrity (optional): HMAC over data using a TPM-internal key, */
    uint8_t *integrity;          /* optional blob */
    uint16_t integrityLen;
} NVEntry;


#endif /* TPM2_NV_ENTRY_H */
