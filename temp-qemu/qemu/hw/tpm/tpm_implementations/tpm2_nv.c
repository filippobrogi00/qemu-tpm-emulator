#include "tpm/tpm2_nv.h"
#include "tpm/tpm2_handles.h"

/* Request for TPM2_NV_DefineSpace */
typedef struct {
    TPMI_ST_COMMAND_TAG tag;      // TPM_ST_SESSIONS
    UINT32              commandSize;
    TPM_CC              commandCode; // TPM_CC_NV_DefineSpace
    // Handles (marshaled separately in TPM order):
    TPMI_RH_PROVISION   authHandle;  // TPM_RH_OWNER or TPM_RH_PLATFORM(+PP)
    // Authorization area (if sessions present) goes here on the wire
    // Parameters:
    TPM2B_AUTH          auth;        // size + buffer (<= digest size of nameAlg)
    TPM2B_NV_PUBLIC     publicInfo;  // contains TPMS_NV_PUBLIC
} TPM2_NV_DefineSpace_Req;

/* Response for TPM2_NV_DefineSpace */
typedef struct {
    TPM_ST tag;
    UINT32 responseSize;
    TPM_RC responseCode;
} TPM2_NV_DefineSpace_Resp;



