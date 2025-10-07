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



TPM_RC tpm2_nv_define_space(TPM2State *s,
                              uint32_t authHandle,
                              const uint8_t *authValue,
                              uint16_t authLen,
                              TPM_NV_INDEX nvHandle,
                              uint16_t nvSize,
                              uint16_t nameAlg,
                              uint32_t attrs){


}





