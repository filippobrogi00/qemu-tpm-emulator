#include "tpm/tpm2_interfaces.h"

typedef struct {
    TPM_RH_OWNER owner;
    TPM_RH_PLATFORM platformhandle;
    TPM_RC_VALUE responsefailcode;
}TPMI_RH_PROVISION;

/******************************
 * TPMI_RH_CLEAR
 ******************************/
typedef struct {
    TPM_RH_OWNER owner;
    TPM_RH_PLATFORM platformhandle;
    TPM_RC_VALUE responserefailcode;
}TPMI_RH_CLEAR;

