#ifndef TPM2_TEST_CC_H
#define TPM2_TEST_CC_H

#include "command_chain/cc_header.h" // TPM_CMD_HEADER

void TPM2_TEST_CC_ValidateCommandHeader (TPM_CMD_HEADER *hdr);

void TPM2_TEST_ValidateMode (void);

void TPM2_TEST_CC (void);

#endif // TPM2_TEST_CC_H
