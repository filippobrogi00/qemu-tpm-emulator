#ifndef TPM_COMMAND_CODES_H
#define TPM_COMMAND_CODES_H

#include "tpm2_base_types.h"

/*
 * TPM 2.0 Part 2: Structures
 * Command Code (TPM_CC) union with bitfields
 * and standard command code constants (TPM_CC_*)
 */

/* 32-bit TPM command code format (Figure 1, Table 11) */
typedef union
{
    UINT32 value; /* Full 32-bit command code */

    struct
    {
        UINT32 CommandIndex : 16; /* Bits 0..15: Command Index */
        UINT32 Reserved1 : 13;    /* Bits 16..28: Reserved, must be 0 */
        UINT32 V : 1;             /* Bit 29: Vendor-specific flag */
        UINT32 Reserved2 : 2;     /* Bits 30..31: Reserved, must be 0 */
    } bits;
} TPM_CC;

/* Helper to initialize a TPM_CC */
static inline TPM_CC
TPM_CC_Init (UINT16 index, int vendor)
{
    TPM_CC cc            = { 0 };
    cc.bits.CommandIndex = index;
    cc.bits.V            = vendor ? 1 : 0;
    return cc;
}

/* Standard TPM command codes (Table 12) */
enum
{
    TPM_CC_FIRST                      = 0x0000011F,
    TPM_CC_NV_UndefineSpaceSpecial    = 0x0000011F,
    TPM_CC_EvictControl               = 0x00000120,
    TPM_CC_HierarchyControl           = 0x00000121,
    TPM_CC_NV_UndefineSpace           = 0x00000122,
    TPM_CC_ChangeEPS                  = 0x00000124,
    TPM_CC_ChangePPS                  = 0x00000125,
    TPM_CC_Clear                      = 0x00000126,
    TPM_CC_ClearControl               = 0x00000127,
    TPM_CC_ClockSet                   = 0x00000128,
    TPM_CC_HierarchyChangeAuth        = 0x00000129,
    TPM_CC_NV_DefineSpace             = 0x0000012A,
    TPM_CC_PCR_Allocate               = 0x0000012B,
    TPM_CC_PCR_SetAuthPolicy          = 0x0000012C,
    TPM_CC_PP_Commands                = 0x0000012D,
    TPM_CC_SetPrimaryPolicy           = 0x0000012E,
    TPM_CC_FieldUpgradeStart          = 0x0000012F,
    TPM_CC_ClockRateAdjust            = 0x00000130,
    TPM_CC_CreatePrimary              = 0x00000131,
    TPM_CC_NV_GlobalWriteLock         = 0x00000132,
    TPM_CC_GetCommandAuditDigest      = 0x00000133,
    TPM_CC_NV_Increment               = 0x00000134,
    TPM_CC_NV_SetBits                 = 0x00000135,
    TPM_CC_NV_Extend                  = 0x00000136,
    TPM_CC_NV_Write                   = 0x00000137,
    TPM_CC_NV_WriteLock               = 0x00000138,
    TPM_CC_DictionaryAttackLockReset  = 0x00000139,
    TPM_CC_DictionaryAttackParameters = 0x0000013A,
    TPM_CC_NV_ChangeAuth              = 0x0000013B,
    TPM_CC_PCR_Event                  = 0x0000013C,
    TPM_CC_PCR_Reset                  = 0x0000013D,
    TPM_CC_SequenceComplete           = 0x0000013E,
    TPM_CC_SetAlgorithmSet            = 0x0000013F,
    TPM_CC_SetCommandCodeAuditStatus  = 0x00000140,
    TPM_CC_FieldUpgradeData           = 0x00000141,
    TPM_CC_IncrementalSelfTest        = 0x00000142,
    TPM_CC_SelfTest                   = 0x00000143,
    TPM_CC_Startup                    = 0x00000144,
    TPM_CC_Shutdown                   = 0x00000145,
    TPM_CC_StirRandom                 = 0x00000146,
    TPM_CC_ActivateCredential         = 0x00000147,
    TPM_CC_Certify                    = 0x00000148,
    TPM_CC_PolicyNV                   = 0x00000149,
    TPM_CC_CertifyCreation            = 0x0000014A,
    TPM_CC_Duplicate                  = 0x0000014B,
    TPM_CC_GetTime                    = 0x0000014C,
    TPM_CC_GetSessionAuditDigest      = 0x0000014D,
    TPM_CC_NV_Read                    = 0x0000014E,
    TPM_CC_NV_ReadLock                = 0x0000014F,
    TPM_CC_ObjectChangeAuth           = 0x00000150,
    TPM_CC_PolicySecret               = 0x00000151,
    TPM_CC_Rewrap                     = 0x00000152,
    TPM_CC_Create                     = 0x00000153,
    TPM_CC_ECDH_ZGen                  = 0x00000154,
    TPM_CC_HMAC                       = 0x00000155,
    TPM_CC_MAC                        = 0x00000155,
    TPM_CC_Import                     = 0x00000156,
    TPM_CC_Load                       = 0x00000157,
    TPM_CC_Quote                      = 0x00000158,
    TPM_CC_RSA_Decrypt                = 0x00000159,
    TPM_CC_HMAC_Start                 = 0x0000015B,
    TPM_CC_MAC_Start                  = 0x0000015B,
    TPM_CC_SequenceUpdate             = 0x0000015C,
    TPM_CC_Sign                       = 0x0000015D,
    TPM_CC_Unseal                     = 0x0000015E,
    TPM_CC_PolicySigned               = 0x00000160,
    TPM_CC_ContextLoad                = 0x00000161,
    TPM_CC_ContextSave                = 0x00000162,
    TPM_CC_ECDH_KeyGen                = 0x00000163,
    TPM_CC_EncryptDecrypt             = 0x00000164,
    TPM_CC_LoadExternal               = 0x00000167,
    TPM_CC_MakeCredential             = 0x00000168,
    TPM_CC_NV_ReadPublic              = 0x00000169,
    TPM_CC_PolicyAuthorize            = 0x0000016A,
    TPM_CC_PolicyAuthValue            = 0x0000016B,
    TPM_CC_PolicyCommandCode          = 0x0000016C,
    TPM_CC_PolicyCounterTimer         = 0x0000016D,
    TPM_CC_PolicyCpHash               = 0x0000016E,
    TPM_CC_PolicyLocality             = 0x0000016F,
    TPM_CC_PolicyNameHash             = 0x00000170,
    TPM_CC_PolicyOR                   = 0x00000171,
    TPM_CC_PolicyTicket               = 0x00000172,
    TPM_CC_ReadPublic                 = 0x00000173,
    TPM_CC_RSA_Encrypt                = 0x00000174,
    TPM_CC_StartAuthSession           = 0x00000176,
    TPM_CC_VerifySignature            = 0x00000177,
    TPM_CC_ECC_Parameters             = 0x00000178,
    TPM_CC_FirmwareRead               = 0x00000179,
    TPM_CC_GetCapability              = 0x0000017A,
    TPM_CC_GetRandom                  = 0x0000017B,
    TPM_CC_GetTestResult              = 0x0000017C,
    TPM_CC_Hash                       = 0x0000017D,
    TPM_CC_PCR_Read                   = 0x0000017E,
    TPM_CC_PolicyPCR                  = 0x0000017F,
    TPM_CC_PolicyRestart              = 0x00000180,
    TPM_CC_ReadClock                  = 0x00000181,
    TPM_CC_PCR_Extend                 = 0x00000182,
    TPM_CC_PCR_SetAuthValue           = 0x00000183,
    TPM_CC_NV_Certify                 = 0x00000184,
    TPM_CC_EventSequenceComplete      = 0x00000185,
    TPM_CC_HashSequenceStart          = 0x00000186,
    TPM_CC_PolicyPhysicalPresence     = 0x00000187,
    TPM_CC_PolicyDuplicationSelect    = 0x00000188,
    TPM_CC_PolicyGetDigest            = 0x00000189,
    TPM_CC_TestParms                  = 0x0000018A,
    TPM_CC_Commit                     = 0x0000018B,
    TPM_CC_PolicyPassword             = 0x0000018C,
    TPM_CC_ZGen_2Phase                = 0x0000018D,
    TPM_CC_EC_Ephemeral               = 0x0000018E,
    TPM_CC_PolicyNvWritten            = 0x0000018F,
    TPM_CC_PolicyTemplate             = 0x00000190,
    TPM_CC_CreateLoaded               = 0x00000191,
    TPM_CC_PolicyAuthorizeNV          = 0x00000192,
    TPM_CC_EncryptDecrypt2            = 0x00000193,
    TPM_CC_AC_GetCapability           = 0x00000194,
    TPM_CC_AC_Send                    = 0x00000195,
    TPM_CC_Policy_AC_SendSelect       = 0x00000196,
    TPM_CC_CertifyX509                = 0x00000197,
    TPM_CC_ACT_SetTimeout             = 0x00000198,
    TPM_CC_ECC_Encrypt                = 0x00000199,
    TPM_CC_ECC_Decrypt                = 0x0000019A,
    TPM_CC_PolicyCapability           = 0x0000019B,
    TPM_CC_PolicyParameters           = 0x0000019C,
    TPM_CC_NV_DefineSpace2            = 0x0000019D,
    TPM_CC_NV_ReadPublic2             = 0x0000019E,
    TPM_CC_SetCapability              = 0x0000019F,
    TPM_CC_LAST                       = 0x0000019F,
    CC_VEND                           = 0x20000000,
    TPM_CC_Vendor_TCG_Test            = CC_VEND + 0x0000
};

#endif /* TPM_COMMAND_CODES_H */
