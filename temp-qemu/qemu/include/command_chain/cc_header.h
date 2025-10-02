/******************************
 * DATA STRUCTURES  
 ******************************/

enum TPMI_ST_COMMAND_TAG {
    TPM_ST_SESSIONS,
    TPM_ST_NO_SESSIONS
};

/******************************
 * FUNCTIONS
 ******************************/

/*TODO*/TPM_ERR_MARSH UnmarshalCommandTag(TPMI_ST_COMMAND_TAG tag) {
    if (tag != TPM_ST_SESSIONS && tag != TPM_ST_NO_SESSIONS) {
        return TPM_RC_BAD_TAG;
    }

    return /*TODO*/;
}

TPM_ERR_MARSH UnmarshalCommandSize(uint32_t commandSize) {
    if (commandSize < 0 || ) {
    
    }
}


 

