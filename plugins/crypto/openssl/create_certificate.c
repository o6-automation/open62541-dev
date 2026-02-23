add_x509V3ext(logger, x509, NID_authority_key_identifier, "keyid");
    if(errRet != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURECHANNEL,
                     "Create Certificate: Setting 'Authority Key Identifier' failed.");
        goto cleanup;
    }
    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 *
    errRet = 