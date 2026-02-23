    if(mbedtls_x509write_crt_set_subject_key_identifier(&crt) != 0) {
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURECHANNEL,
                     "Create Certificate: Setting 'Subject Key Identifier' failed.");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
      Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 *  }

    if(mbedtls_x509write_crt_set_authority_key_identifier(&crt) != 0) {
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURECHANNEL,
                     "Create Certificate: Setting 'Authority Key Identifier' failed.");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }
