/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Interoperability test client for cross-SDK testing.
 * Connects to an external OPC UA server and performs basic operations.
 *
 * Usage:
 *   check_interop_client <url>
 *   check_interop_client <url> <policy_uri> <cert.der> <key.der> [trustlist.der ...]
 *
 * Exit codes:
 *   0 = all tests passed
 *   1 = test failure
 */

#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/log_stdout.h>

#ifdef UA_ENABLE_ENCRYPTION
#include <open62541/plugin/certificategroup_default.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Inline file loader (same as examples/common.h) */
static UA_ByteString loadFileFromDisk(const char *path) {
    UA_ByteString fileContents = UA_STRING_NULL;
    FILE *fp = fopen(path, "rb");
    if(!fp)
        return fileContents;
    fseek(fp, 0, SEEK_END);
    fileContents.length = (size_t)ftell(fp);
    fileContents.data = (UA_Byte *)UA_malloc(fileContents.length);
    if(fileContents.data) {
        fseek(fp, 0, SEEK_SET);
        size_t read = fread(fileContents.data, 1, fileContents.length, fp);
        if(read != fileContents.length) {
            UA_ByteString_clear(&fileContents);
        }
    } else {
        fileContents.length = 0;
    }
    fclose(fp);
    return fileContents;
}

#define INTEROP_LOG(fmt, ...) \
    printf("[interop] " fmt "\n", ##__VA_ARGS__)

#define INTEROP_CHECK(cond, msg) do { \
    if(!(cond)) { \
        fprintf(stderr, "[interop] FAIL: %s\n", msg); \
        failures++; \
    } else { \
        INTEROP_LOG("PASS: %s", msg); \
    } \
} while(0)

static int test_read_server_status(UA_Client *client) {
    int failures = 0;

    /* Read ServerStatus State */
    UA_Variant val;
    UA_Variant_init(&val);
    UA_StatusCode retval = UA_Client_readValueAttribute(
        client, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERSTATUS_STATE), &val);
    INTEROP_CHECK(retval == UA_STATUSCODE_GOOD, "Read ServerStatus State");
    if(retval == UA_STATUSCODE_GOOD) {
        INTEROP_CHECK(val.type != NULL, "ServerStatus has a type");
    }
    UA_Variant_clear(&val);

    /* Read Server NamespaceArray */
    UA_Variant_init(&val);
    retval = UA_Client_readValueAttribute(
        client, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_NAMESPACEARRAY), &val);
    INTEROP_CHECK(retval == UA_STATUSCODE_GOOD, "Read NamespaceArray");
    if(retval == UA_STATUSCODE_GOOD) {
        INTEROP_CHECK(val.arrayLength > 0, "NamespaceArray has entries");
    }
    UA_Variant_clear(&val);

    return failures;
}

static int test_anonymous_connect(const char *url, const char *policyUri,
                                  UA_ByteString *certificate,
                                  UA_ByteString *privateKey,
                                  UA_ByteString *trustList,
                                  size_t trustListSize) {
    int failures = 0;
    INTEROP_LOG("--- Test: Anonymous connect to %s ---", url);

    UA_Client *client = UA_Client_new();
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    UA_ClientConfig_setDefault(cc);

#ifdef UA_ENABLE_ENCRYPTION
    if(certificate->length > 0) {
        UA_ClientConfig_setDefaultEncryption(cc, *certificate, *privateKey,
                                             trustList, trustListSize,
                                             NULL, 0);
        UA_CertificateGroup_AcceptAll(&cc->certificateVerification);
        /* Set application URI to match the certificate's SAN */
        UA_String_clear(&cc->clientDescription.applicationUri);
        cc->clientDescription.applicationUri =
            UA_STRING_ALLOC("urn:open62541.client.application");
        if(policyUri) {
            cc->securityPolicyUri = UA_STRING_ALLOC(policyUri);
        }
    }
#else
    (void)policyUri;
    (void)certificate;
    (void)privateKey;
    (void)trustList;
    (void)trustListSize;
#endif

    UA_StatusCode retval = UA_Client_connect(client, url);
    INTEROP_CHECK(retval == UA_STATUSCODE_GOOD, "Anonymous connect");

    if(retval == UA_STATUSCODE_GOOD) {
        failures += test_read_server_status(client);
        UA_Client_disconnect(client);
    }

    UA_Client_delete(client);
    return failures;
}

static int test_username_connect(const char *url, const char *policyUri,
                                 UA_ByteString *certificate,
                                 UA_ByteString *privateKey,
                                 UA_ByteString *trustList,
                                 size_t trustListSize,
                                 const char *username,
                                 const char *password) {
    int failures = 0;
    INTEROP_LOG("--- Test: Username connect (%s) to %s ---", username, url);

    UA_Client *client = UA_Client_new();
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    UA_ClientConfig_setDefault(cc);

#ifdef UA_ENABLE_ENCRYPTION
    if(certificate->length > 0) {
        UA_ClientConfig_setDefaultEncryption(cc, *certificate, *privateKey,
                                             trustList, trustListSize,
                                             NULL, 0);
        UA_CertificateGroup_AcceptAll(&cc->certificateVerification);
        /* Set application URI to match the certificate's SAN */
        UA_String_clear(&cc->clientDescription.applicationUri);
        cc->clientDescription.applicationUri =
            UA_STRING_ALLOC("urn:open62541.client.application");
        if(policyUri) {
            cc->securityPolicyUri = UA_STRING_ALLOC(policyUri);
        }
    }
#else
    (void)policyUri;
    (void)certificate;
    (void)privateKey;
    (void)trustList;
    (void)trustListSize;
#endif

    UA_StatusCode retval = UA_Client_connectUsername(client, url, username, password);
    INTEROP_CHECK(retval == UA_STATUSCODE_GOOD, "Username connect");

    if(retval == UA_STATUSCODE_GOOD) {
        failures += test_read_server_status(client);
        UA_Client_disconnect(client);
    }

    UA_Client_delete(client);
    return failures;
}

int main(int argc, char *argv[]) {
    if(argc < 2) {
        fprintf(stderr, "Usage: %s <url> [<policy_uri> <cert.der> <key.der> [trustlist.der ...]]\n",
                argv[0]);
        return 1;
    }

    const char *url = argv[1];
    const char *policyUri = NULL;
    UA_ByteString certificate = UA_BYTESTRING_NULL;
    UA_ByteString privateKey = UA_BYTESTRING_NULL;
    UA_ByteString *trustList = NULL;
    size_t trustListSize = 0;

    if(argc >= 5) {
        policyUri = argv[2];
        certificate = loadFileFromDisk(argv[3]);
        privateKey = loadFileFromDisk(argv[4]);
        if(certificate.length == 0 || privateKey.length == 0) {
            fprintf(stderr, "Error: Failed to load certificate or key\n");
            return 1;
        }

        /* Load optional trust list entries */
        if(argc > 5) {
            trustListSize = (size_t)(argc - 5);
            trustList = (UA_ByteString *)calloc(trustListSize, sizeof(UA_ByteString));
            for(int i = 5; i < argc; i++) {
                trustList[i - 5] = loadFileFromDisk(argv[i]);
                if(trustList[i - 5].length == 0) {
                    fprintf(stderr, "Warning: Failed to load trust list file: %s\n",
                            argv[i]);
                }
            }
        }
    }

    int failures = 0;

    /* Test 1: Anonymous connect */
    failures += test_anonymous_connect(url, policyUri,
                                       &certificate, &privateKey,
                                       trustList, trustListSize);

    /* Test 2: Username/password connect (only with encryption) */
    if(certificate.length > 0) {
        failures += test_username_connect(url, policyUri,
                                          &certificate, &privateKey,
                                          trustList, trustListSize,
                                          "user1", "password");
    } else {
        INTEROP_LOG("SKIP: Username connect (no encryption configured)");
    }

    /* Cleanup */
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    for(size_t i = 0; i < trustListSize; i++)
        UA_ByteString_clear(&trustList[i]);
    free(trustList);

    INTEROP_LOG("=== Results: %d failure(s) ===", failures);
    return failures > 0 ? 1 : 0;
}
