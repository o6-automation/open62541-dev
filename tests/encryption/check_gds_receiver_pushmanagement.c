/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/certificategroup_default.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/driver/gds_receiver.h>

#include <check.h>
#include <thread_wrapper.h>
#include "test_helpers.h"

#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

/* PushManagement of the ServerConfiguration (OPC UA Part 12, 7.8.2 and 7.10).
 * The certificates are created at runtime. */

#define APPLICATION_URI "urn:open62541.unconfigured.application"
/* Not the default port, so that the tests run next to other local servers */
#define TEST_PORT 4845
#define TEST_URL "opc.tcp://localhost:4845"
#define DEFAULT_TRUSTLIST \
    UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST
#define USERTOKEN_TRUSTLIST \
    UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST

static UA_Server *server;
static UA_GDSReceiver *receiver;
static UA_ByteString serverCertificate, serverKey;
static UA_ByteString clientCertificate, clientKey;
static UA_atomic(uintptr_t) running;
static THREAD_HANDLE server_thread;

static void
createCertificate(const char *uri, UA_ByteString *certificate,
                  UA_ByteString *privateKey) {
    UA_String subject[2] = {UA_STRING_STATIC("O=open62541"),
                            UA_STRING_STATIC("CN=PushManagement Test")};
    UA_String san[2] = {UA_STRING_NULL, UA_STRING_STATIC("DNS:localhost")};
    ck_assert_uint_eq(UA_String_format(&san[0], "URI:%s", uri), UA_STATUSCODE_GOOD);
    UA_UInt16 keySize = 2048;
    UA_KeyValuePair param;
    param.key = UA_QUALIFIEDNAME(0, "key-size-bits");
    UA_Variant_setScalar(&param.value, &keySize, &UA_TYPES[UA_TYPES_UINT16]);
    UA_KeyValueMap params = {1, &param};
    UA_StatusCode res = UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2,
                                             UA_CERTIFICATEFORMAT_DER, &params,
                                             privateKey, certificate);
    UA_String_clear(&san[0]);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
}

#ifdef UA_ENABLE_RBAC
/* The GDS methods are restricted to the SecurityAdmin role. The tests use
 * anonymous Sessions. */
static void
grantAnonymousSecurityAdmin(void) {
    UA_NodeId secAdminId = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN);
    UA_Role secAdmin;
    ck_assert_uint_eq(UA_Server_getRoleById(server, secAdminId, &secAdmin),
                      UA_STATUSCODE_GOOD);
    UA_IdentityMappingRuleType *rules = (UA_IdentityMappingRuleType *)
        UA_realloc(secAdmin.identityMappingRules,
                   (secAdmin.identityMappingRulesSize + 1) *
                   sizeof(UA_IdentityMappingRuleType));
    ck_assert_ptr_nonnull(rules);
    secAdmin.identityMappingRules = rules;
    UA_IdentityMappingRuleType_init(&rules[secAdmin.identityMappingRulesSize]);
    rules[secAdmin.identityMappingRulesSize].criteriaType =
        UA_IDENTITYCRITERIATYPE_ANONYMOUS;
    secAdmin.identityMappingRulesSize++;
    ck_assert_uint_eq(UA_Server_updateRole(server, &secAdmin), UA_STATUSCODE_GOOD);
    UA_Role_clear(&secAdmin);
}
#endif

/* The server trusts the client certificate. Its TrustLists are Memorystores. */
static void
setup(void) {
    createCertificate(APPLICATION_URI, &serverCertificate, &serverKey);
    createCertificate(APPLICATION_URI, &clientCertificate, &clientKey);
    server = UA_Server_newForUnitTestWithSecurityPolicies(TEST_PORT, &serverCertificate,
                                                          &serverKey,
                                                          &clientCertificate, 1,
                                                          NULL, 0, NULL, 0);
    ck_assert_ptr_nonnull(server);
    UA_ServerConfig *sc = UA_Server_getConfig(server);
    UA_String_clear(&sc->applicationDescription.applicationUri);
    sc->applicationDescription.applicationUri = UA_STRING_ALLOC(APPLICATION_URI);
    receiver = UA_GDSReceiver_new();
    ck_assert_ptr_nonnull(receiver);
    ck_assert_uint_eq(UA_Server_addDriver(server, &receiver->drv), UA_STATUSCODE_GOOD);
#ifdef UA_ENABLE_RBAC
    grantAnonymousSecurityAdmin();
#endif
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
}

static void
teardown(void) {
    ck_assert_uint_eq(UA_Server_run_shutdown(server), UA_STATUSCODE_GOOD);
    UA_Server_delete(server);
    UA_ByteString_clear(&serverCertificate);
    UA_ByteString_clear(&serverKey);
    UA_ByteString_clear(&clientCertificate);
    UA_ByteString_clear(&clientKey);
}

THREAD_CALLBACK(serverloop) {
    while(UA_atomic_load(&running))
        UA_Server_run_iterate(server, true);
    return 0;
}

static void
setupNetworked(void) {
    setup();
    UA_atomic_store(&running, true);
    THREAD_CREATE(server_thread, serverloop);
}

static void
teardownNetworked(void) {
    UA_atomic_store(&running, false);
    THREAD_JOIN(server_thread);
    teardown();
}

/* Local calls through the admin Session */

static UA_CallMethodResult
call(UA_UInt32 objectId, UA_UInt32 methodId, size_t inputSize, UA_Variant *input) {
    UA_CallMethodRequest request;
    UA_CallMethodRequest_init(&request);
    request.objectId = UA_NODEID_NUMERIC(0, objectId);
    request.methodId = UA_NODEID_NUMERIC(0, methodId);
    request.inputArgumentsSize = inputSize;
    request.inputArguments = input;
    return UA_Server_call(server, &request);
}

static UA_StatusCode
callStatus(UA_UInt32 objectId, UA_UInt32 methodId, size_t inputSize,
           UA_Variant *input) {
    UA_CallMethodResult result = call(objectId, methodId, inputSize, input);
    UA_StatusCode res = result.statusCode;
    UA_CallMethodResult_clear(&result);
    return res;
}

/* The methods of a TrustList are resolved by their BrowseName */
static UA_StatusCode
trustListCall(UA_UInt32 trustList, UA_UInt32 typeMethod, size_t inputSize,
              UA_Variant *input, UA_Variant *output) {
    UA_CallMethodResult result = call(trustList, typeMethod, inputSize, input);
    UA_StatusCode res = result.statusCode;
    if(res == UA_STATUSCODE_GOOD && output && result.outputArgumentsSize > 0)
        UA_Variant_copy(&result.outputArguments[0], output);
    UA_CallMethodResult_clear(&result);
    return res;
}

static UA_StatusCode
openTrustList(UA_UInt32 trustList, UA_Byte mode, UA_UInt32 *handle) {
    UA_Variant input, output;
    UA_Variant_init(&output);
    UA_Variant_setScalar(&input, &mode, &UA_TYPES[UA_TYPES_BYTE]);
    UA_StatusCode res = trustListCall(trustList, UA_NS0ID_FILETYPE_OPEN, 1,
                                      &input, &output);
    if(res == UA_STATUSCODE_GOOD)
        *handle = *(UA_UInt32*)output.data;
    UA_Variant_clear(&output);
    return res;
}

static UA_StatusCode
openTrustListWithMasks(UA_UInt32 trustList, UA_UInt32 mask, UA_UInt32 *handle) {
    UA_Variant input, output;
    UA_Variant_init(&output);
    UA_Variant_setScalar(&input, &mask, &UA_TYPES[UA_TYPES_UINT32]);
    UA_StatusCode res = trustListCall(trustList, UA_NS0ID_TRUSTLISTTYPE_OPENWITHMASKS,
                                      1, &input, &output);
    if(res == UA_STATUSCODE_GOOD)
        *handle = *(UA_UInt32*)output.data;
    UA_Variant_clear(&output);
    return res;
}

static UA_StatusCode
writeTrustList(UA_UInt32 trustList, UA_UInt32 handle, const UA_TrustListDataType *tl) {
    UA_ByteString encoded = UA_BYTESTRING_NULL;
    ck_assert_uint_eq(UA_encodeBinary(tl, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE],
                                      &encoded, NULL), UA_STATUSCODE_GOOD);
    UA_Variant input[2];
    UA_Variant_setScalar(&input[0], &handle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&input[1], &encoded, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_StatusCode res = trustListCall(trustList, UA_NS0ID_FILETYPE_WRITE, 2,
                                      input, NULL);
    UA_ByteString_clear(&encoded);
    return res;
}

static UA_StatusCode
closeAndUpdate(UA_UInt32 trustList, UA_UInt32 handle) {
    UA_Variant input, output;
    UA_Variant_init(&output);
    UA_Variant_setScalar(&input, &handle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_StatusCode res = trustListCall(trustList, UA_NS0ID_TRUSTLISTTYPE_CLOSEANDUPDATE,
                                      1, &input, &output);
    if(res == UA_STATUSCODE_GOOD)
        ck_assert(*(UA_Boolean*)output.data); /* ApplyChangesRequired */
    UA_Variant_clear(&output);
    return res;
}

static UA_StatusCode
closeTrustList(UA_UInt32 trustList, UA_UInt32 handle) {
    UA_Variant input;
    UA_Variant_setScalar(&input, &handle, &UA_TYPES[UA_TYPES_UINT32]);
    return trustListCall(trustList, UA_NS0ID_FILETYPE_CLOSE, 1, &input, NULL);
}

static UA_StatusCode
readTrustList(UA_UInt32 trustList, UA_UInt32 handle, UA_TrustListDataType *tl) {
    UA_Int32 length = 1 << 20;
    UA_Variant input[2], output;
    UA_Variant_init(&output);
    UA_Variant_setScalar(&input[0], &handle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&input[1], &length, &UA_TYPES[UA_TYPES_INT32]);
    UA_StatusCode res = trustListCall(trustList, UA_NS0ID_FILETYPE_READ, 2,
                                      input, &output);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_decodeBinary((UA_ByteString*)output.data, tl,
                              &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL);
    UA_Variant_clear(&output);
    return res;
}

/* Write a TrustList in a transaction */
static UA_StatusCode
stageTrustList(UA_UInt32 trustList, const UA_TrustListDataType *tl) {
    UA_UInt32 handle = 0;
    UA_StatusCode res =
        openTrustList(trustList, UA_OPENFILEMODE_WRITE | UA_OPENFILEMODE_ERASEEXISTING,
                      &handle);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    res = writeTrustList(trustList, handle, tl);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    return closeAndUpdate(trustList, handle);
}

static UA_StatusCode
addCertificate(UA_UInt32 trustList, UA_ByteString certificate) {
    UA_Boolean isTrusted = true;
    UA_Variant input[2];
    UA_Variant_setScalar(&input[0], &certificate, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&input[1], &isTrusted, &UA_TYPES[UA_TYPES_BOOLEAN]);
    return trustListCall(trustList, UA_NS0ID_TRUSTLISTTYPE_ADDCERTIFICATE, 2,
                         input, NULL);
}

static UA_StatusCode
applyChanges(void) {
    UA_StatusCode res = callStatus(UA_NS0ID_SERVERCONFIGURATION,
                                   UA_NS0ID_SERVERCONFIGURATION_APPLYCHANGES, 0, NULL);
    /* The transaction is closed in a delayed callback */
    UA_Server_run_iterate(server, false);
    UA_Server_run_iterate(server, false);
    return res;
}

static UA_StatusCode
cancelChanges(void) {
    return callStatus(UA_NS0ID_SERVERCONFIGURATION,
                      UA_NS0ID_SERVERCONFIGURATION_CANCELCHANGES, 0, NULL);
}

static UA_StatusCode
updateCertificate(UA_ByteString certificate, const char *format,
                  UA_ByteString privateKey) {
    UA_NodeId groupId = UA_NODEID_NULL;
    UA_NodeId typeId = UA_NS0ID(RSASHA256APPLICATIONCERTIFICATETYPE);
    UA_String keyFormat = UA_STRING((char*)(uintptr_t)format);
    UA_Variant input[6];
    UA_Variant_setScalar(&input[0], &groupId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&input[1], &typeId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&input[2], &certificate, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setArray(&input[3], NULL, 0, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&input[4], &keyFormat, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&input[5], &privateKey, &UA_TYPES[UA_TYPES_BYTESTRING]);
    return callStatus(UA_NS0ID_SERVERCONFIGURATION,
                      UA_NS0ID_SERVERCONFIGURATION_UPDATECERTIFICATE, 6, input);
}

static UA_StatusCode
createSigningRequest(UA_Boolean regenerateKey, UA_ByteString nonce) {
    UA_NodeId groupId = UA_NODEID_NULL;
    UA_NodeId typeId = UA_NS0ID(RSASHA256APPLICATIONCERTIFICATETYPE);
    UA_String subject = UA_STRING_NULL;
    UA_Variant input[5];
    UA_Variant_setScalar(&input[0], &groupId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&input[1], &typeId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&input[2], &subject, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&input[3], &regenerateKey, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_Variant_setScalar(&input[4], &nonce, &UA_TYPES[UA_TYPES_BYTESTRING]);
    return callStatus(UA_NS0ID_SERVERCONFIGURATION,
                      UA_NS0ID_SERVERCONFIGURATION_CREATESIGNINGREQUEST, 5, input);
}

static UA_TrustListDataType
trustedList(UA_ByteString *certificates, size_t size) {
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    tl.specifiedLists = UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES;
    tl.trustedCertificates = certificates;
    tl.trustedCertificatesSize = size;
    return tl;
}

START_TEST(open_modes) {
    UA_UInt32 handle = 0, readHandle = 0;
    ck_assert_uint_eq(openTrustList(DEFAULT_TRUSTLIST, UA_OPENFILEMODE_WRITE, &handle),
                      UA_STATUSCODE_BADNOTSUPPORTED);

    /* Readers block writers */
    ck_assert_uint_eq(openTrustList(DEFAULT_TRUSTLIST, UA_OPENFILEMODE_READ, &readHandle),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(openTrustList(DEFAULT_TRUSTLIST, UA_OPENFILEMODE_WRITE |
                                    UA_OPENFILEMODE_ERASEEXISTING, &handle),
                      UA_STATUSCODE_BADNOTWRITABLE);
    ck_assert_uint_eq(closeTrustList(DEFAULT_TRUSTLIST, readHandle), UA_STATUSCODE_GOOD);

    /* Writers block readers */
    ck_assert_uint_eq(openTrustList(DEFAULT_TRUSTLIST, UA_OPENFILEMODE_WRITE |
                                    UA_OPENFILEMODE_ERASEEXISTING, &handle),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(openTrustList(DEFAULT_TRUSTLIST, UA_OPENFILEMODE_READ, &readHandle),
                      UA_STATUSCODE_BADNOTREADABLE);
    ck_assert_uint_eq(openTrustListWithMasks(DEFAULT_TRUSTLIST, UA_TRUSTLISTMASKS_ALL,
                                             &readHandle),
                      UA_STATUSCODE_BADNOTREADABLE);

    /* No changes are applied while a TrustList is open for writing */
    ck_assert_uint_eq(applyChanges(), UA_STATUSCODE_BADINVALIDSTATE);

    /* Close discards the write. Nothing is staged, the transaction ends. */
    ck_assert_uint_eq(closeTrustList(DEFAULT_TRUSTLIST, handle), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(applyChanges(), UA_STATUSCODE_BADNOTHINGTODO);

    /* Unknown handles */
    ck_assert_uint_eq(closeTrustList(DEFAULT_TRUSTLIST, 4711),
                      UA_STATUSCODE_BADINVALIDARGUMENT);
} END_TEST

START_TEST(transaction_spans_trustlists_and_certificate) {
    UA_ByteString certificate, privateKey;
    createCertificate(APPLICATION_URI, &certificate, &privateKey);

    /* The TrustList with the new (self-signed) certificate is staged */
    UA_TrustListDataType tl = trustedList(&certificate, 1);
    ck_assert_uint_eq(stageTrustList(DEFAULT_TRUSTLIST, &tl), UA_STATUSCODE_GOOD);

    /* The certificate is validated with the staged TrustList */
    ck_assert_uint_eq(updateCertificate(certificate, "DER", privateKey),
                      UA_STATUSCODE_GOOD);

    /* A second TrustList continues the transaction. Close discards only the
     * data of the handle. */
    UA_UInt32 handle = 0;
    ck_assert_uint_eq(openTrustList(USERTOKEN_TRUSTLIST, UA_OPENFILEMODE_WRITE |
                                    UA_OPENFILEMODE_ERASEEXISTING, &handle),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(closeTrustList(USERTOKEN_TRUSTLIST, handle), UA_STATUSCODE_GOOD);

    /* Readers get the active TrustList during the transaction */
    UA_UInt32 readHandle = 0;
    ck_assert_uint_eq(openTrustList(DEFAULT_TRUSTLIST, UA_OPENFILEMODE_READ, &readHandle),
                      UA_STATUSCODE_GOOD);
    UA_TrustListDataType active;
    UA_TrustListDataType_init(&active);
    ck_assert_uint_eq(readTrustList(DEFAULT_TRUSTLIST, readHandle, &active),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(active.trustedCertificatesSize, 1); /* The client certificate */
    ck_assert(!UA_ByteString_equal(&active.trustedCertificates[0], &certificate));
    UA_TrustListDataType_clear(&active);
    ck_assert_uint_eq(closeTrustList(DEFAULT_TRUSTLIST, readHandle), UA_STATUSCODE_GOOD);

    /* Both changes are applied */
    ck_assert_uint_eq(applyChanges(), UA_STATUSCODE_GOOD);
    UA_ServerConfig *sc = UA_Server_getConfig(server);
    UA_Boolean updated = false;
    for(size_t i = 0; i < sc->endpointsSize; i++)
        updated |= UA_ByteString_equal(&sc->endpoints[i].serverCertificate, &certificate);
    ck_assert(updated);
    UA_TrustListDataType_init(&active);
    active.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    ck_assert_uint_eq(sc->secureChannelPKI.getTrustList(&sc->secureChannelPKI, &active),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(active.trustedCertificatesSize, 1);
    ck_assert(UA_ByteString_equal(&active.trustedCertificates[0], &certificate));
    UA_TrustListDataType_clear(&active);

    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
} END_TEST

START_TEST(cancel_changes) {
    ck_assert_uint_eq(cancelChanges(), UA_STATUSCODE_BADNOTHINGTODO);

    UA_TrustListDataType tl = trustedList(&clientCertificate, 1);
    ck_assert_uint_eq(stageTrustList(DEFAULT_TRUSTLIST, &tl), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(cancelChanges(), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(applyChanges(), UA_STATUSCODE_BADNOTHINGTODO);

    /* CancelChanges closes the write handles of the Session */
    UA_UInt32 handle = 0;
    ck_assert_uint_eq(openTrustList(DEFAULT_TRUSTLIST, UA_OPENFILEMODE_WRITE |
                                    UA_OPENFILEMODE_ERASEEXISTING, &handle),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(cancelChanges(), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(closeAndUpdate(DEFAULT_TRUSTLIST, handle),
                      UA_STATUSCODE_BADINVALIDARGUMENT);
} END_TEST

START_TEST(open_with_masks_filters) {
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    tl.specifiedLists = UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES |
        UA_TRUSTLISTMASKS_ISSUERCERTIFICATES;
    tl.trustedCertificates = &clientCertificate;
    tl.trustedCertificatesSize = 1;
    tl.issuerCertificates = &serverCertificate;
    tl.issuerCertificatesSize = 1;
    ck_assert_uint_eq(stageTrustList(DEFAULT_TRUSTLIST, &tl), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(applyChanges(), UA_STATUSCODE_GOOD);

    UA_UInt32 handle = 0;
    ck_assert_uint_eq(openTrustListWithMasks(DEFAULT_TRUSTLIST,
                                             UA_TRUSTLISTMASKS_ISSUERCERTIFICATES,
                                             &handle), UA_STATUSCODE_GOOD);
    UA_TrustListDataType read;
    UA_TrustListDataType_init(&read);
    ck_assert_uint_eq(readTrustList(DEFAULT_TRUSTLIST, handle, &read), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(read.specifiedLists, UA_TRUSTLISTMASKS_ISSUERCERTIFICATES);
    ck_assert_uint_eq(read.trustedCertificatesSize, 0);
    ck_assert_uint_eq(read.issuerCertificatesSize, 1);
    UA_TrustListDataType_clear(&read);
    ck_assert_uint_eq(closeTrustList(DEFAULT_TRUSTLIST, handle), UA_STATUSCODE_GOOD);
} END_TEST

START_TEST(trustlist_size_limit) {
    /* The limit applies to the resulting TrustList. The upload only replaces
     * the issuers, the trusted client certificate remains. */
    UA_ServerConfig *sc = UA_Server_getConfig(server);
    sc->maxTrustListSize = (UA_UInt32)clientCertificate.length + 200;
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    tl.specifiedLists = UA_TRUSTLISTMASKS_ISSUERCERTIFICATES;
    tl.issuerCertificates = &serverCertificate;
    tl.issuerCertificatesSize = 1;
    ck_assert_uint_eq(stageTrustList(DEFAULT_TRUSTLIST, &tl),
                      UA_STATUSCODE_BADREQUESTTOOLARGE);

    /* The update was discarded and the transaction ended */
    ck_assert_uint_eq(applyChanges(), UA_STATUSCODE_BADNOTHINGTODO);
    ck_assert_uint_eq(addCertificate(DEFAULT_TRUSTLIST, serverCertificate),
                      UA_STATUSCODE_BADREQUESTTOOLARGE);
    sc->maxTrustListSize = 0;
} END_TEST

START_TEST(update_certificate_checks) {
    UA_ByteString certificate, privateKey, other, otherKey;
    createCertificate(APPLICATION_URI, &certificate, &privateKey);
    createCertificate("urn:open62541:test:other", &other, &otherKey);

    /* Not in the TrustList */
    ck_assert_uint_eq(updateCertificate(certificate, "DER", privateKey),
                      UA_STATUSCODE_BADCERTIFICATEUNTRUSTED);
    /* The key does not belong to the certificate */
    ck_assert_uint_eq(updateCertificate(certificate, "DER", otherKey),
                      UA_STATUSCODE_BADNOTSUPPORTED);
    /* No key and not the current key or the key of a signing request */
    ck_assert_uint_eq(updateCertificate(certificate, "", UA_BYTESTRING_NULL),
                      UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    /* The ApplicationUri does not match */
    ck_assert_uint_eq(addCertificate(DEFAULT_TRUSTLIST, other), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(updateCertificate(other, "DER", otherKey),
                      UA_STATUSCODE_BADCERTIFICATEURIINVALID);

    /* A trusted certificate is accepted */
    ck_assert_uint_eq(addCertificate(DEFAULT_TRUSTLIST, certificate), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(updateCertificate(certificate, "PEM", privateKey),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(applyChanges(), UA_STATUSCODE_GOOD);

    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    UA_ByteString_clear(&other);
    UA_ByteString_clear(&otherKey);
} END_TEST

START_TEST(signing_request_checks) {
    UA_Byte shortNonce[16] = {0};
    UA_Byte nonce[32] = {0};
    ck_assert_uint_eq(createSigningRequest(true, (UA_ByteString){16, shortNonce}),
                      UA_STATUSCODE_BADINVALIDARGUMENT);
    ck_assert_uint_eq(createSigningRequest(true, (UA_ByteString){32, nonce}),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(createSigningRequest(false, UA_BYTESTRING_NULL),
                      UA_STATUSCODE_GOOD);
} END_TEST

START_TEST(metadata) {
    UA_Variant v;
    ck_assert_uint_eq(UA_Server_readValue(server,
                          UA_NS0ID(SERVERCONFIGURATION_SUPPORTEDPRIVATEKEYFORMATS), &v),
                      UA_STATUSCODE_GOOD);
    UA_String pem = UA_STRING("PEM");
    ck_assert_uint_eq(v.arrayLength, 1);
    ck_assert(UA_String_equal((UA_String*)v.data, &pem));
    UA_Variant_clear(&v);

    /* Unknown after a start (DateTime.MinValue) */
    ck_assert_uint_eq(UA_Server_readValue(server,
                          UA_NS0ID(SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_LASTUPDATETIME), &v),
                      UA_STATUSCODE_GOOD);
    ck_assert_int_eq(*(UA_DateTime*)v.data, 0);
    UA_Variant_clear(&v);
} END_TEST

START_TEST(set_position_uint64) {
    UA_UInt32 handle = 0;
    ck_assert_uint_eq(openTrustList(DEFAULT_TRUSTLIST, UA_OPENFILEMODE_READ, &handle),
                      UA_STATUSCODE_GOOD);
    /* Beyond the end of the file. The lower 32 bit are 5. */
    UA_UInt64 position = ((UA_UInt64)1 << 32) + 5;
    UA_Variant input[2], output;
    UA_Variant_setScalar(&input[0], &handle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&input[1], &position, &UA_TYPES[UA_TYPES_UINT64]);
    ck_assert_uint_eq(trustListCall(DEFAULT_TRUSTLIST, UA_NS0ID_FILETYPE_SETPOSITION,
                                    2, input, NULL), UA_STATUSCODE_GOOD);
    UA_Variant_init(&output);
    ck_assert_uint_eq(trustListCall(DEFAULT_TRUSTLIST, UA_NS0ID_FILETYPE_GETPOSITION,
                                    1, input, &output), UA_STATUSCODE_GOOD);
    ck_assert_uint_gt(*(UA_UInt64*)output.data, 5);
    UA_Variant_clear(&output);
    ck_assert_uint_eq(closeTrustList(DEFAULT_TRUSTLIST, handle), UA_STATUSCODE_GOOD);
} END_TEST

/* Servers without a TrustList plugin (AcceptAll) must not crash */
START_TEST(accept_all_pki) {
    server = UA_Server_newForUnitTest();
    ck_assert_ptr_nonnull(server);
    UA_GDSReceiver *plainReceiver = UA_GDSReceiver_new();
    ck_assert_uint_eq(UA_Server_addDriver(server, &plainReceiver->drv),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
    createCertificate(APPLICATION_URI, &clientCertificate, &clientKey);

    UA_UInt32 handle = 0;
    ck_assert_uint_eq(openTrustList(DEFAULT_TRUSTLIST, UA_OPENFILEMODE_READ, &handle),
                      UA_STATUSCODE_BADNOTSUPPORTED);
    ck_assert_uint_eq(openTrustListWithMasks(DEFAULT_TRUSTLIST, UA_TRUSTLISTMASKS_ALL,
                                             &handle), UA_STATUSCODE_BADNOTSUPPORTED);
    ck_assert_uint_eq(addCertificate(DEFAULT_TRUSTLIST, clientCertificate),
                      UA_STATUSCODE_BADNOTWRITABLE);
    UA_String thumbprint = UA_STRING("0000000000000000000000000000000000000000");
    UA_Boolean isTrusted = true;
    UA_Variant input[2];
    UA_Variant_setScalar(&input[0], &thumbprint, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&input[1], &isTrusted, &UA_TYPES[UA_TYPES_BOOLEAN]);
    ck_assert_uint_eq(trustListCall(DEFAULT_TRUSTLIST,
                                    UA_NS0ID_TRUSTLISTTYPE_REMOVECERTIFICATE,
                                    2, input, NULL), UA_STATUSCODE_BADNOTWRITABLE);
    UA_CallMethodResult result = call(UA_NS0ID_SERVERCONFIGURATION,
                                      UA_NS0ID_SERVERCONFIGURATION_GETREJECTEDLIST,
                                      0, NULL);
    ck_assert_uint_eq(result.statusCode, UA_STATUSCODE_GOOD);
    UA_CallMethodResult_clear(&result);

    ck_assert_uint_eq(UA_Server_run_shutdown(server), UA_STATUSCODE_GOOD);
    UA_Server_delete(server);
    UA_ByteString_clear(&clientCertificate);
    UA_ByteString_clear(&clientKey);
} END_TEST

#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
/* A CA and a certificate issued by it */

static void
toByteString(X509 *cert, UA_ByteString *out) {
    int len = i2d_X509(cert, NULL);
    ck_assert_int_gt(len, 0);
    UA_ByteString_allocBuffer(out, (size_t)len);
    unsigned char *p = out->data;
    i2d_X509(cert, &p);
}

static X509 *
newCertificate(EVP_PKEY *key, const char *cn, long serial) {
    X509 *cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char*)cn, -1, -1, 0);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
    X509_set_pubkey(cert, key);
    return cert;
}

static void
addExtension(X509 *cert, X509 *issuer, int nid, const char *value) {
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    ck_assert_ptr_nonnull(ext);
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
}

static void
createIssuedCertificate(UA_ByteString *caCertificate, UA_ByteString *certificate,
                        UA_ByteString *privateKey) {
    EVP_PKEY *caKey = EVP_RSA_gen(2048);
    X509 *ca = newCertificate(caKey, "Test CA", 1);
    X509_set_issuer_name(ca, X509_get_subject_name(ca));
    addExtension(ca, ca, NID_basic_constraints, "critical,CA:TRUE");
    addExtension(ca, ca, NID_key_usage, "critical,keyCertSign,cRLSign");
    addExtension(ca, ca, NID_subject_key_identifier, "hash");
    ck_assert_int_gt(X509_sign(ca, caKey, EVP_sha256()), 0);

    EVP_PKEY *key = EVP_RSA_gen(2048);
    X509 *cert = newCertificate(key, "PushManagement Test", 2);
    X509_set_issuer_name(cert, X509_get_subject_name(ca));
    addExtension(cert, ca, NID_basic_constraints, "critical,CA:FALSE");
    addExtension(cert, ca, NID_key_usage,
                 "critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment");
    addExtension(cert, ca, NID_ext_key_usage, "serverAuth,clientAuth");
    addExtension(cert, ca, NID_subject_alt_name, "URI:" APPLICATION_URI ",DNS:localhost");
    addExtension(cert, ca, NID_authority_key_identifier, "keyid");
    ck_assert_int_gt(X509_sign(cert, caKey, EVP_sha256()), 0);

    toByteString(ca, caCertificate);
    toByteString(cert, certificate);
    int len = i2d_PrivateKey(key, NULL);
    UA_ByteString_allocBuffer(privateKey, (size_t)len);
    unsigned char *p = privateKey->data;
    i2d_PrivateKey(key, &p);
    X509_free(ca);
    X509_free(cert);
    EVP_PKEY_free(caKey);
    EVP_PKEY_free(key);
}

START_TEST(trustlist_requires_issuer) {
    UA_ByteString ca, certificate, privateKey;
    createIssuedCertificate(&ca, &certificate, &privateKey);

    /* The issuer of a trusted certificate is missing */
    UA_TrustListDataType tl = trustedList(&certificate, 1);
    ck_assert_uint_eq(stageTrustList(DEFAULT_TRUSTLIST, &tl),
                      UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE);
    ck_assert_uint_eq(addCertificate(DEFAULT_TRUSTLIST, certificate),
                      UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE);

    /* With the CA in the issuer list, the issued certificate can be installed.
     * The issuers of the own certificate need not be trusted (7.10.5). */
    UA_TrustListDataType_init(&tl);
    tl.specifiedLists = UA_TRUSTLISTMASKS_ISSUERCERTIFICATES;
    tl.issuerCertificates = &ca;
    tl.issuerCertificatesSize = 1;
    ck_assert_uint_eq(stageTrustList(DEFAULT_TRUSTLIST, &tl), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(updateCertificate(certificate, "DER", privateKey),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(applyChanges(), UA_STATUSCODE_GOOD);

    UA_ByteString_clear(&ca);
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
} END_TEST

START_TEST(remove_needed_issuer) {
    UA_ByteString ca, certificate, privateKey;
    createIssuedCertificate(&ca, &certificate, &privateKey);

    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    tl.specifiedLists = UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES |
        UA_TRUSTLISTMASKS_ISSUERCERTIFICATES;
    tl.trustedCertificates = &certificate;
    tl.trustedCertificatesSize = 1;
    tl.issuerCertificates = &ca;
    tl.issuerCertificatesSize = 1;
    ck_assert_uint_eq(stageTrustList(DEFAULT_TRUSTLIST, &tl), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(applyChanges(), UA_STATUSCODE_GOOD);

    UA_Byte buf[40];
    UA_String thumbprint = {40, buf};
    ck_assert_uint_eq(UA_CertificateUtils_getThumbprint(&ca, &thumbprint),
                      UA_STATUSCODE_GOOD);
    UA_Boolean isTrusted = false;
    UA_Variant input[2];
    UA_Variant_setScalar(&input[0], &thumbprint, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&input[1], &isTrusted, &UA_TYPES[UA_TYPES_BOOLEAN]);
    ck_assert_uint_eq(trustListCall(DEFAULT_TRUSTLIST,
                                    UA_NS0ID_TRUSTLISTTYPE_REMOVECERTIFICATE,
                                    2, input, NULL),
                      UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE);

    UA_ByteString_clear(&ca);
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
} END_TEST
#endif

/* Calls of clients over the network */

static UA_Client *
connectClient(UA_MessageSecurityMode mode) {
    UA_Client *client = UA_Client_newForUnitTest();
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    if(mode != UA_MESSAGESECURITYMODE_NONE) {
        UA_ClientConfig_setDefaultEncryption(cc, clientCertificate, clientKey,
                                             NULL, 0, NULL, 0);
        cc->certificateVerification.clear(&cc->certificateVerification);
        UA_CertificateGroup_AcceptAll(&cc->certificateVerification);
        UA_String_clear(&cc->securityPolicyUri);
        cc->securityPolicyUri = UA_STRING_ALLOC(
            "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
    }
    cc->securityMode = mode;
    ck_assert_uint_eq(UA_Client_connect(client, TEST_URL),
                      UA_STATUSCODE_GOOD);
    return client;
}

static UA_StatusCode
clientCall(UA_Client *client, UA_UInt32 objectId, UA_UInt32 methodId,
           size_t inputSize, UA_Variant *input, UA_UInt32 *handle) {
    size_t outputSize = 0;
    UA_Variant *output = NULL;
    UA_StatusCode res = UA_Client_call(client, UA_NODEID_NUMERIC(0, objectId),
                                       UA_NODEID_NUMERIC(0, methodId), inputSize,
                                       input, &outputSize, &output);
    if(res == UA_STATUSCODE_GOOD && handle && outputSize == 1)
        *handle = *(UA_UInt32*)output[0].data;
    UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    return res;
}

START_TEST(security_mode) {
    /* Sign protects the integrity, but private keys need encryption */
    UA_Client *client = connectClient(UA_MESSAGESECURITYMODE_SIGN);
    UA_NodeId groupId = UA_NODEID_NULL;
    UA_NodeId typeId = UA_NS0ID(RSASHA256APPLICATIONCERTIFICATETYPE);
    UA_String empty = UA_STRING_NULL;
    UA_Boolean regenerate = false;
    UA_ByteString nonce = UA_BYTESTRING_NULL;
    UA_Variant input[6];
    UA_Variant_setScalar(&input[0], &groupId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&input[1], &typeId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&input[2], &empty, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&input[3], &regenerate, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_Variant_setScalar(&input[4], &nonce, &UA_TYPES[UA_TYPES_BYTESTRING]);
    ck_assert_uint_eq(clientCall(client, UA_NS0ID_SERVERCONFIGURATION,
                                 UA_NS0ID_SERVERCONFIGURATION_CREATESIGNINGREQUEST,
                                 5, input, NULL),
                      UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT);
    UA_Variant_setScalar(&input[2], &clientCertificate, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setArray(&input[3], NULL, 0, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&input[4], &empty, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&input[5], &nonce, &UA_TYPES[UA_TYPES_BYTESTRING]);
    ck_assert_uint_eq(clientCall(client, UA_NS0ID_SERVERCONFIGURATION,
                                 UA_NS0ID_SERVERCONFIGURATION_UPDATECERTIFICATE,
                                 6, input, NULL),
                      UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT);
    ck_assert_uint_eq(clientCall(client, UA_NS0ID_SERVERCONFIGURATION,
                                 UA_NS0ID_SERVERCONFIGURATION_GETREJECTEDLIST,
                                 0, NULL, NULL), UA_STATUSCODE_GOOD);
    UA_Client_disconnect(client);
    UA_Client_delete(client);

    /* Without security */
    client = connectClient(UA_MESSAGESECURITYMODE_NONE);
    ck_assert_uint_eq(clientCall(client, UA_NS0ID_SERVERCONFIGURATION,
                                 UA_NS0ID_SERVERCONFIGURATION_GETREJECTEDLIST,
                                 0, NULL, NULL),
                      UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
} END_TEST

START_TEST(transaction_of_another_session) {
    UA_Client *first = connectClient(UA_MESSAGESECURITYMODE_SIGNANDENCRYPT);
    UA_Client *second = connectClient(UA_MESSAGESECURITYMODE_SIGNANDENCRYPT);

    UA_Byte writeMode = UA_OPENFILEMODE_WRITE | UA_OPENFILEMODE_ERASEEXISTING;
    UA_Byte readMode = UA_OPENFILEMODE_READ;
    UA_Variant input;
    UA_UInt32 handle = 0;
    UA_Variant_setScalar(&input, &writeMode, &UA_TYPES[UA_TYPES_BYTE]);
    ck_assert_uint_eq(clientCall(first, DEFAULT_TRUSTLIST, UA_NS0ID_FILETYPE_OPEN,
                                 1, &input, &handle), UA_STATUSCODE_GOOD);

    /* The transaction belongs to the first Session */
    ck_assert_uint_eq(clientCall(second, USERTOKEN_TRUSTLIST, UA_NS0ID_FILETYPE_OPEN,
                                 1, &input, NULL), UA_STATUSCODE_BADTRANSACTIONPENDING);
    ck_assert_uint_eq(clientCall(second, UA_NS0ID_SERVERCONFIGURATION,
                                 UA_NS0ID_SERVERCONFIGURATION_APPLYCHANGES,
                                 0, NULL, NULL), UA_STATUSCODE_BADSESSIONIDINVALID);
    ck_assert_uint_eq(clientCall(second, UA_NS0ID_SERVERCONFIGURATION,
                                 UA_NS0ID_SERVERCONFIGURATION_CANCELCHANGES,
                                 0, NULL, NULL), UA_STATUSCODE_BADSESSIONIDINVALID);

    /* Other TrustLists can be read */
    UA_Variant_setScalar(&input, &readMode, &UA_TYPES[UA_TYPES_BYTE]);
    ck_assert_uint_eq(clientCall(second, USERTOKEN_TRUSTLIST, UA_NS0ID_FILETYPE_OPEN,
                                 1, &input, NULL), UA_STATUSCODE_GOOD);

    ck_assert_uint_eq(clientCall(first, UA_NS0ID_SERVERCONFIGURATION,
                                 UA_NS0ID_SERVERCONFIGURATION_CANCELCHANGES,
                                 0, NULL, NULL), UA_STATUSCODE_GOOD);

    UA_Client_disconnect(first);
    UA_Client_disconnect(second);
    UA_Client_delete(first);
    UA_Client_delete(second);
} END_TEST

static Suite *
testSuite_pushManagement(void) {
    Suite *s = suite_create("GDS Receiver PushManagement");
    TCase *tc = tcase_create("Local");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, open_modes);
    tcase_add_test(tc, transaction_spans_trustlists_and_certificate);
    tcase_add_test(tc, cancel_changes);
    tcase_add_test(tc, open_with_masks_filters);
    tcase_add_test(tc, trustlist_size_limit);
    tcase_add_test(tc, update_certificate_checks);
    tcase_add_test(tc, signing_request_checks);
    tcase_add_test(tc, metadata);
    tcase_add_test(tc, set_position_uint64);
#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
    tcase_add_test(tc, trustlist_requires_issuer);
    tcase_add_test(tc, remove_needed_issuer);
#endif
    suite_add_tcase(s, tc);

    TCase *tcPlain = tcase_create("AcceptAll");
    tcase_add_test(tcPlain, accept_all_pki);
    suite_add_tcase(s, tcPlain);

    TCase *tcNet = tcase_create("Networked");
    tcase_add_checked_fixture(tcNet, setupNetworked, teardownNetworked);
    tcase_add_test(tcNet, security_mode);
    tcase_add_test(tcNet, transaction_of_another_session);
    suite_add_tcase(s, tcNet);
    return s;
}

int main(void) {
    Suite *s = testSuite_pushManagement();
    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
