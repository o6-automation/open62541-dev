/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* The GDS core shared by the GDS Push and the GDS Pull driver. The test acts
 * as the GDS Pull driver and uses the core of a started GDS Push driver. */

#include <open62541/driver/gds_push.h>
#include <open62541/server_config_default.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/certificategroup_default.h>

#include "../../drivers/gds_common/gds_core.h"

#include <check.h>
#include "test_helpers.h"
#include "testing_clock.h"
#include "certificates.h"

static UA_Server *server;
static UA_GDSPushDriver *driver;
static UA_Boolean serverStarted;

static UA_NodeId defaultApplicationGroup;
static UA_NodeId rsaSha256CertificateType;

static void
setup(void) {
    defaultApplicationGroup = UA_NODEID_NUMERIC(
        0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    rsaSha256CertificateType = UA_NODEID_NUMERIC(
        0, UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE);

    /* With a TrustList, the DefaultApplicationGroup is a certificate store
     * (not AcceptAll) whose TrustList can be changed */
    UA_ByteString certificate = {CERT_DER_LENGTH, CERT_DER_DATA};
    UA_ByteString privateKey = {KEY_DER_LENGTH, KEY_DER_DATA};
    UA_ByteString trustList[1] = {{CERT_DER_LENGTH, CERT_DER_DATA}};
    server = UA_Server_newForUnitTestWithSecurityPolicies(
        4840, &certificate, &privateKey, trustList, 1, NULL, 0, NULL, 0);
    ck_assert_ptr_nonnull(server);

    driver = UA_GDSPushDriver_new(UA_KEYVALUEMAP_NULL);
    ck_assert_ptr_nonnull(driver);
    ck_assert_uint_eq(UA_Server_addDriver(server, &driver->drv),
                      UA_STATUSCODE_GOOD);
    serverStarted = false;
}

static void
teardown(void) {
    if(serverStarted)
        ck_assert_uint_eq(UA_Server_run_shutdown(server), UA_STATUSCODE_GOOD);
    UA_Server_delete(server);
}

static UA_GDSCore *
startup(void) {
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
    serverStarted = true;
    UA_GDSCore *core = UA_GDSCore_find(server, NULL);
    ck_assert_ptr_eq(core, UA_GDSPush_getCore(&driver->drv));
    return core;
}

static UA_StatusCode
callServerConfigurationMethod(UA_UInt32 methodId, size_t inputSize,
                              UA_Variant *input) {
    UA_CallMethodRequest request;
    UA_CallMethodRequest_init(&request);
    request.objectId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION);
    request.methodId = UA_NODEID_NUMERIC(0, methodId);
    request.inputArgumentsSize = inputSize;
    request.inputArguments = input;

    UA_CallMethodResult result = UA_Server_call(server, &request);
    UA_StatusCode res = result.statusCode;
    UA_CallMethodResult_clear(&result);
    return res;
}

/* Stage the current certificate in a transaction of the admin Session */
static UA_StatusCode
stageCertificateUpdate(void) {
    UA_ByteString certificate = {CERT_DER_LENGTH, CERT_DER_DATA};
    UA_ByteString privateKey = {KEY_DER_LENGTH, KEY_DER_DATA};
    UA_String privateKeyFormat = UA_STRING_STATIC("DER");

    UA_Variant input[6];
    memset(input, 0, sizeof(input));
    UA_Variant_setScalar(&input[0], &defaultApplicationGroup,
                         &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&input[1], &rsaSha256CertificateType,
                         &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&input[2], &certificate,
                         &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setArray(&input[3], NULL, 0, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&input[4], &privateKeyFormat,
                         &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&input[5], &privateKey,
                         &UA_TYPES[UA_TYPES_BYTESTRING]);
    return callServerConfigurationMethod(
        UA_NS0ID_SERVERCONFIGURATION_UPDATECERTIFICATE, 6, input);
}

static UA_StatusCode
pushSigningRequest(UA_Boolean regenerateKey) {
    UA_ByteString csr = UA_BYTESTRING_NULL;
    UA_StatusCode res = UA_GDSPushDriver_createSigningRequest(
        driver, defaultApplicationGroup, rsaSha256CertificateType,
        NULL, &regenerateKey, NULL, &csr);
    UA_ByteString_clear(&csr);
    return res;
}

static UA_StatusCode
pullSigningRequest(UA_GDSCore *core) {
    UA_ByteString csr = UA_BYTESTRING_NULL;
    UA_StatusCode res =
        UA_GDSCore_createSigningRequest(core, UA_GDSREQUESTOWNER_PULL,
                                        &rsaSha256CertificateType, NULL, NULL,
                                        false, &csr);
    UA_ByteString_clear(&csr);
    return res;
}

/* The current certificate without a key: the key of the server is kept */
static UA_StatusCode
pullCertificateUpdate(UA_GDSCore *core) {
    UA_ByteString certificate = {CERT_DER_LENGTH, CERT_DER_DATA};
    return UA_GDSCore_updateCertificate(core, UA_GDSREQUESTOWNER_PULL,
                                        &rsaSha256CertificateType, certificate,
                                        UA_BYTESTRING_NULL);
}

static UA_StatusCode
pullTrustListUpdate(UA_GDSCore *core) {
    UA_ByteString trusted = {CERT_DER_LENGTH, CERT_DER_DATA};
    UA_TrustListDataType trustList;
    UA_TrustListDataType_init(&trustList);
    trustList.specifiedLists = UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES;
    trustList.trustedCertificates = &trusted;
    trustList.trustedCertificatesSize = 1;
    return UA_GDSCore_addToTrustList(core, &defaultApplicationGroup, &trustList);
}

/* Without a started GDS Push driver, the GDS Pull driver uses its own core */
START_TEST(findCore) {
    UA_GDSCore fallback;
    ck_assert_ptr_eq(UA_GDSCore_find(server, &fallback), &fallback);
    startup();
    ck_assert_uint_eq(UA_Server_run_shutdown(server), UA_STATUSCODE_GOOD);
    serverStarted = false;
    ck_assert_ptr_eq(UA_GDSCore_find(server, &fallback), &fallback);
} END_TEST

/* The pending changes of a transaction would overwrite the changes of the GDS
 * Pull driver. It has to wait until the transaction is done. */
START_TEST(pullWaitsForTransaction) {
    UA_GDSCore *core = startup();
    ck_assert_uint_eq(stageCertificateUpdate(), UA_STATUSCODE_GOOD);
    ck_assert(UA_GDSCore_changesPending(core));
    ck_assert_uint_eq(pullCertificateUpdate(core),
                      UA_STATUSCODE_BADTRANSACTIONPENDING);
    ck_assert_uint_eq(pullTrustListUpdate(core),
                      UA_STATUSCODE_BADTRANSACTIONPENDING);

    ck_assert_uint_eq(callServerConfigurationMethod(
                          UA_NS0ID_SERVERCONFIGURATION_CANCELCHANGES, 0, NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert(!UA_GDSCore_changesPending(core));
    ck_assert_uint_eq(pullCertificateUpdate(core), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(pullTrustListUpdate(core), UA_STATUSCODE_GOOD);

    /* The changes are pending until the delayed ApplyChanges ran */
    ck_assert_uint_eq(stageCertificateUpdate(), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(callServerConfigurationMethod(
                          UA_NS0ID_SERVERCONFIGURATION_APPLYCHANGES, 0, NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(pullTrustListUpdate(core),
                      UA_STATUSCODE_BADTRANSACTIONPENDING);
    UA_Server_run_iterate(server, false);
    ck_assert_uint_eq(pullTrustListUpdate(core), UA_STATUSCODE_GOOD);
} END_TEST

/* A signing request of one driver must not discard the new key of the other
 * driver's request */
START_TEST(signingRequestKeepsNewKey) {
    UA_GDSCore *core = startup();
    UA_GDSCertificateSlot *slot =
        UA_GDSCore_findSlot(core, &rsaSha256CertificateType);
    ck_assert_ptr_nonnull(slot);

    /* The request of the GDS Push driver has a new key */
    ck_assert_uint_eq(pushSigningRequest(true), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(slot->pendingOwner, UA_GDSREQUESTOWNER_PUSH);
    ck_assert(slot->pendingNewKey);
    ck_assert_uint_eq(pullSigningRequest(core),
                      UA_STATUSCODE_BADTRANSACTIONPENDING);

    /* The same driver can replace its own request */
    ck_assert_uint_eq(pushSigningRequest(false), UA_STATUSCODE_GOOD);
    ck_assert(!slot->pendingNewKey);
    ck_assert_uint_eq(pullSigningRequest(core), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(slot->pendingOwner, UA_GDSREQUESTOWNER_PULL);

    /* The request of the GDS Pull driver keeps the current key. The GDS Push
     * driver can replace it. */
    ck_assert_uint_eq(pushSigningRequest(true), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(slot->pendingOwner, UA_GDSREQUESTOWNER_PUSH);
} END_TEST

/* A certificate for another key does not complete the pending request of the
 * other driver */
START_TEST(certificateKeepsOtherRequest) {
    UA_GDSCore *core = startup();
    UA_GDSCertificateSlot *slot =
        UA_GDSCore_findSlot(core, &rsaSha256CertificateType);
    ck_assert_ptr_nonnull(slot);

    ck_assert_uint_eq(pushSigningRequest(true), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(pullCertificateUpdate(core), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(slot->pendingOwner, UA_GDSREQUESTOWNER_PUSH);
    ck_assert(slot->pendingNewKey);
    ck_assert_uint_gt(slot->pendingCsr.length, 0);

    /* The update of the driver that created the request completes it */
    UA_ByteString certificate = {CERT_DER_LENGTH, CERT_DER_DATA};
    ck_assert_uint_eq(UA_GDSPushDriver_updateCertificate(
                          driver, defaultApplicationGroup,
                          rsaSha256CertificateType, certificate, NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(slot->pendingOwner, UA_GDSREQUESTOWNER_NONE);
    ck_assert_uint_eq(slot->pendingCsr.length, 0);
} END_TEST

/* Without a key, the certificate must belong to the current key or to the key
 * of the pending request */
START_TEST(certificateChecks) {
    UA_GDSCore *core = startup();
    UA_ByteString certificate = {APPLICATION_CERT_DER_LENGTH,
                                 APPLICATION_CERT_DER_DATA};
    UA_NodeId unknownType =
        UA_NODEID_NUMERIC(0, UA_NS0ID_ECCCURVE448APPLICATIONCERTIFICATETYPE);
    ck_assert_uint_eq(UA_GDSCore_updateCertificate(core, UA_GDSREQUESTOWNER_PULL,
                                                   &unknownType, certificate,
                                                   UA_BYTESTRING_NULL),
                      UA_STATUSCODE_BADINVALIDARGUMENT);
    ck_assert_uint_eq(UA_GDSCore_updateCertificate(core, UA_GDSREQUESTOWNER_PULL,
                                                   &rsaSha256CertificateType,
                                                   certificate, UA_BYTESTRING_NULL),
                      UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    UA_ByteString wrongKey = {KEY_DER_LENGTH, KEY_DER_DATA};
    ck_assert_uint_eq(UA_GDSCore_updateCertificate(core, UA_GDSREQUESTOWNER_PULL,
                                                   &rsaSha256CertificateType,
                                                   certificate, wrongKey),
                      UA_STATUSCODE_BADNOTSUPPORTED);
} END_TEST

/* A TrustList change outside of a transaction updates the LastUpdateTime of
 * the TrustList of the GDS Push driver */
START_TEST(trustListLastUpdateTime) {
    UA_GDSCore *core = startup();
    UA_NodeId lastUpdateTimeId = UA_NODEID_NUMERIC(
        0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_LASTUPDATETIME);
    UA_Variant before, after;
    ck_assert_uint_eq(UA_Server_readValue(server, lastUpdateTimeId, &before),
                      UA_STATUSCODE_GOOD);
    UA_DateTime beforeTime = 0; /* Empty before the first update */
    if(UA_Variant_hasScalarType(&before, &UA_TYPES[UA_TYPES_UTCTIME]))
        beforeTime = *(UA_UtcTime*)before.data;

    UA_fakeSleep(1000);
    ck_assert_uint_eq(pullTrustListUpdate(core), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_readValue(server, lastUpdateTimeId, &after),
                      UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasScalarType(&after, &UA_TYPES[UA_TYPES_UTCTIME]));
    ck_assert_int_gt(*(UA_UtcTime*)after.data, beforeTime);
    UA_Variant_clear(&before);
    UA_Variant_clear(&after);

    /* An unknown group is refused */
    UA_NodeId unknownGroup = UA_NODEID_NUMERIC(1, 4711);
    UA_TrustListDataType empty;
    UA_TrustListDataType_init(&empty);
    ck_assert_uint_eq(UA_GDSCore_setTrustList(core, &unknownGroup, &empty),
                      UA_STATUSCODE_BADINVALIDARGUMENT);
} END_TEST

/*
 * SecureChannels after a TrustList change
 */

/* The client certificate is issued by the intermediate CA of the TrustList */
static void
setupChannels(void) {
    defaultApplicationGroup = UA_NODEID_NUMERIC(
        0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);

    UA_ByteString certificate = {CERT_DER_LENGTH, CERT_DER_DATA};
    UA_ByteString privateKey = {KEY_DER_LENGTH, KEY_DER_DATA};
    UA_ByteString trustList[2] = {
        {INTERMEDIATE_CERT_DER_LENGTH, INTERMEDIATE_CERT_DER_DATA},
        {ROOT_CERT_DER_LENGTH, ROOT_CERT_DER_DATA}};
    UA_ByteString issuerList[2] = {
        {INTERMEDIATE_CERT_DER_LENGTH, INTERMEDIATE_CERT_DER_DATA},
        {ROOT_CERT_DER_LENGTH, ROOT_CERT_DER_DATA}};
    UA_ByteString revocationList[2] = {
        {ROOT_EMPTY_CRL_PEM_LENGTH, ROOT_EMPTY_CRL_PEM_DATA},
        {INTERMEDIATE_EMPTY_CRL_PEM_LENGTH, INTERMEDIATE_EMPTY_CRL_PEM_DATA}};
    server = UA_Server_newForUnitTestWithSecurityPolicies(
        4840, &certificate, &privateKey, trustList, 2, issuerList, 2,
        revocationList, 2);
    ck_assert_ptr_nonnull(server);

    driver = UA_GDSPushDriver_new(UA_KEYVALUEMAP_NULL);
    ck_assert_ptr_nonnull(driver);
    ck_assert_uint_eq(UA_Server_addDriver(server, &driver->drv),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
    serverStarted = true;
}

static UA_Boolean channelClosed;

static void
clientStateCallback(UA_Client *client, UA_SecureChannelState channelState,
                    UA_SessionState sessionState, UA_StatusCode connectStatus) {
    if(channelState == UA_SECURECHANNELSTATE_CLOSED ||
       channelState == UA_SECURECHANNELSTATE_CLOSING)
        channelClosed = true;
}

static void
iterate(UA_Client *client, size_t rounds) {
    for(size_t i = 0; i < rounds; i++) {
        UA_Server_run_iterate(server, false);
        UA_Client_run_iterate(client, 0);
    }
}

static UA_Client *
connectSecureClient(void) {
    UA_ByteString certificate = {APPLICATION_CERT_DER_LENGTH,
                                 APPLICATION_CERT_DER_DATA};
    UA_ByteString privateKey = {APPLICATION_KEY_DER_LENGTH,
                                APPLICATION_KEY_DER_DATA};
    UA_Client *client = UA_Client_newForUnitTest();
    ck_assert_ptr_nonnull(client);
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    UA_ClientConfig_setDefaultEncryption(cc, certificate, privateKey,
                                         NULL, 0, NULL, 0);
    cc->certificateVerification.clear(&cc->certificateVerification);
    UA_CertificateGroup_AcceptAll(&cc->certificateVerification);
    UA_String_clear(&cc->clientDescription.applicationUri);
    cc->clientDescription.applicationUri =
        UA_STRING_ALLOC("urn:unconfigured:application");
    cc->securityPolicyUri = UA_STRING_ALLOC(
        "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep");
    ck_assert_uint_eq(UA_Client_connectAsync(client, "opc.tcp://localhost:4840"),
                      UA_STATUSCODE_GOOD);

    UA_SecureChannelState channelState;
    UA_SessionState sessionState = UA_SESSIONSTATE_CLOSED;
    UA_StatusCode connectStatus;
    for(size_t i = 0; i < 1000 && sessionState != UA_SESSIONSTATE_ACTIVATED; i++) {
        iterate(client, 1);
        UA_Client_getState(client, &channelState, &sessionState, &connectStatus);
        ck_assert_uint_eq(connectStatus, UA_STATUSCODE_GOOD);
    }
    ck_assert_uint_eq(sessionState, UA_SESSIONSTATE_ACTIVATED);

    /* Only closures after the connection count */
    channelClosed = false;
    cc->stateCallback = clientStateCallback;
    return client;
}

/* The server is iterated in the same thread. A synchronous CloseSession
 * would wait for it forever. */
static void
disconnectClient(UA_Client *client) {
    UA_Client_disconnectAsync(client);
    iterate(client, 50);
    UA_Client_delete(client);
}

static void
setTrustListAndIterate(UA_Client *client, const UA_TrustListDataType *trustList) {
    UA_GDSCore *core = UA_GDSCore_find(server, NULL);
    ck_assert_ptr_nonnull(core);
    ck_assert_uint_eq(UA_GDSCore_setTrustList(core, &defaultApplicationGroup,
                                              trustList),
                      UA_STATUSCODE_GOOD);
    iterate(client, 50);
}

/* A SecureChannel stays open while its remote certificate is trusted */
START_TEST(trustedChannelStaysOpen) {
    UA_Client *client = connectSecureClient();

    UA_ByteString trusted[2] = {
        {INTERMEDIATE_CERT_DER_LENGTH, INTERMEDIATE_CERT_DER_DATA},
        {ROOT_CERT_DER_LENGTH, ROOT_CERT_DER_DATA}};
    UA_ByteString crls[2] = {
        {ROOT_EMPTY_CRL_PEM_LENGTH, ROOT_EMPTY_CRL_PEM_DATA},
        {INTERMEDIATE_EMPTY_CRL_PEM_LENGTH, INTERMEDIATE_EMPTY_CRL_PEM_DATA}};
    UA_TrustListDataType trustList;
    UA_TrustListDataType_init(&trustList);
    trustList.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    trustList.trustedCertificates = trusted;
    trustList.trustedCertificatesSize = 2;
    trustList.trustedCrls = crls;
    trustList.trustedCrlsSize = 2;
    setTrustListAndIterate(client, &trustList);
    ck_assert(!channelClosed);

    disconnectClient(client);
} END_TEST

/* The GDS Pull driver replaces the TrustList. The SecureChannel of a client
 * that is no longer trusted is closed. */
START_TEST(untrustedChannelIsClosed) {
    UA_Client *client = connectSecureClient();

    UA_ByteString other = {CERT_DER_LENGTH, CERT_DER_DATA};
    UA_TrustListDataType trustList;
    UA_TrustListDataType_init(&trustList);
    trustList.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    trustList.trustedCertificates = &other;
    trustList.trustedCertificatesSize = 1;
    setTrustListAndIterate(client, &trustList);
    ck_assert(channelClosed);

    disconnectClient(client);
} END_TEST

static Suite *
testSuite_gdsCore(void) {
    Suite *suite = suite_create("GDS Core");

    TCase *tc = tcase_create("Push and Pull");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, findCore);
    tcase_add_test(tc, pullWaitsForTransaction);
    tcase_add_test(tc, signingRequestKeepsNewKey);
    tcase_add_test(tc, certificateKeepsOtherRequest);
    tcase_add_test(tc, certificateChecks);
    tcase_add_test(tc, trustListLastUpdateTime);
    suite_add_tcase(suite, tc);

    TCase *tcChannels = tcase_create("SecureChannels");
    tcase_add_checked_fixture(tcChannels, setupChannels, teardown);
    tcase_add_test(tcChannels, trustedChannelStaysOpen);
    tcase_add_test(tcChannels, untrustedChannelIsClosed);
    suite_add_tcase(suite, tcChannels);
    return suite;
}

int main(void) {
    SRunner *sr = srunner_create(testSuite_gdsCore());
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int numberFailed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (numberFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
