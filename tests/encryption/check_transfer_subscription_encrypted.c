/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Test subscription transfer between anonymous sessions on secure channels.
 *
 * OPC UA Part 4, §5.13.7: The Server shall validate that the Client of that
 * Session is operating on behalf of the same user. For anonymous users over
 * secure channels, the ApplicationUri from the client certificate is used
 * to verify identity. */

#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/securitypolicy.h>
#include <open62541/plugin/pki_default.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>

#include "client/ua_client_internal.h"
#include "ua_server_internal.h"

#include <stdio.h>
#include <stdlib.h>

#include "certificates.h"
#include "check.h"
#include "testing_clock.h"
#include "testing_networklayers.h"
#include "thread_wrapper.h"

UA_Server *server;
UA_Boolean running;
THREAD_HANDLE server_thread;

THREAD_CALLBACK(serverloop) {
    while(running)
        UA_Server_run_iterate(server, true);
    return 0;
}

static void setup(void) {
    running = true;

    /* Load certificate and private key */
    UA_ByteString certificate;
    certificate.length = CERT_DER_LENGTH;
    certificate.data = CERT_DER_DATA;

    UA_ByteString privateKey;
    privateKey.length = KEY_DER_LENGTH;
    privateKey.data = KEY_DER_DATA;

    server = UA_Server_new();
    ck_assert(server != NULL);
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_setDefaultWithSecurityPolicies(config, 4840,
                                                   &certificate, &privateKey,
                                                   NULL, 0, NULL, 0, NULL, 0);

    /* Accept all certificates for testing */
    UA_CertificateVerification_AcceptAll(&config->secureChannelPKI);
    UA_CertificateVerification_AcceptAll(&config->sessionPKI);

    /* Set the ApplicationUri used in the certificate */
    UA_String_clear(&config->applicationDescription.applicationUri);
    config->applicationDescription.applicationUri =
        UA_STRING_ALLOC("urn:unconfigured:application");

    UA_Server_run_startup(server);
    THREAD_CREATE(server_thread, serverloop);
}

static void teardown(void) {
    running = false;
    THREAD_JOIN(server_thread);
    UA_Server_run_shutdown(server);
    UA_Server_delete(server);
}

static UA_Client *
createEncryptedAnonymousClient(void) {
    UA_ByteString certificate;
    certificate.length = CERT_DER_LENGTH;
    certificate.data = CERT_DER_DATA;

    UA_ByteString privateKey;
    privateKey.length = KEY_DER_LENGTH;
    privateKey.data = KEY_DER_DATA;

    UA_Client *client = UA_Client_new();
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    UA_ClientConfig_setDefaultEncryption(cc, certificate, privateKey,
                                         NULL, 0, NULL, 0);
    UA_CertificateVerification_AcceptAll(&cc->certificateVerification);
    cc->securityPolicyUri =
        UA_STRING_ALLOC("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
    /* Anonymous identity (default) - no username/password */
    return client;
}

static void
statusChangeHandler(UA_Client *client, UA_UInt32 subId, void *subContext,
                    UA_StatusChangeNotification *notification) {
}

static void
dataChangeHandler(UA_Client *client, UA_UInt32 subId, void *subContext,
                  UA_UInt32 monId, void *monContext, UA_DataValue *value) {
}

/* Test: Two anonymous clients on encrypted channels (same applicationUri)
 * transferring a subscription. This should SUCCEED per OPC UA spec Part 4
 * §5.13.7 because both sessions are from the same application (verified
 * by the applicationUri in the client certificate). */
START_TEST(transfer_subscription_anonymous_secure_same_appuri) {
    /* Client 1: Connect with encryption + anonymous */
    UA_Client *client1 = createEncryptedAnonymousClient();
    UA_StatusCode retval = UA_Client_connect(client1, "opc.tcp://localhost:4840");
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);

    /* Client 1: Create a subscription */
    UA_CreateSubscriptionRequest subReq = UA_CreateSubscriptionRequest_default();
    UA_CreateSubscriptionResponse subResp =
        UA_Client_Subscriptions_create(client1, subReq, NULL, statusChangeHandler, NULL);
    ck_assert_uint_eq(subResp.responseHeader.serviceResult, UA_STATUSCODE_GOOD);
    UA_UInt32 subId = subResp.subscriptionId;

    /* Client 1: Create a monitored item */
    UA_MonitoredItemCreateRequest monReq =
        UA_MonitoredItemCreateRequest_default(
            UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERSTATUS_CURRENTTIME));
    UA_MonitoredItemCreateResult monResp =
        UA_Client_MonitoredItems_createDataChange(client1, subId,
                                                  UA_TIMESTAMPSTORETURN_BOTH,
                                                  monReq, NULL, dataChangeHandler, NULL);
    ck_assert_uint_eq(monResp.statusCode, UA_STATUSCODE_GOOD);

    /* Client 2: Connect with encryption + anonymous (same cert/applicationUri) */
    UA_Client *client2 = createEncryptedAnonymousClient();
    retval = UA_Client_connect(client2, "opc.tcp://localhost:4840");
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);

    /* Client 2: Transfer the subscription from client 1 */
    UA_TransferSubscriptionsRequest tReq;
    UA_TransferSubscriptionsRequest_init(&tReq);
    tReq.subscriptionIds = &subId;
    tReq.subscriptionIdsSize = 1;
    tReq.sendInitialValues = true;

    UA_TransferSubscriptionsResponse tResp;
    __UA_Client_Service(client2,
                        &tReq, &UA_TYPES[UA_TYPES_TRANSFERSUBSCRIPTIONSREQUEST],
                        &tResp, &UA_TYPES[UA_TYPES_TRANSFERSUBSCRIPTIONSRESPONSE]);

    /* Transfer should succeed: both anonymous sessions use secure channels
     * and have the same applicationUri */
    ck_assert_uint_eq(tResp.responseHeader.serviceResult, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(tResp.resultsSize, 1);
    ck_assert_uint_eq(tResp.results[0].statusCode, UA_STATUSCODE_GOOD);

    UA_TransferSubscriptionsResponse_clear(&tResp);

    /* Let both clients process a bit */
    for(size_t i = 0; i < 5; i++) {
        UA_Client_run_iterate(client1, 1);
        UA_Client_run_iterate(client2, 1);
        UA_fakeSleep(100);
    }

    UA_Client_disconnect(client1);
    UA_Client_delete(client1);
    UA_Client_disconnect(client2);
    UA_Client_delete(client2);
}
END_TEST

/* Test: Anonymous transfer on SecurityPolicy#None must be DENIED.
 * Without a secure channel, the ApplicationUri cannot be verified
 * from the certificate, so transfers between anonymous sessions
 * must not be allowed. */
START_TEST(transfer_subscription_anonymous_none_denied) {
    /* Client 1: Connect without encryption (SecurityPolicy#None) */
    UA_Client *client1 = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(client1));
    UA_StatusCode retval = UA_Client_connect(client1, "opc.tcp://localhost:4840");
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);

    /* Client 1: Create a subscription */
    UA_CreateSubscriptionRequest subReq = UA_CreateSubscriptionRequest_default();
    UA_CreateSubscriptionResponse subResp =
        UA_Client_Subscriptions_create(client1, subReq, NULL, statusChangeHandler, NULL);
    ck_assert_uint_eq(subResp.responseHeader.serviceResult, UA_STATUSCODE_GOOD);
    UA_UInt32 subId = subResp.subscriptionId;

    /* Client 1: Create a monitored item */
    UA_MonitoredItemCreateRequest monReq =
        UA_MonitoredItemCreateRequest_default(
            UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERSTATUS_CURRENTTIME));
    UA_MonitoredItemCreateResult monResp =
        UA_Client_MonitoredItems_createDataChange(client1, subId,
                                                  UA_TIMESTAMPSTORETURN_BOTH,
                                                  monReq, NULL, dataChangeHandler, NULL);
    ck_assert_uint_eq(monResp.statusCode, UA_STATUSCODE_GOOD);

    /* Client 2: Connect without encryption (SecurityPolicy#None) */
    UA_Client *client2 = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(client2));
    retval = UA_Client_connect(client2, "opc.tcp://localhost:4840");
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);

    /* Client 2: Attempt to transfer the subscription */
    UA_TransferSubscriptionsRequest tReq;
    UA_TransferSubscriptionsRequest_init(&tReq);
    tReq.subscriptionIds = &subId;
    tReq.subscriptionIdsSize = 1;
    tReq.sendInitialValues = false;

    UA_TransferSubscriptionsResponse tResp;
    __UA_Client_Service(client2,
                        &tReq, &UA_TYPES[UA_TYPES_TRANSFERSUBSCRIPTIONSREQUEST],
                        &tResp, &UA_TYPES[UA_TYPES_TRANSFERSUBSCRIPTIONSRESPONSE]);

    /* Transfer should be denied: both sessions use SecurityPolicy#None */
    ck_assert_uint_eq(tResp.responseHeader.serviceResult, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(tResp.resultsSize, 1);
    ck_assert_uint_eq(tResp.results[0].statusCode, UA_STATUSCODE_BADUSERACCESSDENIED);

    UA_TransferSubscriptionsResponse_clear(&tResp);

    UA_Client_disconnect(client1);
    UA_Client_delete(client1);
    UA_Client_disconnect(client2);
    UA_Client_delete(client2);
}
END_TEST

/* Test: Mixed security policies - subscription created on encrypted channel,
 * transfer attempted from None policy channel. Should be DENIED because
 * the None policy session's ApplicationUri cannot be verified. */
START_TEST(transfer_subscription_anonymous_mixed_security_denied) {
    /* Client 1: Connect with encryption + anonymous, create subscription */
    UA_Client *client1 = createEncryptedAnonymousClient();
    UA_StatusCode retval = UA_Client_connect(client1, "opc.tcp://localhost:4840");
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);

    UA_CreateSubscriptionRequest subReq = UA_CreateSubscriptionRequest_default();
    UA_CreateSubscriptionResponse subResp =
        UA_Client_Subscriptions_create(client1, subReq, NULL, statusChangeHandler, NULL);
    ck_assert_uint_eq(subResp.responseHeader.serviceResult, UA_STATUSCODE_GOOD);
    UA_UInt32 subId = subResp.subscriptionId;

    UA_MonitoredItemCreateRequest monReq =
        UA_MonitoredItemCreateRequest_default(
            UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERSTATUS_CURRENTTIME));
    UA_MonitoredItemCreateResult monResp =
        UA_Client_MonitoredItems_createDataChange(client1, subId,
                                                  UA_TIMESTAMPSTORETURN_BOTH,
                                                  monReq, NULL, dataChangeHandler, NULL);
    ck_assert_uint_eq(monResp.statusCode, UA_STATUSCODE_GOOD);

    /* Client 2: Connect WITHOUT encryption (SecurityPolicy#None) + anonymous */
    UA_Client *client2 = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(client2));
    retval = UA_Client_connect(client2, "opc.tcp://localhost:4840");
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);

    /* Client 2: Attempt to transfer the subscription */
    UA_TransferSubscriptionsRequest tReq;
    UA_TransferSubscriptionsRequest_init(&tReq);
    tReq.subscriptionIds = &subId;
    tReq.subscriptionIdsSize = 1;
    tReq.sendInitialValues = false;

    UA_TransferSubscriptionsResponse tResp;
    __UA_Client_Service(client2,
                        &tReq, &UA_TYPES[UA_TYPES_TRANSFERSUBSCRIPTIONSREQUEST],
                        &tResp, &UA_TYPES[UA_TYPES_TRANSFERSUBSCRIPTIONSRESPONSE]);

    /* Transfer should be denied: client2 uses None policy, so its
     * ApplicationUri is not verified from the certificate */
    ck_assert_uint_eq(tResp.responseHeader.serviceResult, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(tResp.resultsSize, 1);
    ck_assert_uint_eq(tResp.results[0].statusCode, UA_STATUSCODE_BADUSERACCESSDENIED);

    UA_TransferSubscriptionsResponse_clear(&tResp);

    UA_Client_disconnect(client1);
    UA_Client_delete(client1);
    UA_Client_disconnect(client2);
    UA_Client_delete(client2);
}
END_TEST

/* Test: Transfer between same session should return Good and sequence numbers.
 * (Edge case: client tries to transfer its own subscription) */
START_TEST(transfer_subscription_same_session) {
    UA_Client *client1 = createEncryptedAnonymousClient();
    UA_StatusCode retval = UA_Client_connect(client1, "opc.tcp://localhost:4840");
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);

    UA_CreateSubscriptionRequest subReq = UA_CreateSubscriptionRequest_default();
    UA_CreateSubscriptionResponse subResp =
        UA_Client_Subscriptions_create(client1, subReq, NULL, statusChangeHandler, NULL);
    ck_assert_uint_eq(subResp.responseHeader.serviceResult, UA_STATUSCODE_GOOD);
    UA_UInt32 subId = subResp.subscriptionId;

    /* Transfer to ourselves */
    UA_TransferSubscriptionsRequest tReq;
    UA_TransferSubscriptionsRequest_init(&tReq);
    tReq.subscriptionIds = &subId;
    tReq.subscriptionIdsSize = 1;

    UA_TransferSubscriptionsResponse tResp;
    __UA_Client_Service(client1,
                        &tReq, &UA_TYPES[UA_TYPES_TRANSFERSUBSCRIPTIONSREQUEST],
                        &tResp, &UA_TYPES[UA_TYPES_TRANSFERSUBSCRIPTIONSRESPONSE]);

    /* Same session → should return Good with sequence numbers */
    ck_assert_uint_eq(tResp.responseHeader.serviceResult, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(tResp.resultsSize, 1);
    ck_assert_uint_eq(tResp.results[0].statusCode, UA_STATUSCODE_GOOD);

    UA_TransferSubscriptionsResponse_clear(&tResp);

    UA_Client_disconnect(client1);
    UA_Client_delete(client1);
}
END_TEST

static Suite *testSuite_encryption(void) {
    Suite *s = suite_create("Subscription transfer with encrypted anonymous sessions");
    TCase *tc = tcase_create("subscription_transfer_encrypted");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, transfer_subscription_anonymous_secure_same_appuri);
    tcase_add_test(tc, transfer_subscription_anonymous_none_denied);
    tcase_add_test(tc, transfer_subscription_anonymous_mixed_security_denied);
    tcase_add_test(tc, transfer_subscription_same_session);
    suite_add_tcase(s, tc);
    return s;
}

int main(void) {
    Suite *s = testSuite_encryption();
    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
