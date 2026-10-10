/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

/* The Endpoint filters of a Role (Part 18 §4.4.1) are compared with the
 * configured ServerUrl of the listener that accepted the SecureChannel, never
 * with a URL sent by the client. */

#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/log_stdout.h>

#include "test_helpers.h"
#include "test_helpers_rbac.h"
#include "client/ua_client_internal.h"

#include <check.h>
#include <stdlib.h>

/* The only port of this file */
#define LISTENER_URL "opc.tcp://localhost:4868"
#define UATCP "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"
#define WSS "http://opcfoundation.org/UA-Profile/Transport/wss-uasc-uabinary"

static UA_Server *server;
static UA_SecureChannel channel;

static void setup(void) {
    UA_ServerConfig config;
    memset(&config, 0, sizeof(config));
    config.logging = UA_Log_Stdout_new(UA_LOGLEVEL_WARNING);
    ck_assert_uint_eq(UA_ServerConfig_setMinimal(&config, 4868, NULL),
                      UA_STATUSCODE_GOOD);
    UA_Array_delete(config.serverUrls, config.serverUrlsSize,
                    &UA_TYPES[UA_TYPES_STRING]);
    config.serverUrls = UA_String_new();
    *config.serverUrls = UA_STRING_ALLOC(LISTENER_URL);
    config.serverUrlsSize = 1;
    config.tcpReuseAddr = true;
    server = UA_Server_newWithConfig(&config);
    ck_assert_ptr_nonnull(server);
}

static void teardown(void) {
    UA_Server_run_shutdown(server);
    UA_Server_delete(server);
    UA_SecureChannel_clear(&channel);
}

/* A Role for anonymous Sessions with one Endpoint filter entry */
static UA_NodeId
addEndpointRole(const char *name, const char *url, const char *profile,
                UA_Boolean exclude) {
    UA_IdentityMappingRuleType rule;
    UA_IdentityMappingRuleType_init(&rule);
    rule.criteriaType = UA_IDENTITYCRITERIATYPE_ANONYMOUS;
    UA_EndpointType filter;
    UA_EndpointType_init(&filter);
    filter.endpointUrl = UA_STRING((char*)(uintptr_t)url);
    filter.transportProfileUri = UA_STRING((char*)(uintptr_t)profile);
    UA_Role role;
    UA_Role_init(&role);
    role.roleName = UA_QUALIFIEDNAME(1, (char*)(uintptr_t)name);
    role.identityMappingRules = &rule;
    role.identityMappingRulesSize = 1;
    role.endpoints = &filter;
    role.endpointsSize = 1;
    role.endpointsExclude = exclude;
    UA_NodeId roleId;
    ck_assert_uint_eq(UA_Server_addRole(server, &role, &roleId), UA_STATUSCODE_GOOD);
    return roleId;
}

/* Scheme, host and port compare case-insensitively, the path without outer '/'.
 * A listener without a host matches every host. Unknown URLs never match. */
static const struct {
    const char *filter;
    const char *profile;
    UA_Boolean exclude;
    const char *listener;
    UA_Boolean granted;
} cases[] = {
    {"opc.tcp://host:4840", NULL, false, "opc.tcp://host:4840", true},
    {"opc.tcp://host:4840", NULL, false, "opc.tcp://other:4840", false},
    {"opc.tcp://host:4840", NULL, false, "opc.tcp://:4840", true},
    {"opc.tcp://host:4840", NULL, false, "opc.tcp://:4841", false},
    {"opc.tcp://host:4840", NULL, false, "opc.tcp://host:4841", false},
    {"opc.tcp://host:4840", NULL, false, "opc.wss://host:4840", false},
    {"opc.tcp://host:4840", NULL, false, "opc.tcp://host", true},
    {"opc.tcp://host:4840", NULL, false, "OPC.TCP://HOST:4840/", true},
    {"opc.tcp://host:4840", NULL, false, NULL, false},
    {"opc.tcp://host:4840", NULL, false, "not-a-url", false},
    {"opc.tcp://host:4840", NULL, false, "opc.tcp://host:0", false},
    {"opc.tcp://Host:4840/ua/server/", NULL, false, "opc.tcp://host:4840//ua/server//", true},
    {"opc.tcp://Host:4840/ua/server/", NULL, false, "opc.tcp://host:4840/UA/server", false},
    {"opc.tcp://Host:4840/ua/server/", NULL, false, "opc.tcp://host:4840", false},
    {"opc.tcp://Host:4840/ua/server/", NULL, false, "opc.tcp://:4840/ua/server", true},
    {"opc.tcp://[FE80::1]:4840", NULL, false, "opc.tcp://[fe80::1]:4840", true},
    {"opc.tcp://[FE80::1]:4840", NULL, false, "opc.tcp://[fe80::2]:4840", false},
    {"opc.tcp://host:4840", NULL, true, "opc.tcp://other:4840", true},
    {"opc.tcp://host:4840", NULL, true, "opc.tcp://host:4840", false},
    {"opc.tcp://host:4840", NULL, true, "opc.tcp://:4840", false},
    {"opc.tcp://host:4840", NULL, true, NULL, false},
    {"opc.tcp://host:4840", NULL, true, "opc.tcp://host:0", false},
    /* The in-process channel has no connection, so no transport profile */
    {NULL, UATCP, false, "opc.tcp://host:4840", false},
    {NULL, UATCP, true, "opc.tcp://host:4840", false}
};

/* In-process Sessions on SecureChannels of a listener with the URL */
START_TEST(filter_matchesListenerUrl) {
    UA_Server_getConfig(server)->tcpEnabled = false;
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        UA_NodeId roleId = addEndpointRole("EndpointRole", cases[i].filter,
                                           cases[i].profile, cases[i].exclude);
        rbacChannelInit(server, &channel, UA_MESSAGESECURITYMODE_NONE,
                        cases[i].listener);
        UA_NodeId sessionId;
        ck_assert_uint_eq(rbacLogin(server, &channel, NULL, NULL, &sessionId),
                          UA_STATUSCODE_GOOD);
        ck_assert_msg(rbacHasRole(server, &sessionId, roleId) == cases[i].granted,
                      "case %u", (unsigned)i);
        ck_assert_uint_eq(UA_Server_closeSession(server, &sessionId), UA_STATUSCODE_GOOD);
        UA_SecureChannel_clear(&channel);
        ck_assert_uint_eq(UA_Server_removeRole(server,
                                               UA_QUALIFIEDNAME(1, "EndpointRole")),
                          UA_STATUSCODE_GOOD);
        UA_NodeId_clear(&roleId);
    }
} END_TEST

/* A TCP client. The listener is configured with a hostname, the client
 * connects with the IP address. The transport profile is uatcp. */
START_TEST(filter_tcpListener) {
    UA_NodeId roles[5] = {
        addEndpointRole("Listener", LISTENER_URL, NULL, false),
        addEndpointRole("ClientUrl", "opc.tcp://127.0.0.1:4868", NULL, false),
        addEndpointRole("ExcludeListener", LISTENER_URL, NULL, true),
        addEndpointRole("Uatcp", NULL, UATCP, false),
        addEndpointRole("Wss", NULL, WSS, false)};
    const UA_Boolean granted[5] = {true, false, false, true, false};
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);

    UA_Client *client = UA_Client_newForUnitTest();
    ck_assert_uint_eq(UA_Client_connectAsync(client, "opc.tcp://127.0.0.1:4868"),
                      UA_STATUSCODE_GOOD);
    UA_SessionState state = UA_SESSIONSTATE_CLOSED;
    UA_StatusCode status = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < 1000 && state != UA_SESSIONSTATE_ACTIVATED &&
            status == UA_STATUSCODE_GOOD; i++) {
        UA_Server_run_iterate(server, false);
        UA_Client_run_iterate(client, 1);
        UA_Client_getState(client, NULL, &state, &status);
    }
    ck_assert_uint_eq(state, UA_SESSIONSTATE_ACTIVATED);
    for(size_t i = 0; i < 5; i++) {
        ck_assert_msg(rbacHasRole(server, &client->sessionId, roles[i]) == granted[i],
                      "role %u", (unsigned)i);
        UA_NodeId_clear(&roles[i]);
    }
    UA_Client_disconnectAsync(client);
    UA_SecureChannelState channelState = UA_SECURECHANNELSTATE_OPEN;
    for(size_t i = 0; i < 1000 && channelState != UA_SECURECHANNELSTATE_CLOSED; i++) {
        UA_Server_run_iterate(server, false);
        UA_Client_run_iterate(client, 1);
        UA_Client_getState(client, &channelState, NULL, NULL);
    }
    UA_Client_delete(client);
} END_TEST

static Suite *testSuite_rbacEndpoints(void) {
    Suite *s = suite_create("RBAC Endpoint filters");
    TCase *tc = tcase_create("Listener URL");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, filter_matchesListenerUrl);
    tcase_add_test(tc, filter_tcpListener);
    suite_add_tcase(s, tc);
    return s;
}

int main(void) {
    SRunner *sr = srunner_create(testSuite_rbacEndpoints());
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
