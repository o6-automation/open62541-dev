/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2019 (c) basysKom GmbH <opensource@basyskom.com> (Author: Frank Meerkötter)
 */

#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/types.h>
#include <open62541/transport_generated_handling.h>
#include <open62541/plugin/accesscontrol_default.h>

#include "server/ua_server_internal.h"
#include "server/ua_services.h"
#include "ua_types_encoding_binary.h"
#include "testing_networklayers.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "check.h"

static UA_Server *server = NULL;

static void setup(void) {
    server = UA_Server_new();
    ck_assert(server != NULL);
    UA_ServerConfig_setDefault(UA_Server_getConfig(server));
}

static void teardown(void) {
    UA_Server_delete(server);
}

START_TEST(checkGetConfig) {
    ck_assert_ptr_eq(UA_Server_getConfig(NULL), NULL);
    ck_assert_ptr_ne(UA_Server_getConfig(server), NULL);
} END_TEST

START_TEST(checkGetNamespaceByName) {
    size_t notFoundIndex = 62541;
    UA_StatusCode notFound = UA_Server_getNamespaceByName(server, UA_STRING("http://opcfoundation.org/UA/invalid"), &notFoundIndex);
    ck_assert_uint_eq(notFoundIndex, 62541); // not changed
    ck_assert_uint_eq(notFound, UA_STATUSCODE_BADNOTFOUND);

    size_t foundIndex = 62541;
    UA_StatusCode found = UA_Server_getNamespaceByName(server, UA_STRING("http://opcfoundation.org/UA/"), &foundIndex);
    ck_assert_uint_eq(foundIndex, 0); // this namespace always has index 0 (defined by the standard)
    ck_assert_uint_eq(found, UA_STATUSCODE_GOOD);
} END_TEST

START_TEST(checkGetNamespaceById) {
    UA_String searchResultNamespace;
    UA_StatusCode notFound = UA_Server_getNamespaceByIndex(server, 10, &searchResultNamespace);
    ck_assert_uint_eq(notFound, UA_STATUSCODE_BADNOTFOUND);

    UA_StatusCode found1 = UA_Server_getNamespaceByIndex(server, 1, &searchResultNamespace);
    ck_assert_uint_eq(found1, UA_STATUSCODE_GOOD);
    UA_String_clear(&searchResultNamespace);

    UA_StatusCode notFound2 = UA_Server_getNamespaceByIndex(server, 2, &searchResultNamespace);
    ck_assert_uint_eq(notFound2, UA_STATUSCODE_BADNOTFOUND);

    UA_String compareNamespace = UA_STRING("http://opcfoundation.org/UA/");
    UA_StatusCode found = UA_Server_getNamespaceByIndex(server, 0, &searchResultNamespace);
    ck_assert(UA_String_equal(&compareNamespace, &searchResultNamespace));
    ck_assert_uint_eq(found, UA_STATUSCODE_GOOD);
    UA_String_clear(&searchResultNamespace);
} END_TEST

static void timedCallbackHandler(UA_Server *s, void *data) {
    *((UA_Boolean*)data) = false;  // stop the server via a timedCallback
}

START_TEST(checkServer_run) {
    UA_Boolean running = true;
    // 0 is in the past so the server will terminate on the first iteration
    UA_StatusCode ret;
    ret = UA_Server_addTimedCallback(server, &timedCallbackHandler, &running, 0, NULL);
    ck_assert_int_eq(ret, UA_STATUSCODE_GOOD);
    ret = UA_Server_run(server, &running);
    ck_assert_int_eq(ret, UA_STATUSCODE_GOOD);
} END_TEST

static unsigned closeCount;
static UA_StatusCode
closeConnection(UA_ConnectionManager *cm, uintptr_t connectionId) {
    (void)cm;
    ck_assert_uint_eq(connectionId, 2);
    closeCount++;
    return UA_STATUSCODE_GOOD;
}

static void
checkHello(size_t urlLength, size_t trailing, UA_UInt32 version, UA_StatusCode expected) {
    UA_ConnectionManager cm = testConnectionManagerTCP;
    cm.eventSource.eventLoop = UA_Server_getConfig(server)->eventLoop;
    cm.closeConnection = closeConnection;
    UA_ServerComponent *bpm = getServerComponentByName(server, UA_STRING("binary"));
    ck_assert_ptr_ne(bpm, NULL);
    UA_ByteString response = UA_BYTESTRING_NULL;
    testConnectionLastSentBuf = &response;
    closeCount = 0;
    void *listener = NULL;
    serverNetworkCallback(&cm, 1, bpm, &listener, UA_CONNECTIONSTATE_ESTABLISHED,
                          &UA_KEYVALUEMAP_NULL, UA_BYTESTRING_NULL);
    ck_assert_ptr_ne(listener, NULL);

    UA_TcpHelloMessage hello;
    UA_TcpHelloMessage_init(&hello);
    hello.protocolVersion = version;
    hello.receiveBufferSize = hello.sendBufferSize = 65536;
    ck_assert_uint_eq(UA_ByteString_allocBuffer(&hello.endpointUrl, urlLength),
                      UA_STATUSCODE_GOOD);
    memset(hello.endpointUrl.data, 'x', urlLength);
    UA_ByteString body = UA_BYTESTRING_NULL;
    ck_assert_uint_eq(UA_encodeBinary(&hello, &UA_TRANSPORT[UA_TRANSPORT_TCPHELLOMESSAGE],
                                     &body), UA_STATUSCODE_GOOD);
    UA_TcpHelloMessage_clear(&hello);
    UA_ByteString frame;
    ck_assert_uint_eq(UA_ByteString_allocBuffer(&frame, 8 + body.length + trailing),
                      UA_STATUSCODE_GOOD);
    UA_TcpMessageHeader header = {UA_MESSAGETYPE_HEL + UA_CHUNKTYPE_FINAL,
                                  (UA_UInt32)frame.length};
    UA_ByteString headerBuf = {8, frame.data};
    ck_assert_uint_eq(UA_encodeBinary(&header, &UA_TRANSPORT[UA_TRANSPORT_TCPMESSAGEHEADER],
                                     &headerBuf), UA_STATUSCODE_GOOD);
    memcpy(frame.data + 8, body.data, body.length);
    memset(frame.data + 8 + body.length, 0xab, trailing);
    UA_ByteString_clear(&body);

    void *connection = listener;
    serverNetworkCallback(&cm, 2, bpm, &connection, UA_CONNECTIONSTATE_ESTABLISHED,
                          &UA_KEYVALUEMAP_NULL, frame);
    size_t offset = 0;
    ck_assert_uint_eq(UA_decodeBinaryInternal(&response, &offset, &header,
                      &UA_TRANSPORT[UA_TRANSPORT_TCPMESSAGEHEADER], NULL), UA_STATUSCODE_GOOD);
    if(expected == UA_STATUSCODE_GOOD) {
        ck_assert_uint_eq(header.messageTypeAndChunkType, UA_MESSAGETYPE_ACK + UA_CHUNKTYPE_FINAL);
        UA_TcpAcknowledgeMessage ack;
        ck_assert_uint_eq(UA_decodeBinaryInternal(&response, &offset, &ack,
                          &UA_TRANSPORT[UA_TRANSPORT_TCPACKNOWLEDGEMESSAGE], NULL), UA_STATUSCODE_GOOD);
        ck_assert_uint_eq(ack.protocolVersion, 0);
        ck_assert_uint_eq(closeCount, 0);
    } else {
        ck_assert_uint_eq(header.messageTypeAndChunkType, UA_MESSAGETYPE_ERR + UA_CHUNKTYPE_FINAL);
        UA_TcpErrorMessage error;
        ck_assert_uint_eq(UA_decodeBinaryInternal(&response, &offset, &error,
                          &UA_TRANSPORT[UA_TRANSPORT_TCPERRORMESSAGE], NULL), UA_STATUSCODE_GOOD);
        ck_assert_uint_eq(error.error, expected);
        ck_assert_uint_eq(closeCount, 1);
        UA_TcpErrorMessage_clear(&error);
    }
    serverNetworkCallback(&cm, 2, bpm, &connection, UA_CONNECTIONSTATE_CLOSING,
                          &UA_KEYVALUEMAP_NULL, UA_BYTESTRING_NULL);
    serverNetworkCallback(&cm, 1, bpm, &listener, UA_CONNECTIONSTATE_CLOSING,
                          &UA_KEYVALUEMAP_NULL, UA_BYTESTRING_NULL);
    testConnectionLastSentBuf = NULL;
    UA_ByteString_clear(&response);
    UA_ByteString_clear(&frame);
}

START_TEST(helloEndpointUrlLimit) {
    checkHello(32, 0, 0, UA_STATUSCODE_GOOD);
    checkHello(4096, 0, 0, UA_STATUSCODE_GOOD);
    checkHello(4097, 0, 0, UA_STATUSCODE_BADTCPENDPOINTURLINVALID);
    checkHello(5000, 0, 0, UA_STATUSCODE_BADTCPENDPOINTURLINVALID);
    checkHello(32, 0, 0xdeadbeef, UA_STATUSCODE_GOOD);
} END_TEST

START_TEST(helloTrailingData) {
    checkHello(32, 1, 0, UA_STATUSCODE_BADDECODINGERROR);
    checkHello(32, 8, 0, UA_STATUSCODE_BADDECODINGERROR);
} END_TEST

static size_t
countNoneEndpointTokens(UA_UserTokenType tokenType) {
    UA_GetEndpointsRequest request;
    UA_GetEndpointsRequest_init(&request);
    request.endpointUrl = UA_STRING("opc.tcp://localhost:4840");
    UA_GetEndpointsResponse response;
    UA_GetEndpointsResponse_init(&response);
    lockServer(server);
    Service_GetEndpoints(server, &server->adminSession, &request, &response);
    unlockServer(server);
    ck_assert_uint_eq(response.responseHeader.serviceResult, UA_STATUSCODE_GOOD);

    size_t count = 0;
    for(size_t i = 0; i < response.endpointsSize; i++) {
        const UA_EndpointDescription *ep = &response.endpoints[i];
        if(!UA_String_equal(&ep->securityPolicyUri, &UA_SECURITY_POLICY_NONE_URI))
            continue;
        for(size_t j = 0; j < ep->userIdentityTokensSize; j++) {
            if(ep->userIdentityTokens[j].tokenType == tokenType)
                count++;
        }
    }
    UA_GetEndpointsResponse_clear(&response);
    return count;
}

/* Without an encrypting SecurityPolicy, ActivateSession rejects x509 and
 * password tokens on #None. So the #None endpoint does not offer them. */
START_TEST(checkNoneEndpointUserTokens) {
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_UsernamePasswordLogin login = {UA_STRING_STATIC("user"),
                                      UA_STRING_STATIC("password")};
    ck_assert_uint_eq(UA_AccessControl_default(config, true, NULL, 1, &login),
                      UA_STATUSCODE_GOOD);

    /* The AccessControl offers x509, as the session PKI accepts all */
    UA_Boolean haveX509 = false;
    for(size_t i = 0; i < config->accessControl.userTokenPoliciesSize; i++) {
        if(config->accessControl.userTokenPolicies[i].tokenType ==
           UA_USERTOKENTYPE_CERTIFICATE)
            haveX509 = true;
    }
    ck_assert(haveX509);

    config->allowNonePolicyPassword = false;
    ck_assert_uint_gt(countNoneEndpointTokens(UA_USERTOKENTYPE_ANONYMOUS), 0);
    ck_assert_uint_eq(countNoneEndpointTokens(UA_USERTOKENTYPE_USERNAME), 0);
    ck_assert_uint_eq(countNoneEndpointTokens(UA_USERTOKENTYPE_CERTIFICATE), 0);

    /* Passwords can be allowed without encryption, x509 tokens cannot */
    config->allowNonePolicyPassword = true;
    ck_assert_uint_gt(countNoneEndpointTokens(UA_USERTOKENTYPE_USERNAME), 0);
    ck_assert_uint_eq(countNoneEndpointTokens(UA_USERTOKENTYPE_CERTIFICATE), 0);
} END_TEST

int main(void) {
    Suite *s = suite_create("server");

    TCase *tc_call = tcase_create("server - basics");
    tcase_add_checked_fixture(tc_call, setup, teardown);
    tcase_add_test(tc_call, checkGetConfig);
    tcase_add_test(tc_call, checkGetNamespaceByName);
    tcase_add_test(tc_call, checkGetNamespaceById);
    tcase_add_test(tc_call, checkServer_run);
    tcase_add_test(tc_call, helloEndpointUrlLimit);
    tcase_add_test(tc_call, helloTrailingData);
    tcase_add_test(tc_call, checkNoneEndpointUserTokens);
    suite_add_tcase(s, tc_call);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
