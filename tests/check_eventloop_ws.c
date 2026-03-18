/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2025 (c) Fraunhofer IOSB (Author: Noel Graf)
 *    Copyright 2025 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 */

#include <open62541/plugin/eventloop.h>
#include <open62541/plugin/log_stdout.h>
#include "open62541/types.h"
#include "open62541/types_generated.h"

#include "testing_clock.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>

/* Test state */
static UA_Boolean serverListening = false;
static UA_Boolean clientConnected = false;
static UA_Boolean serverReceivedData = false;
static UA_Boolean clientReceivedData = false;
static UA_Boolean serverConnectionClosed = false;
static UA_Boolean clientConnectionClosed = false;
static uintptr_t serverChildConnectionId = 0;
static uintptr_t clientConnectionId = 0;
static size_t serverBytesReceived = 0;
static size_t clientBytesReceived = 0;

static const char *testMessage = "Hello OPC UA over WebSocket!";

static void resetState(void) {
    serverListening = false;
    clientConnected = false;
    serverReceivedData = false;
    clientReceivedData = false;
    serverConnectionClosed = false;
    clientConnectionClosed = false;
    serverChildConnectionId = 0;
    clientConnectionId = 0;
    serverBytesReceived = 0;
    clientBytesReceived = 0;
}

/* Server callback: called for the listening socket and for child connections */
static void
serverCallback(UA_ConnectionManager *cm, uintptr_t connectionId,
               void *application, void **connectionContext,
               UA_ConnectionState state,
               const UA_KeyValueMap *params, UA_ByteString msg) {
    if(state == UA_CONNECTIONSTATE_ESTABLISHED && msg.length == 0 &&
       serverChildConnectionId == 0 && serverListening) {
        /* New child connection from a client */
        serverChildConnectionId = connectionId;
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "SERVER\t| New client connected, id=%lu",
                    (unsigned long)connectionId);
    } else if(state == UA_CONNECTIONSTATE_ESTABLISHED && msg.length == 0 &&
              !serverListening) {
        /* Listener socket established */
        serverListening = true;
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "SERVER\t| Listening socket established, id=%lu",
                    (unsigned long)connectionId);
    } else if(state == UA_CONNECTIONSTATE_ESTABLISHED && msg.length > 0) {
        /* Data received on a child connection */
        serverReceivedData = true;
        serverBytesReceived += msg.length;
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "SERVER\t| Received %zu bytes on connection %lu",
                    msg.length, (unsigned long)connectionId);

        /* Echo the data back */
        UA_ByteString snd;
        UA_StatusCode res =
            cm->allocNetworkBuffer(cm, connectionId, &snd, msg.length);
        if(res == UA_STATUSCODE_GOOD) {
            memcpy(snd.data, msg.data, msg.length);
            cm->sendWithConnection(cm, connectionId, &UA_KEYVALUEMAP_NULL, &snd);
        }
    } else if(state == UA_CONNECTIONSTATE_CLOSING ||
              state == UA_CONNECTIONSTATE_CLOSED) {
        if(connectionId == serverChildConnectionId) {
            serverConnectionClosed = true;
            serverChildConnectionId = 0;
        }
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "SERVER\t| Connection %lu closing",
                    (unsigned long)connectionId);
    }
}

/* Client callback */
static void
clientCallback(UA_ConnectionManager *cm, uintptr_t connectionId,
               void *application, void **connectionContext,
               UA_ConnectionState state,
               const UA_KeyValueMap *params, UA_ByteString msg) {
    if(state == UA_CONNECTIONSTATE_ESTABLISHED && msg.length == 0) {
        clientConnected = true;
        clientConnectionId = connectionId;
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "CLIENT\t| Connected, id=%lu",
                    (unsigned long)connectionId);
    } else if(state == UA_CONNECTIONSTATE_ESTABLISHED && msg.length > 0) {
        clientReceivedData = true;
        clientBytesReceived += msg.length;
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "CLIENT\t| Received %zu bytes",
                    msg.length);
    } else if(state == UA_CONNECTIONSTATE_CLOSING ||
              state == UA_CONNECTIONSTATE_CLOSED) {
        clientConnectionClosed = true;
        clientConnectionId = 0;
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "CLIENT\t| Connection closing");
    } else if(state == UA_CONNECTIONSTATE_OPENING) {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "CLIENT\t| Connection opening, id=%lu",
                    (unsigned long)connectionId);
        clientConnectionId = connectionId;
    }
}

static void
stopEventLoop(UA_EventLoop *el) {
    int maxIter = 200;
    int iter = 0;
    el->stop(el);
    while(el->state != UA_EVENTLOOPSTATE_STOPPED && iter < maxIter) {
        el->run(el, 10);
        iter++;
    }
}

/**
 * Test: Open a WebSocket listening socket and verify it reports ESTABLISHED
 */
START_TEST(listenWS) {
    resetState();

    UA_ConnectionManager *cm =
        UA_ConnectionManager_new_POSIX_WS(UA_STRING("wsCM"));
    UA_EventLoop *el = UA_EventLoop_new_POSIX(UA_Log_Stdout);
    el->registerEventSource(el, &cm->eventSource);
    el->start(el);

    /* Open a passive (server) connection */
    UA_UInt16 port = 4843;
    UA_Boolean listen = true;

    UA_KeyValuePair params[2];
    params[0].key = UA_QUALIFIEDNAME(0, "port");
    UA_Variant_setScalar(&params[0].value, &port, &UA_TYPES[UA_TYPES_UINT16]);
    params[1].key = UA_QUALIFIEDNAME(0, "listen");
    UA_Variant_setScalar(&params[1].value, &listen, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_KeyValueMap kvm = {2, params};

    UA_StatusCode res = cm->openConnection(cm, &kvm, NULL, NULL, serverCallback);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    ck_assert(serverListening);

    /* Run for a few iterations */
    for(int i = 0; i < 5; i++) {
        UA_DateTime next = el->run(el, 1);
        UA_fakeSleep((UA_UInt32)((next - UA_DateTime_now()) / UA_DATETIME_MSEC));
    }

    ck_assert(serverListening);

    /* Stop */
    stopEventLoop(el);
    ck_assert(el->state == UA_EVENTLOOPSTATE_STOPPED);
    el->free(el);
} END_TEST

/**
 * Test: Server listens, client connects, send + receive, close.
 * This is the core loopback test for the WebSocket ConnectionManager.
 */
START_TEST(connectAndSendWS) {
    resetState();

    /* Create a single event loop with the WS CM */
    UA_ConnectionManager *cm =
        UA_ConnectionManager_new_POSIX_WS(UA_STRING("wsCM"));
    UA_EventLoop *el = UA_EventLoop_new_POSIX(UA_Log_Stdout);
    el->registerEventSource(el, &cm->eventSource);
    el->start(el);

    /* 1. Open the server listening socket */
    UA_UInt16 port = 4844;
    UA_Boolean listen = true;

    UA_KeyValuePair serverParams[2];
    serverParams[0].key = UA_QUALIFIEDNAME(0, "port");
    UA_Variant_setScalar(&serverParams[0].value, &port,
                         &UA_TYPES[UA_TYPES_UINT16]);
    serverParams[1].key = UA_QUALIFIEDNAME(0, "listen");
    UA_Variant_setScalar(&serverParams[1].value, &listen,
                         &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_KeyValueMap serverKvm = {2, serverParams};

    UA_StatusCode res = cm->openConnection(cm, &serverKvm, NULL, NULL,
                                           serverCallback);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    ck_assert(serverListening);

    /* 2. Open a client connection to the server */
    UA_String address = UA_STRING("127.0.0.1");

    UA_KeyValuePair clientParams[2];
    clientParams[0].key = UA_QUALIFIEDNAME(0, "port");
    UA_Variant_setScalar(&clientParams[0].value, &port,
                         &UA_TYPES[UA_TYPES_UINT16]);
    clientParams[1].key = UA_QUALIFIEDNAME(0, "address");
    UA_Variant_setScalar(&clientParams[1].value, &address,
                         &UA_TYPES[UA_TYPES_STRING]);
    UA_KeyValueMap clientKvm = {2, clientParams};

    res = cm->openConnection(cm, &clientKvm, NULL, NULL, clientCallback);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);

    /* 3. Pump the event loop to let the WS handshake complete */
    for(int i = 0; i < 20; i++) {
        el->run(el, 1);
        if(clientConnected && serverChildConnectionId != 0)
            break;
    }

    /* Check that the client connected and the server accepted */
    ck_assert(clientConnected);
    ck_assert(serverChildConnectionId != 0);

    /* 4. Send data from client to server */
    size_t msgLen = strlen(testMessage);
    UA_ByteString snd;
    res = cm->allocNetworkBuffer(cm, clientConnectionId, &snd, msgLen);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    memcpy(snd.data, testMessage, msgLen);
    res = cm->sendWithConnection(cm, clientConnectionId,
                                 &UA_KEYVALUEMAP_NULL, &snd);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);

    /* 5. Pump the event loop to let data flow */
    for(int i = 0; i < 100; i++) {
        el->run(el, 1);
        if(serverReceivedData && clientReceivedData)
            break;
    }

    /* Server should have received the data and echoed it back */
    ck_assert(serverReceivedData);
    ck_assert_uint_eq(serverBytesReceived, msgLen);

    /* Client should have received the echo */
    ck_assert(clientReceivedData);
    ck_assert_uint_eq(clientBytesReceived, msgLen);

    /* 6. Close the client connection */
    res = cm->closeConnection(cm, clientConnectionId);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);

    for(int i = 0; i < 100; i++) {
        el->run(el, 10);
        if(clientConnectionClosed)
            break;
    }

    /* 7. Stop */
    stopEventLoop(el);
    ck_assert(el->state == UA_EVENTLOOPSTATE_STOPPED);
    el->free(el);
} END_TEST

int main(void) {
    Suite *s = suite_create("Test WebSocket EventLoop");
    TCase *tc = tcase_create("test cases");
    tcase_set_timeout(tc, 30);
    tcase_add_test(tc, listenWS);
    tcase_add_test(tc, connectAndSendWS);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
