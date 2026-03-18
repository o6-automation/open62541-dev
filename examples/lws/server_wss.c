/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 * Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 *
 * OPC UA WebSocket Server Example
 * --------------------------------
 * Demonstrates an OPC UA server listening on opc.wss:// using the WebSocket
 * ConnectionManager (libwebsockets). The server accepts binary (opcua+uacp)
 * OPC UA connections over WebSocket transport as specified in OPC UA Part 6,
 * Section 7.5.
 *
 * Build with: -DUA_ENABLE_LWS=ON
 * Run:        ./bin/examples/server_wss
 *
 * Connect with any OPC UA client supporting opc.wss, e.g.:
 *   opc.wss://localhost:4843
 */

#include <open62541/server.h>
#include <open62541/types.h>
#include <open62541/plugin/eventloop.h>
#include <open62541/plugin/log_stdout.h>

#include <signal.h>

static volatile UA_Boolean running = true;
static void stopHandler(int sign) {
    running = false;
}

int main(void) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);

    /* Register a WebSocket ConnectionManager on the EventLoop.
     * The server's BinaryProtocolManager will use it for opc.wss:// URLs. */
    UA_ConnectionManager *wsCM =
        UA_ConnectionManager_new_POSIX_WS(UA_STRING("ws connection manager"));
    if(wsCM)
        config->eventLoop->registerEventSource(config->eventLoop,
                                               &wsCM->eventSource);

    /* Tell the server to listen on opc.wss:// port 4843 in addition to the
     * default opc.tcp:// on 4840. The BinaryProtocolManager automatically
     * selects the "ws" ConnectionManager for opc.wss URLs and the "tcp"
     * ConnectionManager for opc.tcp URLs. */
    UA_Array_delete(config->serverUrls, config->serverUrlsSize,
                    &UA_TYPES[UA_TYPES_STRING]);
    config->serverUrls = NULL;
    config->serverUrlsSize = 0;

    UA_String serverUrls[2];
    serverUrls[0] = UA_STRING("opc.tcp://localhost:4840");
    serverUrls[1] = UA_STRING("opc.wss://localhost:4843");
    UA_Array_copy(serverUrls, 2,
                  (void **)&config->serverUrls, &UA_TYPES[UA_TYPES_STRING]);
    config->serverUrlsSize = 2;

    /* Run until ctrl-c */
    UA_Server_run(server, &running);
    UA_Server_delete(server);
    return 0;
}
