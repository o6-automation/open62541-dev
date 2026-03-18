/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 * Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 *
 * OPC UA Multi-Transport Server Example
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * Demonstrates an OPC UA server listening on multiple transports:
 *   opc.tcp://localhost:4840  — Standard OPC UA binary over TCP
 *   opc.ws://localhost:4843   — OPC UA binary over WebSocket (plain)
 *   opc.wss://localhost:4844  — OPC UA binary over WebSocket with TLS
 *
 * The opc.wss endpoint requires a TLS certificate and private key:
 *   ./server_wss <certificate.pem> <private_key.pem>
 *
 * Without TLS arguments, only opc.tcp and opc.ws endpoints are started.
 *
 * WebSocket clients negotiate the "opcua+uacp" (binary) or "opcua+uajson"
 * (JSON) sub-protocol as defined in OPC UA Part 6, Section 7.5.
 *
 * Build with: -DUA_ENABLE_LWS=ON
 */

#include <open62541/server.h>
#include <open62541/types.h>
#include <open62541/plugin/eventloop.h>
#include <open62541/plugin/log_stdout.h>

#include <signal.h>
#include <stdio.h>

#include "../common.h"

static volatile UA_Boolean running = true;
static void stopHandler(int sign) {
    running = false;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);

    /* Register a WebSocket ConnectionManager on the EventLoop.
     * The server's BinaryProtocolManager will use it for opc.ws(s):// URLs. */
    UA_ConnectionManager *wsCM =
        UA_ConnectionManager_new_POSIX_WS(UA_STRING("ws connection manager"));
    if(wsCM)
        config->eventLoop->registerEventSource(config->eventLoop,
                                               &wsCM->eventSource);

    /* Configure server endpoints. Always: TCP + WS (plain).
     * With certs: additionally WSS (TLS). */
    UA_Array_delete(config->serverUrls, config->serverUrlsSize,
                    &UA_TYPES[UA_TYPES_STRING]);
    config->serverUrls = NULL;
    config->serverUrlsSize = 0;

    UA_Boolean hasTls = false;
    if(argc >= 3) {
        config->wssCertificate = loadFile(argv[1]);
        config->wssPrivateKey = loadFile(argv[2]);
        if(config->wssCertificate.length > 0 && config->wssPrivateKey.length > 0) {
            hasTls = true;
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                        "TLS enabled — adding opc.wss:// endpoint on port 4844");
        } else {
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                           "Could not load TLS certificate/key");
        }
    }

    if(hasTls) {
        UA_String serverUrls[3];
        serverUrls[0] = UA_STRING("opc.tcp://localhost:4840");
        serverUrls[1] = UA_STRING("opc.ws://localhost:4843");
        serverUrls[2] = UA_STRING("opc.wss://localhost:4844");
        UA_Array_copy(serverUrls, 3,
                      (void **)&config->serverUrls, &UA_TYPES[UA_TYPES_STRING]);
        config->serverUrlsSize = 3;
    } else {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                    "No TLS certificate. Usage: %s [cert.pem key.pem]", argv[0]);
        UA_String serverUrls[2];
        serverUrls[0] = UA_STRING("opc.tcp://localhost:4840");
        serverUrls[1] = UA_STRING("opc.ws://localhost:4843");
        UA_Array_copy(serverUrls, 2,
                      (void **)&config->serverUrls, &UA_TYPES[UA_TYPES_STRING]);
        config->serverUrlsSize = 2;
    }

    /* Run until ctrl-c */
    UA_StatusCode retval = UA_Server_run(server, &running);
    UA_Server_delete(server);
    return retval == UA_STATUSCODE_GOOD ? 0 : 1;
}
