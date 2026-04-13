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
#include <open62541/server_config_default.h>
#include <open62541/plugin/accesscontrol_default.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common.h"

static volatile UA_Boolean running = true;
static void stopHandler(int sign) {
    running = false;
}

/* ── Method callbacks ─────────────────────────────────────────── */

static UA_StatusCode
multiplyCallback(UA_Server *server,
                 const UA_NodeId *sessionId, void *sessionHandle,
                 const UA_NodeId *methodId, void *methodContext,
                 const UA_NodeId *objectId, void *objectContext,
                 size_t inputSize, const UA_Variant *input,
                 size_t outputSize, UA_Variant *output) {
    UA_Double a = *(UA_Double *)input[0].data;
    UA_Double b = *(UA_Double *)input[1].data;
    UA_Double result = a * b;
    UA_Variant_setScalarCopy(output, &result, &UA_TYPES[UA_TYPES_DOUBLE]);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
helloCallback(UA_Server *server,
              const UA_NodeId *sessionId, void *sessionHandle,
              const UA_NodeId *methodId, void *methodContext,
              const UA_NodeId *objectId, void *objectContext,
              size_t inputSize, const UA_Variant *input,
              size_t outputSize, UA_Variant *output) {
    UA_String *name = (UA_String *)input[0].data;
    /* Build "Hello <name>" string */
    size_t len = 6 + name->length; /* "Hello " */
    UA_Byte *buf = (UA_Byte *)UA_malloc(len);
    memcpy(buf, "Hello ", 6);
    memcpy(buf + 6, name->data, name->length);
    UA_String greeting;
    greeting.data = buf;
    greeting.length = len;
    UA_Variant_setScalarCopy(output, &greeting, &UA_TYPES[UA_TYPES_STRING]);
    UA_free(buf);
    return UA_STATUSCODE_GOOD;
}

/* ── Populate address space with test data ────────────────────── */

static void
addTestNodes(UA_Server *server) {
    /* -- Static Scalars folder ----------------------------------------- */
    UA_NodeId staticScalarsId;
    {
        UA_ObjectAttributes oAttr = UA_ObjectAttributes_default;
        oAttr.displayName = UA_LOCALIZEDTEXT("en-US", "Static Scalars");
        UA_Server_addObjectNode(server, UA_NODEID_STRING(1, "StaticScalars"),
                                UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                                UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                                UA_QUALIFIEDNAME(1, "Static Scalars"),
                                UA_NODEID_NUMERIC(0, UA_NS0ID_FOLDERTYPE),
                                oAttr, NULL, &staticScalarsId);
    }

    /* Int32Scalar = 42 */
    {
        UA_VariableAttributes vAttr = UA_VariableAttributes_default;
        UA_Int32 val = 42;
        UA_Variant_setScalar(&vAttr.value, &val, &UA_TYPES[UA_TYPES_INT32]);
        vAttr.displayName = UA_LOCALIZEDTEXT("en-US", "Int32Scalar");
        vAttr.dataType = UA_TYPES[UA_TYPES_INT32].typeId;
        vAttr.valueRank = UA_VALUERANK_SCALAR;
        vAttr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        UA_Server_addVariableNode(server, UA_NODEID_STRING(1, "Int32Scalar"),
                                  staticScalarsId,
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                  UA_QUALIFIEDNAME(1, "Int32Scalar"),
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                                  vAttr, NULL, NULL);
    }

    /* BooleanScalar = true */
    {
        UA_VariableAttributes vAttr = UA_VariableAttributes_default;
        UA_Boolean val = true;
        UA_Variant_setScalar(&vAttr.value, &val, &UA_TYPES[UA_TYPES_BOOLEAN]);
        vAttr.displayName = UA_LOCALIZEDTEXT("en-US", "BooleanScalar");
        vAttr.dataType = UA_TYPES[UA_TYPES_BOOLEAN].typeId;
        vAttr.valueRank = UA_VALUERANK_SCALAR;
        vAttr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        UA_Server_addVariableNode(server, UA_NODEID_STRING(1, "BooleanScalar"),
                                  staticScalarsId,
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                  UA_QUALIFIEDNAME(1, "BooleanScalar"),
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                                  vAttr, NULL, NULL);
    }

    /* StringScalar = "Hello OPC UA" */
    {
        UA_VariableAttributes vAttr = UA_VariableAttributes_default;
        UA_String val = UA_STRING("Hello OPC UA");
        UA_Variant_setScalar(&vAttr.value, &val, &UA_TYPES[UA_TYPES_STRING]);
        vAttr.displayName = UA_LOCALIZEDTEXT("en-US", "StringScalar");
        vAttr.dataType = UA_TYPES[UA_TYPES_STRING].typeId;
        vAttr.valueRank = UA_VALUERANK_SCALAR;
        vAttr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        UA_Server_addVariableNode(server, UA_NODEID_STRING(1, "StringScalar"),
                                  staticScalarsId,
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                  UA_QUALIFIEDNAME(1, "StringScalar"),
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                                  vAttr, NULL, NULL);
    }

    /* -- Methods folder ------------------------------------------------ */
    UA_NodeId methodsFolderId;
    {
        UA_ObjectAttributes oAttr = UA_ObjectAttributes_default;
        oAttr.displayName = UA_LOCALIZEDTEXT("en-US", "Methods");
        UA_Server_addObjectNode(server, UA_NODEID_STRING(1, "Methods"),
                                UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                                UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                                UA_QUALIFIEDNAME(1, "Methods"),
                                UA_NODEID_NUMERIC(0, UA_NS0ID_FOLDERTYPE),
                                oAttr, NULL, &methodsFolderId);
    }

    /* Multiply(Double a, Double b) → Double */
    {
        UA_Argument inputArgs[2];
        UA_Argument_init(&inputArgs[0]);
        inputArgs[0].name = UA_STRING("a");
        inputArgs[0].dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        inputArgs[0].valueRank = UA_VALUERANK_SCALAR;
        inputArgs[0].description = UA_LOCALIZEDTEXT("en-US", "First factor");

        UA_Argument_init(&inputArgs[1]);
        inputArgs[1].name = UA_STRING("b");
        inputArgs[1].dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        inputArgs[1].valueRank = UA_VALUERANK_SCALAR;
        inputArgs[1].description = UA_LOCALIZEDTEXT("en-US", "Second factor");

        UA_Argument outputArg;
        UA_Argument_init(&outputArg);
        outputArg.name = UA_STRING("result");
        outputArg.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        outputArg.valueRank = UA_VALUERANK_SCALAR;
        outputArg.description = UA_LOCALIZEDTEXT("en-US", "Product");

        UA_MethodAttributes mAttr = UA_MethodAttributes_default;
        mAttr.displayName = UA_LOCALIZEDTEXT("en-US", "Multiply");
        mAttr.executable = true;
        mAttr.userExecutable = true;

        UA_Server_addMethodNode(server, UA_NODEID_STRING(1, "Multiply"),
                                methodsFolderId,
                                UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                UA_QUALIFIEDNAME(1, "Multiply"),
                                mAttr, &multiplyCallback,
                                2, inputArgs, 1, &outputArg,
                                NULL, NULL);
    }

    /* Hello(String name) → String */
    {
        UA_Argument inputArg;
        UA_Argument_init(&inputArg);
        inputArg.name = UA_STRING("name");
        inputArg.dataType = UA_TYPES[UA_TYPES_STRING].typeId;
        inputArg.valueRank = UA_VALUERANK_SCALAR;
        inputArg.description = UA_LOCALIZEDTEXT("en-US", "Your name");

        UA_Argument outputArg;
        UA_Argument_init(&outputArg);
        outputArg.name = UA_STRING("greeting");
        outputArg.dataType = UA_TYPES[UA_TYPES_STRING].typeId;
        outputArg.valueRank = UA_VALUERANK_SCALAR;
        outputArg.description = UA_LOCALIZEDTEXT("en-US", "Greeting");

        UA_MethodAttributes mAttr = UA_MethodAttributes_default;
        mAttr.displayName = UA_LOCALIZEDTEXT("en-US", "Hello");
        mAttr.executable = true;
        mAttr.userExecutable = true;

        UA_Server_addMethodNode(server, UA_NODEID_STRING(1, "Hello"),
                                methodsFolderId,
                                UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                UA_QUALIFIEDNAME(1, "Hello"),
                                mAttr, &helloCallback,
                                1, &inputArg, 1, &outputArg,
                                NULL, NULL);
    }
}

/* ── Main ─────────────────────────────────────────────────────── */

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

    /* Parse optional port overrides: --tcp-port N --ws-port N --wss-port N */
    int tcpPort = 4840, wsPort = 4843, wssPort = 4844;
    const char *certFile = NULL, *keyFile = NULL;
    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "--tcp-port") == 0 && i + 1 < argc) { tcpPort = atoi(argv[++i]); }
        else if(strcmp(argv[i], "--ws-port") == 0 && i + 1 < argc) { wsPort = atoi(argv[++i]); }
        else if(strcmp(argv[i], "--wss-port") == 0 && i + 1 < argc) { wssPort = atoi(argv[++i]); }
        else if(!certFile) { certFile = argv[i]; }
        else if(!keyFile) { keyFile = argv[i]; }
    }

    UA_Boolean hasTls = false;
    UA_ByteString certificate = UA_BYTESTRING_NULL;
    UA_ByteString privateKey = UA_BYTESTRING_NULL;
    if(certFile && keyFile) {
        certificate = loadFile(certFile);
        privateKey = loadFile(keyFile);
        if(certificate.length > 0 && privateKey.length > 0) {
            config->wssCertificate = loadFile(certFile);
            config->wssPrivateKey = loadFile(keyFile);
            hasTls = true;
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                        "TLS enabled — adding opc.wss:// endpoint on port %d", wssPort);
        } else {
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                           "Could not load TLS certificate/key");
        }
    }

#ifdef UA_ENABLE_ENCRYPTION
    /* Add security policies when certificate is available */
    if(certificate.length > 0 && privateKey.length > 0) {
        UA_ServerConfig_addSecurityPolicyBasic256Sha256(config, &certificate, &privateKey);
        UA_ServerConfig_addSecurityPolicyAes128Sha256RsaOaep(config, &certificate, &privateKey);
        UA_ServerConfig_addSecurityPolicyAes256Sha256RsaPss(config, &certificate, &privateKey);
        UA_ServerConfig_addAllEndpoints(config);
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                    "Security policies: None, Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss");
    }
#endif

    /* Set up access control: allow anonymous + user/password */
    UA_UsernamePasswordLogin users[1] = {
        {UA_STRING_STATIC("user"), UA_STRING_STATIC("password")}
    };
    UA_AccessControl_default(config, true, NULL, 1, users);

    if(hasTls) {
        char url0[64], url1[64], url2[64];
        snprintf(url0, sizeof(url0), "opc.tcp://localhost:%d", tcpPort);
        snprintf(url1, sizeof(url1), "opc.ws://localhost:%d", wsPort);
        snprintf(url2, sizeof(url2), "opc.wss://localhost:%d", wssPort);
        UA_String serverUrls[3];
        serverUrls[0] = UA_STRING(url0);
        serverUrls[1] = UA_STRING(url1);
        serverUrls[2] = UA_STRING(url2);
        UA_Array_copy(serverUrls, 3,
                      (void **)&config->serverUrls, &UA_TYPES[UA_TYPES_STRING]);
        config->serverUrlsSize = 3;
    } else {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                    "No TLS certificate. Usage: %s [cert.pem key.pem] [--tcp-port N] [--ws-port N]", argv[0]);
        char url0[64], url1[64];
        snprintf(url0, sizeof(url0), "opc.tcp://localhost:%d", tcpPort);
        snprintf(url1, sizeof(url1), "opc.ws://localhost:%d", wsPort);
        UA_String serverUrls[2];
        serverUrls[0] = UA_STRING(url0);
        serverUrls[1] = UA_STRING(url1);
        UA_Array_copy(serverUrls, 2,
                      (void **)&config->serverUrls, &UA_TYPES[UA_TYPES_STRING]);
        config->serverUrlsSize = 2;
    }

    /* Populate the address space with test nodes */
    addTestNodes(server);

    /* Run until ctrl-c */
    UA_StatusCode retval = UA_Server_run(server, &running);
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    UA_Server_delete(server);
    return retval == UA_STATUSCODE_GOOD ? 0 : 1;
}
