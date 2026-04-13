/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#include "eventloop_emscripten.h"

#if defined(__EMSCRIPTEN__)

#include <open62541/plugin/eventloop.h>
#include <emscripten/emscripten.h>
#include <emscripten/websocket.h>
#include <stdio.h>

/**
 * Emscripten TCP Bridge ConnectionManager
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * Enables ``opc.tcp://`` connections from the browser by tunnelling the
 * OPC UA binary stream through a WebSocket to a local bridge process.
 *
 * Protocol string: "tcp"
 *
 * When the open62541 client resolves ``opc.tcp://host:port``, it looks for
 * a ConnectionManager with protocol "tcp". This CM intercepts the request
 * and creates a browser WebSocket to:
 *
 *     ws[s]://bridge_host:bridge_port/relay/{target_host}/{target_port}
 *
 * The bridge (ae-opcua-client-bridge) running on the user's computer
 * parses the URL path, opens a real TCP socket to the target OPC UA
 * server, and relays bytes bidirectionally. The browser-side OPC UA
 * stack sees a normal TCP-like byte stream and uses correct ``opc.tcp://``
 * URLs in HEL, GetEndpoints, etc.
 *
 * Connection parameters (identical to the WS CM from the client's perspective):
 * - 0:address  [string]  Target OPC UA hostname (required)
 * - 0:port     [uint16]  Target OPC UA port (required)
 *
 * The bridge address is configured separately via the global setters
 * ``EmscriptenTCPBridge_setHost()`` / ``EmscriptenTCPBridge_setPort()``.
 */

/* Connection parameter indices */
#define EMTCP_PARAMETERSSIZE 2
#define EMTCP_PARAMINDEX_ADDR 0
#define EMTCP_PARAMINDEX_PORT 1

static UA_KeyValueRestriction emtcpConnectionParams[EMTCP_PARAMETERSSIZE] = {
    {{0, UA_STRING_STATIC("address")}, &UA_TYPES[UA_TYPES_STRING],  true,  true, false},
    {{0, UA_STRING_STATIC("port")},    &UA_TYPES[UA_TYPES_UINT16],  true,  true, false}
};

/* Bridge configuration — set from JavaScript via o6_set_bridge_url() */
static char g_bridge_host[256] = "localhost";
static int  g_bridge_port      = 48400;
static int  g_bridge_configured = 0;

void
EmscriptenTCPBridge_setHost(const char *host) {
    if(!host) return;
    size_t len = strlen(host);
    if(len >= sizeof(g_bridge_host)) len = sizeof(g_bridge_host) - 1;
    memcpy(g_bridge_host, host, len);
    g_bridge_host[len] = '\0';
}

void
EmscriptenTCPBridge_setPort(int port) {
    g_bridge_port = port;
}

void
EmscriptenTCPBridge_setConfigured(int configured) {
    g_bridge_configured = configured;
}

/* No sub-protocol for bridge path — the bridge is a raw byte relay
 * and does not participate in OPC UA protocol negotiation. The WebSocket
 * sub-protocol is only relevant for direct WS connections to OPC UA
 * servers that implement Part 6 §7.5 (opcua+uacp). */

/**********************/
/* Connection Helpers  */
/**********************/

/* Re-use the same connection structure type as the WS CM */

static EmscriptenWSConnection *
EMTCP_findConnection(EmscriptenWSConnectionManager *wcm, uintptr_t id) {
    EmscriptenWSConnection *wc = wcm->connections;
    while(wc) {
        if(wc->connectionId == id)
            return wc;
        wc = wc->next;
    }
    return NULL;
}

static void
EMTCP_removeConnection(EmscriptenWSConnection *wc) {
    if(!wc)
        return;
    EmscriptenWSConnectionManager *wcm =
        (EmscriptenWSConnectionManager *)wc->dc.application;

    EmscriptenWSConnection **prev = &wcm->connections;
    while(*prev) {
        if(*prev == wc) {
            *prev = wc->next;
            break;
        }
        prev = &(*prev)->next;
    }
}

static void
EMTCP_deferredFree(void *application, void *context) {
    EmscriptenWSConnection *wc = (EmscriptenWSConnection *)context;
    UA_free(wc);
}

/****************************/
/* WebSocket Event Handlers */
/****************************/

static EM_BOOL
EMTCP_onOpen(int eventType, const EmscriptenWebSocketOpenEvent *wsEvent,
             void *userData) {
    EmscriptenWSConnection *wc = (EmscriptenWSConnection *)userData;
    if(!wc || wc->closing)
        return EM_TRUE;

    wc->established = true;

    emscripten_console_log("[EMTCP] onOpen fired");

    UA_LOG_INFO(wc->dc.application ?
                ((EmscriptenWSConnectionManager *)wc->dc.application)->cm.eventSource.eventLoop->logger : NULL,
                UA_LOGCATEGORY_NETWORK,
                "TCP-Bridge %u\t| Connection established via bridge",
                (unsigned)wc->connectionId);

    /* Notify the application — same as WS CM */
    UA_ByteString empty = UA_BYTESTRING_NULL;
    UA_KeyValueMap emptyParams = {0, NULL};
    wc->applicationCB(&((EmscriptenWSConnectionManager *)wc->dc.application)->cm,
                       wc->connectionId, wc->application, &wc->context,
                       UA_CONNECTIONSTATE_ESTABLISHED, &emptyParams, empty);

    return EM_TRUE;
}

static EM_BOOL
EMTCP_onMessage(int eventType, const EmscriptenWebSocketMessageEvent *wsEvent,
                void *userData) {
    EmscriptenWSConnection *wc = (EmscriptenWSConnection *)userData;
    if(!wc || wc->closing)
        return EM_TRUE;

    char debugMsg[128];
    snprintf(debugMsg, sizeof(debugMsg), "[EMTCP] onMessage fired: isText=%d numBytes=%d",
             wsEvent->isText, wsEvent->numBytes);
    emscripten_console_log(debugMsg);

    /* Only accept binary messages */
    if(!wsEvent->isText && wsEvent->numBytes > 0) {
        UA_ByteString msg;
        msg.data = (UA_Byte *)wsEvent->data;
        msg.length = (size_t)wsEvent->numBytes;

        UA_KeyValueMap emptyParams = {0, NULL};
        wc->applicationCB(&((EmscriptenWSConnectionManager *)wc->dc.application)->cm,
                           wc->connectionId, wc->application, &wc->context,
                           UA_CONNECTIONSTATE_ESTABLISHED, &emptyParams, msg);
    }

    return EM_TRUE;
}

static EM_BOOL
EMTCP_onError(int eventType, const EmscriptenWebSocketErrorEvent *wsEvent,
              void *userData) {
    EmscriptenWSConnection *wc = (EmscriptenWSConnection *)userData;
    if(!wc)
        return EM_TRUE;

    emscripten_console_log("[EMTCP] onError fired");

    EmscriptenWSConnectionManager *wcm =
        (EmscriptenWSConnectionManager *)wc->dc.application;

    UA_LOG_WARNING(wcm->cm.eventSource.eventLoop->logger,
                   UA_LOGCATEGORY_NETWORK,
                   "TCP-Bridge %u\t| WebSocket error (bridge unreachable?)",
                   (unsigned)wc->connectionId);

    wc->closing = true;
    return EM_TRUE;
}

static EM_BOOL
EMTCP_onClose(int eventType, const EmscriptenWebSocketCloseEvent *wsEvent,
              void *userData) {
    EmscriptenWSConnection *wc = (EmscriptenWSConnection *)userData;
    if(!wc)
        return EM_TRUE;

    EmscriptenWSConnectionManager *wcm =
        (EmscriptenWSConnectionManager *)wc->dc.application;

    char debugCloseMsg[128];
    snprintf(debugCloseMsg, sizeof(debugCloseMsg),
             "[EMTCP] onClose fired: code=%d wasClean=%d",
             (int)wsEvent->code, (int)wsEvent->wasClean);
    emscripten_console_log(debugCloseMsg);

    UA_LOG_INFO(wcm->cm.eventSource.eventLoop->logger,
                UA_LOGCATEGORY_NETWORK,
                "TCP-Bridge %u\t| Connection closed (code=%d)",
                (unsigned)wc->connectionId, (int)wsEvent->code);

    if(!wc->closing)
        wc->closing = true;

    /* Notify the application */
    UA_ByteString empty = UA_BYTESTRING_NULL;
    UA_KeyValueMap emptyParams = {0, NULL};
    wc->applicationCB(&wcm->cm, wc->connectionId, wc->application,
                       &wc->context, UA_CONNECTIONSTATE_CLOSING,
                       &emptyParams, empty);

    EMTCP_removeConnection(wc);

    /* Deferred free */
    wc->dc.callback = EMTCP_deferredFree;
    wc->dc.context = wc;
    wcm->cm.eventSource.eventLoop->addDelayedCallback(
        wcm->cm.eventSource.eventLoop, &wc->dc);

    return EM_TRUE;
}

/****************************************/
/* ConnectionManager Interface Methods  */
/****************************************/

static UA_StatusCode
EMTCP_openConnection(UA_ConnectionManager *cm, const UA_KeyValueMap *params,
                     void *application, void *context,
                     UA_ConnectionManager_connectionCallback connectionCallback) {
    EmscriptenWSConnectionManager *wcm = (EmscriptenWSConnectionManager *)cm;
    UA_EventLoop *el = cm->eventSource.eventLoop;

    if(!g_bridge_configured) {
        emscripten_console_log("[EMTCP] openConnection FAILED: bridge not configured");
        UA_LOG_ERROR(el->logger, UA_LOGCATEGORY_NETWORK,
                     "TCP-Bridge\t| Bridge not configured. Call o6_set_bridge_url() first.");
        return UA_STATUSCODE_BADNOTCONNECTED;
    }

    /* Validate parameters */
    UA_StatusCode res =
        UA_KeyValueRestriction_validate(el->logger, "TCP-Bridge",
                                        emtcpConnectionParams,
                                        EMTCP_PARAMETERSSIZE, params);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* Extract target address */
    const UA_String *address = (const UA_String *)
        UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, "address"),
                                 &UA_TYPES[UA_TYPES_STRING]);
    if(!address || address->length == 0)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Extract target port */
    const UA_UInt16 *port = (const UA_UInt16 *)
        UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, "port"),
                                 &UA_TYPES[UA_TYPES_UINT16]);
    if(!port)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Build bridge WebSocket URL: ws://bridge_host:bridge_port/relay/{host}/{port} */
    char url[1024];
    int urlLen = snprintf(url, sizeof(url), "ws://%s:%d/relay/%.*s/%u",
                          g_bridge_host, g_bridge_port,
                          (int)address->length, (char *)address->data,
                          (unsigned)*port);
    if(urlLen < 0 || (size_t)urlLen >= sizeof(url))
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Create connection struct */
    EmscriptenWSConnection *wc = (EmscriptenWSConnection *)
        UA_calloc(1, sizeof(EmscriptenWSConnection));
    if(!wc)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    wc->connectionId = ++wcm->lastConnectionId;
    wc->application = application;
    wc->context = context;
    wc->applicationCB = connectionCallback;
    wc->dc.application = wcm;

    /* Create browser WebSocket to bridge — request "opcua-relay" sub-protocol
     * so LWS routes the connection to the correct protocol handler */
    EmscriptenWebSocketCreateAttributes wsAttrs = {
        url,
        "opcua-relay",
        EM_TRUE
    };

    wc->wsHandle = emscripten_websocket_new(&wsAttrs);
    if(wc->wsHandle <= 0) {
        UA_LOG_ERROR(el->logger, UA_LOGCATEGORY_NETWORK,
                     "TCP-Bridge\t| Failed to create WebSocket to %s", url);
        UA_free(wc);
        return UA_STATUSCODE_BADCONNECTIONREJECTED;
    }

    /* Register event handlers */
    emscripten_websocket_set_onopen_callback(wc->wsHandle, wc, EMTCP_onOpen);
    emscripten_websocket_set_onmessage_callback(wc->wsHandle, wc, EMTCP_onMessage);
    emscripten_websocket_set_onerror_callback(wc->wsHandle, wc, EMTCP_onError);
    emscripten_websocket_set_onclose_callback(wc->wsHandle, wc, EMTCP_onClose);

    /* Add to linked list */
    wc->next = wcm->connections;
    wcm->connections = wc;

    UA_LOG_INFO(el->logger, UA_LOGCATEGORY_NETWORK,
                "TCP-Bridge %u\t| Connecting opc.tcp://%.*s:%u via bridge %s",
                (unsigned)wc->connectionId,
                (int)address->length, (char *)address->data,
                (unsigned)*port, url);

    /* Notify OPENING state */
    UA_ByteString empty = UA_BYTESTRING_NULL;
    UA_KeyValueMap emptyParams = {0, NULL};
    connectionCallback(cm, wc->connectionId, application, &wc->context,
                       UA_CONNECTIONSTATE_OPENING, &emptyParams, empty);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
EMTCP_sendWithConnection(UA_ConnectionManager *cm, uintptr_t connectionId,
                         const UA_KeyValueMap *params, UA_ByteString *buf) {
    EmscriptenWSConnectionManager *wcm = (EmscriptenWSConnectionManager *)cm;
    EmscriptenWSConnection *wc = EMTCP_findConnection(wcm, connectionId);
    if(!wc || wc->closing || !wc->established) {
        char debugSendMsg[128];
        snprintf(debugSendMsg, sizeof(debugSendMsg),
                 "[EMTCP] sendWithConnection BLOCKED: wc=%p closing=%d established=%d",
                 (void*)wc, wc ? wc->closing : -1, wc ? wc->established : -1);
        emscripten_console_log(debugSendMsg);
        UA_ByteString_clear(buf);
        return UA_STATUSCODE_BADCONNECTIONCLOSED;
    }

    char debugSendMsg2[128];
    snprintf(debugSendMsg2, sizeof(debugSendMsg2),
             "[EMTCP] sendWithConnection: %u bytes", (unsigned)buf->length);
    emscripten_console_log(debugSendMsg2);

    EMSCRIPTEN_RESULT result =
        emscripten_websocket_send_binary(wc->wsHandle, buf->data, buf->length);

    UA_ByteString_clear(buf);

    if(result != EMSCRIPTEN_RESULT_SUCCESS) {
        UA_LOG_WARNING(cm->eventSource.eventLoop->logger,
                       UA_LOGCATEGORY_NETWORK,
                       "TCP-Bridge %u\t| Send failed (result=%d)",
                       (unsigned)connectionId, (int)result);
        return UA_STATUSCODE_BADCONNECTIONCLOSED;
    }

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
EMTCP_closeConnection(UA_ConnectionManager *cm, uintptr_t connectionId) {
    EmscriptenWSConnectionManager *wcm = (EmscriptenWSConnectionManager *)cm;
    EmscriptenWSConnection *wc = EMTCP_findConnection(wcm, connectionId);
    if(!wc)
        return UA_STATUSCODE_BADCONNECTIONCLOSED;

    if(wc->closing)
        return UA_STATUSCODE_GOOD;

    wc->closing = true;

    UA_LOG_INFO(cm->eventSource.eventLoop->logger, UA_LOGCATEGORY_NETWORK,
                "TCP-Bridge %u\t| Closing connection", (unsigned)connectionId);

    emscripten_websocket_close(wc->wsHandle, 1000, "Normal closure");
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
EMTCP_allocNetworkBuffer(UA_ConnectionManager *cm, uintptr_t connectionId,
                         UA_ByteString *buf, size_t bufSize) {
    return UA_ByteString_allocBuffer(buf, bufSize);
}

static void
EMTCP_freeNetworkBuffer(UA_ConnectionManager *cm, uintptr_t connectionId,
                        UA_ByteString *buf) {
    UA_ByteString_clear(buf);
}

/*****************************/
/* EventSource Start / Stop  */
/*****************************/

static UA_StatusCode
EMTCP_eventSourceStart(UA_EventSource *es) {
    UA_LOG_INFO(es->eventLoop->logger, UA_LOGCATEGORY_NETWORK,
                "TCP-Bridge\t| Emscripten TCP Bridge ConnectionManager started");
    es->state = UA_EVENTSOURCESTATE_STARTED;
    return UA_STATUSCODE_GOOD;
}

static void
EMTCP_eventSourceStop(UA_EventSource *es) {
    EmscriptenWSConnectionManager *wcm = (EmscriptenWSConnectionManager *)
        ((char *)es - offsetof(UA_ConnectionManager, eventSource));

    UA_LOG_INFO(es->eventLoop->logger, UA_LOGCATEGORY_NETWORK,
                "TCP-Bridge\t| Stopping Emscripten TCP Bridge ConnectionManager");

    EmscriptenWSConnection *wc = wcm->connections;
    while(wc) {
        EmscriptenWSConnection *next = wc->next;
        if(!wc->closing)
            EMTCP_closeConnection(&wcm->cm, wc->connectionId);
        wc = next;
    }

    es->state = UA_EVENTSOURCESTATE_STOPPED;
}

static UA_StatusCode
EMTCP_eventSourceFree(UA_EventSource *es) {
    EmscriptenWSConnectionManager *wcm = (EmscriptenWSConnectionManager *)
        ((char *)es - offsetof(UA_ConnectionManager, eventSource));

    EmscriptenWSConnection *wc = wcm->connections;
    while(wc) {
        EmscriptenWSConnection *next = wc->next;
        UA_free(wc);
        wc = next;
    }

    UA_String_clear(&es->name);
    UA_String_clear(&wcm->cm.protocol);
    UA_KeyValueMap_clear(&es->params);
    UA_free(wcm);
    return UA_STATUSCODE_GOOD;
}

/********************/
/* Factory Function */
/********************/

UA_ConnectionManager *
UA_ConnectionManager_new_Emscripten_TCPBridge(const UA_String eventSourceName) {
    EmscriptenWSConnectionManager *wcm = (EmscriptenWSConnectionManager *)
        UA_calloc(1, sizeof(EmscriptenWSConnectionManager));
    if(!wcm)
        return NULL;

    wcm->connections = NULL;
    wcm->lastConnectionId = 0;

    /* Set EventSource fields */
    wcm->cm.eventSource.eventSourceType = UA_EVENTSOURCETYPE_CONNECTIONMANAGER;
    UA_String_copy(&eventSourceName, &wcm->cm.eventSource.name);
    wcm->cm.eventSource.start = EMTCP_eventSourceStart;
    wcm->cm.eventSource.stop  = EMTCP_eventSourceStop;
    wcm->cm.eventSource.free  = EMTCP_eventSourceFree;

    /* Protocol "tcp" — matches what ua_client_connect.c maps opc.tcp:// to */
    wcm->cm.protocol = UA_STRING_ALLOC("tcp");

    /* ConnectionManager interface */
    wcm->cm.openConnection      = EMTCP_openConnection;
    wcm->cm.sendWithConnection  = EMTCP_sendWithConnection;
    wcm->cm.closeConnection     = EMTCP_closeConnection;
    wcm->cm.allocNetworkBuffer  = EMTCP_allocNetworkBuffer;
    wcm->cm.freeNetworkBuffer   = EMTCP_freeNetworkBuffer;

    return &wcm->cm;
}

#endif /* __EMSCRIPTEN__ */
