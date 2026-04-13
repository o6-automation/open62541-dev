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
 * Emscripten WebSocket ConnectionManager
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * Browser-native WebSocket transport for OPC UA. Replaces the libwebsockets-
 * based POSIX WS ConnectionManager with Emscripten's emscripten_websocket_*
 * API. Client-only — browsers cannot accept incoming WS connections.
 *
 * Protocol string: "ws"
 *
 * Connection parameters:
 * - 0:address  [string]  Hostname (required)
 * - 0:port     [uint16]  Port (required)
 * - 0:path     [string]  URL path (default: "/")
 * - 0:tls      [bool]    Use wss:// (default: true)
 */

/* Connection parameter indices */
#define EMWS_PARAMETERSSIZE 4
#define EMWS_PARAMINDEX_ADDR 0
#define EMWS_PARAMINDEX_PORT 1
#define EMWS_PARAMINDEX_PATH 2
#define EMWS_PARAMINDEX_TLS  3

static UA_KeyValueRestriction emwsConnectionParams[EMWS_PARAMETERSSIZE] = {
    {{0, UA_STRING_STATIC("address")}, &UA_TYPES[UA_TYPES_STRING],  true,  true, false},
    {{0, UA_STRING_STATIC("port")},    &UA_TYPES[UA_TYPES_UINT16],  true,  true, false},
    {{0, UA_STRING_STATIC("path")},    &UA_TYPES[UA_TYPES_STRING],  false, true, false},
    {{0, UA_STRING_STATIC("tls")},     &UA_TYPES[UA_TYPES_BOOLEAN], false, true, false}
};

/* Sub-protocol for OPC UA binary over WebSocket (Part 6, §7.5) */
#define EMWS_SUBPROTOCOL "opcua+uacp"

/* Maximum message size (matches POSIX WS CM) */
#define EMWS_MAX_MESSAGE_SIZE (16u * 1024u * 1024u)

/**********************/
/* Connection Helpers */
/**********************/

static EmscriptenWSConnection *
EMWS_findConnection(EmscriptenWSConnectionManager *wcm, uintptr_t id) {
    EmscriptenWSConnection *wc = wcm->connections;
    while(wc) {
        if(wc->connectionId == id)
            return wc;
        wc = wc->next;
    }
    return NULL;
}

static EmscriptenWSConnection *
EMWS_findConnectionByHandle(EmscriptenWSConnectionManager *wcm, int handle) {
    EmscriptenWSConnection *wc = wcm->connections;
    while(wc) {
        if(wc->wsHandle == handle)
            return wc;
        wc = wc->next;
    }
    return NULL;
}

static void
EMWS_removeConnection(EmscriptenWSConnection *wc) {
    if(!wc)
        return;
    EmscriptenWSConnectionManager *wcm =
        (EmscriptenWSConnectionManager *)wc->dc.application;

    /* Remove from singly-linked list */
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
EMWS_deferredFree(void *application, void *context) {
    EmscriptenWSConnection *wc = (EmscriptenWSConnection *)context;
    UA_free(wc);
}

/****************************/
/* WebSocket Event Handlers */
/****************************/

static EM_BOOL
EMWS_onOpen(int eventType, const EmscriptenWebSocketOpenEvent *wsEvent,
            void *userData) {
    EmscriptenWSConnection *wc = (EmscriptenWSConnection *)userData;
    if(!wc || wc->closing)
        return EM_TRUE;

    wc->established = true;

    UA_LOG_INFO(wc->dc.application ?
                ((EmscriptenWSConnectionManager *)wc->dc.application)->cm.eventSource.eventLoop->logger : NULL,
                UA_LOGCATEGORY_NETWORK,
                "WS %u\t| Connection established",
                (unsigned)wc->connectionId);

    /* Notify the application */
    UA_KeyValuePair kvp;
    kvp.key = UA_QUALIFIEDNAME(0, "subprotocol");
    UA_String subproto = UA_STRING(EMWS_SUBPROTOCOL);
    UA_Variant_setScalar(&kvp.value, &subproto, &UA_TYPES[UA_TYPES_STRING]);
    UA_KeyValueMap params;
    params.map = &kvp;
    params.mapSize = 1;

    UA_ByteString empty = UA_BYTESTRING_NULL;
    wc->applicationCB(&((EmscriptenWSConnectionManager *)wc->dc.application)->cm,
                       wc->connectionId, wc->application, &wc->context,
                       UA_CONNECTIONSTATE_ESTABLISHED, &params, empty);

    return EM_TRUE;
}

static EM_BOOL
EMWS_onMessage(int eventType, const EmscriptenWebSocketMessageEvent *wsEvent,
               void *userData) {
    EmscriptenWSConnection *wc = (EmscriptenWSConnection *)userData;
    if(!wc || wc->closing)
        return EM_TRUE;

    /* Only accept binary messages for OPC UA */
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
EMWS_onError(int eventType, const EmscriptenWebSocketErrorEvent *wsEvent,
             void *userData) {
    EmscriptenWSConnection *wc = (EmscriptenWSConnection *)userData;
    if(!wc)
        return EM_TRUE;

    EmscriptenWSConnectionManager *wcm =
        (EmscriptenWSConnectionManager *)wc->dc.application;

    UA_LOG_WARNING(wcm->cm.eventSource.eventLoop->logger,
                   UA_LOGCATEGORY_NETWORK,
                   "WS %u\t| WebSocket error",
                   (unsigned)wc->connectionId);

    /* Mark as closing to prevent further sends.
     * Don't notify or clean up here — the browser always fires onClose
     * after onError, and onClose handles the final notification. */
    wc->closing = true;

    return EM_TRUE;
}

static EM_BOOL
EMWS_onClose(int eventType, const EmscriptenWebSocketCloseEvent *wsEvent,
             void *userData) {
    EmscriptenWSConnection *wc = (EmscriptenWSConnection *)userData;
    if(!wc)
        return EM_TRUE;

    EmscriptenWSConnectionManager *wcm =
        (EmscriptenWSConnectionManager *)wc->dc.application;

    UA_LOG_INFO(wcm->cm.eventSource.eventLoop->logger,
                UA_LOGCATEGORY_NETWORK,
                "WS %u\t| Connection closed (code=%d)",
                (unsigned)wc->connectionId, (int)wsEvent->code);

    if(!wc->closing)
        wc->closing = true;

    /* Always notify the application that the connection is fully closed.
     * This is needed regardless of whether the close was initiated locally
     * (via closeConnection) or remotely. Without this notification the
     * SecureChannel never transitions to CLOSED and synchronous disconnect
     * loops spin forever. */
    UA_ByteString empty = UA_BYTESTRING_NULL;
    UA_KeyValueMap emptyParams = {0, NULL};
    wc->applicationCB(&wcm->cm, wc->connectionId, wc->application,
                       &wc->context, UA_CONNECTIONSTATE_CLOSING,
                       &emptyParams, empty);

    EMWS_removeConnection(wc);

    /* Deferred free — we're inside a callback */
    wc->dc.callback = EMWS_deferredFree;
    wc->dc.context = wc;
    wcm->cm.eventSource.eventLoop->addDelayedCallback(
        wcm->cm.eventSource.eventLoop, &wc->dc);

    return EM_TRUE;
}

/****************************************/
/* ConnectionManager Interface Methods  */
/****************************************/

static UA_StatusCode
EMWS_openConnection(UA_ConnectionManager *cm, const UA_KeyValueMap *params,
                    void *application, void *context,
                    UA_ConnectionManager_connectionCallback connectionCallback) {
    EmscriptenWSConnectionManager *wcm = (EmscriptenWSConnectionManager *)cm;
    UA_EventLoop *el = cm->eventSource.eventLoop;

    /* Validate parameters */
    UA_StatusCode res =
        UA_KeyValueRestriction_validate(el->logger, "WS",
                                        emwsConnectionParams,
                                        EMWS_PARAMETERSSIZE, params);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* Extract address */
    const UA_String *address = (const UA_String *)
        UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, "address"),
                                 &UA_TYPES[UA_TYPES_STRING]);
    if(!address || address->length == 0)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Extract port */
    const UA_UInt16 *port = (const UA_UInt16 *)
        UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, "port"),
                                 &UA_TYPES[UA_TYPES_UINT16]);
    if(!port)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Extract optional path */
    const UA_String *path = (const UA_String *)
        UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, "path"),
                                 &UA_TYPES[UA_TYPES_STRING]);

    /* Extract optional TLS flag (default: true) */
    const UA_Boolean *tls = (const UA_Boolean *)
        UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, "tls"),
                                 &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_Boolean useTls = tls ? *tls : false;

    /* Build URL: ws[s]://address:port[/path] */
    char url[512];
    const char *scheme = useTls ? "wss" : "ws";
    char pathBuf[256] = "/";
    if(path && path->length > 0 && path->length < sizeof(pathBuf) - 1) {
        if(path->data[0] != '/')
            pathBuf[0] = '/';
        memcpy(pathBuf + (path->data[0] != '/' ? 1 : 0),
               path->data, path->length);
        pathBuf[(path->data[0] != '/' ? 1 : 0) + path->length] = '\0';
    }

    int urlLen = snprintf(url, sizeof(url), "%s://%.*s:%u%s",
                          scheme, (int)address->length, (char *)address->data,
                          (unsigned)*port, pathBuf);
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
    wc->dc.application = wcm;  /* Backpointer for callbacks */

    /* Create browser WebSocket */
    EmscriptenWebSocketCreateAttributes wsAttrs = {
        url,
        EMWS_SUBPROTOCOL,  /* protocols */
        EM_TRUE             /* createOnMainThread */
    };

    wc->wsHandle = emscripten_websocket_new(&wsAttrs);
    if(wc->wsHandle <= 0) {
        UA_LOG_ERROR(el->logger, UA_LOGCATEGORY_NETWORK,
                     "WS\t| Failed to create WebSocket to %s", url);
        UA_free(wc);
        return UA_STATUSCODE_BADCONNECTIONREJECTED;
    }

    /* Register event handlers */
    emscripten_websocket_set_onopen_callback(wc->wsHandle, wc, EMWS_onOpen);
    emscripten_websocket_set_onmessage_callback(wc->wsHandle, wc, EMWS_onMessage);
    emscripten_websocket_set_onerror_callback(wc->wsHandle, wc, EMWS_onError);
    emscripten_websocket_set_onclose_callback(wc->wsHandle, wc, EMWS_onClose);

    /* Add to linked list */
    wc->next = wcm->connections;
    wcm->connections = wc;

    UA_LOG_INFO(el->logger, UA_LOGCATEGORY_NETWORK,
                "WS %u\t| Opening connection to %s",
                (unsigned)wc->connectionId, url);

    /* Notify OPENING state */
    UA_ByteString empty = UA_BYTESTRING_NULL;
    UA_KeyValueMap emptyParams = {0, NULL};
    connectionCallback(cm, wc->connectionId, application, &wc->context,
                       UA_CONNECTIONSTATE_OPENING, &emptyParams, empty);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
EMWS_sendWithConnection(UA_ConnectionManager *cm, uintptr_t connectionId,
                        const UA_KeyValueMap *params, UA_ByteString *buf) {
    EmscriptenWSConnectionManager *wcm = (EmscriptenWSConnectionManager *)cm;
    EmscriptenWSConnection *wc = EMWS_findConnection(wcm, connectionId);
    if(!wc || wc->closing || !wc->established) {
        UA_ByteString_clear(buf);
        return UA_STATUSCODE_BADCONNECTIONCLOSED;
    }

    /* Send as binary frame */
    EMSCRIPTEN_RESULT result =
        emscripten_websocket_send_binary(wc->wsHandle, buf->data, buf->length);

    /* Free the buffer (it was allocated with allocNetworkBuffer) */
    UA_ByteString_clear(buf);

    if(result != EMSCRIPTEN_RESULT_SUCCESS) {
        UA_LOG_WARNING(cm->eventSource.eventLoop->logger,
                       UA_LOGCATEGORY_NETWORK,
                       "WS %u\t| Send failed (result=%d)",
                       (unsigned)connectionId, (int)result);
        return UA_STATUSCODE_BADCONNECTIONCLOSED;
    }

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
EMWS_closeConnection(UA_ConnectionManager *cm, uintptr_t connectionId) {
    EmscriptenWSConnectionManager *wcm = (EmscriptenWSConnectionManager *)cm;
    EmscriptenWSConnection *wc = EMWS_findConnection(wcm, connectionId);
    if(!wc)
        return UA_STATUSCODE_BADCONNECTIONCLOSED;

    if(wc->closing)
        return UA_STATUSCODE_GOOD;

    wc->closing = true;

    UA_LOG_INFO(cm->eventSource.eventLoop->logger, UA_LOGCATEGORY_NETWORK,
                "WS %u\t| Closing connection", (unsigned)connectionId);

    /* Close the browser WebSocket — this triggers the onClose callback */
    emscripten_websocket_close(wc->wsHandle, 1000, "Normal closure");

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
EMWS_allocNetworkBuffer(UA_ConnectionManager *cm, uintptr_t connectionId,
                        UA_ByteString *buf, size_t bufSize) {
    return UA_ByteString_allocBuffer(buf, bufSize);
}

static void
EMWS_freeNetworkBuffer(UA_ConnectionManager *cm, uintptr_t connectionId,
                       UA_ByteString *buf) {
    UA_ByteString_clear(buf);
}

/*****************************/
/* EventSource Start / Stop  */
/*****************************/

static UA_StatusCode
EMWS_eventSourceStart(UA_EventSource *es) {
    UA_LOG_INFO(es->eventLoop->logger, UA_LOGCATEGORY_NETWORK,
                "WS\t| Emscripten WebSocket ConnectionManager started");
    es->state = UA_EVENTSOURCESTATE_STARTED;
    return UA_STATUSCODE_GOOD;
}

static void
EMWS_eventSourceStop(UA_EventSource *es) {
    EmscriptenWSConnectionManager *wcm = (EmscriptenWSConnectionManager *)
        ((char *)es - offsetof(UA_ConnectionManager, eventSource));

    UA_LOG_INFO(es->eventLoop->logger, UA_LOGCATEGORY_NETWORK,
                "WS\t| Stopping Emscripten WebSocket ConnectionManager");

    /* Close all open connections */
    EmscriptenWSConnection *wc = wcm->connections;
    while(wc) {
        EmscriptenWSConnection *next = wc->next;
        if(!wc->closing)
            EMWS_closeConnection(&wcm->cm, wc->connectionId);
        wc = next;
    }

    es->state = UA_EVENTSOURCESTATE_STOPPED;
}

static UA_StatusCode
EMWS_eventSourceFree(UA_EventSource *es) {
    EmscriptenWSConnectionManager *wcm = (EmscriptenWSConnectionManager *)
        ((char *)es - offsetof(UA_ConnectionManager, eventSource));

    /* Free any remaining connections */
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
UA_ConnectionManager_new_Emscripten_WS(const UA_String eventSourceName) {
    EmscriptenWSConnectionManager *wcm = (EmscriptenWSConnectionManager *)
        UA_calloc(1, sizeof(EmscriptenWSConnectionManager));
    if(!wcm)
        return NULL;

    wcm->connections = NULL;
    wcm->lastConnectionId = 0;

    /* Set EventSource fields */
    wcm->cm.eventSource.eventSourceType = UA_EVENTSOURCETYPE_CONNECTIONMANAGER;
    UA_String_copy(&eventSourceName, &wcm->cm.eventSource.name);
    wcm->cm.eventSource.start = EMWS_eventSourceStart;
    wcm->cm.eventSource.stop  = EMWS_eventSourceStop;
    wcm->cm.eventSource.free  = EMWS_eventSourceFree;

    /* Protocol string — must match what ua_client_connect.c maps "ws" to */
    wcm->cm.protocol = UA_STRING_ALLOC("ws");

    /* ConnectionManager interface */
    wcm->cm.openConnection      = EMWS_openConnection;
    wcm->cm.sendWithConnection  = EMWS_sendWithConnection;
    wcm->cm.closeConnection     = EMWS_closeConnection;
    wcm->cm.allocNetworkBuffer  = EMWS_allocNetworkBuffer;
    wcm->cm.freeNetworkBuffer   = EMWS_freeNetworkBuffer;

    return &wcm->cm;
}

#endif /* __EMSCRIPTEN__ */
