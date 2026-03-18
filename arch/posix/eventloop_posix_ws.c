/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2025 (c) Fraunhofer IOSB (Author: Noel Graf)
 *    Copyright 2025 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 */

#include <open62541/plugin/eventloop.h>

#include "eventloop_posix_lws.h"

/**
 * WebSocket ConnectionManager
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * OPC UA WebSocket transport as defined in OPC UA Part 6, Section 7.5.
 * Uses libwebsockets for both server-side (passive) and client-side (active)
 * WebSocket connections. Supports the opcua+uacp (binary) sub-protocol.
 *
 * Protocol string: "ws"
 *
 * Server-side: Opens a listening vhost on the configured port with TLS.
 * Each incoming WS connection gets its own connectionId and invokes the
 * application callback with ESTABLISHED, data, and CLOSING states —
 * identical to TCP ConnectionManager semantics.
 *
 * Client-side: Connects to a remote WS server. The application callback
 * receives OPENING, ESTABLISHED, data, and CLOSING states.
 */

struct WSConnectionManager;
typedef struct WSConnectionManager WSConnectionManager;

struct WSConnection;
typedef struct WSConnection WSConnection;

/* Connection parameters for openConnection */
#define WS_PARAMETERSSIZE 7
#define WS_PARAMINDEX_ADDR     0
#define WS_PARAMINDEX_PORT     1
#define WS_PARAMINDEX_LISTEN   2
#define WS_PARAMINDEX_VALIDATE 3
#define WS_PARAMINDEX_CERT     4
#define WS_PARAMINDEX_KEY      5
#define WS_PARAMINDEX_PATH     6

static UA_KeyValueRestriction wsConnectionParams[WS_PARAMETERSSIZE] = {
    {{0, UA_STRING_STATIC("address")},     &UA_TYPES[UA_TYPES_STRING],     false, true, true},
    {{0, UA_STRING_STATIC("port")},        &UA_TYPES[UA_TYPES_UINT16],     true,  true, false},
    {{0, UA_STRING_STATIC("listen")},      &UA_TYPES[UA_TYPES_BOOLEAN],    false, true, false},
    {{0, UA_STRING_STATIC("validate")},    &UA_TYPES[UA_TYPES_BOOLEAN],    false, true, false},
    {{0, UA_STRING_STATIC("certificate")}, &UA_TYPES[UA_TYPES_BYTESTRING], false, true, false},
    {{0, UA_STRING_STATIC("privatekey")},  &UA_TYPES[UA_TYPES_BYTESTRING], false, true, false},
    {{0, UA_STRING_STATIC("path")},        &UA_TYPES[UA_TYPES_STRING],     false, true, false}
};

/* Per-connection state */
struct WSConnection {
    LIST_ENTRY(WSConnection) pointers;
    WSConnectionManager *wcm;     /* Backpointer */
    uintptr_t connectionId;       /* Unique ID */
    UA_Boolean isListener;        /* True for server listening socket */

    struct lws_context *lwsContext; /* lws context (one per listen or one per client) */
    struct lws *wsi;               /* lws WebSocket instance (NULL for listener) */

    /* Application callback */
    void *application;
    void *context;
    UA_ConnectionManager_connectionCallback applicationCB;

    /* Send buffer queue — lws requires writing only from WRITEABLE callback */
    UA_ByteString sendBuffer;      /* Pending outgoing data */
    UA_Boolean sendPending;        /* lws_callback_on_writable was called */
    UA_Boolean closing;            /* Connection is shutting down */
};

/* The ConnectionManager */
struct WSConnectionManager {
    UA_ConnectionManager cm;
    LIST_HEAD(, WSConnection) connections;
    uintptr_t lastConnectionId;
    UA_EventLoop *foreign_loop;    /* Passed to lws as foreign event loop */
};

/* Prototypes */
static void WS_removeConnection(WSConnection *wc);
static void WS_closeConnection_internal(WSConnection *wc);

static WSConnection *
WS_findConnection(WSConnectionManager *wcm, uintptr_t id) {
    WSConnection *wc;
    LIST_FOREACH(wc, &wcm->connections, pointers) {
        if(wc->connectionId == id)
            return wc;
    }
    return NULL;
}

/* Find a WSConnection by its lws wsi pointer */
static WSConnection *
WS_findConnectionByWsi(WSConnectionManager *wcm, struct lws *wsi) {
    WSConnection *wc;
    LIST_FOREACH(wc, &wcm->connections, pointers) {
        if(wc->wsi == wsi)
            return wc;
    }
    return NULL;
}

/* Find the listener WSConnection for a given lws_context (server-side) */
static WSConnection *
WS_findListener(WSConnectionManager *wcm, struct lws_context *ctx) {
    WSConnection *wc;
    LIST_FOREACH(wc, &wcm->connections, pointers) {
        if(wc->isListener && wc->lwsContext == ctx)
            return wc;
    }
    return NULL;
}

static void
WS_removeConnection(WSConnection *wc) {
    if(!wc)
        return;
    WSConnectionManager *wcm = wc->wcm;

    LIST_REMOVE(wc, pointers);

    /* Notify the application that the connection is now closed */
    if(wc->applicationCB) {
        wc->applicationCB(&wcm->cm, wc->connectionId,
                          wc->application, &wc->context,
                          UA_CONNECTIONSTATE_CLOSED,
                          &UA_KEYVALUEMAP_NULL, UA_BYTESTRING_NULL);
    }

    UA_ByteString_clear(&wc->sendBuffer);
    UA_free(wc);

    /* Check if we can transition to STOPPED */
    if(wcm->cm.eventSource.state == UA_EVENTSOURCESTATE_STOPPING &&
       LIST_EMPTY(&wcm->connections))
        wcm->cm.eventSource.state = UA_EVENTSOURCESTATE_STOPPED;
}

static void
WS_closeConnection_internal(WSConnection *wc) {
    if(!wc || wc->closing)
        return;
    wc->closing = true;

    if(wc->isListener) {
        /* Destroy the lws context for the listener */
        if(wc->lwsContext) {
            lws_context_destroy(wc->lwsContext);
            wc->lwsContext = NULL;
        }
        WS_removeConnection(wc);
    } else if(wc->wsi) {
        /* Request lws to close the WebSocket gracefully.
         * The WSI_DESTROY callback will trigger removal. */
        lws_set_timeout(wc->wsi, PENDING_TIMEOUT_CLOSE_SEND,
                        LWS_TO_KILL_ASYNC);
        wc->wsi = NULL;
    } else {
        WS_removeConnection(wc);
    }
}

/****************************/
/* lws Protocol Callback    */
/****************************/

static int
callback_ws(struct lws *wsi, enum lws_callback_reasons reason,
            void *user, void *in, size_t len) {
    struct lws_context *lws_cx = lws_get_context(wsi);
    WSConnectionManager *wcm = (WSConnectionManager *)lws_context_user(lws_cx);
    if(!wcm)
        return 0;
    UA_EventLoop *el = wcm->cm.eventSource.eventLoop;

    switch(reason) {
    /* ===== Server-side callbacks ===== */
    case LWS_CALLBACK_ESTABLISHED: {
        /* A new client connected to our WebSocket server.
         * Create a WSConnection for the new client. */
        WSConnection *wc = (WSConnection *)UA_calloc(1, sizeof(WSConnection));
        if(!wc) {
            UA_LOG_ERROR(el->logger, UA_LOGCATEGORY_NETWORK,
                         "WS\t| Out of memory for new connection");
            return -1;
        }

        wc->wcm = wcm;
        wc->connectionId = ++wcm->lastConnectionId;
        wc->wsi = wsi;
        wc->isListener = false;

        /* Inherit the application callback from the listener */
        WSConnection *listener = WS_findListener(wcm, lws_cx);
        if(listener) {
            wc->applicationCB = listener->applicationCB;
            wc->application = listener->application;
            wc->context = listener->context;
        }

        LIST_INSERT_HEAD(&wcm->connections, wc, pointers);

        /* Store connection pointer in per-session user data pointer */
        *(WSConnection **)user = wc;

        /* Report the new connection as ESTABLISHED.
         * Provide listen-port and listen-address like TCP CM does. */
        UA_UInt16 listenPort = 0;
        if(listener) {
            /* Try to get port from listener context */
            listenPort = (UA_UInt16)lws_get_vhost_port(
                lws_get_vhost(wsi));
        }
        char peerName[256];
        lws_get_peer_simple(wsi, peerName, sizeof(peerName));
        UA_String remoteAddr = UA_STRING(peerName);

        UA_KeyValuePair kvp[2];
        kvp[0].key = UA_QUALIFIEDNAME(0, "listen-port");
        UA_Variant_setScalar(&kvp[0].value, &listenPort,
                             &UA_TYPES[UA_TYPES_UINT16]);
        kvp[1].key = UA_QUALIFIEDNAME(0, "remote-address");
        UA_Variant_setScalar(&kvp[1].value, &remoteAddr,
                             &UA_TYPES[UA_TYPES_STRING]);
        UA_KeyValueMap kvm = {2, kvp};

        wc->applicationCB(&wcm->cm, wc->connectionId, wc->application,
                          &wc->context, UA_CONNECTIONSTATE_ESTABLISHED,
                          &kvm, UA_BYTESTRING_NULL);

        UA_LOG_INFO(el->logger, UA_LOGCATEGORY_NETWORK,
                    "WS %u\t| New WebSocket connection from %s",
                    (unsigned)wc->connectionId, peerName);
        break;
    }

    case LWS_CALLBACK_RECEIVE: {
        /* Server received data from a client */
        WSConnection *wc = user ? *(WSConnection **)user : NULL;
        if(!wc || wc->closing)
            break;

        UA_ByteString msg;
        msg.data = (UA_Byte *)in;
        msg.length = len;

        UA_LOG_DEBUG(el->logger, UA_LOGCATEGORY_NETWORK,
                     "WS %u\t| Received %zu bytes",
                     (unsigned)wc->connectionId, len);

        wc->applicationCB(&wcm->cm, wc->connectionId,
                          wc->application, &wc->context,
                          UA_CONNECTIONSTATE_ESTABLISHED,
                          &UA_KEYVALUEMAP_NULL, msg);
        break;
    }

    case LWS_CALLBACK_SERVER_WRITEABLE: {
        /* Server can write to a client */
        WSConnection *wc = user ? *(WSConnection **)user : NULL;
        if(!wc || !wc->sendPending)
            break;

        if(wc->sendBuffer.length > 0) {
            int written = lws_write(wsi,
                                    wc->sendBuffer.data + LWS_PRE,
                                    wc->sendBuffer.length - LWS_PRE,
                                    LWS_WRITE_BINARY);
            if(written < 0) {
                UA_LOG_WARNING(el->logger, UA_LOGCATEGORY_NETWORK,
                               "WS %u\t| Write failed",
                               (unsigned)wc->connectionId);
                UA_ByteString_clear(&wc->sendBuffer);
                wc->sendPending = false;
                return -1;
            }
            UA_ByteString_clear(&wc->sendBuffer);
        }
        wc->sendPending = false;
        break;
    }

    /* ===== Client-side callbacks ===== */
    case LWS_CALLBACK_CLIENT_ESTABLISHED: {
        /* Client WebSocket connection established */
        WSConnection *wc = WS_findConnectionByWsi(wcm, wsi);
        if(!wc)
            break;

        UA_LOG_INFO(el->logger, UA_LOGCATEGORY_NETWORK,
                    "WS %u\t| Client WebSocket connected",
                    (unsigned)wc->connectionId);

        wc->applicationCB(&wcm->cm, wc->connectionId,
                          wc->application, &wc->context,
                          UA_CONNECTIONSTATE_ESTABLISHED,
                          &UA_KEYVALUEMAP_NULL, UA_BYTESTRING_NULL);
        break;
    }

    case LWS_CALLBACK_CLIENT_RECEIVE: {
        /* Client received data */
        WSConnection *wc = WS_findConnectionByWsi(wcm, wsi);
        if(!wc || wc->closing)
            break;

        UA_ByteString msg;
        msg.data = (UA_Byte *)in;
        msg.length = len;

        UA_LOG_DEBUG(el->logger, UA_LOGCATEGORY_NETWORK,
                     "WS %u\t| Client received %zu bytes",
                     (unsigned)wc->connectionId, len);

        wc->applicationCB(&wcm->cm, wc->connectionId,
                          wc->application, &wc->context,
                          UA_CONNECTIONSTATE_ESTABLISHED,
                          &UA_KEYVALUEMAP_NULL, msg);
        break;
    }

    case LWS_CALLBACK_CLIENT_WRITEABLE: {
        /* Client can write */
        WSConnection *wc = WS_findConnectionByWsi(wcm, wsi);
        if(!wc || !wc->sendPending)
            break;

        if(wc->sendBuffer.length > 0) {
            int written = lws_write(wsi,
                                    wc->sendBuffer.data + LWS_PRE,
                                    wc->sendBuffer.length - LWS_PRE,
                                    LWS_WRITE_BINARY);
            if(written < 0) {
                UA_LOG_WARNING(el->logger, UA_LOGCATEGORY_NETWORK,
                               "WS %u\t| Client write failed",
                               (unsigned)wc->connectionId);
                UA_ByteString_clear(&wc->sendBuffer);
                wc->sendPending = false;
                return -1;
            }
            UA_ByteString_clear(&wc->sendBuffer);
        }
        wc->sendPending = false;
        break;
    }

    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
        /* Client connection failed */
        WSConnection *wc = WS_findConnectionByWsi(wcm, wsi);
        if(!wc)
            break;

        const char *errMsg = in ? (const char *)in : "unknown error";
        UA_LOG_WARNING(el->logger, UA_LOGCATEGORY_NETWORK,
                       "WS %u\t| Client connection error: %s",
                       (unsigned)wc->connectionId, errMsg);

        wc->wsi = NULL;
        wc->applicationCB(&wcm->cm, wc->connectionId,
                          wc->application, &wc->context,
                          UA_CONNECTIONSTATE_CLOSING,
                          &UA_KEYVALUEMAP_NULL, UA_BYTESTRING_NULL);
        WS_removeConnection(wc);
        break;
    }

    case LWS_CALLBACK_CLOSED:
    case LWS_CALLBACK_CLIENT_CLOSED: {
        /* Connection closed (server or client side) */
        WSConnection *wc = NULL;
        if(reason == LWS_CALLBACK_CLOSED) {
            wc = user ? *(WSConnection **)user : NULL;
        } else {
            wc = WS_findConnectionByWsi(wcm, wsi);
        }
        if(!wc)
            break;

        UA_LOG_INFO(el->logger, UA_LOGCATEGORY_NETWORK,
                    "WS %u\t| Connection closed",
                    (unsigned)wc->connectionId);

        wc->wsi = NULL;
        WS_removeConnection(wc);
        break;
    }

    case LWS_CALLBACK_WSI_DESTROY: {
        /* Final cleanup for a wsi — this is the very last callback.
         * For server child connections, also try to clean up. */
        WSConnection *wc = NULL;
        if(user)
            wc = *(WSConnection **)user;
        if(!wc)
            wc = WS_findConnectionByWsi(wcm, wsi);
        if(wc) {
            wc->wsi = NULL;
            if(!wc->isListener)
                WS_removeConnection(wc);
        }
        break;
    }

    default:
        break;
    }

    return 0;
}

static const struct lws_protocols ws_protocols[] = {
    {"opcua+uacp", callback_ws, sizeof(WSConnection *), 65536, 0, NULL, 0},
    LWS_PROTOCOL_LIST_TERM
};

/****************************/
/* Buffer Management        */
/****************************/

static UA_StatusCode
WS_allocNetworkBuffer(UA_ConnectionManager *cm, uintptr_t connectionId,
                      UA_ByteString *buf, size_t bufSize) {
    /* Allocate with LWS_PRE bytes of headroom for lws framing */
    size_t totalSize = bufSize + LWS_PRE;
    UA_StatusCode res = UA_ByteString_allocBuffer(buf, totalSize);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    /* Shift the data pointer past the LWS_PRE region.
     * The caller sees a buffer of the requested size.
     * We preserve the full allocation in buf->length for
     * sendWithConnection to know the actual layout. */
    buf->data += LWS_PRE;
    buf->length = bufSize;
    return UA_STATUSCODE_GOOD;
}

static void
WS_freeNetworkBuffer(UA_ConnectionManager *cm, uintptr_t connectionId,
                     UA_ByteString *buf) {
    if(!buf || !buf->data)
        return;
    /* Reverse the LWS_PRE offset to free the original allocation */
    buf->data -= LWS_PRE;
    buf->length += LWS_PRE;
    UA_ByteString_clear(buf);
}

/****************************/
/* Open Connection          */
/****************************/

static UA_StatusCode
WS_openPassiveConnection(WSConnectionManager *wcm, const UA_KeyValueMap *params,
                         void *application, void *context,
                         UA_ConnectionManager_connectionCallback connectionCallback,
                         UA_Boolean validate) {
    UA_EventLoop *el = wcm->cm.eventSource.eventLoop;

    /* Read port */
    const UA_UInt16 *port = (const UA_UInt16 *)
        UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, "port"),
                                 &UA_TYPES[UA_TYPES_UINT16]);
    if(!port) {
        UA_LOG_ERROR(el->logger, UA_LOGCATEGORY_NETWORK,
                     "WS\t| Port is required for passive (server) connections");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Validate only? */
    if(validate) {
        connectionCallback(&wcm->cm, 0, application, &context,
                           UA_CONNECTIONSTATE_ESTABLISHED,
                           &UA_KEYVALUEMAP_NULL, UA_BYTESTRING_NULL);
        connectionCallback(&wcm->cm, 0, application, &context,
                           UA_CONNECTIONSTATE_CLOSING,
                           &UA_KEYVALUEMAP_NULL, UA_BYTESTRING_NULL);
        return UA_STATUSCODE_GOOD;
    }

    /* Read optional TLS certificate and key */
    const UA_ByteString *cert = (const UA_ByteString *)
        UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, "certificate"),
                                 &UA_TYPES[UA_TYPES_BYTESTRING]);
    const UA_ByteString *key = (const UA_ByteString *)
        UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, "privatekey"),
                                 &UA_TYPES[UA_TYPES_BYTESTRING]);

    /* Read optional bind address */
    const UA_String *address = (const UA_String *)
        UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, "address"),
                                 &UA_TYPES[UA_TYPES_STRING]);

    /* Allocate the listener connection */
    WSConnection *wc = (WSConnection *)UA_calloc(1, sizeof(WSConnection));
    if(!wc)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    wc->wcm = wcm;
    wc->connectionId = ++wcm->lastConnectionId;
    wc->isListener = true;
    wc->application = application;
    wc->context = context;
    wc->applicationCB = connectionCallback;

    /* Create lws context with a listening vhost */
    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = *port;
    info.protocols = ws_protocols;
    info.user = wcm; /* accessible via lws_context_user() */
    info.log_cx = &open62541_log_cx;
    info.event_lib_custom = &evlib_open62541;
    info.foreign_loops = (void **)&wcm->foreign_loop;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

    /* Bind address */
    char iface_str[256];
    if(address && address->length > 0 && address->length < sizeof(iface_str)) {
        memcpy(iface_str, address->data, address->length);
        iface_str[address->length] = '\0';
        info.iface = iface_str;
    }

    /* TLS configuration */
    if(cert && cert->length > 0 && key && key->length > 0) {
        info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
        /* lws supports passing cert/key as in-memory buffers */
        info.server_ssl_cert_mem = cert->data;
        info.server_ssl_cert_mem_len = (unsigned int)cert->length;
        info.server_ssl_private_key_mem = key->data;
        info.server_ssl_private_key_mem_len = (unsigned int)key->length;
    }

    wc->lwsContext = lws_create_context(&info);
    if(!wc->lwsContext) {
        UA_LOG_ERROR(el->logger, UA_LOGCATEGORY_NETWORK,
                     "WS\t| Could not create lws context for listening on port %u",
                     (unsigned)*port);
        UA_free(wc);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    LIST_INSERT_HEAD(&wcm->connections, wc, pointers);

    /* Notify the application that the server socket is open.
     * Provide listen-port and listen-address like TCP CM does. */
    UA_String listenAddr = UA_STRING("0.0.0.0");
    if(address && address->length > 0)
        listenAddr = *address;

    UA_KeyValuePair kvp[2];
    kvp[0].key = UA_QUALIFIEDNAME(0, "listen-port");
    UA_Variant_setScalar(&kvp[0].value, (UA_UInt16 *)(uintptr_t)port,
                         &UA_TYPES[UA_TYPES_UINT16]);
    kvp[1].key = UA_QUALIFIEDNAME(0, "listen-address");
    UA_Variant_setScalar(&kvp[1].value, &listenAddr,
                         &UA_TYPES[UA_TYPES_STRING]);
    UA_KeyValueMap kvm = {2, kvp};

    connectionCallback(&wcm->cm, wc->connectionId, application,
                       &wc->context, UA_CONNECTIONSTATE_ESTABLISHED,
                       &kvm, UA_BYTESTRING_NULL);

    UA_LOG_INFO(el->logger, UA_LOGCATEGORY_NETWORK,
                "WS %u\t| Listening for WebSocket connections on port %u",
                (unsigned)wc->connectionId, (unsigned)*port);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
WS_openActiveConnection(WSConnectionManager *wcm, const UA_KeyValueMap *params,
                        void *application, void *context,
                        UA_ConnectionManager_connectionCallback connectionCallback,
                        UA_Boolean validate) {
    UA_EventLoop *el = wcm->cm.eventSource.eventLoop;

    /* Read required parameters */
    const UA_String *hostname = (const UA_String *)
        UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, "address"),
                                 &UA_TYPES[UA_TYPES_STRING]);
    if(!hostname || hostname->length == 0) {
        UA_LOG_ERROR(el->logger, UA_LOGCATEGORY_NETWORK,
                     "WS\t| Address is required for active (client) connections");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    const UA_UInt16 *port = (const UA_UInt16 *)
        UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, "port"),
                                 &UA_TYPES[UA_TYPES_UINT16]);
    if(!port) {
        UA_LOG_ERROR(el->logger, UA_LOGCATEGORY_NETWORK,
                     "WS\t| Port is required for active (client) connections");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Optional path */
    const UA_String *path = (const UA_String *)
        UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, "path"),
                                 &UA_TYPES[UA_TYPES_STRING]);

    if(validate) {
        connectionCallback(&wcm->cm, 0, application, &context,
                           UA_CONNECTIONSTATE_ESTABLISHED,
                           &UA_KEYVALUEMAP_NULL, UA_BYTESTRING_NULL);
        connectionCallback(&wcm->cm, 0, application, &context,
                           UA_CONNECTIONSTATE_CLOSING,
                           &UA_KEYVALUEMAP_NULL, UA_BYTESTRING_NULL);
        return UA_STATUSCODE_GOOD;
    }

    /* Allocate the connection */
    WSConnection *wc = (WSConnection *)UA_calloc(1, sizeof(WSConnection));
    if(!wc)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    wc->wcm = wcm;
    wc->connectionId = ++wcm->lastConnectionId;
    wc->isListener = false;
    wc->application = application;
    wc->context = context;
    wc->applicationCB = connectionCallback;

    /* Create client lws context */
    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = ws_protocols;
    info.user = wcm;
    info.log_cx = &open62541_log_cx;
    info.event_lib_custom = &evlib_open62541;
    info.foreign_loops = (void **)&wcm->foreign_loop;

    wc->lwsContext = lws_create_context(&info);
    if(!wc->lwsContext) {
        UA_LOG_ERROR(el->logger, UA_LOGCATEGORY_NETWORK,
                     "WS\t| Could not create lws context for client connection");
        UA_free(wc);
        return UA_STATUSCODE_BADCONNECTIONREJECTED;
    }

    LIST_INSERT_HEAD(&wcm->connections, wc, pointers);

    /* Build address string */
    char addr_str[512];
    if(hostname->length >= sizeof(addr_str)) {
        WS_closeConnection_internal(wc);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    memcpy(addr_str, hostname->data, hostname->length);
    addr_str[hostname->length] = '\0';

    /* Build path string */
    char path_str[512];
    path_str[0] = '/';
    path_str[1] = '\0';
    if(path && path->length > 0 && path->length < sizeof(path_str) - 1) {
        path_str[0] = '/';
        memcpy(path_str + 1, path->data, path->length);
        path_str[path->length + 1] = '\0';
    }

    /* Initiate client WebSocket connection */
    struct lws_client_connect_info ccinfo;
    memset(&ccinfo, 0, sizeof(ccinfo));
    ccinfo.context = wc->lwsContext;
    ccinfo.address = addr_str;
    ccinfo.port = *port;
    ccinfo.path = path_str;
    ccinfo.host = addr_str;
    ccinfo.origin = addr_str;
    ccinfo.protocol = "opcua+uacp";
    ccinfo.ssl_connection = LCCSCF_USE_SSL |
                            LCCSCF_ALLOW_SELFSIGNED |
                            LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;

    wc->wsi = lws_client_connect_via_info(&ccinfo);
    if(!wc->wsi) {
        UA_LOG_ERROR(el->logger, UA_LOGCATEGORY_NETWORK,
                     "WS %u\t| Client connect initiation failed to %s:%u",
                     (unsigned)wc->connectionId, addr_str, (unsigned)*port);
        WS_closeConnection_internal(wc);
        return UA_STATUSCODE_BADCONNECTIONREJECTED;
    }

    /* Signal OPENING state */
    connectionCallback(&wcm->cm, wc->connectionId, application,
                       &wc->context, UA_CONNECTIONSTATE_OPENING,
                       &UA_KEYVALUEMAP_NULL, UA_BYTESTRING_NULL);

    UA_LOG_INFO(el->logger, UA_LOGCATEGORY_NETWORK,
                "WS %u\t| Connecting to %s:%u%s",
                (unsigned)wc->connectionId, addr_str,
                (unsigned)*port, path_str);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
WS_openConnection(UA_ConnectionManager *cm, const UA_KeyValueMap *params,
                  void *application, void *context,
                  UA_ConnectionManager_connectionCallback connectionCallback) {
    if(cm->eventSource.state != UA_EVENTSOURCESTATE_STARTED) {
        UA_LOG_ERROR(cm->eventSource.eventLoop->logger, UA_LOGCATEGORY_NETWORK,
                     "WS\t| ConnectionManager not started");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Validate parameters */
    WSConnectionManager *wcm = (WSConnectionManager *)cm;
    UA_StatusCode res =
        UA_KeyValueRestriction_validate(cm->eventSource.eventLoop->logger, "WS",
                                        wsConnectionParams, WS_PARAMETERSSIZE,
                                        params);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* Check if this is a listen connection or active connect */
    const UA_Boolean *listen = (const UA_Boolean *)
        UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, "listen"),
                                 &UA_TYPES[UA_TYPES_BOOLEAN]);

    /* Check validate flag */
    const UA_Boolean *validate = (const UA_Boolean *)
        UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, "validate"),
                                 &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_Boolean isValidate = (validate && *validate);

    if(listen && *listen)
        return WS_openPassiveConnection(wcm, params, application, context,
                                        connectionCallback, isValidate);
    return WS_openActiveConnection(wcm, params, application, context,
                                   connectionCallback, isValidate);
}

/****************************/
/* Send                     */
/****************************/

static UA_StatusCode
WS_sendWithConnection(UA_ConnectionManager *cm, uintptr_t connectionId,
                      const UA_KeyValueMap *params, UA_ByteString *buf) {
    WSConnectionManager *wcm = (WSConnectionManager *)cm;
    WSConnection *wc = WS_findConnection(wcm, connectionId);
    if(!wc || wc->closing || !wc->wsi) {
        WS_freeNetworkBuffer(cm, connectionId, buf);
        return UA_STATUSCODE_BADCONNECTIONCLOSED;
    }

    /* The buffer was allocated with WS_allocNetworkBuffer which added
     * LWS_PRE bytes before buf->data. Restore the full allocation
     * for lws_write. */
    UA_ByteString sendBuf;
    sendBuf.data = buf->data - LWS_PRE;
    sendBuf.length = buf->length + LWS_PRE;

    /* If there is already a pending send, we need to queue. For now
     * we support a single pending buffer and reject additional sends. */
    if(wc->sendPending) {
        /* Try direct write if writable */
        int written = lws_write(wc->wsi, buf->data, buf->length,
                                LWS_WRITE_BINARY);
        /* Free original allocation */
        UA_free(sendBuf.data);
        UA_ByteString_init(buf);
        if(written < 0)
            return UA_STATUSCODE_BADCONNECTIONCLOSED;
        return UA_STATUSCODE_GOOD;
    }

    /* Store the buffer and request a writable callback */
    wc->sendBuffer = sendBuf;
    wc->sendPending = true;
    UA_ByteString_init(buf); /* Ownership transferred */

    lws_callback_on_writable(wc->wsi);
    return UA_STATUSCODE_GOOD;
}

/****************************/
/* Close Connection         */
/****************************/

static UA_StatusCode
WS_closeConnection(UA_ConnectionManager *cm, uintptr_t connectionId) {
    WSConnectionManager *wcm = (WSConnectionManager *)cm;
    WSConnection *wc = WS_findConnection(wcm, connectionId);
    if(!wc) {
        UA_LOG_WARNING(cm->eventSource.eventLoop->logger, UA_LOGCATEGORY_NETWORK,
                       "WS\t| Cannot close connection %u - not found",
                       (unsigned)connectionId);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    WS_closeConnection_internal(wc);
    return UA_STATUSCODE_GOOD;
}

/****************************/
/* EventSource Lifecycle    */
/****************************/

static UA_StatusCode
WS_eventSourceStart(UA_ConnectionManager *cm) {
    /* Shut off lws logging */
    lws_set_log_level(0, NULL);

    UA_EventLoop *el = cm->eventSource.eventLoop;
    if(!el)
        return UA_STATUSCODE_BADINTERNALERROR;

    if(cm->eventSource.state != UA_EVENTSOURCESTATE_STOPPED) {
        UA_LOG_ERROR(el->logger, UA_LOGCATEGORY_NETWORK,
                     "WS\t| To start the ConnectionManager, it has to be "
                     "registered in an EventLoop and not started yet");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_LOG_INFO(el->logger, UA_LOGCATEGORY_EVENTLOOP,
                "WS\t| Starting the WebSocket ConnectionManager");

    WSConnectionManager *wcm = (WSConnectionManager *)cm;
    wcm->foreign_loop = el;
    cm->eventSource.state = UA_EVENTSOURCESTATE_STARTED;
    return UA_STATUSCODE_GOOD;
}

static void
WS_eventSourceStop(UA_ConnectionManager *cm) {
    if(cm->eventSource.state == UA_EVENTSOURCESTATE_STOPPING ||
       cm->eventSource.state == UA_EVENTSOURCESTATE_STOPPED)
        return;

    UA_LOG_INFO(cm->eventSource.eventLoop->logger, UA_LOGCATEGORY_EVENTLOOP,
                "WS\t| Stopping the WebSocket ConnectionManager");

    cm->eventSource.state = UA_EVENTSOURCESTATE_STOPPING;

    WSConnectionManager *wcm = (WSConnectionManager *)cm;
    WSConnection *wc, *wc_tmp;
    LIST_FOREACH_SAFE(wc, &wcm->connections, pointers, wc_tmp) {
        WS_closeConnection_internal(wc);
    }

    if(LIST_EMPTY(&wcm->connections))
        cm->eventSource.state = UA_EVENTSOURCESTATE_STOPPED;
}

static UA_StatusCode
WS_eventSourceDelete(UA_ConnectionManager *cm) {
    if(cm->eventSource.state >= UA_EVENTSOURCESTATE_STARTING) {
        UA_LOG_ERROR(cm->eventSource.eventLoop->logger, UA_LOGCATEGORY_EVENTLOOP,
                     "WS\t| The EventSource must be stopped before it can be deleted");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_String_clear(&cm->eventSource.name);
    UA_KeyValueMap_clear(&cm->eventSource.params);
    UA_free(cm);
    return UA_STATUSCODE_GOOD;
}

/****************************/
/* Factory Function         */
/****************************/

static const char *wsName = "ws";

UA_ConnectionManager *
UA_ConnectionManager_new_POSIX_WS(const UA_String eventSourceName) {
    WSConnectionManager *cm = (WSConnectionManager *)
        UA_calloc(1, sizeof(WSConnectionManager));
    if(!cm)
        return NULL;

    cm->cm.eventSource.eventSourceType = UA_EVENTSOURCETYPE_CONNECTIONMANAGER;
    UA_String_copy(&eventSourceName, &cm->cm.eventSource.name);
    cm->cm.eventSource.start =
        (UA_StatusCode(*)(UA_EventSource *))WS_eventSourceStart;
    cm->cm.eventSource.stop =
        (void (*)(UA_EventSource *))WS_eventSourceStop;
    cm->cm.eventSource.free =
        (UA_StatusCode(*)(UA_EventSource *))WS_eventSourceDelete;
    cm->cm.protocol = UA_STRING((char *)(uintptr_t)wsName);
    cm->cm.openConnection = WS_openConnection;
    cm->cm.allocNetworkBuffer = WS_allocNetworkBuffer;
    cm->cm.freeNetworkBuffer = WS_freeNetworkBuffer;
    cm->cm.sendWithConnection = WS_sendWithConnection;
    cm->cm.closeConnection = WS_closeConnection;
    return &cm->cm;
}
