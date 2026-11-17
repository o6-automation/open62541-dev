/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 * Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

/* The http driver on an own HTTP ConnectionManager with POSIX sockets,
 * without libwebsockets. */

#define _POSIX_C_SOURCE 200112L

#include <open62541/server.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/***************************************************/
/* A minimal HTTP ConnectionManager (client only) */
/***************************************************/

typedef struct {
    UA_ConnectionManager cm;
    UA_ConnectionManager_connectionCallback callback;
    void *application;
    void *context;
    char host[256];
    char port[8];
} SocketHttp;

static const void *
param(const UA_KeyValueMap *params, const char *name, UA_UInt16 type) {
    return UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, (char *)(uintptr_t)name),
                                    &UA_TYPES[type]);
}

static UA_StatusCode
socketOpen(UA_ConnectionManager *cm, const UA_KeyValueMap *params, void *application,
           void *context, UA_ConnectionManager_connectionCallback callback) {
    SocketHttp *sh = (SocketHttp *)cm;
    const UA_String *address =
        (const UA_String *)param(params, "address", UA_TYPES_STRING);
    const UA_UInt16 *port = (const UA_UInt16 *)param(params, "port", UA_TYPES_UINT16);
    const UA_Boolean *ssl = (const UA_Boolean *)param(params, "useSSL", UA_TYPES_BOOLEAN);
    if(!address || !port || address->length >= sizeof(sh->host) || (ssl && *ssl))
        return UA_STATUSCODE_BADNOTSUPPORTED;
    memcpy(sh->host, address->data, address->length);
    sh->host[address->length] = '\0';
    snprintf(sh->port, sizeof(sh->port), "%u", (unsigned)*port);
    sh->callback = callback;
    sh->application = application;
    sh->context = context;
    callback(cm, 1, application, &sh->context, UA_CONNECTIONSTATE_OPENING,
             &UA_KEYVALUEMAP_NULL, UA_BYTESTRING_NULL);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
socketSend(UA_ConnectionManager *cm, uintptr_t connectionId,
           const UA_KeyValueMap *params, UA_ByteString *buf) {
    SocketHttp *sh = (SocketHttp *)cm;
    const UA_String *method = (const UA_String *)param(params, "method", UA_TYPES_STRING);
    const UA_String *path = (const UA_String *)param(params, "path", UA_TYPES_STRING);
    const UA_Variant *headers =
        UA_KeyValueMap_get(params, UA_QUALIFIEDNAME(0, "headers"));

    static char request[8192], response[65536];
    size_t bodyLength = buf ? buf->length : 0;
    int n = snprintf(request, sizeof(request),
                     "%.*s %.*s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
                     "Content-Length: %zu\r\n", (int)method->length, method->data,
                     (int)path->length, path->data, sh->host, bodyLength);
    for(size_t i = 0; headers && i < headers->arrayLength; i++) {
        const UA_KeyValuePair *h = &((const UA_KeyValuePair *)headers->data)[i];
        const UA_String *v = (const UA_String *)h->value.data;
        n += snprintf(request + n, sizeof(request) - (size_t)n, "%.*s: %.*s\r\n",
                      (int)h->key.name.length, h->key.name.data,
                      (int)v->length, v->data);
    }
    n += snprintf(request + n, sizeof(request) - (size_t)n, "\r\n%.*s",
                  (int)bodyLength, bodyLength ? (const char *)buf->data : "");
    if(buf)
        UA_ByteString_clear(buf);

    struct addrinfo hints, *ai = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    if(getaddrinfo(sh->host, sh->port, &hints, &ai) != 0)
        return UA_STATUSCODE_BADCONNECTIONREJECTED;
    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    int connected = (fd >= 0 && connect(fd, ai->ai_addr, ai->ai_addrlen) == 0);
    freeaddrinfo(ai);
    if(!connected) {
        if(fd >= 0)
            close(fd);
        return UA_STATUSCODE_BADCONNECTIONREJECTED;
    }
    send(fd, request, (size_t)n, 0);
    size_t length = 0;
    ssize_t r;
    while((r = recv(fd, response + length, sizeof(response) - length - 1, 0)) > 0)
        length += (size_t)r;
    close(fd);
    response[length] = '\0';

    UA_UInt16 status = (UA_UInt16)atoi(response + 9);
    char *start = strstr(response, "\r\n\r\n");
    UA_ByteString body = UA_BYTESTRING(start ? start + 4 : "");
    UA_Boolean complete = true;
    UA_StatusCode requestStatus = UA_STATUSCODE_GOOD;
    UA_KeyValuePair p[4];
    memset(p, 0, sizeof(p));
    p[0].key = UA_QUALIFIEDNAME(0, "status-code");
    UA_Variant_setScalar(&p[0].value, &status, &UA_TYPES[UA_TYPES_UINT16]);
    p[1].key = UA_QUALIFIEDNAME(0, "handle");
    p[1].value = *UA_KeyValueMap_get(params, UA_QUALIFIEDNAME(0, "handle"));
    UA_KeyValueMap map = {2, p};
    sh->callback(cm, connectionId, sh->application, &sh->context,
                 UA_CONNECTIONSTATE_ESTABLISHED, &map, body);
    p[2].key = UA_QUALIFIEDNAME(0, "response-complete");
    UA_Variant_setScalar(&p[2].value, &complete, &UA_TYPES[UA_TYPES_BOOLEAN]);
    p[3].key = UA_QUALIFIEDNAME(0, "request-status");
    UA_Variant_setScalar(&p[3].value, &requestStatus, &UA_TYPES[UA_TYPES_STATUSCODE]);
    map.mapSize = 4;
    sh->callback(cm, connectionId, sh->application, &sh->context,
                 UA_CONNECTIONSTATE_ESTABLISHED, &map, UA_BYTESTRING_NULL);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
socketClose(UA_ConnectionManager *cm, uintptr_t connectionId) {
    SocketHttp *sh = (SocketHttp *)cm;
    sh->callback(cm, connectionId, sh->application, &sh->context,
                 UA_CONNECTIONSTATE_CLOSING, &UA_KEYVALUEMAP_NULL, UA_BYTESTRING_NULL);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
socketStart(UA_EventSource *es) {
    es->state = UA_EVENTSOURCESTATE_STARTED;
    return UA_STATUSCODE_GOOD;
}

static void
socketStop(UA_EventSource *es) {
    es->state = UA_EVENTSOURCESTATE_STOPPED;
}

static UA_StatusCode
socketFree(UA_EventSource *es) {
    UA_free(es);
    return UA_STATUSCODE_GOOD;
}

static UA_ConnectionManager *
SocketHttp_new(void) {
    SocketHttp *sh = (SocketHttp *)UA_calloc(1, sizeof(SocketHttp));
    if(!sh)
        return NULL;
    sh->cm.eventSource.eventSourceType = UA_EVENTSOURCETYPE_CONNECTIONMANAGER;
    sh->cm.eventSource.name = UA_STRING("sockets");
    sh->cm.eventSource.start = socketStart;
    sh->cm.eventSource.stop = socketStop;
    sh->cm.eventSource.free = socketFree;
    sh->cm.protocol = UA_STRING("http");
    sh->cm.openConnection = socketOpen;
    sh->cm.sendWithConnection = socketSend;
    sh->cm.closeConnection = socketClose;
    return &sh->cm;
}

/***************/
/* Application */
/***************/

static UA_Boolean done;

static void
onResponse(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    (void)context;
    const UA_ByteString *body = (const UA_ByteString *)UA_KeyValueMap_getScalar(
        result, UA_QUALIFIEDNAME(0, "body"), &UA_TYPES[UA_TYPES_BYTESTRING]);
    printf("%s: %.*s\n", UA_StatusCode_name(status),
           body ? (int)body->length : 0, body ? (const char *)body->data : "");
    done = true;
}

int main(void) {
    UA_Server *server = UA_Server_newFromFile(UA_STRING(
        "{ drivers: [{ driver: 'http', name: 'web', url: 'http://localhost:8000',"
        "              'connection-manager': 'sockets' }] }"));
    if(!server)
        return EXIT_FAILURE;

    UA_ConnectionManager *cm = SocketHttp_new();
    UA_EventLoop *el = UA_Server_getConfig(server)->eventLoop;
    if(!cm || el->registerEventSource(el, &cm->eventSource) != UA_STATUSCODE_GOOD ||
       UA_Server_run_startup(server) != UA_STATUSCODE_GOOD) {
        UA_Server_delete(server);
        return EXIT_FAILURE;
    }

    if(UA_Server_callDriver(server, "web", "GET", NULL, onResponse, NULL) ==
       UA_STATUSCODE_GOOD) {
        while(!done)
            UA_Server_run_iterate(server, true);
    }

    UA_Server_run_shutdown(server);
    UA_Server_delete(server);
    return done ? EXIT_SUCCESS : EXIT_FAILURE;
}
