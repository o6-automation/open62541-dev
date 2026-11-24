/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

#include <open62541/driver/http.h>

#include "open62541_queue.h"
#include "../driver_params.h"

#ifdef UA_ENABLE_DRIVER_REST

typedef struct HttpRequest {
    LIST_ENTRY(HttpRequest) next;
    UA_UInt32 handle;
    UA_DriverCallCallback callback;
    void *context;
    UA_UInt16 status;
    UA_Variant headers;
    UA_ByteString body;
} HttpRequest;

typedef struct {
    UA_Driver drv;
    UA_ConnectionManager *cm;
    uintptr_t connectionId;

    UA_String host;
    UA_UInt16 port;
    UA_Boolean secure;
    UA_String basePath;

    UA_UInt32 lastHandle;
    LIST_HEAD(, HttpRequest) requests;
} HttpDriver;

static const UA_DriverParameter httpParameters[] = {
    {"url", UA_TYPES_STRING, false, true},
    {"headers", UA_TYPES_KEYVALUEPAIR, true, false},
    {"timeout", UA_TYPES_UINT16, false, false},
    {"connection-manager", UA_TYPES_STRING, false, false}
};

static UA_StatusCode
httpCreate(UA_Server *server, const UA_KeyValueMap params, UA_Driver **outDriver) {
    (void)server;
    return UA_HttpDriver_new(params, outDriver);
}

const UA_DriverRegistration UA_HttpDriver_registration = {
    "http", httpParameters,
    sizeof(httpParameters) / sizeof(httpParameters[0]),
    httpCreate
};

static const void *
getParam(const UA_KeyValueMap *params, const char *name, UA_UInt16 typeIndex) {
    return UA_KeyValueMap_getScalar(params, UA_QUALIFIEDNAME(0, (char *)(uintptr_t)name),
                                    &UA_TYPES[typeIndex]);
}

static const UA_Variant *
getHeaders(const UA_KeyValueMap *params) {
    const UA_Variant *v = UA_KeyValueMap_get(params, UA_QUALIFIEDNAME(0, "headers"));
    return (v && UA_Variant_hasArrayType(v, &UA_TYPES[UA_TYPES_KEYVALUEPAIR])) ? v : NULL;
}

/************/
/* Requests */
/************/

static void
finishRequest(HttpRequest *req, UA_StatusCode status) {
    /* Unlinked before the callback, which may send the next request */
    LIST_REMOVE(req, next);
    UA_KeyValuePair result[3];
    memset(result, 0, sizeof(result));
    result[0].key = UA_QUALIFIEDNAME(0, "status");
    UA_Variant_setScalar(&result[0].value, &req->status, &UA_TYPES[UA_TYPES_UINT16]);
    result[1].key = UA_QUALIFIEDNAME(0, "headers");
    result[1].value = req->headers;
    result[2].key = UA_QUALIFIEDNAME(0, "body");
    UA_Variant_setScalar(&result[2].value, &req->body, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_KeyValueMap map = {3, result};
    req->callback(req->context, status, &map);
    UA_Variant_clear(&req->headers);
    UA_ByteString_clear(&req->body);
    UA_free(req);
}

static void
failAllRequests(HttpDriver *hd, UA_StatusCode status) {
    HttpRequest *req, *tmp;
    LIST_FOREACH_SAFE(req, &hd->requests, next, tmp) {
        finishRequest(req, status);
    }
}

static HttpRequest *
findRequest(HttpDriver *hd, const UA_KeyValueMap *params) {
    const UA_UInt32 *handle = (const UA_UInt32 *)
        getParam(params, "handle", UA_TYPES_UINT32);
    if(!handle)
        return NULL;
    HttpRequest *req;
    LIST_FOREACH(req, &hd->requests, next) {
        if(req->handle == *handle)
            return req;
    }
    return NULL;
}

static void
processResponse(HttpDriver *hd, const UA_KeyValueMap *params, UA_ByteString msg) {
    HttpRequest *req = findRequest(hd, params);
    if(!req)
        return;
    const UA_UInt16 *status = (const UA_UInt16 *)
        getParam(params, "status-code", UA_TYPES_UINT16);
    if(status)
        req->status = *status;
    const UA_Variant *headers = getHeaders(params);
    if(headers && UA_Variant_isEmpty(&req->headers))
        UA_Variant_copy(headers, &req->headers);
    if(msg.length > 0 && UA_String_append(&req->body, msg) != UA_STATUSCODE_GOOD) {
        finishRequest(req, UA_STATUSCODE_BADOUTOFMEMORY);
        return;
    }
    const UA_Boolean *complete = (const UA_Boolean *)
        getParam(params, "response-complete", UA_TYPES_BOOLEAN);
    if(!complete || !*complete)
        return;
    const UA_StatusCode *requestStatus = (const UA_StatusCode *)
        getParam(params, "request-status", UA_TYPES_STATUSCODE);
    finishRequest(req, requestStatus ? *requestStatus : UA_STATUSCODE_GOOD);
}

static void
finishStopIfDrained(HttpDriver *hd) {
    if(hd->drv.state == UA_LIFECYCLESTATE_STOPPING && hd->connectionId == 0)
        hd->drv.state = UA_LIFECYCLESTATE_STOPPED;
}

static void
httpNetworkCallback(UA_ConnectionManager *cm, uintptr_t connectionId,
                    void *application, void **connectionContext,
                    UA_ConnectionState state, const UA_KeyValueMap *params,
                    UA_ByteString msg) {
    (void)cm;
    (void)connectionContext;
    HttpDriver *hd = (HttpDriver *)application;
    if(state == UA_CONNECTIONSTATE_CLOSING) {
        if(connectionId == hd->connectionId) {
            hd->connectionId = 0;
            failAllRequests(hd, UA_STATUSCODE_BADCONNECTIONCLOSED);
        }
        finishStopIfDrained(hd);
        return;
    }
    if(hd->connectionId == 0)
        hd->connectionId = connectionId;
    if(state == UA_CONNECTIONSTATE_ESTABLISHED)
        processResponse(hd, params, msg);
}

static UA_StatusCode
openEndpointConnection(HttpDriver *hd) {
    UA_KeyValuePair p[4];
    memset(p, 0, sizeof(p));
    size_t n = 0;
    p[n].key = UA_QUALIFIEDNAME(0, "address");
    UA_Variant_setScalar(&p[n++].value, &hd->host, &UA_TYPES[UA_TYPES_STRING]);
    p[n].key = UA_QUALIFIEDNAME(0, "port");
    UA_Variant_setScalar(&p[n++].value, &hd->port, &UA_TYPES[UA_TYPES_UINT16]);
    p[n].key = UA_QUALIFIEDNAME(0, "tls");
    UA_Variant_setScalar(&p[n++].value, &hd->secure, &UA_TYPES[UA_TYPES_BOOLEAN]);
    const UA_UInt16 *timeout = (const UA_UInt16 *)
        getParam(&hd->drv.params, "timeout", UA_TYPES_UINT16);
    if(timeout) {
        p[n].key = UA_QUALIFIEDNAME(0, "timeout");
        UA_Variant_setScalar(&p[n++].value, (void *)(uintptr_t)timeout,
                             &UA_TYPES[UA_TYPES_UINT16]);
    }
    UA_KeyValueMap map = {n, p};
    UA_StatusCode res =
        hd->cm->openConnection(hd->cm, &map, hd, NULL, httpNetworkCallback);
    if(res == UA_STATUSCODE_GOOD && hd->connectionId == 0)
        res = UA_STATUSCODE_BADCONNECTIONREJECTED;
    return res;
}

static UA_StatusCode
mergeHeaders(const UA_Variant *defaults, const UA_Variant *extra, UA_Variant *out) {
    size_t d = defaults ? defaults->arrayLength : 0;
    size_t e = extra ? extra->arrayLength : 0;
    UA_KeyValuePair *headers = (UA_KeyValuePair *)
        UA_Array_new(d + e, &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
    if(!headers)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < d; i++)
        res |= UA_KeyValuePair_copy(&((UA_KeyValuePair *)defaults->data)[i], &headers[i]);
    for(size_t i = 0; i < e; i++)
        res |= UA_KeyValuePair_copy(&((UA_KeyValuePair *)extra->data)[i],
                                    &headers[d + i]);
    UA_Variant_setArray(out, headers, d + e, &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
    return res;
}

static UA_StatusCode
httpCall(UA_Driver *drv, const UA_String call, const UA_KeyValueMap *input,
         UA_DriverCallCallback callback, void *context) {
    HttpDriver *hd = (HttpDriver *)drv;
    if(call.length == 0)
        return UA_STATUSCODE_BADNOTFOUND;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(hd->connectionId == 0)
        res = openEndpointConnection(hd);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    HttpRequest *req = (HttpRequest *)UA_calloc(1, sizeof(HttpRequest));
    if(!req)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    req->handle = ++hd->lastHandle;
    req->callback = callback;
    req->context = context;

    const UA_String *path = (const UA_String *)getParam(input, "path", UA_TYPES_STRING);
    UA_String subPath = path ? *path : UA_STRING_NULL;
    if(subPath.length > 0 && subPath.data[0] == '/') {
        subPath.data++;
        subPath.length--;
    }
    UA_String fullPath = UA_STRING_NULL;
    if(hd->basePath.length > 0 && subPath.length > 0)
        res = UA_String_format(&fullPath, "/%S/%S", hd->basePath, subPath);
    else
        res = UA_String_format(&fullPath, "/%S%S", hd->basePath, subPath);
    UA_Variant headers;
    UA_Variant_init(&headers);
    res |= mergeHeaders(getHeaders(&drv->params), getHeaders(input), &headers);

    const UA_ByteString *bodyText = driverParamsText(input, "body");
    UA_ByteString body = UA_BYTESTRING_NULL;
    if(bodyText)
        res |= UA_ByteString_copy(bodyText, &body);

    UA_KeyValuePair p[4];
    memset(p, 0, sizeof(p));
    p[0].key = UA_QUALIFIEDNAME(0, "method");
    UA_Variant_setScalar(&p[0].value, (void *)(uintptr_t)&call,
                         &UA_TYPES[UA_TYPES_STRING]);
    p[1].key = UA_QUALIFIEDNAME(0, "path");
    UA_Variant_setScalar(&p[1].value, &fullPath, &UA_TYPES[UA_TYPES_STRING]);
    p[2].key = UA_QUALIFIEDNAME(0, "headers");
    p[2].value = headers;
    p[3].key = UA_QUALIFIEDNAME(0, "handle");
    UA_Variant_setScalar(&p[3].value, &req->handle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_KeyValueMap map = {4, p};

    if(res == UA_STATUSCODE_GOOD) {
        LIST_INSERT_HEAD(&hd->requests, req, next);
        res = hd->cm->sendWithConnection(hd->cm, hd->connectionId, &map, &body);
        if(res != UA_STATUSCODE_GOOD)
            LIST_REMOVE(req, next);
    } else {
        UA_ByteString_clear(&body);
    }
    UA_String_clear(&fullPath);
    UA_Variant_clear(&headers);
    if(res != UA_STATUSCODE_GOOD)
        UA_free(req);
    return res;
}

/*************/
/* Lifecycle */
/*************/

/* host[:port][/path] after the scheme, like UA_parseEndpointUrl. The outputs
 * point into the url. */
static UA_StatusCode
parseHttpUrl(const UA_String *url, size_t start, UA_String *host,
             UA_UInt16 *port, UA_String *path) {
    size_t curr = start;
    UA_Boolean ipv6 = (curr < url->length && url->data[curr] == '[');
    while(curr < url->length &&
          (ipv6 ? url->data[curr] != ']' :
           (url->data[curr] != ':' && url->data[curr] != '/')))
        curr++;
    if(ipv6) {
        if(curr == url->length)
            return UA_STATUSCODE_BADTCPENDPOINTURLINVALID;
        curr++;
        host->data = &url->data[start + 1]; /* Without the brackets */
        host->length = curr - start - 2;
    } else {
        host->data = &url->data[start];
        host->length = curr - start;
    }
    if(host->length == 0)
        return UA_STATUSCODE_BADTCPENDPOINTURLINVALID;

    if(curr < url->length && url->data[curr] == ':') {
        UA_UInt32 number = 0;
        size_t progress = UA_readNumber(&url->data[curr + 1],
                                        url->length - curr - 1, &number);
        if(progress == 0 || number > 65535)
            return UA_STATUSCODE_BADTCPENDPOINTURLINVALID;
        *port = (UA_UInt16)number;
        curr += 1 + progress;
    }
    if(curr == url->length)
        return UA_STATUSCODE_GOOD;
    if(url->data[curr] != '/')
        return UA_STATUSCODE_BADTCPENDPOINTURLINVALID;
    curr++;
    path->data = &url->data[curr];
    path->length = url->length - curr;
    if(path->length > 0 && path->data[path->length - 1] == '/')
        path->length--; /* Without a trailing slash */
    if(path->length == 0)
        path->data = NULL;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
httpStart(UA_Driver *drv) {
    HttpDriver *hd = (HttpDriver *)drv;
    if(drv->state != UA_LIFECYCLESTATE_STOPPED)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_ServerConfig *config = UA_Server_getConfig(drv->server);

    static const UA_String schemes[2] = {
        UA_STRING_STATIC("http://"), UA_STRING_STATIC("https://")};
    const UA_String *url = (const UA_String *)
        getParam(&drv->params, "url", UA_TYPES_STRING);
    UA_StatusCode res = UA_STATUSCODE_BADCONFIGURATIONERROR;
    for(size_t i = 0; url && i < 2; i++) {
        if(url->length < schemes[i].length ||
           memcmp(url->data, schemes[i].data, schemes[i].length) != 0)
            continue;
        hd->secure = (i == 1);
        hd->port = hd->secure ? 443 : 80;
        hd->host = UA_STRING_NULL;
        hd->basePath = UA_STRING_NULL;
        res = parseHttpUrl(url, schemes[i].length, &hd->host, &hd->port,
                           &hd->basePath);
        break;
    }
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(config->logging, UA_LOGCATEGORY_SERVER,
                     "HTTP driver \"%S\": The url must be http(s)://host[:port][/path]",
                     drv->name);
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }

    const UA_String *cmName = (const UA_String *)
        getParam(&drv->params, "connection-manager", UA_TYPES_STRING);
    static const UA_String http = UA_STRING_STATIC("http");
    hd->cm = NULL;
    for(UA_EventSource *es = config->eventLoop->eventSources; es; es = es->next) {
        if(es->eventSourceType != UA_EVENTSOURCETYPE_CONNECTIONMANAGER)
            continue;
        UA_ConnectionManager *cm = (UA_ConnectionManager *)es;
        if(UA_String_equal(&cm->protocol, &http) &&
           (!cmName || UA_String_equal(&es->name, cmName))) {
            hd->cm = cm;
            break;
        }
    }
    if(!hd->cm) {
        UA_LOG_ERROR(config->logging, UA_LOGCATEGORY_SERVER,
                     "HTTP driver \"%S\": No HTTP ConnectionManager is registered "
                     "(see UA_ConnectionManager_new_HTTP)", drv->name);
        return UA_STATUSCODE_BADNOTFOUND;
    }
    drv->state = UA_LIFECYCLESTATE_STARTED;
    return UA_STATUSCODE_GOOD;
}

static void
httpStop(UA_Driver *drv) {
    HttpDriver *hd = (HttpDriver *)drv;
    if(drv->state != UA_LIFECYCLESTATE_STARTED)
        return;
    drv->state = UA_LIFECYCLESTATE_STOPPING;
    if(hd->connectionId)
        hd->cm->closeConnection(hd->cm, hd->connectionId);
    finishStopIfDrained(hd);
}

static UA_StatusCode
httpFree(UA_Driver *drv) {
    if(drv->state != UA_LIFECYCLESTATE_STOPPED)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_KeyValueMap_clear(&drv->params);
    UA_free(drv);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_HttpDriver_new(const UA_KeyValueMap params, UA_Driver **outDriver) {
    HttpDriver *hd = (HttpDriver *)UA_calloc(1, sizeof(HttpDriver));
    if(!hd)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode res = UA_KeyValueMap_copy(&params, &hd->drv.params);
    if(res != UA_STATUSCODE_GOOD) {
        UA_free(hd);
        return res;
    }
    LIST_INIT(&hd->requests);
    hd->drv.name = UA_STRING("http");
    hd->drv.start = httpStart;
    hd->drv.stop = httpStop;
    hd->drv.free = httpFree;
    hd->drv.call = httpCall;
    *outDriver = &hd->drv;
    return UA_STATUSCODE_GOOD;
}

#endif /* UA_ENABLE_DRIVER_REST */
