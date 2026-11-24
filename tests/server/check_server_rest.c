/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

#include <open62541/server.h>

#include <open62541/driver/rest.h>

#include "test_helpers.h"
#include "testing_clock.h"
#include "testing_networklayers.h"

#include <check.h>
#include <stdlib.h>
#include <string.h>

/* The HTTP and REST drivers run on a mock HTTP ConnectionManager that answers
 * like the REST API of a machine. This is also how a third-party HTTP
 * implementation is used. */

static UA_Server *server;
static UA_ConnectionManager *mock;
static UA_Boolean mockResponds;

/* The last request */
static UA_String lastMethod, lastPath, lastAuthorization, lastAccept;
static UA_ByteString lastBody;
static UA_UInt16 openedPort;

/* The result of the last call */
static size_t results;
static UA_StatusCode resultStatus;
static UA_UInt16 resultHttpStatus;
static UA_String resultCall;
static UA_ByteString resultBody;

static UA_Boolean
contains(const UA_ByteString *s, const char *text) {
    size_t len = strlen(text);
    for(size_t i = 0; i + len <= s->length; i++) {
        if(memcmp(&s->data[i], text, len) == 0)
            return true;
    }
    return false;
}

static UA_Boolean
equals(const UA_String *s, const char *text) {
    UA_String t = UA_STRING((char *)(uintptr_t)text);
    return UA_String_equal(s, &t);
}

static void
copyHeader(const UA_KeyValueMap *params, const char *name, UA_String *out) {
    UA_String_clear(out);
    const UA_Variant *v = UA_KeyValueMap_get(params, UA_QUALIFIEDNAME(0, "headers"));
    if(!v || !UA_Variant_hasArrayType(v, &UA_TYPES[UA_TYPES_KEYVALUEPAIR]))
        return;
    UA_KeyValueMap headers = {v->arrayLength, (UA_KeyValuePair *)v->data};
    const UA_String *value = (const UA_String *)UA_KeyValueMap_getScalar(
        &headers, UA_QUALIFIEDNAME(0, (char *)(uintptr_t)name), &UA_TYPES[UA_TYPES_STRING]);
    if(value)
        UA_String_copy(value, out);
}

/* The REST API of the machine */
static UA_UInt16
answer(UA_ByteString *body) {
    const char *text = NULL;
    UA_UInt16 status = 404;
    if(equals(&lastMethod, "POST") && equals(&lastPath, "/api/login")) {
        status = contains(&lastBody, "\"user\":\"opc\"") ? 200 : 401;
        text = (status == 200) ? "{\"token\":\"abc123\"}" : "{\"error\":\"denied\"}";
    } else if(equals(&lastMethod, "GET") && equals(&lastPath, "/api/jobs/42")) {
        status = equals(&lastAuthorization, "Bearer abc123") ? 200 : 401;
        if(status == 200)
            text = "{\"id\":42,\"name\":\"Milling\",\"items\":[{\"id\":7},{\"id\":8}]}";
    } else if(equals(&lastMethod, "GET") && equals(&lastPath, "/api/items/8")) {
        status = 200;
        text = "{\"name\":\"Bolt\"}";
    } else if(equals(&lastMethod, "PUT") && equals(&lastPath, "/api/jobs/42")) {
        status = 204;
    } else if(equals(&lastMethod, "GET") && equals(&lastPath, "/api/weather")) {
        /* Trimmed from the DWD API (stationOverviewExtended) */
        status = 200;
        text = "{\"10865\":{\"forecast1\":{\"stationId\":\"10865\","
            "\"start\":1763510400000,\"temperature\":[84,81,79],\"windSpeed\":null,"
            "\"mixed\":[1,2.5]},\"forecast2\":{\"temperature\":[]},"
            "\"forecastStart\":null,\"days\":["
            "{\"dayDate\":\"2026-11-19\",\"temperatureMin\":73,\"temperatureMax\":91},"
            "{\"dayDate\":\"2026-11-20\",\"temperatureMin\":40,\"temperatureMax\":65}],"
            "\"warnings\":[]}}";
    } else if(equals(&lastMethod, "GET") && equals(&lastPath, "/api/text")) {
        status = 200;
        text = "<html>not json</html>";
    }
    *body = text ? UA_BYTESTRING_ALLOC(text) : UA_BYTESTRING_NULL;
    return status;
}

static UA_StatusCode
mockOpen(UA_ConnectionManager *cm, const UA_KeyValueMap *params,
         void *application, void *context,
         UA_ConnectionManager_connectionCallback callback) {
    const UA_UInt16 *port = (const UA_UInt16 *)UA_KeyValueMap_getScalar(
        params, UA_QUALIFIEDNAME(0, "port"), &UA_TYPES[UA_TYPES_UINT16]);
    openedPort = port ? *port : 0;
    uintptr_t id = 0;
    UA_StatusCode res = TestConnectionManager_createConnection(
        cm, application, context, callback, &id);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    /* Like libwebsockets, the connection id is reported during the open */
    return TestConnectionManager_inject(cm, id, UA_CONNECTIONSTATE_OPENING, NULL, NULL);
}

static UA_StatusCode
mockSend(UA_ConnectionManager *cm, uintptr_t connectionId,
         const UA_KeyValueMap *params, UA_ByteString *buf) {
    UA_String_clear(&lastMethod);
    UA_String_clear(&lastPath);
    UA_String_copy((const UA_String *)UA_KeyValueMap_getScalar(
        params, UA_QUALIFIEDNAME(0, "method"), &UA_TYPES[UA_TYPES_STRING]), &lastMethod);
    UA_String_copy((const UA_String *)UA_KeyValueMap_getScalar(
        params, UA_QUALIFIEDNAME(0, "path"), &UA_TYPES[UA_TYPES_STRING]), &lastPath);
    copyHeader(params, "authorization", &lastAuthorization);
    copyHeader(params, "accept", &lastAccept);
    UA_ByteString_clear(&lastBody);
    if(buf) {
        lastBody = *buf;
        UA_ByteString_init(buf);
    }
    if(!mockResponds)
        return UA_STATUSCODE_GOOD;

    /* The response: status and body, then completion */
    UA_UInt32 handle = *(const UA_UInt32 *)UA_KeyValueMap_getScalar(
        params, UA_QUALIFIEDNAME(0, "handle"), &UA_TYPES[UA_TYPES_UINT32]);
    UA_ByteString body;
    UA_UInt16 status = answer(&body);
    UA_Boolean complete = true;
    UA_StatusCode requestStatus = UA_STATUSCODE_GOOD;
    UA_KeyValuePair p[4];
    memset(p, 0, sizeof(p));
    p[0].key = UA_QUALIFIEDNAME(0, "status-code");
    UA_Variant_setScalar(&p[0].value, &status, &UA_TYPES[UA_TYPES_UINT16]);
    p[1].key = UA_QUALIFIEDNAME(0, "handle");
    UA_Variant_setScalar(&p[1].value, &handle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_KeyValueMap map = {2, p};
    TestConnectionManager_inject(cm, connectionId, UA_CONNECTIONSTATE_ESTABLISHED,
                                 &map, &body);
    p[2].key = UA_QUALIFIEDNAME(0, "response-complete");
    UA_Variant_setScalar(&p[2].value, &complete, &UA_TYPES[UA_TYPES_BOOLEAN]);
    p[3].key = UA_QUALIFIEDNAME(0, "request-status");
    UA_Variant_setScalar(&p[3].value, &requestStatus, &UA_TYPES[UA_TYPES_STATUSCODE]);
    map.mapSize = 4;
    TestConnectionManager_inject(cm, connectionId, UA_CONNECTIONSTATE_ESTABLISHED,
                                 &map, NULL);
    UA_ByteString_clear(&body);
    return UA_STATUSCODE_GOOD;
}

static void
onResult(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    (void)context;
    results++;
    resultStatus = status;
    const UA_UInt16 *s = (const UA_UInt16 *)UA_KeyValueMap_getScalar(
        result, UA_QUALIFIEDNAME(0, "status"), &UA_TYPES[UA_TYPES_UINT16]);
    resultHttpStatus = s ? *s : 0;
    UA_String_clear(&resultCall);
    const UA_String *call = (const UA_String *)UA_KeyValueMap_getScalar(
        result, UA_QUALIFIEDNAME(0, "call"), &UA_TYPES[UA_TYPES_STRING]);
    if(call)
        UA_String_copy(call, &resultCall);
    UA_ByteString_clear(&resultBody);
    const UA_ByteString *body = (const UA_ByteString *)UA_KeyValueMap_getScalar(
        result, UA_QUALIFIEDNAME(0, "body"), &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(body)
        UA_ByteString_copy(body, &resultBody);
}

static const char *config =
    "{tcpEnabled:false,drivers:["
    "{driver:'http',name:'machine',url:'http://localhost:8000/api',"
    " headers:{accept:'application/json'}},"
    "{driver:'rest',name:'machine-api',defaults:{user:'opc'},calls:{"
    " login:{endpoint:'machine',method:'POST',path:'/login',"
    "        headers:{'content-type':'application/json'},"
    "        body:'{\"user\":\"${input.user}\"}'},"
    " getJob:{endpoint:'machine',method:'GET',path:'/jobs/${input.job}',"
    "         headers:{authorization:'Bearer ${login.body.token}'},after:'login'},"
    " secondItem:{endpoint:'machine',method:'GET',path:'/items/${getJob.body.items[1].id}',"
    "             after:'getJob'},"
    " setJob:{endpoint:'machine',method:'PUT',path:'/jobs/42',body:'${input.data}'},"
    " broken:{endpoint:'machine',method:'GET',path:'/${input.missing}'},"
    /* A device that is not HTTP: any keys are passed to the endpoint driver */
    " readRegister:{endpoint:'plc',method:'read',address:'${input.address}',"
    "               options:{unit:'${input.unit}',retries:3},list:['a','${input.unit}']},"
    " useRegister:{endpoint:'plc',method:'write',after:'readRegister',"
    "              value:'${readRegister.options.unit}-${readRegister.address}-"
    "${readRegister.list.1}-${readRegister.options.retries}-${readRegister.method}'}}},"
    "{driver:'device',name:'plc'},"
    /* The endpoint nested in the REST driver: no endpoint key needed */
    "{driver:'rest',name:'nested-api',calls:{"
    " job:{method:'GET',path:'/jobs/42',headers:{authorization:'Bearer abc123'}}},"
    " drivers:[{driver:'http',url:'http://localhost:8000/api'}]}]}";

/* A driver for a device that is not HTTP. It answers with its input and the
 * name of the call. */
static UA_StatusCode
deviceCall(UA_Driver *drv, const UA_String call, const UA_KeyValueMap *input,
           UA_DriverCallCallback callback, void *context) {
    (void)drv;
    UA_KeyValueMap result = UA_KEYVALUEMAP_NULL;
    UA_StatusCode res = UA_KeyValueMap_copy(input, &result);
    res |= UA_KeyValueMap_setScalar(&result, UA_QUALIFIEDNAME(0, "method"),
                                    (void *)(uintptr_t)&call, &UA_TYPES[UA_TYPES_STRING]);
    if(res == UA_STATUSCODE_GOOD)
        callback(context, UA_STATUSCODE_GOOD, &result);
    UA_KeyValueMap_clear(&result);
    return res;
}

static UA_StatusCode
deviceStart(UA_Driver *drv) {
    drv->state = UA_LIFECYCLESTATE_STARTED;
    return UA_STATUSCODE_GOOD;
}

static void
deviceStop(UA_Driver *drv) {
    drv->state = UA_LIFECYCLESTATE_STOPPED;
}

static UA_StatusCode
deviceFree(UA_Driver *drv) {
    UA_free(drv);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
deviceCreate(UA_Server *s, const UA_KeyValueMap params, UA_Driver **outDriver) {
    (void)s;
    (void)params;
    UA_Driver *drv = (UA_Driver *)UA_calloc(1, sizeof(UA_Driver));
    if(!drv)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    drv->start = deviceStart;
    drv->stop = deviceStop;
    drv->free = deviceFree;
    drv->call = deviceCall;
    *outDriver = drv;
    return UA_STATUSCODE_GOOD;
}

static const UA_DriverRegistration deviceRegistration = {
    "device", NULL, 0, deviceCreate
};

static void
startServer(const char *json) {
    server = UA_Server_newFromFile(UA_STRING((char *)(uintptr_t)json));
    ck_assert_ptr_nonnull(server);
    UA_ServerConfig *sc = UA_Server_getConfig(server);
    sc->eventLoop->dateTime_now = UA_DateTime_now_fake;
    sc->eventLoop->dateTime_nowMonotonic = UA_DateTime_now_fake;
    UA_ServerConfig_registerDriver(sc, &deviceRegistration);
    TestConnectionManager_CallbackOverloads overloads;
    memset(&overloads, 0, sizeof(overloads));
    overloads.openConnection = mockOpen;
    overloads.sendWithConnection = mockSend;
    mock = TestConnectionManager_new("http", &overloads);
    ck_assert_ptr_nonnull(mock);
    UA_EventLoop *el = UA_Server_getConfig(server)->eventLoop;
    ck_assert_uint_eq(el->registerEventSource(el, &mock->eventSource), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
}

static void setup(void) {
    results = 0;
    mockResponds = true;
    startServer(config);
}

static void teardown(void) {
    ck_assert_uint_eq(UA_Server_run_shutdown(server), UA_STATUSCODE_GOOD);
    for(UA_Driver *drv = UA_Server_getDrivers(server); drv; drv = drv->next)
        ck_assert_int_eq(drv->state, UA_LIFECYCLESTATE_STOPPED);
    UA_Server_delete(server);
    UA_String_clear(&lastMethod);
    UA_String_clear(&lastPath);
    UA_String_clear(&lastAuthorization);
    UA_String_clear(&lastAccept);
    UA_ByteString_clear(&lastBody);
    UA_String_clear(&resultCall);
    UA_ByteString_clear(&resultBody);
}

START_TEST(HttpRequest) {
    UA_KeyValueMap input = UA_KEYVALUEMAP_NULL;
    UA_String path = UA_STRING("/login");
    UA_String body = UA_STRING("{\"user\":\"opc\"}");
    UA_KeyValueMap_setScalar(&input, UA_QUALIFIEDNAME(0, "path"), &path,
                             &UA_TYPES[UA_TYPES_STRING]);
    UA_KeyValueMap_setScalar(&input, UA_QUALIFIEDNAME(0, "body"), &body,
                             &UA_TYPES[UA_TYPES_STRING]);
    ck_assert_uint_eq(UA_Server_callDriver(server, "machine", "POST", &input,
                                           onResult, NULL), UA_STATUSCODE_GOOD);
    UA_KeyValueMap_clear(&input);
    ck_assert_uint_eq(openedPort, 8000);
    ck_assert(equals(&lastPath, "/api/login"));
    ck_assert(equals(&lastAccept, "application/json")); /* Default header */
    ck_assert_uint_eq(results, 1);
    ck_assert_uint_eq(resultStatus, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(resultHttpStatus, 200);
    ck_assert(contains(&resultBody, "abc123"));
} END_TEST

static UA_Driver *
driverByName(UA_Server *s, const char *name) {
    UA_String n = UA_STRING((char *)(uintptr_t)name);
    for(UA_Driver *drv = UA_Server_getDrivers(s); drv; drv = drv->next) {
        if(UA_String_equal(&drv->name, &n))
            return drv;
    }
    return NULL;
}

START_TEST(NestedEndpoint) {
    ck_assert_uint_eq(UA_Server_callDriver(server, "nested-api", "job", NULL,
                                           onResult, NULL), UA_STATUSCODE_GOOD);
    ck_assert(equals(&lastPath, "/api/jobs/42"));
    ck_assert_uint_eq(results, 1);
    ck_assert_uint_eq(resultHttpStatus, 200);
    ck_assert(contains(&resultBody, "Milling"));
    /* The nested http driver has the composed name */
    ck_assert_ptr_nonnull(driverByName(server, "nested-api/http"));
} END_TEST

START_TEST(ChainWithPlaceholders) {
    UA_KeyValueMap input = UA_KEYVALUEMAP_NULL;
    UA_String user = UA_STRING("opc");
    UA_Int64 job = 42;
    UA_KeyValueMap_setScalar(&input, UA_QUALIFIEDNAME(0, "user"), &user,
                             &UA_TYPES[UA_TYPES_STRING]);
    UA_KeyValueMap_setScalar(&input, UA_QUALIFIEDNAME(0, "job"), &job,
                             &UA_TYPES[UA_TYPES_INT64]);

    /* login -> getJob with the token */
    ck_assert_uint_eq(UA_Server_callDriver(server, "machine-api", "getJob", &input,
                                           onResult, NULL), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(results, 1);
    ck_assert_uint_eq(resultHttpStatus, 200);
    ck_assert(equals(&resultCall, "getJob"));
    ck_assert(equals(&lastAuthorization, "Bearer abc123"));
    ck_assert(contains(&resultBody, "Milling"));

    /* login -> getJob -> secondItem with a value from an array */
    ck_assert_uint_eq(UA_Server_callDriver(server, "machine-api", "secondItem", &input,
                                           onResult, NULL), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(results, 2);
    ck_assert(equals(&lastPath, "/api/items/8"));
    ck_assert(contains(&resultBody, "Bolt"));
    UA_KeyValueMap_clear(&input);
} END_TEST

START_TEST(DefaultsFromConfig) {
    /* The user comes from the defaults, only the job is given */
    UA_KeyValueMap input = UA_KEYVALUEMAP_NULL;
    UA_Int64 job = 42;
    UA_KeyValueMap_setScalar(&input, UA_QUALIFIEDNAME(0, "job"), &job,
                             &UA_TYPES[UA_TYPES_INT64]);
    ck_assert_uint_eq(UA_Server_callDriver(server, "machine-api", "getJob", &input,
                                           onResult, NULL), UA_STATUSCODE_GOOD);
    UA_KeyValueMap_clear(&input);
    ck_assert_uint_eq(resultHttpStatus, 200);
    ck_assert(contains(&resultBody, "Milling"));
} END_TEST

START_TEST(ChainStopsAtHttpError) {
    UA_KeyValueMap input = UA_KEYVALUEMAP_NULL;
    UA_String user = UA_STRING("guest");
    UA_KeyValueMap_setScalar(&input, UA_QUALIFIEDNAME(0, "user"), &user,
                             &UA_TYPES[UA_TYPES_STRING]);
    ck_assert_uint_eq(UA_Server_callDriver(server, "machine-api", "getJob", &input,
                                           onResult, NULL), UA_STATUSCODE_GOOD);
    UA_KeyValueMap_clear(&input);
    ck_assert_uint_eq(results, 1);
    ck_assert_uint_eq(resultStatus, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(resultHttpStatus, 401);
    ck_assert(equals(&resultCall, "login"));
    ck_assert(equals(&lastPath, "/api/login")); /* getJob was not sent */
} END_TEST

START_TEST(WriteWithBody) {
    UA_KeyValueMap input = UA_KEYVALUEMAP_NULL;
    UA_String data = UA_STRING("{\"speed\":1200}");
    UA_KeyValueMap_setScalar(&input, UA_QUALIFIEDNAME(0, "data"), &data,
                             &UA_TYPES[UA_TYPES_STRING]);
    ck_assert_uint_eq(UA_Server_callDriver(server, "machine-api", "setJob", &input,
                                           onResult, NULL), UA_STATUSCODE_GOOD);
    UA_KeyValueMap_clear(&input);
    ck_assert_uint_eq(resultHttpStatus, 204);
    ck_assert(equals(&lastMethod, "PUT"));
    ck_assert(contains(&lastBody, "\"speed\":1200"));
} END_TEST

/* Fire and forget: the request is sent, the result is dropped */
START_TEST(CallWithoutCallback) {
    UA_KeyValueMap input = UA_KEYVALUEMAP_NULL;
    UA_String data = UA_STRING("{\"speed\":1200}");
    UA_KeyValueMap_setScalar(&input, UA_QUALIFIEDNAME(0, "data"), &data,
                             &UA_TYPES[UA_TYPES_STRING]);
    ck_assert_uint_eq(UA_Server_callDriver(server, "machine-api", "setJob", &input,
                                           NULL, NULL), UA_STATUSCODE_GOOD);
    UA_KeyValueMap_clear(&input);
    ck_assert(equals(&lastMethod, "PUT"));
    ck_assert_uint_eq(results, 0);
} END_TEST

static UA_String deviceValue, deviceMethod;

static void
onDeviceResult(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    (void)context;
    ck_assert_uint_eq(status, UA_STATUSCODE_GOOD);
    results++;
    UA_String_copy((const UA_String *)UA_KeyValueMap_getScalar(
        result, UA_QUALIFIEDNAME(0, "value"), &UA_TYPES[UA_TYPES_STRING]), &deviceValue);
    UA_String_copy((const UA_String *)UA_KeyValueMap_getScalar(
        result, UA_QUALIFIEDNAME(0, "method"), &UA_TYPES[UA_TYPES_STRING]), &deviceMethod);
}

START_TEST(OtherProtocol) {
    UA_KeyValueMap input = UA_KEYVALUEMAP_NULL;
    UA_String address = UA_STRING("40001");
    UA_String unit = UA_STRING("bar");
    UA_KeyValueMap_setScalar(&input, UA_QUALIFIEDNAME(0, "address"), &address,
                             &UA_TYPES[UA_TYPES_STRING]);
    UA_KeyValueMap_setScalar(&input, UA_QUALIFIEDNAME(0, "unit"), &unit,
                             &UA_TYPES[UA_TYPES_STRING]);
    ck_assert_uint_eq(UA_Server_callDriver(server, "machine-api", "useRegister", &input,
                                           onDeviceResult, NULL), UA_STATUSCODE_GOOD);
    UA_KeyValueMap_clear(&input);
    ck_assert_uint_eq(results, 1);
    /* Values from an object, from an array, a number and the call name of
     * the first result */
    ck_assert(equals(&deviceValue, "bar-40001-bar-3-read"));
    ck_assert(equals(&deviceMethod, "write"));
    UA_String_clear(&deviceValue);
    UA_String_clear(&deviceMethod);
} END_TEST

START_TEST(InvalidCalls) {
    /* A missing input value fails before anything is sent */
    ck_assert_uint_eq(UA_Server_callDriver(server, "machine-api", "broken", NULL,
                                           onResult, NULL), UA_STATUSCODE_BADNOTFOUND);
    ck_assert_uint_eq(UA_Server_callDriver(server, "machine-api", "unknown", NULL,
                                           onResult, NULL), UA_STATUSCODE_BADNOTFOUND);
    ck_assert_uint_eq(results, 0);
    ck_assert_uint_eq(lastMethod.length, 0);
} END_TEST

START_TEST(ShutdownCompletesOpenCalls) {
    mockResponds = false;
    UA_KeyValueMap input = UA_KEYVALUEMAP_NULL;
    UA_String data = UA_STRING("{}");
    UA_KeyValueMap_setScalar(&input, UA_QUALIFIEDNAME(0, "data"), &data,
                             &UA_TYPES[UA_TYPES_STRING]);
    ck_assert_uint_eq(UA_Server_callDriver(server, "machine-api", "setJob", &input,
                                           onResult, NULL), UA_STATUSCODE_GOOD);
    UA_KeyValueMap_clear(&input);
    ck_assert_uint_eq(results, 0);

    /* The HTTP driver closes the connection and completes the open request */
    ck_assert_uint_eq(UA_Server_run_shutdown(server), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(results, 1);
    ck_assert_uint_eq(resultStatus, UA_STATUSCODE_BADCONNECTIONCLOSED);
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
} END_TEST

START_TEST(InvalidConfiguration) {
    UA_Server_delete(server);
    server = UA_Server_newFromFile(UA_STRING(
        "{tcpEnabled:false,drivers:["
        "{driver:'rest',name:'bad',calls:{a:{endpoint:'x',after:'b'},"
        "b:{endpoint:'x',after:'a'}}},"
        "{driver:'rest',name:'unknown-endpoint',calls:{a:{endpoint:'nobody',method:'GET'}}},"
        "{driver:'rest',name:'no-endpoint',calls:{a:{method:'GET'}}}]}"));
    ck_assert_ptr_nonnull(server);
    /* Like other drivers, the failed start is only logged */
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_callDriver(server, "bad", "a", NULL, onResult, NULL),
                      UA_STATUSCODE_BADINVALIDSTATE);
    /* A wrong endpoint fails the call */
    ck_assert_uint_eq(UA_Server_callDriver(server, "unknown-endpoint", "a", NULL,
                                           onResult, NULL), UA_STATUSCODE_BADNOTFOUND);
    ck_assert_uint_eq(UA_Server_callDriver(server, "no-endpoint", "a", NULL,
                                           onResult, NULL), UA_STATUSCODE_BADNOTFOUND);
} END_TEST

/***********/
/* Polling */
/***********/

static const char *pollingConfig =
    "{tcpEnabled:false,drivers:["
    "{driver:'rest',name:'weather',path:'/weather',interval:1000,"
    " drivers:[{driver:'http',url:'http://localhost:8000/api'}]},"
    "{driver:'rest',name:'text',path:'/text',"
    " drivers:[{driver:'http',url:'http://localhost:8000/api'}]},"
    "{driver:'rest',name:'missing',path:'/nothing',"
    " drivers:[{driver:'http',url:'http://localhost:8000/api'}]},"
    "{driver:'rest',name:'missing-quiet',path:'/nothing','log-only-changes':true,"
    " drivers:[{driver:'http',url:'http://localhost:8000/api'}]},"
    "{driver:'http',name:'machine',url:'http://localhost:8000/api'},"
    "{driver:'rest',name:'job',poll:'getJob',defaults:{user:'opc',job:42},calls:{"
    " login:{endpoint:'machine',method:'POST',path:'/login',"
    "        body:'{\"user\":\"${input.user}\"}'},"
    " getJob:{endpoint:'machine',method:'GET',path:'/jobs/${input.job}',"
    "         headers:{authorization:'Bearer ${login.body.token}'},after:'login'}}}]}";

typedef struct {
    UA_Driver *rest;
    UA_UInt64 id;
    UA_Boolean removeSelf;
    size_t results;
    UA_StatusCode status;
    UA_UInt16 httpStatus;
    UA_String call;
    UA_Variant data;
} Polled;

static void
onPolled(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    Polled *c = (Polled *)context;
    c->results++;
    c->status = status;
    const UA_UInt16 *s = (const UA_UInt16 *)UA_KeyValueMap_getScalar(
        result, UA_QUALIFIEDNAME(0, "status"), &UA_TYPES[UA_TYPES_UINT16]);
    c->httpStatus = s ? *s : 0;
    UA_String_clear(&c->call);
    const UA_String *call = (const UA_String *)UA_KeyValueMap_getScalar(
        result, UA_QUALIFIEDNAME(0, "call"), &UA_TYPES[UA_TYPES_STRING]);
    if(call)
        UA_String_copy(call, &c->call);
    UA_Variant_clear(&c->data);
    const UA_Variant *data = UA_KeyValueMap_get(result, UA_QUALIFIEDNAME(0, "data"));
    if(data)
        UA_Variant_copy(data, &c->data);
    if(c->removeSelf)
        ck_assert_uint_eq(UA_RestDriver_removeCallback(c->rest, c->id),
                          UA_STATUSCODE_GOOD);
}

/* The context of the callback ends with the test */
static void
clearPolled(Polled *c) {
    if(c->rest)
        UA_RestDriver_removeCallback(c->rest, c->id);
    UA_String_clear(&c->call);
    UA_Variant_clear(&c->data);
}

static void
restartServer(const char *json) {
    ck_assert_uint_eq(UA_Server_run_shutdown(server), UA_STATUSCODE_GOOD);
    UA_Server_delete(server);
    startServer(json);
}

/* The callback is added after the startup, the first poll is in the next
 * iteration */
static void
startPolled(const char *name, Polled *c) {
    restartServer(pollingConfig);
    memset(c, 0, sizeof(Polled));
    c->rest = UA_Server_getDriver(server, NULL, name);
    ck_assert_ptr_nonnull(c->rest);
    ck_assert_uint_eq(UA_RestDriver_addCallback(c->rest, onPolled, c, &c->id),
                      UA_STATUSCODE_GOOD);
}

/* An object key or an array index of the data */
static const UA_Variant *
child(const UA_Variant *v, const char *key) {
    const UA_Variant *found = NULL;
    if(UA_Variant_hasArrayType(v, &UA_TYPES[UA_TYPES_KEYVALUEPAIR])) {
        UA_KeyValueMap map = {v->arrayLength, (UA_KeyValuePair *)v->data};
        found = UA_KeyValueMap_get(&map, UA_QUALIFIEDNAME(0, (char *)(uintptr_t)key));
    } else if(UA_Variant_hasArrayType(v, &UA_TYPES[UA_TYPES_VARIANT])) {
        size_t i = (size_t)atoi(key);
        if(i < v->arrayLength)
            found = &((const UA_Variant *)v->data)[i];
    }
    ck_assert_msg(found != NULL, "%s not found", key);
    return found;
}

START_TEST(PollsPath) {
    Polled c;
    startPolled("weather", &c);
    UA_Server_run_iterate(server, false);
    ck_assert_uint_eq(c.results, 1);
    ck_assert_uint_eq(c.status, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(c.httpStatus, 200);

    /* The body as a value tree */
    const UA_Variant *station = child(&c.data, "10865");
    const UA_Variant *f1 = child(station, "forecast1");
    ck_assert(UA_Variant_hasScalarType(child(f1, "stationId"), &UA_TYPES[UA_TYPES_STRING]));
    ck_assert(UA_Variant_hasScalarType(child(f1, "start"), &UA_TYPES[UA_TYPES_INT64]));
    ck_assert(UA_Variant_hasArrayType(child(f1, "temperature"), &UA_TYPES[UA_TYPES_INT64]));
    ck_assert_uint_eq(child(f1, "temperature")->arrayLength, 3);
    ck_assert(UA_Variant_hasArrayType(child(f1, "mixed"), &UA_TYPES[UA_TYPES_DOUBLE]));
    ck_assert(UA_Variant_isEmpty(child(f1, "windSpeed")));
    ck_assert(UA_Variant_isEmpty(child(station, "forecastStart")));
    const UA_Variant *empty = child(child(station, "forecast2"), "temperature");
    ck_assert(UA_Variant_hasArrayType(empty, &UA_TYPES[UA_TYPES_VARIANT]));
    ck_assert_uint_eq(empty->arrayLength, 0);
    const UA_Variant *days = child(station, "days");
    ck_assert(UA_Variant_hasArrayType(days, &UA_TYPES[UA_TYPES_VARIANT]));
    ck_assert_uint_eq(days->arrayLength, 2);
    const UA_Variant *max = child(child(days, "1"), "temperatureMax");
    ck_assert(UA_Variant_hasScalarType(max, &UA_TYPES[UA_TYPES_INT64]));
    ck_assert_int_eq(*(UA_Int64 *)max->data, 65);

    /* Polled again after the interval */
    UA_fakeSleep(500);
    UA_Server_run_iterate(server, false);
    ck_assert_uint_eq(c.results, 1);
    UA_fakeSleep(600);
    UA_Server_run_iterate(server, false);
    ck_assert_uint_eq(c.results, 2);
    clearPolled(&c);
} END_TEST

/* A call that logs in first */
START_TEST(PollsCall) {
    Polled c;
    startPolled("job", &c);
    UA_Server_run_iterate(server, false);
    ck_assert_uint_eq(c.results, 1);
    ck_assert_uint_eq(c.status, UA_STATUSCODE_GOOD);
    ck_assert(equals(&c.call, "getJob"));
    const UA_Variant *name = child(&c.data, "name");
    ck_assert(UA_Variant_hasScalarType(name, &UA_TYPES[UA_TYPES_STRING]));
    ck_assert(equals((const UA_String *)name->data, "Milling"));
    clearPolled(&c);
} END_TEST

START_TEST(NotJsonGivesDecodingError) {
    Polled c;
    startPolled("text", &c);
    UA_Server_run_iterate(server, false);
    ck_assert_uint_eq(c.results, 1);
    ck_assert_uint_eq(c.status, UA_STATUSCODE_BADDECODINGERROR);
    ck_assert_uint_eq(c.httpStatus, 200);
    ck_assert(UA_Variant_isEmpty(&c.data));
    clearPolled(&c);
} END_TEST

START_TEST(HttpErrorIsNotParsed) {
    Polled c;
    startPolled("missing", &c);
    UA_Server_run_iterate(server, false);
    ck_assert_uint_eq(c.results, 1);
    ck_assert_uint_eq(c.status, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(c.httpStatus, 404);
    ck_assert(UA_Variant_isEmpty(&c.data));
    clearPolled(&c);
} END_TEST

/* JSONPath into the data of a result */
START_TEST(JsonPathAccess) {
    Polled c;
    startPolled("weather", &c);
    UA_Server_run_iterate(server, false);
    UA_KeyValuePair pair = {UA_QUALIFIEDNAME(0, "data"), c.data};
    UA_KeyValueMap result = {1, &pair};

    UA_Double d = 0.0;
    ck_assert_uint_eq(UA_RestDriver_getNumber(&result, "$['10865'].days[1].temperatureMax",
                                              &d), UA_STATUSCODE_GOOD);
    ck_assert(d == 65.0);
    ck_assert_uint_eq(UA_RestDriver_getNumber(&result, "$.10865.forecast1.temperature[2]",
                                              &d), UA_STATUSCODE_GOOD);
    ck_assert(d == 79.0); /* From an Int64 array */
    ck_assert_uint_eq(UA_RestDriver_getNumber(&result, "$.10865.forecast1.mixed[1]", &d),
                      UA_STATUSCODE_GOOD);
    ck_assert(d == 2.5);

    UA_Variant v;
    ck_assert_uint_eq(UA_RestDriver_getValue(&result, "$.10865.days[0].dayDate", &v),
                      UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_STRING]));
    ck_assert(equals((const UA_String *)v.data, "2026-11-19"));
    UA_Variant_clear(&v);
    ck_assert_uint_eq(UA_RestDriver_getValue(&result, "$", &v), UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_KEYVALUEPAIR]));
    UA_Variant_clear(&v);

    /* Wildcards give all matches */
    ck_assert_uint_eq(UA_RestDriver_getValue(&result, "$.10865.days[*].temperatureMax",
                                             &v), UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_VARIANT]));
    ck_assert_uint_eq(v.arrayLength, 2);
    ck_assert_int_eq(*(UA_Int64 *)((UA_Variant *)v.data)[1].data, 65);
    UA_Variant_clear(&v);
    ck_assert_uint_eq(UA_RestDriver_getValue(&result, "$.10865.forecast1.temperature[*]",
                                             &v), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(v.arrayLength, 3); /* From an Int64 array */
    UA_Variant_clear(&v);
    ck_assert_uint_eq(UA_RestDriver_getValue(&result, "$.*.days.*.dayDate", &v),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(v.arrayLength, 2);
    UA_Variant_clear(&v);
    ck_assert_uint_eq(UA_RestDriver_getValue(&result, "$.10865.nothing[*]", &v),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(v.arrayLength, 0); /* No matches */
    UA_Variant_clear(&v);
    ck_assert_uint_eq(UA_RestDriver_getValue(&result, "$['*']", &v), /* A key */
                      UA_STATUSCODE_BADNOTFOUND);
    ck_assert_uint_eq(UA_RestDriver_getNumber(&result, "$.10865.days[*].temperatureMax",
                                              &d), UA_STATUSCODE_BADTYPEMISMATCH);

    ck_assert_uint_eq(UA_RestDriver_getNumber(&result, "$.10865.days[0].dayDate", &d),
                      UA_STATUSCODE_BADTYPEMISMATCH);
    ck_assert_uint_eq(UA_RestDriver_getValue(&result, "$.10865.days[5]", &v),
                      UA_STATUSCODE_BADNOTFOUND);
    ck_assert_uint_eq(UA_RestDriver_getValue(&result, "$.nothing", &v),
                      UA_STATUSCODE_BADNOTFOUND);
    clearPolled(&c);
} END_TEST

/* Without an interval, the driver polls every second */
START_TEST(DefaultInterval) {
    Polled c;
    startPolled("missing", &c);
    UA_Server_run_iterate(server, false);
    ck_assert_uint_eq(c.results, 1);
    UA_fakeSleep(900);
    UA_Server_run_iterate(server, false);
    ck_assert_uint_eq(c.results, 1);
    UA_fakeSleep(200);
    UA_Server_run_iterate(server, false);
    ck_assert_uint_eq(c.results, 2);
    clearPolled(&c);
} END_TEST

/* Every failed poll is logged, with log-only-changes only the first */
static size_t loudFailures, quietFailures;

static void
countFailures(void *context, UA_LogLevel level, UA_LogCategory category,
              const char *msg, va_list args) {
    (void)context, (void)category;
    UA_String text = UA_STRING_NULL;
    if(level != UA_LOGLEVEL_WARNING ||
       UA_String_vformat(&text, msg, args) != UA_STATUSCODE_GOOD)
        return;
    if(contains(&text, "\"missing\": The poll failed"))
        loudFailures++;
    if(contains(&text, "\"missing-quiet\": The poll failed"))
        quietFailures++;
    UA_String_clear(&text);
}

START_TEST(LogFailures) {
    restartServer(pollingConfig);
    UA_Server_getConfig(server)->logging->log = countFailures;
    loudFailures = 0;
    quietFailures = 0;
    for(size_t i = 0; i < 3; i++) {
        UA_Server_run_iterate(server, false);
        UA_fakeSleep(1000);
    }
    ck_assert_uint_eq(loudFailures, 3);
    ck_assert_uint_eq(quietFailures, 1);
} END_TEST

START_TEST(CallbackAddRemove) {
    Polled c;
    startPolled("weather", &c);
    Polled once;
    memset(&once, 0, sizeof(Polled));
    once.rest = c.rest;
    once.removeSelf = true;
    ck_assert_uint_eq(UA_RestDriver_addCallback(c.rest, onPolled, &once, &once.id),
                      UA_STATUSCODE_GOOD);
    UA_Server_run_iterate(server, false);
    UA_fakeSleep(1000);
    UA_Server_run_iterate(server, false);
    ck_assert_uint_eq(c.results, 2);
    ck_assert_uint_eq(once.results, 1);

    ck_assert_uint_eq(UA_RestDriver_removeCallback(c.rest, once.id),
                      UA_STATUSCODE_BADNOTFOUND);
    UA_Driver *http = UA_Server_getDriver(server, NULL, "machine");
    ck_assert_uint_eq(UA_RestDriver_addCallback(http, onPolled, &c, NULL),
                      UA_STATUSCODE_BADTYPEMISMATCH);
    ck_assert_uint_eq(UA_RestDriver_addCallback(NULL, onPolled, &c, NULL),
                      UA_STATUSCODE_BADINVALIDARGUMENT);
    clearPolled(&c);
    clearPolled(&once);
} END_TEST

START_TEST(FreeNotifiesShutdown) {
    Polled c;
    startPolled("weather", &c);
    ck_assert_uint_eq(UA_Server_run_shutdown(server), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(c.results, 0);
    UA_Server_delete(server);
    ck_assert_uint_eq(c.results, 1);
    ck_assert_uint_eq(c.status, UA_STATUSCODE_BADSHUTDOWN);
    c.rest = NULL; /* Freed */
    clearPolled(&c);
    startServer(config); /* For the teardown */
} END_TEST

START_TEST(InvalidPollingConfig) {
    restartServer(
        "{tcpEnabled:false,drivers:["
        "{driver:'rest',name:'both',path:'/x',poll:'a',calls:{a:{endpoint:'x',method:'GET'}}},"
        "{driver:'rest',name:'unknown-call',poll:'b',calls:{a:{endpoint:'x',method:'GET'}}},"
        "{driver:'rest',name:'zero-interval',path:'/x',interval:0},"
        "{driver:'rest',name:'nothing'}]}");
    const char *names[] = {"both", "unknown-call", "zero-interval", "nothing"};
    for(size_t i = 0; i < 4; i++) {
        UA_Driver *drv = UA_Server_getDriver(server, NULL, names[i]);
        ck_assert_ptr_nonnull(drv);
        ck_assert_msg(drv->state == UA_LIFECYCLESTATE_STOPPED, "%s started", names[i]);
    }
} END_TEST

static Suite *testSuite_Rest(void) {
    Suite *s = suite_create("HTTP and REST drivers");
    TCase *tc = tcase_create("Calls");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, HttpRequest);
    tcase_add_test(tc, ChainWithPlaceholders);
    tcase_add_test(tc, DefaultsFromConfig);
    tcase_add_test(tc, ChainStopsAtHttpError);
    tcase_add_test(tc, WriteWithBody);
    tcase_add_test(tc, CallWithoutCallback);
    tcase_add_test(tc, OtherProtocol);
    tcase_add_test(tc, NestedEndpoint);
    tcase_add_test(tc, InvalidCalls);
    tcase_add_test(tc, ShutdownCompletesOpenCalls);
    tcase_add_test(tc, InvalidConfiguration);
    suite_add_tcase(s, tc);
    TCase *tcPolling = tcase_create("Polling");
    tcase_add_checked_fixture(tcPolling, setup, teardown);
    tcase_add_test(tcPolling, PollsPath);
    tcase_add_test(tcPolling, PollsCall);
    tcase_add_test(tcPolling, NotJsonGivesDecodingError);
    tcase_add_test(tcPolling, HttpErrorIsNotParsed);
    tcase_add_test(tcPolling, DefaultInterval);
    tcase_add_test(tcPolling, JsonPathAccess);
    tcase_add_test(tcPolling, LogFailures);
    tcase_add_test(tcPolling, CallbackAddRemove);
    tcase_add_test(tcPolling, FreeNotifiesShutdown);
    tcase_add_test(tcPolling, InvalidPollingConfig);
    suite_add_tcase(s, tcPolling);
    return s;
}

int main(void) {
    Suite *s = testSuite_Rest();
    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
