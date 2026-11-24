/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

#include <open62541/server.h>

#include "test_helpers.h"
#include "testing_clock.h"

#include <check.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

/* The binding driver on top of a fake device driver. The device answers
 * synchronously, later (completed by the test) or with errors. */

static UA_Server *server;

/* A call of the device that is completed by the test */
static UA_DriverCallCallback laterCallback;
static void *laterContext;

/* The cancel callback of the application. The binding driver leaves it alone. */
static size_t cancelled;

static void
appCancel(UA_Server *s, const void *out) {
    (void)s, (void)out;
    cancelled++;
}

static void
answer(UA_DriverCallCallback callback, void *context, UA_StatusCode status,
       UA_UInt16 httpStatus, const char *body, const UA_KeyValueMap *extra) {
    UA_KeyValueMap result = UA_KEYVALUEMAP_NULL;
    if(extra)
        UA_KeyValueMap_copy(extra, &result);
    UA_KeyValueMap_setScalar(&result, UA_QUALIFIEDNAME(0, "status"), &httpStatus,
                             &UA_TYPES[UA_TYPES_UINT16]);
    UA_ByteString b = UA_BYTESTRING((char *)(uintptr_t)body);
    UA_KeyValueMap_setScalar(&result, UA_QUALIFIEDNAME(0, "body"), &b,
                             &UA_TYPES[UA_TYPES_BYTESTRING]);
    callback(context, status, &result);
    UA_KeyValueMap_clear(&result);
}

static void
completeLater(UA_StatusCode status, UA_UInt16 httpStatus) {
    ck_assert(laterCallback != NULL);
    UA_DriverCallCallback cb = laterCallback;
    laterCallback = NULL;
    answer(cb, laterContext, status, httpStatus, "", NULL);
}

static UA_Boolean
callIs(const UA_String *call, const char *name) {
    UA_String n = UA_STRING((char *)(uintptr_t)name);
    return UA_String_equal(call, &n);
}

/* The answer to GET, polled by a REST driver */
static const char *pollBody;
static UA_UInt16 pollHttpStatus;

static UA_StatusCode
deviceCall(UA_Driver *drv, const UA_String call, const UA_KeyValueMap *input,
           UA_DriverCallCallback callback, void *context) {
    (void)drv;
    if(callIs(&call, "GET")) {
        answer(callback, context, UA_STATUSCODE_GOOD, pollHttpStatus, pollBody, NULL);
    } else if(callIs(&call, "read")) {
        answer(callback, context, UA_STATUSCODE_GOOD, 200,
               "{\"speed\":12.5,\"job\":{\"name\":\"Milling\"},\"since\":"
               "\"2026-11-10T08:00:00Z\"}", NULL);
    } else if(callIs(&call, "echo")) {
        answer(callback, context, UA_STATUSCODE_GOOD, 200, "", input);
    } else if(callIs(&call, "fail")) {
        answer(callback, context, UA_STATUSCODE_GOOD, 500, "{}", NULL);
    } else if(callIs(&call, "later")) {
        if(laterCallback)
            return UA_STATUSCODE_BADTOOMANYOPERATIONS;
        laterCallback = callback;
        laterContext = context;
    } else {
        return UA_STATUSCODE_BADNOTSUPPORTED;
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
deviceStart(UA_Driver *drv) {
    drv->state = UA_LIFECYCLESTATE_STARTED;
    return UA_STATUSCODE_GOOD;
}

/* Open calls are completed when the device stops */
static void
deviceStop(UA_Driver *drv) {
    if(laterCallback)
        completeLater(UA_STATUSCODE_BADSHUTDOWN, 0);
    drv->state = UA_LIFECYCLESTATE_STOPPED;
}

static UA_StatusCode
deviceFree(UA_Driver *drv) {
    UA_free(drv);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
deviceCreate(UA_Server *s, const UA_KeyValueMap params, UA_Driver **outDriver) {
    (void)s, (void)params;
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

static const char *config =
    "{tcpEnabled:false,drivers:["
    "{driver:'device',name:'plc'},"
    "{driver:'binding',name:'Machine',methods:{"
    " Read:{driver:'plc',call:'read',outputs:{status:'UInt16',"
    "       speed:{type:'Double',from:'body.speed'},"
    "       job:{type:'String',from:'body.job.name'},"
    "       since:{type:'DateTime',from:'body.since'}}},"
    " Echo:{driver:'plc',call:'echo',defaults:{unit:'mm',value:1},"
    "       inputs:{value:'Int32',name:'String'},"
    "       outputs:{value:'Int32',unit:'String',name:'String'}},"
    " Later:{driver:'plc',call:'later',outputs:{status:'UInt16'}},"
    " Fail:{driver:'plc',call:'fail',outputs:{status:'UInt16'}},"
    " Missing:{driver:'plc',call:'read',outputs:{x:{type:'Double',from:'body.nothing'}}},"
    " Unsupported:{driver:'plc',call:'unknown'},"
    " Nobody:{driver:'nobody',call:'x'},"
    " Unnested:{call:'x'}},"
    "variables:{"
    " Speed:{driver:'plc',call:'read',type:'Double',from:'body.speed',interval:20},"
    " Broken:{driver:'plc',call:'fail',type:'Double',from:'body.speed',interval:20}}}]}";

static void setup(void) {
    laterCallback = NULL;
    cancelled = 0;
    server = UA_Server_newFromFile(UA_STRING((char *)(uintptr_t)config));
    ck_assert_ptr_nonnull(server);
    UA_ServerConfig *sc = UA_Server_getConfig(server);
    sc->asyncOperationCancelCallback = appCancel;
    sc->eventLoop->dateTime_now = UA_DateTime_now_fake;
    sc->eventLoop->dateTime_nowMonotonic = UA_DateTime_now_fake;
    UA_ServerConfig_registerDriver(sc, &deviceRegistration);
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
}

static void teardown(void) {
    ck_assert_uint_eq(UA_Server_run_shutdown(server), UA_STATUSCODE_GOOD);
    for(UA_Driver *drv = UA_Server_getDrivers(server); drv; drv = drv->next)
        ck_assert_int_eq(drv->state, UA_LIFECYCLESTATE_STOPPED);
    ck_assert(UA_Server_getConfig(server)->asyncOperationCancelCallback == appCancel);
    UA_Server_delete(server);
}

static UA_CallMethodResult
callMethod(const char *method, size_t inputSize, UA_Variant *input) {
    char id[64];
    snprintf(id, sizeof(id), "Machine.%s", method);
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = UA_NODEID_STRING(1, "Machine");
    req.methodId = UA_NODEID_STRING(1, id);
    req.inputArgumentsSize = inputSize;
    req.inputArguments = input;
    return UA_Server_call(server, &req);
}

static void
iterate(size_t times) {
    for(size_t i = 0; i < times; i++)
        UA_Server_run_iterate(server, false);
}

START_TEST(NodesAreCreated) {
    UA_NodeClass nc;
    ck_assert_uint_eq(UA_Server_readNodeClass(server, UA_NODEID_STRING(1, "Machine"), &nc),
                      UA_STATUSCODE_GOOD);
    ck_assert_int_eq(nc, UA_NODECLASS_OBJECT);
    ck_assert_uint_eq(UA_Server_readNodeClass(server, UA_NODEID_STRING(1, "Machine.Read"),
                                              &nc), UA_STATUSCODE_GOOD);
    ck_assert_int_eq(nc, UA_NODECLASS_METHOD);
    ck_assert_uint_eq(UA_Server_readNodeClass(server, UA_NODEID_STRING(1, "Machine.Speed"),
                                              &nc), UA_STATUSCODE_GOOD);
    ck_assert_int_eq(nc, UA_NODECLASS_VARIABLE);
} END_TEST

START_TEST(OutputsFromTheResult) {
    UA_CallMethodResult r = callMethod("Read", 0, NULL);
    ck_assert_uint_eq(r.statusCode, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(r.outputArgumentsSize, 4);
    ck_assert_uint_eq(*(UA_UInt16 *)r.outputArguments[0].data, 200);
    ck_assert(*(UA_Double *)r.outputArguments[1].data == 12.5);
    UA_String milling = UA_STRING("Milling");
    ck_assert(UA_String_equal((UA_String *)r.outputArguments[2].data, &milling));
    ck_assert(UA_Variant_hasScalarType(&r.outputArguments[3], &UA_TYPES[UA_TYPES_DATETIME]));
    UA_DateTimeStruct dts = UA_DateTime_toStruct(*(UA_DateTime *)r.outputArguments[3].data);
    ck_assert_uint_eq(dts.year, 2026);
    ck_assert_uint_eq(dts.hour, 8);
    UA_CallMethodResult_clear(&r);
} END_TEST

START_TEST(InputArgumentsAndDefaults) {
    UA_Int32 value = 7;
    UA_String name = UA_STRING("x");
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &value, &UA_TYPES[UA_TYPES_INT32]);
    UA_Variant_setScalar(&in[1], &name, &UA_TYPES[UA_TYPES_STRING]);
    UA_CallMethodResult r = callMethod("Echo", 2, in);
    ck_assert_uint_eq(r.statusCode, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(r.outputArgumentsSize, 3);
    ck_assert_int_eq(*(UA_Int32 *)r.outputArguments[0].data, 7); /* Input wins */
    UA_String mm = UA_STRING("mm");
    ck_assert(UA_String_equal((UA_String *)r.outputArguments[1].data, &mm));
    ck_assert(UA_String_equal((UA_String *)r.outputArguments[2].data, &name));
    UA_CallMethodResult_clear(&r);
} END_TEST

START_TEST(Errors) {
    UA_CallMethodResult r = callMethod("Fail", 0, NULL);
    ck_assert_uint_eq(r.statusCode, UA_STATUSCODE_BADCOMMUNICATIONERROR);
    UA_CallMethodResult_clear(&r);
    r = callMethod("Missing", 0, NULL);
    ck_assert_uint_eq(r.statusCode, UA_STATUSCODE_BADNOTFOUND);
    UA_CallMethodResult_clear(&r);
    r = callMethod("Unsupported", 0, NULL);
    ck_assert_uint_eq(r.statusCode, UA_STATUSCODE_BADNOTSUPPORTED);
    /* A wrong reference fails the call */
    r = callMethod("Nobody", 0, NULL);
    ck_assert_uint_eq(r.statusCode, UA_STATUSCODE_BADNOTFOUND);
    UA_CallMethodResult_clear(&r);
    r = callMethod("Unnested", 0, NULL); /* No driver and nothing nested */
    ck_assert_uint_eq(r.statusCode, UA_STATUSCODE_BADNOTFOUND);
    UA_CallMethodResult_clear(&r);
} END_TEST

/* The result of an async local call */
static size_t asyncResults;
static UA_StatusCode asyncStatus;
static UA_UInt16 asyncHttpStatus;

static void
onAsyncResult(UA_Server *s, void *context, const UA_CallMethodResult *result) {
    (void)s, (void)context;
    asyncResults++;
    asyncStatus = result->statusCode;
    asyncHttpStatus = 0;
    if(result->outputArgumentsSize == 1 && result->outputArguments[0].data)
        asyncHttpStatus = *(UA_UInt16 *)result->outputArguments[0].data;
}

static void
callLater(UA_UInt32 timeout) {
    asyncResults = 0;
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = UA_NODEID_STRING(1, "Machine");
    req.methodId = UA_NODEID_STRING(1, "Machine.Later");
    ck_assert_uint_eq(UA_Server_call_async(server, &req, onAsyncResult, NULL, timeout),
                      UA_STATUSCODE_GOOD);
    ck_assert(laterCallback != NULL);
}

START_TEST(AsyncResult) {
    callLater(0);
    iterate(2);
    ck_assert_uint_eq(asyncResults, 0);
    completeLater(UA_STATUSCODE_GOOD, 201);
    for(size_t i = 0; i < 20 && asyncResults == 0; i++)
        iterate(1);
    ck_assert_uint_eq(asyncResults, 1);
    ck_assert_uint_eq(asyncStatus, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(asyncHttpStatus, 201);
} END_TEST

/* The server gives up before the device answers. The late answer is still
 * handed back, else the shutdown in the teardown waits for it. */
START_TEST(CancelledByTimeout) {
    callLater(20);
    for(size_t i = 0; i < 100 && asyncResults == 0; i++) {
        UA_fakeSleep(10);
        iterate(1);
    }
    ck_assert_uint_eq(asyncResults, 1);
    ck_assert_uint_eq(asyncStatus, UA_STATUSCODE_BADTIMEOUT);
    ck_assert_uint_eq(cancelled, 1);
    completeLater(UA_STATUSCODE_GOOD, 200);
    iterate(2);
    ck_assert_uint_eq(asyncResults, 1);
} END_TEST

/* The device completes the open call when it stops */
START_TEST(ShutdownWithOpenCall) {
    callLater(0);
} END_TEST

START_TEST(VariablesArePolled) {
    for(size_t i = 0; i < 10; i++) {
        UA_fakeSleep(25);
        iterate(1);
    }
    UA_Variant v;
    ck_assert_uint_eq(UA_Server_readValue(server, UA_NODEID_STRING(1, "Machine.Speed"), &v),
                      UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_DOUBLE]));
    ck_assert(*(UA_Double *)v.data == 12.5);
    UA_Variant_clear(&v);

    UA_ReadValueId rvi;
    UA_ReadValueId_init(&rvi);
    rvi.nodeId = UA_NODEID_STRING(1, "Machine.Broken");
    rvi.attributeId = UA_ATTRIBUTEID_VALUE;
    UA_DataValue dv = UA_Server_read(server, &rvi, UA_TIMESTAMPSTORETURN_NEITHER);
    ck_assert_uint_eq(dv.status, UA_STATUSCODE_BADCOMMUNICATIONERROR);
    UA_DataValue_clear(&dv);
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

/* The drivers the binding uses are nested in it. Without "driver", the only
 * nested driver is called. */
START_TEST(NestedDriver) {
    UA_Server *s = UA_Server_newFromFile(UA_STRING(
        "{tcpEnabled:false,drivers:[{driver:'binding',name:'Press',"
        " methods:{Read:{call:'read',outputs:{speed:{type:'Double',from:'body.speed'}}}},"
        " drivers:[{driver:'device'}]}]}"));
    ck_assert_ptr_nonnull(s);
    UA_ServerConfig_registerDriver(UA_Server_getConfig(s), &deviceRegistration);
    ck_assert_uint_eq(UA_Server_run_startup(s), UA_STATUSCODE_GOOD);
    ck_assert_ptr_nonnull(driverByName(s, "Press/device"));
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = UA_NODEID_STRING(1, "Press");
    req.methodId = UA_NODEID_STRING(1, "Press.Read");
    UA_CallMethodResult r = UA_Server_call(s, &req);
    ck_assert_uint_eq(r.statusCode, UA_STATUSCODE_GOOD);
    ck_assert(*(UA_Double *)r.outputArguments[0].data == 12.5);
    UA_CallMethodResult_clear(&r);
    ck_assert_uint_eq(UA_Server_run_shutdown(s), UA_STATUSCODE_GOOD);
    UA_Server_delete(s);
} END_TEST

/**********/
/* Nodes from the data */
/**********/

/* Trimmed from the DWD API (stationOverviewExtended) */
static const char *weatherToday =
    "{\"10865\":{\"forecast1\":{\"start\":1763510400000,\"temperature\":[84,81],"
    "\"windSpeed\":null},\"forecast2\":{\"temperature\":[]},\"forecastStart\":null,"
    "\"days\":[{\"dayDate\":\"2026-11-19\",\"temperatureMin\":73}],\"warnings\":[],"
    "\"countdown\":\"6\"}}";

/* Changed values and types, a new key and a missing one (warnings) */
static const char *weatherLater =
    "{\"10865\":{\"forecast1\":{\"start\":1763514000000,\"temperature\":[80,78],"
    "\"windSpeed\":12,\"humidity\":870},\"forecast2\":{\"temperature\":[75,70]},"
    "\"forecastStart\":5,\"days\":[{\"dayDate\":\"2026-11-19\",\"temperatureMin\":7.5}]}}";

/* The polling REST driver is nested in the binding, the station level is skipped */
static const char *nodesConfig =
    "{tcpEnabled:false,drivers:[{driver:'binding',name:'Weather',nodes:{from:\"$['10865']\"},"
    " drivers:[{driver:'rest',path:'/weather',interval:1000,"
    "           drivers:[{driver:'device'}]}]}]}";

static UA_Server *
newPollingServer(const char *json) {
    pollBody = weatherToday;
    pollHttpStatus = 200;
    UA_Server *s = UA_Server_newFromFile(UA_STRING((char *)(uintptr_t)json));
    ck_assert_ptr_nonnull(s);
    UA_ServerConfig *sc = UA_Server_getConfig(s);
    sc->eventLoop->dateTime_now = UA_DateTime_now_fake;
    sc->eventLoop->dateTime_nowMonotonic = UA_DateTime_now_fake;
    UA_ServerConfig_registerDriver(sc, &deviceRegistration);
    ck_assert_uint_eq(UA_Server_run_startup(s), UA_STATUSCODE_GOOD);
    return s;
}

static void
nextPoll(UA_Server *s) {
    UA_fakeSleep(1000);
    UA_Server_run_iterate(s, false);
}

static UA_DataValue
readNode(UA_Server *s, const char *id) {
    UA_ReadValueId rvi;
    UA_ReadValueId_init(&rvi);
    rvi.nodeId = UA_NODEID_STRING(1, (char *)(uintptr_t)id);
    rvi.attributeId = UA_ATTRIBUTEID_VALUE;
    return UA_Server_read(s, &rvi, UA_TIMESTAMPSTORETURN_NEITHER);
}

static UA_Boolean
nodeExists(UA_Server *s, const char *id, UA_NodeClass expected) {
    UA_NodeClass nc;
    return UA_Server_readNodeClass(s, UA_NODEID_STRING(1, (char *)(uintptr_t)id), &nc) ==
        UA_STATUSCODE_GOOD && nc == expected;
}

static void
assertInt(UA_Server *s, const char *id, UA_Int64 expected) {
    UA_DataValue dv = readNode(s, id);
    ck_assert_msg(dv.status == UA_STATUSCODE_GOOD &&
                  UA_Variant_hasScalarType(&dv.value, &UA_TYPES[UA_TYPES_INT64]) &&
                  *(UA_Int64 *)dv.value.data == expected, "%s is not %ld", id,
                  (long)expected);
    UA_DataValue_clear(&dv);
}

START_TEST(NodesFromData) {
    UA_Server *s = newPollingServer(nodesConfig);
    UA_Server_run_iterate(s, false);

    ck_assert(nodeExists(s, "Weather.days", UA_NODECLASS_OBJECT));
    ck_assert(nodeExists(s, "Weather.days.0", UA_NODECLASS_OBJECT));
    ck_assert(nodeExists(s, "Weather.forecast1.temperature", UA_NODECLASS_VARIABLE));
    ck_assert(!nodeExists(s, "Weather.10865", UA_NODECLASS_OBJECT));

    UA_DataValue dv = readNode(s, "Weather.days.0.dayDate");
    ck_assert(UA_Variant_hasScalarType(&dv.value, &UA_TYPES[UA_TYPES_STRING]));
    UA_String date = UA_STRING("2026-11-19");
    ck_assert(UA_String_equal((UA_String *)dv.value.data, &date));
    UA_DataValue_clear(&dv);

    dv = readNode(s, "Weather.forecast1.temperature");
    ck_assert(UA_Variant_hasArrayType(&dv.value, &UA_TYPES[UA_TYPES_INT64]));
    ck_assert_uint_eq(dv.value.arrayLength, 2);
    UA_DataValue_clear(&dv);

    /* Null and an empty array */
    dv = readNode(s, "Weather.forecastStart");
    ck_assert_uint_eq(dv.status, UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_isEmpty(&dv.value));
    UA_DataValue_clear(&dv);
    dv = readNode(s, "Weather.forecast2.temperature");
    ck_assert(UA_Variant_hasArrayType(&dv.value, &UA_TYPES[UA_TYPES_VARIANT]));
    ck_assert_uint_eq(dv.value.arrayLength, 0);
    UA_DataValue_clear(&dv);

    UA_NodeId dataType;
    UA_NodeId number = UA_NS0ID(NUMBER);
    ck_assert_uint_eq(UA_Server_readDataType(s, UA_NODEID_STRING(1, "Weather.forecast1.start"),
                                             &dataType), UA_STATUSCODE_GOOD);
    ck_assert(UA_NodeId_equal(&dataType, &number));

    /* The nodes are removed at the stop */
    ck_assert_uint_eq(UA_Server_run_shutdown(s), UA_STATUSCODE_GOOD);
    ck_assert(!nodeExists(s, "Weather.days.0.dayDate", UA_NODECLASS_VARIABLE));
    ck_assert(!nodeExists(s, "Weather", UA_NODECLASS_OBJECT));
    UA_Server_delete(s);
} END_TEST

START_TEST(NodesFollowChanges) {
    UA_Server *s = newPollingServer(nodesConfig);
    UA_Server_run_iterate(s, false);
    pollBody = weatherLater;
    nextPoll(s);

    /* An integer becomes a double */
    UA_DataValue dv = readNode(s, "Weather.days.0.temperatureMin");
    ck_assert(UA_Variant_hasScalarType(&dv.value, &UA_TYPES[UA_TYPES_DOUBLE]));
    ck_assert(*(UA_Double *)dv.value.data == 7.5);
    UA_DataValue_clear(&dv);

    /* Values after null and after an empty array */
    assertInt(s, "Weather.forecast1.windSpeed", 12);
    assertInt(s, "Weather.forecastStart", 5);
    dv = readNode(s, "Weather.forecast2.temperature");
    ck_assert(UA_Variant_hasArrayType(&dv.value, &UA_TYPES[UA_TYPES_INT64]));
    UA_DataValue_clear(&dv);

    /* A new key and a missing one */
    assertInt(s, "Weather.forecast1.humidity", 870);
    dv = readNode(s, "Weather.warnings");
    ck_assert_uint_eq(dv.status, UA_STATUSCODE_BADNODATA);
    UA_DataValue_clear(&dv);

    UA_Server_run_shutdown(s);
    UA_Server_delete(s);
} END_TEST

START_TEST(BadResultSetsStatus) {
    UA_Server *s = newPollingServer(nodesConfig);
    UA_Server_run_iterate(s, false);
    pollHttpStatus = 500;
    nextPoll(s);
    UA_DataValue dv = readNode(s, "Weather.forecast1.start");
    ck_assert_uint_eq(dv.status, UA_STATUSCODE_BADCOMMUNICATIONERROR);
    UA_DataValue_clear(&dv);

    pollHttpStatus = 200;
    nextPoll(s);
    assertInt(s, "Weather.forecast1.start", 1763510400000);
    UA_Server_run_shutdown(s);
    UA_Server_delete(s);
} END_TEST

/* Factors by key name, also for the numbers in arrays */
START_TEST(NodesScale) {
    UA_Server *s = newPollingServer(
        "{tcpEnabled:false,drivers:[{driver:'binding',name:'Weather',"
        " nodes:{from:'$.10865',scale:{temperature:0.1,temperatureMin:0.1}},"
        " drivers:[{driver:'rest',path:'/weather',drivers:[{driver:'device'}]}]}]}");
    UA_Server_run_iterate(s, false);

    UA_DataValue dv = readNode(s, "Weather.days.0.temperatureMin");
    ck_assert(UA_Variant_hasScalarType(&dv.value, &UA_TYPES[UA_TYPES_DOUBLE]));
    ck_assert(fabs(*(UA_Double *)dv.value.data - 7.3) < 1e-9);
    UA_DataValue_clear(&dv);

    dv = readNode(s, "Weather.forecast1.temperature");
    ck_assert(UA_Variant_hasArrayType(&dv.value, &UA_TYPES[UA_TYPES_DOUBLE]));
    ck_assert(fabs(((UA_Double *)dv.value.data)[1] - 8.1) < 1e-9);
    UA_DataValue_clear(&dv);

    assertInt(s, "Weather.forecast1.start", 1763510400000); /* Not scaled */
    UA_Server_run_shutdown(s);
    UA_Server_delete(s);
} END_TEST

/* Variables without call take their values from the polling */
START_TEST(PolledVariables) {
    UA_Server *s = newPollingServer(
        "{tcpEnabled:false,drivers:[{driver:'binding',name:'Station',variables:{"
        " Date:{type:'String',from:'$.10865.days[0].dayDate'},"
        " Min:{type:'Double',from:\"$['10865'].days[0].temperatureMin\"},"
        " Second:{type:'Int32',from:'$.10865.forecast1.temperature[1]'},"
        " Countdown:{type:'Int32',from:'$.10865.countdown'},"
        " Missing:{type:'Int32',from:'$.10865.nothing'}},"
        " drivers:[{driver:'rest',path:'/weather',drivers:[{driver:'device'}]}]}]}");
    UA_DataValue dv = readNode(s, "Station.Date");
    ck_assert_uint_eq(dv.status, UA_STATUSCODE_BADWAITINGFORINITIALDATA);
    UA_DataValue_clear(&dv);
    UA_Server_run_iterate(s, false);

    dv = readNode(s, "Station.Date");
    UA_String date = UA_STRING("2026-11-19");
    ck_assert(UA_Variant_hasScalarType(&dv.value, &UA_TYPES[UA_TYPES_STRING]));
    ck_assert(UA_String_equal((UA_String *)dv.value.data, &date));
    UA_DataValue_clear(&dv);
    dv = readNode(s, "Station.Min");
    ck_assert(UA_Variant_hasScalarType(&dv.value, &UA_TYPES[UA_TYPES_DOUBLE]));
    ck_assert(*(UA_Double *)dv.value.data == 73.0);
    UA_DataValue_clear(&dv);
    dv = readNode(s, "Station.Second");
    ck_assert(UA_Variant_hasScalarType(&dv.value, &UA_TYPES[UA_TYPES_INT32]));
    ck_assert_int_eq(*(UA_Int32 *)dv.value.data, 81);
    UA_DataValue_clear(&dv);
    dv = readNode(s, "Station.Countdown"); /* From the text "6" */
    ck_assert(UA_Variant_hasScalarType(&dv.value, &UA_TYPES[UA_TYPES_INT32]));
    ck_assert_int_eq(*(UA_Int32 *)dv.value.data, 6);
    UA_DataValue_clear(&dv);
    dv = readNode(s, "Station.Missing");
    ck_assert_uint_eq(dv.status, UA_STATUSCODE_BADNOTFOUND);
    UA_DataValue_clear(&dv);

    /* Only the configured values are nodes */
    ck_assert(!nodeExists(s, "Station.days", UA_NODECLASS_OBJECT));
    UA_Server_run_shutdown(s);
    ck_assert(!nodeExists(s, "Station.Date", UA_NODECLASS_VARIABLE));
    UA_Server_delete(s);
} END_TEST

/* The EngineeringUnits property of a node, or an empty unit */
static UA_EUInformation
readUnit(UA_Server *s, const char *id) {
    UA_EUInformation eu;
    UA_EUInformation_init(&eu);
    UA_QualifiedName name = UA_QUALIFIEDNAME(0, "EngineeringUnits");
    UA_BrowsePathResult bpr = UA_Server_browseSimplifiedBrowsePath(
        s, UA_NODEID_STRING(1, (char *)(uintptr_t)id), 1, &name);
    if(bpr.statusCode == UA_STATUSCODE_GOOD && bpr.targetsSize == 1) {
        UA_Variant v;
        if(UA_Server_readValue(s, bpr.targets[0].targetId.nodeId, &v) ==
           UA_STATUSCODE_GOOD) {
            if(UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_EUINFORMATION]))
                UA_EUInformation_copy((UA_EUInformation *)v.data, &eu);
            UA_Variant_clear(&v);
        }
    }
    UA_BrowsePathResult_clear(&bpr);
    return eu;
}

/* Wildcards give array variables, unit gives EngineeringUnits */
START_TEST(ArrayVariablesWithUnits) {
    UA_Server *s = newPollingServer(
        "{tcpEnabled:false,drivers:[{driver:'binding',name:'Station',variables:{"
        " Temps:{type:'Double',from:'$.10865.forecast1.temperature[*]',scale:0.1,"
        "        unit:'°C'},"
        " Dates:{type:'String',from:'$.10865.days[*].dayDate'}},"
        " drivers:[{driver:'rest',path:'/weather',drivers:[{driver:'device'}]}]}]}");
    UA_Server_run_iterate(s, false);

    UA_DataValue dv = readNode(s, "Station.Temps");
    ck_assert(UA_Variant_hasArrayType(&dv.value, &UA_TYPES[UA_TYPES_DOUBLE]));
    ck_assert_uint_eq(dv.value.arrayLength, 2);
    ck_assert(fabs(((UA_Double *)dv.value.data)[1] - 8.1) < 1e-9); /* Scaled */
    UA_DataValue_clear(&dv);
    dv = readNode(s, "Station.Dates");
    ck_assert(UA_Variant_hasArrayType(&dv.value, &UA_TYPES[UA_TYPES_STRING]));
    ck_assert_uint_eq(dv.value.arrayLength, 1);
    UA_DataValue_clear(&dv);
    UA_Int32 valueRank = 0;
    ck_assert_uint_eq(UA_Server_readValueRank(s, UA_NODEID_STRING(1, "Station.Temps"),
                                              &valueRank), UA_STATUSCODE_GOOD);
    ck_assert_int_eq(valueRank, UA_VALUERANK_ONE_DIMENSION);

    UA_EUInformation eu = readUnit(s, "Station.Temps");
    UA_String celsius = UA_STRING("°C");
    ck_assert(UA_String_equal(&eu.displayName.text, &celsius));
    ck_assert_int_eq(eu.unitId, 4408652); /* CEL */
    UA_EUInformation_clear(&eu);
    eu = readUnit(s, "Station.Dates");
    ck_assert_uint_eq(eu.displayName.text.length, 0); /* No unit */
    UA_EUInformation_clear(&eu);

    UA_Server_run_shutdown(s);
    UA_Server_delete(s);
} END_TEST

/* Patterns with wildcards in scale and units */
START_TEST(NodesPatterns) {
    UA_Server *s = newPollingServer(
        "{tcpEnabled:false,drivers:[{driver:'binding',name:'Weather',nodes:{from:'$.10865',"
        " scale:{'$.days[*].temperatureMin':0.1},"
        " units:{temperatureMin:'°C','$.forecast1.temperature':'dK'}},"
        " drivers:[{driver:'rest',path:'/weather',drivers:[{driver:'device'}]}]}]}");
    UA_Server_run_iterate(s, false);

    UA_DataValue dv = readNode(s, "Weather.days.0.temperatureMin");
    ck_assert(UA_Variant_hasScalarType(&dv.value, &UA_TYPES[UA_TYPES_DOUBLE]));
    ck_assert(*(UA_Double *)dv.value.data == 7.3); /* 73 / 10, not 73 * 0.1 */
    UA_DataValue_clear(&dv);
    dv = readNode(s, "Weather.forecast1.temperature"); /* Not scaled */
    ck_assert(UA_Variant_hasArrayType(&dv.value, &UA_TYPES[UA_TYPES_INT64]));
    UA_DataValue_clear(&dv);

    UA_EUInformation eu = readUnit(s, "Weather.days.0.temperatureMin");
    ck_assert_int_eq(eu.unitId, 4408652);
    UA_EUInformation_clear(&eu);
    eu = readUnit(s, "Weather.forecast1.temperature"); /* Unknown unit */
    UA_String dk = UA_STRING("dK");
    ck_assert(UA_String_equal(&eu.displayName.text, &dk));
    ck_assert_int_eq(eu.unitId, -1);
    UA_EUInformation_clear(&eu);

    UA_Server_run_shutdown(s);
    UA_Server_delete(s);
} END_TEST

/* A polling REST driver on the top level, referenced by its name */
START_TEST(NodesByName) {
    UA_Server *s = newPollingServer(
        "{tcpEnabled:false,drivers:[{driver:'device',name:'plc'},"
        "{driver:'rest',name:'poller',endpoint:'plc',path:'/weather'},"
        "{driver:'binding',name:'Flat',nodes:{driver:'poller'}}]}");
    UA_Server_run_iterate(s, false);
    assertInt(s, "Flat.10865.days.0.temperatureMin", 73);
    UA_Server_run_shutdown(s);
    UA_Server_delete(s);
} END_TEST

/* Invalid configurations of the binding itself */
static const char *invalidConfigs[] = {
    /* Nodes of an unknown driver */
    "{tcpEnabled:false,drivers:[{driver:'binding',nodes:{driver:'nobody'}}]}",
    /* A variable without call from a driver that is not a REST driver */
    "{tcpEnabled:false,drivers:[{driver:'binding',variables:{V:{type:'Int32',from:'a'}},"
    " drivers:[{driver:'http',url:'http://localhost'}]}]}",
    /* Wildcards in the path of the nodes */
    "{tcpEnabled:false,drivers:[{driver:'binding',nodes:{from:'$.a[*]'},"
    " drivers:[{driver:'rest',path:'/x',drivers:[{driver:'http',url:'http://localhost'}]}]}]}",
    /* A scale of a variable that is not Double */
    "{tcpEnabled:false,drivers:[{driver:'binding',variables:{V:{type:'Int32',from:'a',"
    " scale:0.1}},drivers:[{driver:'rest',path:'/x',"
    " drivers:[{driver:'http',url:'http://localhost'}]}]}]}",
    /* A unit that is not a string */
    "{tcpEnabled:false,drivers:[{driver:'binding',nodes:{units:{a:1}},"
    " drivers:[{driver:'rest',path:'/x',drivers:[{driver:'http',url:'http://localhost'}]}]}]}",
    /* A scale that is not a number */
    "{tcpEnabled:false,drivers:[{driver:'binding',nodes:{scale:{a:'x'}},"
    " drivers:[{driver:'rest',path:'/x',drivers:[{driver:'http',url:'http://localhost'}]}]}]}",
    /* Nodes of a driver that is not a REST driver */
    "{tcpEnabled:false,drivers:[{driver:'binding',nodes:{},"
    " drivers:[{driver:'http',url:'http://localhost'}]}]}",
    /* No call */
    "{tcpEnabled:false,drivers:[{driver:'binding',methods:{M:{}},"
    " drivers:[{driver:'http',url:'http://localhost'}]}]}",
    /* Unknown type */
    "{tcpEnabled:false,drivers:[{driver:'binding',"
    " methods:{M:{call:'x',inputs:{a:'Unknown'}}},"
    " drivers:[{driver:'http',url:'http://localhost'}]}]}",
    /* No path */
    "{tcpEnabled:false,drivers:[{driver:'binding',"
    " variables:{V:{call:'x',type:'Double'}},"
    " drivers:[{driver:'http',url:'http://localhost'}]}]}",
    /* Invalid interval */
    "{tcpEnabled:false,drivers:[{driver:'binding',"
    " variables:{V:{call:'x',type:'Double',from:'a',interval:0}},"
    " drivers:[{driver:'http',url:'http://localhost'}]}]}"
};

/* A driver that fails to start is logged, the server starts anyway */
START_TEST(InvalidConfiguration) {
    UA_Server *s = UA_Server_newFromFile(UA_STRING((char *)(uintptr_t)invalidConfigs[_i]));
    ck_assert_ptr_nonnull(s);
    ck_assert_uint_eq(UA_Server_run_startup(s), UA_STATUSCODE_GOOD);
    UA_Driver *drv = driverByName(s, "binding");
    ck_assert_ptr_nonnull(drv);
    ck_assert_int_eq(drv->state, UA_LIFECYCLESTATE_STOPPED);
    UA_NodeClass nc;
    ck_assert_uint_ne(UA_Server_readNodeClass(s, UA_NODEID_STRING(1, "binding"), &nc),
                      UA_STATUSCODE_GOOD);
    UA_Server_run_shutdown(s);
    ck_assert(UA_Server_getConfig(s)->asyncOperationCancelCallback == NULL);
    UA_Server_delete(s);
} END_TEST

static Suite *testSuite_Binding(void) {
    TCase *tc = tcase_create("Binding");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, NodesAreCreated);
    tcase_add_test(tc, OutputsFromTheResult);
    tcase_add_test(tc, InputArgumentsAndDefaults);
    tcase_add_test(tc, Errors);
    tcase_add_test(tc, AsyncResult);
    tcase_add_test(tc, CancelledByTimeout);
    tcase_add_test(tc, ShutdownWithOpenCall);
    tcase_add_test(tc, VariablesArePolled);
    TCase *tcConfig = tcase_create("Configuration");
    tcase_add_test(tcConfig, NestedDriver);
    tcase_add_loop_test(tcConfig, InvalidConfiguration, 0,
                        sizeof(invalidConfigs) / sizeof(invalidConfigs[0]));
    TCase *tcNodes = tcase_create("Nodes");
    tcase_add_test(tcNodes, NodesFromData);
    tcase_add_test(tcNodes, NodesFollowChanges);
    tcase_add_test(tcNodes, BadResultSetsStatus);
    tcase_add_test(tcNodes, NodesByName);
    tcase_add_test(tcNodes, NodesScale);
    tcase_add_test(tcNodes, PolledVariables);
    tcase_add_test(tcNodes, ArrayVariablesWithUnits);
    tcase_add_test(tcNodes, NodesPatterns);
    Suite *s = suite_create("Binding Driver");
    suite_add_tcase(s, tc);
    suite_add_tcase(s, tcConfig);
    suite_add_tcase(s, tcNodes);
    return s;
}

int main(void) {
    SRunner *sr = srunner_create(testSuite_Binding());
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
