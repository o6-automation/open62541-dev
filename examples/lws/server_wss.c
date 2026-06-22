/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 * Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 *
 * OPC UA Multi-Transport Server Example with Security
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * Demonstrates an OPC UA server listening on multiple transports with
 * all current (non-deprecated) OPC UA security policies:
 *
 * Transports:
 *   opc.tcp://localhost:4840  — Standard OPC UA binary over TCP
 *   opc.ws://localhost:4843   — OPC UA binary over WebSocket (plain)
 *   opc.wss://localhost:4844  — OPC UA binary over WebSocket with TLS
 *
 * Security Policies (each with Sign and SignAndEncrypt modes):
 *   SecurityPolicy#None
 *   SecurityPolicy#Basic256Sha256
 *   SecurityPolicy#Aes128_Sha256_RsaOaep
 *   SecurityPolicy#Aes256_Sha256_RsaPss
 *
 * Authentication:
 *   Anonymous access enabled
 *   Username/Password: user / password
 *
 * The opc.wss endpoint requires TLS certificate and private key arguments:
 *   ./server_wss <certificate.pem> <private_key.pem>
 *
 * Without TLS arguments, a self-signed certificate is auto-generated and
 * only opc.tcp and opc.ws endpoints are started (opc.wss requires PEM files).
 *
 * Build with: -DUA_ENABLE_LWS=ON -DUA_ENABLE_ENCRYPTION=OPENSSL
 */

#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/types.h>
#include <open62541/plugin/eventloop.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/securitypolicy.h>
#include <open62541/plugin/certificategroup_default.h>
#include <open62541/plugin/accesscontrol_default.h>
#include <open62541/plugin/historydata/history_data_backend_memory.h>
#include <open62541/plugin/historydata/history_data_gathering_default.h>
#include <open62541/plugin/historydata/history_database_default.h>
#include <open62541/plugin/historydatabase.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#include "../common.h"

static volatile UA_Boolean running = true;
static void stopHandler(int sign) {
    running = false;
}

/* -----------------------------------------------------------
 * Periodic event generation — fires every 10 seconds
 * ----------------------------------------------------------- */
static UA_UInt32 eventCounter = 0;

static void
generateEventCallback(UA_Server *server, void *data) {
    eventCounter++;

    /* Rotate severity through a few levels */
    static const UA_UInt16 severities[] = {100, 300, 500, 700, 900};
    UA_UInt16 severity = severities[eventCounter % 5];

    /* Build a human-readable message */
    char msgBuf[128];
    snprintf(msgBuf, sizeof(msgBuf),
             "Periodic server event #%u (severity %u)", eventCounter, severity);

    UA_LocalizedText message = UA_LOCALIZEDTEXT("en-US", msgBuf);

    /* Source: the Server object (i=2253) */
    UA_NodeId sourceNode = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER);

    /* Event type: BaseEventType (i=2041) */
    UA_NodeId eventType = UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE);

    UA_ByteString eventId = UA_BYTESTRING_NULL;
    UA_StatusCode retval = UA_Server_createEvent(
        server, sourceNode, eventType, severity,
        message, NULL, NULL, &eventId);

    if(retval == UA_STATUSCODE_GOOD) {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                    "Event #%u triggered (severity %u)", eventCounter, severity);
        UA_ByteString_clear(&eventId);
    } else {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                       "Failed to create event: 0x%08x", retval);
    }
}

/* -----------------------------------------------------------
 * Helper: Add a folder under a parent
 * ----------------------------------------------------------- */
static UA_NodeId
addFolder(UA_Server *server, UA_NodeId parentId,
          const char *name, UA_UInt32 numericId) {
    UA_ObjectAttributes oAttr = UA_ObjectAttributes_default;
    oAttr.displayName = UA_LOCALIZEDTEXT("en-US", (char *)name);
    UA_NodeId folderId = UA_NODEID_NUMERIC(1, numericId);
    UA_Server_addObjectNode(server, folderId, parentId,
                            UA_NS0ID(ORGANIZES),
                            UA_QUALIFIEDNAME(1, (char *)name),
                            UA_NS0ID(FOLDERTYPE), oAttr, NULL, NULL);
    return folderId;
}

/* -----------------------------------------------------------
 * Static Scalars
 * ----------------------------------------------------------- */
static void
addStaticScalars(UA_Server *server) {
    UA_NodeId folder = addFolder(server, UA_NS0ID(OBJECTSFOLDER), "Static Scalars", 10000);

    /* Int32 */
    {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        UA_Int32 val = 42;
        UA_Variant_setScalar(&attr.value, &val, &UA_TYPES[UA_TYPES_INT32]);
        attr.displayName = UA_LOCALIZEDTEXT("en-US", "Int32Scalar");
        attr.dataType = UA_TYPES[UA_TYPES_INT32].typeId;
        attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        UA_Server_addVariableNode(server, UA_NODEID_NUMERIC(1, 10001), folder,
                                  UA_NS0ID(ORGANIZES), UA_QUALIFIEDNAME(1, "Int32Scalar"),
                                  UA_NS0ID(BASEDATAVARIABLETYPE), attr, NULL, NULL);
    }
    /* Double */
    {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        UA_Double val = 3.14159265;
        UA_Variant_setScalar(&attr.value, &val, &UA_TYPES[UA_TYPES_DOUBLE]);
        attr.displayName = UA_LOCALIZEDTEXT("en-US", "DoubleScalar");
        attr.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        UA_Server_addVariableNode(server, UA_NODEID_NUMERIC(1, 10002), folder,
                                  UA_NS0ID(ORGANIZES), UA_QUALIFIEDNAME(1, "DoubleScalar"),
                                  UA_NS0ID(BASEDATAVARIABLETYPE), attr, NULL, NULL);
    }
    /* String */
    {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        UA_String val = UA_STRING("Hello OPC UA");
        UA_Variant_setScalar(&attr.value, &val, &UA_TYPES[UA_TYPES_STRING]);
        attr.displayName = UA_LOCALIZEDTEXT("en-US", "StringScalar");
        attr.dataType = UA_TYPES[UA_TYPES_STRING].typeId;
        attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        UA_Server_addVariableNode(server, UA_NODEID_NUMERIC(1, 10003), folder,
                                  UA_NS0ID(ORGANIZES), UA_QUALIFIEDNAME(1, "StringScalar"),
                                  UA_NS0ID(BASEDATAVARIABLETYPE), attr, NULL, NULL);
    }
    /* Boolean */
    {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        UA_Boolean val = true;
        UA_Variant_setScalar(&attr.value, &val, &UA_TYPES[UA_TYPES_BOOLEAN]);
        attr.displayName = UA_LOCALIZEDTEXT("en-US", "BooleanScalar");
        attr.dataType = UA_TYPES[UA_TYPES_BOOLEAN].typeId;
        attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        UA_Server_addVariableNode(server, UA_NODEID_NUMERIC(1, 10004), folder,
                                  UA_NS0ID(ORGANIZES), UA_QUALIFIEDNAME(1, "BooleanScalar"),
                                  UA_NS0ID(BASEDATAVARIABLETYPE), attr, NULL, NULL);
    }
    /* Float */
    {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        UA_Float val = 2.718f;
        UA_Variant_setScalar(&attr.value, &val, &UA_TYPES[UA_TYPES_FLOAT]);
        attr.displayName = UA_LOCALIZEDTEXT("en-US", "FloatScalar");
        attr.dataType = UA_TYPES[UA_TYPES_FLOAT].typeId;
        attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        UA_Server_addVariableNode(server, UA_NODEID_NUMERIC(1, 10005), folder,
                                  UA_NS0ID(ORGANIZES), UA_QUALIFIEDNAME(1, "FloatScalar"),
                                  UA_NS0ID(BASEDATAVARIABLETYPE), attr, NULL, NULL);
    }
    /* UInt16 */
    {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        UA_UInt16 val = 1234;
        UA_Variant_setScalar(&attr.value, &val, &UA_TYPES[UA_TYPES_UINT16]);
        attr.displayName = UA_LOCALIZEDTEXT("en-US", "UInt16Scalar");
        attr.dataType = UA_TYPES[UA_TYPES_UINT16].typeId;
        attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        UA_Server_addVariableNode(server, UA_NODEID_NUMERIC(1, 10006), folder,
                                  UA_NS0ID(ORGANIZES), UA_QUALIFIEDNAME(1, "UInt16Scalar"),
                                  UA_NS0ID(BASEDATAVARIABLETYPE), attr, NULL, NULL);
    }
    /* DateTime */
    {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        UA_DateTime val = UA_DateTime_now();
        UA_Variant_setScalar(&attr.value, &val, &UA_TYPES[UA_TYPES_DATETIME]);
        attr.displayName = UA_LOCALIZEDTEXT("en-US", "DateTimeScalar");
        attr.dataType = UA_TYPES[UA_TYPES_DATETIME].typeId;
        attr.accessLevel = UA_ACCESSLEVELMASK_READ;
        UA_Server_addVariableNode(server, UA_NODEID_NUMERIC(1, 10007), folder,
                                  UA_NS0ID(ORGANIZES), UA_QUALIFIEDNAME(1, "DateTimeScalar"),
                                  UA_NS0ID(BASEDATAVARIABLETYPE), attr, NULL, NULL);
    }
}

/* -----------------------------------------------------------
 * Static Arrays
 * ----------------------------------------------------------- */
static void
addStaticArrays(UA_Server *server) {
    UA_NodeId folder = addFolder(server, UA_NS0ID(OBJECTSFOLDER), "Static Arrays", 11000);

    /* Int32 Array */
    {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        UA_Int32 vals[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        UA_Variant_setArray(&attr.value, vals, 10, &UA_TYPES[UA_TYPES_INT32]);
        attr.displayName = UA_LOCALIZEDTEXT("en-US", "Int32Array");
        attr.dataType = UA_TYPES[UA_TYPES_INT32].typeId;
        attr.valueRank = UA_VALUERANK_ONE_DIMENSION;
        UA_UInt32 dim = 10;
        attr.arrayDimensions = &dim;
        attr.arrayDimensionsSize = 1;
        attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        UA_Server_addVariableNode(server, UA_NODEID_NUMERIC(1, 11001), folder,
                                  UA_NS0ID(ORGANIZES), UA_QUALIFIEDNAME(1, "Int32Array"),
                                  UA_NS0ID(BASEDATAVARIABLETYPE), attr, NULL, NULL);
    }
    /* Double Array */
    {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        UA_Double vals[] = {1.1, 2.2, 3.3, 4.4, 5.5};
        UA_Variant_setArray(&attr.value, vals, 5, &UA_TYPES[UA_TYPES_DOUBLE]);
        attr.displayName = UA_LOCALIZEDTEXT("en-US", "DoubleArray");
        attr.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        attr.valueRank = UA_VALUERANK_ONE_DIMENSION;
        UA_UInt32 dim = 5;
        attr.arrayDimensions = &dim;
        attr.arrayDimensionsSize = 1;
        attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        UA_Server_addVariableNode(server, UA_NODEID_NUMERIC(1, 11002), folder,
                                  UA_NS0ID(ORGANIZES), UA_QUALIFIEDNAME(1, "DoubleArray"),
                                  UA_NS0ID(BASEDATAVARIABLETYPE), attr, NULL, NULL);
    }
    /* String Array */
    {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        UA_String vals[3];
        vals[0] = UA_STRING("Alpha");
        vals[1] = UA_STRING("Beta");
        vals[2] = UA_STRING("Gamma");
        UA_Variant_setArray(&attr.value, vals, 3, &UA_TYPES[UA_TYPES_STRING]);
        attr.displayName = UA_LOCALIZEDTEXT("en-US", "StringArray");
        attr.dataType = UA_TYPES[UA_TYPES_STRING].typeId;
        attr.valueRank = UA_VALUERANK_ONE_DIMENSION;
        UA_UInt32 dim = 3;
        attr.arrayDimensions = &dim;
        attr.arrayDimensionsSize = 1;
        attr.accessLevel = UA_ACCESSLEVELMASK_READ;
        UA_Server_addVariableNode(server, UA_NODEID_NUMERIC(1, 11003), folder,
                                  UA_NS0ID(ORGANIZES), UA_QUALIFIEDNAME(1, "StringArray"),
                                  UA_NS0ID(BASEDATAVARIABLETYPE), attr, NULL, NULL);
    }
}

/* -----------------------------------------------------------
 * Dynamic Scalars (changing every second) + History
 * ----------------------------------------------------------- */
/* Node IDs for dynamic variables */
#define DYN_SINE_ID      12001
#define DYN_RAMP_ID      12002
#define DYN_SAWTOOTH_ID  12003
#define DYN_RANDOM_ID    12004
#define DYN_BOOL_ID      12005

static UA_UInt32 dynamicTick = 0;

static void
updateDynamicVariables(UA_Server *server, void *data) {
    (void)data;
    dynamicTick++;
    double t = (double)dynamicTick;

    /* Sine: amplitude 100, period ~60 ticks (60s at 1Hz) */
    {
        UA_Double val = 100.0 * sin(t * 2.0 * M_PI / 60.0);
        UA_Variant v;
        UA_Variant_setScalar(&v, &val, &UA_TYPES[UA_TYPES_DOUBLE]);
        UA_Server_writeValue(server, UA_NODEID_NUMERIC(1, DYN_SINE_ID), v);
    }
    /* Ramp: 0..100 over 100 ticks, then reset */
    {
        UA_Double val = fmod(t, 100.0);
        UA_Variant v;
        UA_Variant_setScalar(&v, &val, &UA_TYPES[UA_TYPES_DOUBLE]);
        UA_Server_writeValue(server, UA_NODEID_NUMERIC(1, DYN_RAMP_ID), v);
    }
    /* Sawtooth: -50..+50 over 50 ticks */
    {
        UA_Double val = fmod(t, 50.0) - 25.0;
        UA_Variant v;
        UA_Variant_setScalar(&v, &val, &UA_TYPES[UA_TYPES_DOUBLE]);
        UA_Server_writeValue(server, UA_NODEID_NUMERIC(1, DYN_SAWTOOTH_ID), v);
    }
    /* Random: 0..1000 */
    {
        UA_Int32 val = (UA_Int32)(rand() % 1000);
        UA_Variant v;
        UA_Variant_setScalar(&v, &val, &UA_TYPES[UA_TYPES_INT32]);
        UA_Server_writeValue(server, UA_NODEID_NUMERIC(1, DYN_RANDOM_ID), v);
    }
    /* Toggle Boolean every 5 ticks */
    {
        UA_Boolean val = ((dynamicTick / 5) % 2) == 0;
        UA_Variant v;
        UA_Variant_setScalar(&v, &val, &UA_TYPES[UA_TYPES_BOOLEAN]);
        UA_Server_writeValue(server, UA_NODEID_NUMERIC(1, DYN_BOOL_ID), v);
    }
}

static void
addDynamicScalars(UA_Server *server, UA_HistoryDataGathering *gathering) {
    UA_NodeId folder = addFolder(server, UA_NS0ID(OBJECTSFOLDER), "Dynamic Scalars", 12000);

    struct {
        const char *name;
        UA_UInt32 nodeId;
        const UA_DataType *type;
        UA_Boolean historize;
    } vars[] = {
        {"Sine",      DYN_SINE_ID,     &UA_TYPES[UA_TYPES_DOUBLE],  true},
        {"Ramp",      DYN_RAMP_ID,     &UA_TYPES[UA_TYPES_DOUBLE],  true},
        {"Sawtooth",  DYN_SAWTOOTH_ID, &UA_TYPES[UA_TYPES_DOUBLE],  true},
        {"Random",    DYN_RANDOM_ID,   &UA_TYPES[UA_TYPES_INT32],   true},
        {"Toggle",    DYN_BOOL_ID,     &UA_TYPES[UA_TYPES_BOOLEAN], false},
    };

    for(size_t i = 0; i < sizeof(vars)/sizeof(vars[0]); i++) {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        attr.displayName = UA_LOCALIZEDTEXT("en-US", (char *)vars[i].name);
        attr.dataType = vars[i].type->typeId;
        attr.accessLevel = UA_ACCESSLEVELMASK_READ;

        if(vars[i].historize) {
            attr.accessLevel |= UA_ACCESSLEVELMASK_HISTORYREAD;
            attr.historizing = true;
        }

        /* Set initial value */
        if(vars[i].type == &UA_TYPES[UA_TYPES_DOUBLE]) {
            UA_Double z = 0.0;
            UA_Variant_setScalar(&attr.value, &z, vars[i].type);
        } else if(vars[i].type == &UA_TYPES[UA_TYPES_INT32]) {
            UA_Int32 z = 0;
            UA_Variant_setScalar(&attr.value, &z, vars[i].type);
        } else if(vars[i].type == &UA_TYPES[UA_TYPES_BOOLEAN]) {
            UA_Boolean z = false;
            UA_Variant_setScalar(&attr.value, &z, vars[i].type);
        }

        UA_NodeId outId;
        UA_NodeId_init(&outId);
        UA_Server_addVariableNode(server, UA_NODEID_NUMERIC(1, vars[i].nodeId),
                                  folder, UA_NS0ID(ORGANIZES),
                                  UA_QUALIFIEDNAME(1, (char *)vars[i].name),
                                  UA_NS0ID(BASEDATAVARIABLETYPE),
                                  attr, NULL, &outId);

        /* Register historizing nodes */
        if(vars[i].historize && gathering) {
            UA_HistorizingNodeIdSettings setting;
            setting.historizingBackend = UA_HistoryDataBackend_Memory(1, 1000);
            setting.maxHistoryDataResponseSize = 100;
            setting.historizingUpdateStrategy = UA_HISTORIZINGUPDATESTRATEGY_VALUESET;
            gathering->registerNodeId(server, gathering->context, &outId, setting);
        }
        UA_NodeId_clear(&outId);
    }
}

/* -----------------------------------------------------------
 * Methods
 * ----------------------------------------------------------- */
static UA_StatusCode
multiplyMethodCallback(UA_Server *server,
                       const UA_NodeId *sessionId, void *sessionHandle,
                       const UA_NodeId *methodId, void *methodContext,
                       const UA_NodeId *objectId, void *objectContext,
                       size_t inputSize, const UA_Variant *input,
                       size_t outputSize, UA_Variant *output) {
    UA_Double a = *(UA_Double *)input[0].data;
    UA_Double b = *(UA_Double *)input[1].data;
    UA_Double result = a * b;
    UA_Variant_setScalarCopy(output, &result, &UA_TYPES[UA_TYPES_DOUBLE]);
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                "Multiply(%f, %f) = %f", a, b, result);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
helloMethodCallback(UA_Server *server,
                    const UA_NodeId *sessionId, void *sessionHandle,
                    const UA_NodeId *methodId, void *methodContext,
                    const UA_NodeId *objectId, void *objectContext,
                    size_t inputSize, const UA_Variant *input,
                    size_t outputSize, UA_Variant *output) {
    UA_String *name = (UA_String *)input[0].data;
    char buf[256];
    int len = snprintf(buf, sizeof(buf), "Hello, %.*s!",
                       (int)name->length, (char *)name->data);
    UA_String result = {(size_t)len, (UA_Byte *)buf};
    UA_Variant_setScalarCopy(output, &result, &UA_TYPES[UA_TYPES_STRING]);
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                "Hello(\"%.*s\")", (int)name->length, (char *)name->data);
    return UA_STATUSCODE_GOOD;
}

/* ScaleRange(InputRange: Range, Factor: Double) → Range
 * Scales a Range structure by multiplying Low and High by a factor.
 * Demonstrates structure input and output arguments. */
static UA_StatusCode
scaleRangeMethodCallback(UA_Server *server,
                         const UA_NodeId *sessionId, void *sessionHandle,
                         const UA_NodeId *methodId, void *methodContext,
                         const UA_NodeId *objectId, void *objectContext,
                         size_t inputSize, const UA_Variant *input,
                         size_t outputSize, UA_Variant *output) {
    UA_Range *range = (UA_Range *)input[0].data;
    UA_Double factor = *(UA_Double *)input[1].data;
    UA_Range result;
    result.low = range->low * factor;
    result.high = range->high * factor;
    UA_Variant_setScalarCopy(output, &result, &UA_TYPES[UA_TYPES_RANGE]);
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                "ScaleRange({low=%f, high=%f}, %f) = {low=%f, high=%f}",
                range->low, range->high, factor, result.low, result.high);
    return UA_STATUSCODE_GOOD;
}

/* ScaleArray(Values: Double[], Factor: Double) → Double[]
 * Multiplies every element of a 1-D array by a scalar factor and
 * returns a new array of the same length. Demonstrates one-
 * dimensional array input/output. */
static UA_StatusCode
scaleArrayMethodCallback(UA_Server *server,
                         const UA_NodeId *sessionId, void *sessionHandle,
                         const UA_NodeId *methodId, void *methodContext,
                         const UA_NodeId *objectId, void *objectContext,
                         size_t inputSize, const UA_Variant *input,
                         size_t outputSize, UA_Variant *output) {
    if (inputSize < 2 || !UA_Variant_hasArrayType(&input[0], &UA_TYPES[UA_TYPES_DOUBLE]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_Double *src = (UA_Double *)input[0].data;
    size_t n = input[0].arrayLength;
    UA_Double factor = *(UA_Double *)input[1].data;

    UA_Double *dst = (UA_Double *)UA_Array_new(n, &UA_TYPES[UA_TYPES_DOUBLE]);
    if (!dst) return UA_STATUSCODE_BADOUTOFMEMORY;
    for (size_t i = 0; i < n; i++) dst[i] = src[i] * factor;

    UA_Variant_setArray(output, dst, n, &UA_TYPES[UA_TYPES_DOUBLE]);
    output->storageType = UA_VARIANT_DATA; /* take ownership */
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                "ScaleArray(len=%zu, factor=%f)", n, factor);
    return UA_STATUSCODE_GOOD;
}

/* TransposeMatrix(Matrix: Double[N,M]) → Double[M,N]
 * Transposes a 2-D matrix supplied as an OPC UA multi-dimensional array.
 * Demonstrates multi-dimensional array input/output (arrayDimensions). */
static UA_StatusCode
transposeMatrixMethodCallback(UA_Server *server,
                              const UA_NodeId *sessionId, void *sessionHandle,
                              const UA_NodeId *methodId, void *methodContext,
                              const UA_NodeId *objectId, void *objectContext,
                              size_t inputSize, const UA_Variant *input,
                              size_t outputSize, UA_Variant *output) {
    if (inputSize < 1 || !UA_Variant_hasArrayType(&input[0], &UA_TYPES[UA_TYPES_DOUBLE]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if (input[0].arrayDimensionsSize != 2)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_UInt32 rows = input[0].arrayDimensions[0];
    UA_UInt32 cols = input[0].arrayDimensions[1];
    if ((size_t)rows * (size_t)cols != input[0].arrayLength)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_Double *src = (UA_Double *)input[0].data;
    size_t total = (size_t)rows * (size_t)cols;
    UA_Double *dst = (UA_Double *)UA_Array_new(total, &UA_TYPES[UA_TYPES_DOUBLE]);
    if (!dst) return UA_STATUSCODE_BADOUTOFMEMORY;

    /* Transpose: dst[c,r] = src[r,c]   (row-major) */
    for (UA_UInt32 r = 0; r < rows; r++) {
        for (UA_UInt32 c = 0; c < cols; c++) {
            dst[(size_t)c * rows + r] = src[(size_t)r * cols + c];
        }
    }

    UA_Variant_setArray(output, dst, total, &UA_TYPES[UA_TYPES_DOUBLE]);
    output->storageType = UA_VARIANT_DATA;
    UA_UInt32 *dims = (UA_UInt32 *)UA_Array_new(2, &UA_TYPES[UA_TYPES_UINT32]);
    if (dims) {
        dims[0] = cols;
        dims[1] = rows;
        output->arrayDimensions = dims;
        output->arrayDimensionsSize = 2;
    }
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                "TransposeMatrix(%ux%u) -> %ux%u", rows, cols, cols, rows);
    return UA_STATUSCODE_GOOD;
}

static void
addMethods(UA_Server *server) {
    UA_NodeId folder = addFolder(server, UA_NS0ID(OBJECTSFOLDER), "Methods", 13000);

    /* Multiply(a: Double, b: Double) → Double */
    {
        UA_Argument inputs[2];
        UA_Argument_init(&inputs[0]);
        inputs[0].name = UA_STRING("A");
        inputs[0].description = UA_LOCALIZEDTEXT("en-US", "First operand");
        inputs[0].dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        inputs[0].valueRank = UA_VALUERANK_SCALAR;

        UA_Argument_init(&inputs[1]);
        inputs[1].name = UA_STRING("B");
        inputs[1].description = UA_LOCALIZEDTEXT("en-US", "Second operand");
        inputs[1].dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        inputs[1].valueRank = UA_VALUERANK_SCALAR;

        UA_Argument output;
        UA_Argument_init(&output);
        output.name = UA_STRING("Result");
        output.description = UA_LOCALIZEDTEXT("en-US", "Product of A and B");
        output.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        output.valueRank = UA_VALUERANK_SCALAR;

        UA_MethodAttributes attr = UA_MethodAttributes_default;
        attr.displayName = UA_LOCALIZEDTEXT("en-US", "Multiply");
        attr.description = UA_LOCALIZEDTEXT("en-US", "Multiplies two numbers");
        attr.executable = true;
        attr.userExecutable = true;
        UA_Server_addMethodNode(server, UA_NODEID_NUMERIC(1, 13001), folder,
                                UA_NS0ID(HASCOMPONENT),
                                UA_QUALIFIEDNAME(1, "Multiply"),
                                attr, &multiplyMethodCallback,
                                2, inputs, 1, &output, NULL, NULL);
    }

    /* Hello(Name: String) → String */
    {
        UA_Argument input;
        UA_Argument_init(&input);
        input.name = UA_STRING("Name");
        input.description = UA_LOCALIZEDTEXT("en-US", "Your name");
        input.dataType = UA_TYPES[UA_TYPES_STRING].typeId;
        input.valueRank = UA_VALUERANK_SCALAR;

        UA_Argument output;
        UA_Argument_init(&output);
        output.name = UA_STRING("Greeting");
        output.description = UA_LOCALIZEDTEXT("en-US", "Greeting message");
        output.dataType = UA_TYPES[UA_TYPES_STRING].typeId;
        output.valueRank = UA_VALUERANK_SCALAR;

        UA_MethodAttributes attr = UA_MethodAttributes_default;
        attr.displayName = UA_LOCALIZEDTEXT("en-US", "Hello");
        attr.description = UA_LOCALIZEDTEXT("en-US", "Returns a greeting");
        attr.executable = true;
        attr.userExecutable = true;
        UA_Server_addMethodNode(server, UA_NODEID_NUMERIC(1, 13002), folder,
                                UA_NS0ID(HASCOMPONENT),
                                UA_QUALIFIEDNAME(1, "Hello"),
                                attr, &helloMethodCallback,
                                1, &input, 1, &output, NULL, NULL);
    }

    /* ScaleRange(InputRange: Range, Factor: Double) → Range */
    {
        UA_Argument inputs[2];
        UA_Argument_init(&inputs[0]);
        inputs[0].name = UA_STRING("InputRange");
        inputs[0].description = UA_LOCALIZEDTEXT("en-US", "Range to scale (Low, High)");
        inputs[0].dataType = UA_TYPES[UA_TYPES_RANGE].typeId;
        inputs[0].valueRank = UA_VALUERANK_SCALAR;

        UA_Argument_init(&inputs[1]);
        inputs[1].name = UA_STRING("Factor");
        inputs[1].description = UA_LOCALIZEDTEXT("en-US", "Scale factor");
        inputs[1].dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        inputs[1].valueRank = UA_VALUERANK_SCALAR;

        UA_Argument output;
        UA_Argument_init(&output);
        output.name = UA_STRING("ScaledRange");
        output.description = UA_LOCALIZEDTEXT("en-US", "Resulting scaled Range");
        output.dataType = UA_TYPES[UA_TYPES_RANGE].typeId;
        output.valueRank = UA_VALUERANK_SCALAR;

        UA_MethodAttributes attr = UA_MethodAttributes_default;
        attr.displayName = UA_LOCALIZEDTEXT("en-US", "ScaleRange");
        attr.description = UA_LOCALIZEDTEXT("en-US",
            "Scales a Range structure by multiplying Low and High by a factor");
        attr.executable = true;
        attr.userExecutable = true;
        UA_Server_addMethodNode(server, UA_NODEID_NUMERIC(1, 13003), folder,
                                UA_NS0ID(HASCOMPONENT),
                                UA_QUALIFIEDNAME(1, "ScaleRange"),
                                attr, &scaleRangeMethodCallback,
                                2, inputs, 1, &output, NULL, NULL);
    }

    /* ScaleArray(Values: Double[], Factor: Double) → Double[] */
    {
        UA_Argument inputs[2];
        UA_Argument_init(&inputs[0]);
        inputs[0].name = UA_STRING("Values");
        inputs[0].description = UA_LOCALIZEDTEXT("en-US",
            "1-D array of doubles to be multiplied element-wise");
        inputs[0].dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        inputs[0].valueRank = UA_VALUERANK_ONE_DIMENSION;

        UA_Argument_init(&inputs[1]);
        inputs[1].name = UA_STRING("Factor");
        inputs[1].description = UA_LOCALIZEDTEXT("en-US", "Scalar multiplier");
        inputs[1].dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        inputs[1].valueRank = UA_VALUERANK_SCALAR;

        UA_Argument output;
        UA_Argument_init(&output);
        output.name = UA_STRING("Scaled");
        output.description = UA_LOCALIZEDTEXT("en-US", "Element-wise scaled array");
        output.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        output.valueRank = UA_VALUERANK_ONE_DIMENSION;

        UA_MethodAttributes attr = UA_MethodAttributes_default;
        attr.displayName = UA_LOCALIZEDTEXT("en-US", "ScaleArray");
        attr.description = UA_LOCALIZEDTEXT("en-US",
            "Consumes a 1-D Double array and returns a new array with each "
            "value multiplied by Factor");
        attr.executable = true;
        attr.userExecutable = true;
        UA_Server_addMethodNode(server, UA_NODEID_NUMERIC(1, 13004), folder,
                                UA_NS0ID(HASCOMPONENT),
                                UA_QUALIFIEDNAME(1, "ScaleArray"),
                                attr, &scaleArrayMethodCallback,
                                2, inputs, 1, &output, NULL, NULL);
    }

    /* TransposeMatrix(Matrix: Double[N,M]) → Double[M,N] */
    {
        UA_Argument input;
        UA_Argument_init(&input);
        input.name = UA_STRING("Matrix");
        input.description = UA_LOCALIZEDTEXT("en-US",
            "Multi-dimensional Double array (matrix) to transpose");
        input.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        input.valueRank = 2; /* exactly 2 dimensions */
        UA_UInt32 inDims[2] = {0, 0}; /* any size accepted */
        input.arrayDimensions = inDims;
        input.arrayDimensionsSize = 2;

        UA_Argument output;
        UA_Argument_init(&output);
        output.name = UA_STRING("Transposed");
        output.description = UA_LOCALIZEDTEXT("en-US", "Transposed matrix");
        output.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        output.valueRank = 2;
        UA_UInt32 outDims[2] = {0, 0};
        output.arrayDimensions = outDims;
        output.arrayDimensionsSize = 2;

        UA_MethodAttributes attr = UA_MethodAttributes_default;
        attr.displayName = UA_LOCALIZEDTEXT("en-US", "TransposeMatrix");
        attr.description = UA_LOCALIZEDTEXT("en-US",
            "Consumes a 2-D Double matrix (rows x cols) and returns its "
            "transpose (cols x rows). Demonstrates multi-dimensional array "
            "input and output.");
        attr.executable = true;
        attr.userExecutable = true;
        UA_Server_addMethodNode(server, UA_NODEID_NUMERIC(1, 13005), folder,
                                UA_NS0ID(HASCOMPONENT),
                                UA_QUALIFIEDNAME(1, "TransposeMatrix"),
                                attr, &transposeMatrixMethodCallback,
                                1, &input, 1, &output, NULL, NULL);
    }
}

int main(int argc, char *argv[]) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    /* ---------------------------------------------------------
     * Parse optional port overrides: --tcp-port N  --ws-port N
     * Must come before cert/key args. Filter them out before
     * the original argc/argv processing below.
     * --------------------------------------------------------- */
    UA_UInt16 tcpPort = 4840;
    UA_UInt16 wsPort  = 4843;
    /* Build a filtered argv without the port flags */
    int   fargc = 0;
    char *fargv[16];
    for(int i = 0; i < argc && i < 15; i++) {
        if(strcmp(argv[i], "--tcp-port") == 0 && i + 1 < argc) {
            tcpPort = (UA_UInt16)atoi(argv[++i]);
        } else if(strcmp(argv[i], "--ws-port") == 0 && i + 1 < argc) {
            wsPort = (UA_UInt16)atoi(argv[++i]);
        } else {
            fargv[fargc++] = argv[i];
        }
    }
    fargv[fargc] = NULL;
    /* Replace argc/argv with the filtered version for cert/key handling */
    argc = fargc;
    argv = fargv;

    /* ---------------------------------------------------------
     * Certificate & private key: load from CLI or auto-generate
     * --------------------------------------------------------- */
    UA_ByteString certificate = UA_BYTESTRING_NULL;
    UA_ByteString privateKey = UA_BYTESTRING_NULL;
    UA_Boolean hasTls = false;

    if(argc >= 3) {
        /* CLI-provided cert/key (PEM or DER) */
        certificate = loadFile(argv[1]);
        privateKey = loadFile(argv[2]);
        if(certificate.length > 0 && privateKey.length > 0) {
            hasTls = true;
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                        "Loaded certificate and key from files — "
                        "TLS enabled for opc.wss://");
        } else {
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                           "Could not load certificate/key files");
        }
    }

    /* Auto-generate a self-signed certificate when none provided */
    if(certificate.length == 0 || privateKey.length == 0) {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                    "No certificate provided — generating self-signed certificate");
        UA_String subject[3] = {
            UA_STRING_STATIC("C=DE"),
            UA_STRING_STATIC("O=open62541"),
            UA_STRING_STATIC("CN=open62541Server@localhost")
        };
        UA_String subjectAltName[2] = {
            UA_STRING_STATIC("DNS:localhost"),
            UA_STRING_STATIC("URI:urn:open62541.server.application")
        };
        UA_KeyValueMap *kvm = UA_KeyValueMap_new();
        UA_UInt16 expiresIn = 365;
        UA_KeyValueMap_setScalar(kvm, UA_QUALIFIEDNAME(0, "expires-in-days"),
                                 (void *)&expiresIn, &UA_TYPES[UA_TYPES_UINT16]);
        UA_UInt16 keySize = 2048;
        UA_KeyValueMap_setScalar(kvm, UA_QUALIFIEDNAME(0, "key-size-bits"),
                                 (void *)&keySize, &UA_TYPES[UA_TYPES_UINT16]);
        UA_StatusCode certRet = UA_CreateCertificate(
            UA_Log_Stdout, subject, 3, subjectAltName, 2,
            UA_CERTIFICATEFORMAT_DER, kvm, &privateKey, &certificate);
        UA_KeyValueMap_delete(kvm);
        if(certRet != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                         "Certificate generation failed: %s",
                         UA_StatusCode_name(certRet));
            return EXIT_FAILURE;
        }
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                    "Self-signed certificate generated (2048-bit RSA, 365 days)");
    }

    /* ---------------------------------------------------------
     * Server creation & basic configuration
     * --------------------------------------------------------- */
    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);

    /* Initialize defaults (no policies/endpoints yet) */
    UA_StatusCode retval = UA_ServerConfig_setBasics(config);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                     "UA_ServerConfig_setBasics failed: %s",
                     UA_StatusCode_name(retval));
        goto cleanup;
    }

    /* Set ApplicationUri to match certificate SAN */
    UA_String_clear(&config->applicationDescription.applicationUri);
    config->applicationDescription.applicationUri =
        UA_STRING_ALLOC("urn:open62541.server.application");
    UA_LocalizedText_clear(&config->applicationDescription.applicationName);
    config->applicationDescription.applicationName =
        UA_LOCALIZEDTEXT_ALLOC("en-US", "open62541 OPC UA Server");

    /* ---------------------------------------------------------
     * Security policies: None + all current non-deprecated RSA
     * --------------------------------------------------------- */
    retval = UA_ServerConfig_addSecurityPolicyNone(config, &certificate);
    if(retval != UA_STATUSCODE_GOOD)
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                       "addSecurityPolicyNone failed: %s",
                       UA_StatusCode_name(retval));

    retval = UA_ServerConfig_addSecurityPolicyBasic256Sha256(
        config, &certificate, &privateKey);
    if(retval != UA_STATUSCODE_GOOD)
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                       "addSecurityPolicyBasic256Sha256 failed: %s",
                       UA_StatusCode_name(retval));

    retval = UA_ServerConfig_addSecurityPolicyAes128Sha256RsaOaep(
        config, &certificate, &privateKey);
    if(retval != UA_STATUSCODE_GOOD)
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                       "addSecurityPolicyAes128Sha256RsaOaep failed: %s",
                       UA_StatusCode_name(retval));

    retval = UA_ServerConfig_addSecurityPolicyAes256Sha256RsaPss(
        config, &certificate, &privateKey);
    if(retval != UA_STATUSCODE_GOOD)
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                       "addSecurityPolicyAes256Sha256RsaPss failed: %s",
                       UA_StatusCode_name(retval));

    /* Create all (policy × mode) endpoint combinations */
    retval = UA_ServerConfig_addAllEndpoints(config);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                     "addAllEndpoints failed: %s",
                     UA_StatusCode_name(retval));
        goto cleanup;
    }

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                "Configured %lu security policies, %lu endpoints",
                (unsigned long)config->securityPoliciesSize,
                (unsigned long)config->endpointsSize);

    /* ---------------------------------------------------------
     * Certificate validation: accept all (dev/test server)
     * --------------------------------------------------------- */
    config->secureChannelPKI.clear(&config->secureChannelPKI);
    UA_CertificateGroup_AcceptAll(&config->secureChannelPKI);
    config->sessionPKI.clear(&config->sessionPKI);
    UA_CertificateGroup_AcceptAll(&config->sessionPKI);

    /* ---------------------------------------------------------
     * Access control: anonymous + username/password
     * --------------------------------------------------------- */
    UA_UsernamePasswordLogin logins[1];
    logins[0].username = UA_STRING("user");
    logins[0].password = UA_STRING("password");
    config->accessControl.clear(&config->accessControl);
    const UA_String userTokenPolicyUri =
        UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
    retval = UA_AccessControl_default(config, true,
                                      &userTokenPolicyUri, 1, logins);
    if(retval != UA_STATUSCODE_GOOD)
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                       "AccessControl_default failed: %s",
                       UA_StatusCode_name(retval));

    /* ---------------------------------------------------------
     * WebSocket transport (WS + WSS)
     * --------------------------------------------------------- */

    /* Register a WebSocket ConnectionManager on the EventLoop.
     * The server's BinaryProtocolManager will use it for opc.ws(s):// URLs. */
    UA_ConnectionManager *wsCM =
        UA_ConnectionManager_new_POSIX_WS(UA_STRING("ws connection manager"));
    if(wsCM)
        config->eventLoop->registerEventSource(config->eventLoop,
                                               &wsCM->eventSource);

    /* Configure server transport URLs */
    UA_Array_delete(config->serverUrls, config->serverUrlsSize,
                    &UA_TYPES[UA_TYPES_STRING]);
    config->serverUrls = NULL;
    config->serverUrlsSize = 0;

    if(hasTls) {
        /* Load WSS TLS cert/key (transport-layer TLS, separate from
         * OPC UA message security) */
        config->wssCertificate = loadFile(argv[1]);
        config->wssPrivateKey = loadFile(argv[2]);

        char tcpUrl[64], wsUrl[64], wssUrl[64];
        snprintf(tcpUrl, sizeof(tcpUrl), "opc.tcp://localhost:%u", (unsigned)tcpPort);
        snprintf(wsUrl,  sizeof(wsUrl),  "opc.ws://localhost:%u",  (unsigned)wsPort);
        snprintf(wssUrl, sizeof(wssUrl), "opc.wss://localhost:%u", (unsigned)(wsPort + 1));
        UA_String serverUrls[3];
        serverUrls[0] = UA_STRING(tcpUrl);
        serverUrls[1] = UA_STRING(wsUrl);
        serverUrls[2] = UA_STRING(wssUrl);
        UA_Array_copy(serverUrls, 3,
                      (void **)&config->serverUrls, &UA_TYPES[UA_TYPES_STRING]);
        config->serverUrlsSize = 3;
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                    "Transports: opc.tcp://:%u, opc.ws://:%u, opc.wss://:%u",
                    (unsigned)tcpPort, (unsigned)wsPort, (unsigned)(wsPort + 1));
    } else {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                    "No PEM files for WSS transport. Usage: %s [cert.pem key.pem]",
                    argv[0]);
        char tcpUrl[64], wsUrl[64];
        snprintf(tcpUrl, sizeof(tcpUrl), "opc.tcp://localhost:%u", (unsigned)tcpPort);
        snprintf(wsUrl,  sizeof(wsUrl),  "opc.ws://localhost:%u",  (unsigned)wsPort);
        UA_String serverUrls[2];
        serverUrls[0] = UA_STRING(tcpUrl);
        serverUrls[1] = UA_STRING(wsUrl);
        UA_Array_copy(serverUrls, 2,
                      (void **)&config->serverUrls, &UA_TYPES[UA_TYPES_STRING]);
        config->serverUrlsSize = 2;
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                    "Transports: opc.tcp://:%u, opc.ws://:%u",
                    (unsigned)tcpPort, (unsigned)wsPort);
    }

    /* Done with OPC UA application-layer certificate */
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);

    /* --- History database setup --- */
    UA_HistoryDataGathering gathering = UA_HistoryDataGathering_Default(5);
    config->historyDatabase = UA_HistoryDatabase_default(gathering);

    /* --- Add test data nodes --- */
    addStaticScalars(server);
    addStaticArrays(server);
    addDynamicScalars(server, &gathering);
    addMethods(server);

    /* Update dynamic variables every 500ms */
    UA_UInt64 dynamicCallbackId = 0;
    UA_Server_addRepeatedCallback(server, updateDynamicVariables, NULL,
                                  500.0, &dynamicCallbackId);
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                "Dynamic variables updating every 500ms");

    /* Register a periodic event every 5 seconds */
    UA_UInt64 eventCallbackId = 0;
    UA_Server_addRepeatedCallback(server, generateEventCallback, NULL,
                                  5000.0, &eventCallbackId);
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                "Event generation enabled — firing every 5 seconds");

    /* Run until ctrl-c */
    retval = UA_Server_run(server, &running);

 cleanup:
    UA_Server_delete(server);
    return retval == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}
