/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

/* Load: the information model of the REST driver (the object Objects/<name>
 * with methods, variables and the nodes of the polled data), events and
 * alarms. Works on the parsed answers (RestData) only. */

#include "rest_internal.h"

#ifdef UA_ENABLE_DRIVER_REST

#define REST_FAILURE_SEVERITY 500
#define REST_RECOVERY_SEVERITY 100

#define MODEL_DEFAULT_INTERVAL_MS 1000.0
#define AUTO_MAX_PATH 512

typedef struct ModelDriver ModelDriver;

typedef struct {
    UA_String name;
    const UA_DataType *type;
    UA_String from;
    UA_Boolean array;
} ModelArgument;

typedef struct {
    ModelDriver *md;
    UA_String name;
    char *call;
    UA_KeyValueMap defaults;
    UA_NodeId nodeId;
} ModelNode;

typedef struct {
    ModelNode node;
    size_t inputsSize;
    ModelArgument *inputs;
    size_t outputsSize;
    ModelArgument *outputs;
} ModelMethod;

typedef struct {
    ModelNode node;
    ModelArgument value;
    UA_Double interval;
    UA_UInt64 firstCallbackId;
    UA_UInt64 callbackId;
    UA_Boolean busy;
    UA_StatusCode lastStatus;
    UA_String unit; /* Empty without engineering units */
    UA_Double scale; /* 0 without scaling */
} ModelVariable;

typedef struct PendingCall {
    LIST_ENTRY(PendingCall) next;
    ModelMethod *method;
    UA_Variant *output;
    UA_Boolean inCallback;
    UA_Boolean done;
    UA_StatusCode status;
} PendingCall;

typedef struct {
    UA_String path;
    UA_NodeId nodeId;
    UA_Boolean variable;
    UA_UInt32 seen;
} AutoNode;

/* The data of the polls as nodes */
typedef struct {
    UA_Boolean enabled;
    UA_String from;
    UA_KeyValueMap scale; /* Factor by key name or path pattern */
    UA_KeyValueMap units; /* Unit by key name or path pattern */
    UA_StatusCode lastStatus;
    UA_UInt32 generation;
    size_t cursor; /* The next node in the usual order of the results */
    size_t nodesSize;
    AutoNode *nodes;
} AutoNodes;

struct ModelDriver {
    UA_Driver drv;
    RestDriver *rd; /* The owner, which is called and polls */
    UA_UInt16 ns;     /* Of the NodeIds and BrowseNames, default 1 */
    UA_NodeId parent; /* Of the object, default the Objects folder */
    UA_NodeId objectId;
    size_t methodsSize;
    ModelMethod *methods;
    size_t variablesSize;
    ModelVariable *variables;
    AutoNodes autoNodes;
    LIST_HEAD(, PendingCall) calls;
    size_t polls;
};

/***********/
/* Helpers */
/***********/

static UA_Logger *
getLogger(ModelDriver *md) {
    return UA_Server_getConfig(md->drv.server)->logging;
}

static const struct {
    const char *name;
    UA_UInt16 index;
} modelTypes[] = {
    {"Boolean", UA_TYPES_BOOLEAN}, {"SByte", UA_TYPES_SBYTE},
    {"Byte", UA_TYPES_BYTE}, {"Int16", UA_TYPES_INT16},
    {"UInt16", UA_TYPES_UINT16}, {"Int32", UA_TYPES_INT32},
    {"UInt32", UA_TYPES_UINT32}, {"Int64", UA_TYPES_INT64},
    {"UInt64", UA_TYPES_UINT64}, {"Float", UA_TYPES_FLOAT},
    {"Double", UA_TYPES_DOUBLE}, {"String", UA_TYPES_STRING},
    {"DateTime", UA_TYPES_DATETIME}, {"ByteString", UA_TYPES_BYTESTRING}
};

static const UA_DataType *
findType(const UA_String *name) {
    if(!name)
        return NULL;
    for(size_t i = 0; i < sizeof(modelTypes) / sizeof(modelTypes[0]); i++) {
        UA_String n = UA_STRING((char *)(uintptr_t)modelTypes[i].name);
        if(UA_String_equal(&n, name))
            return &UA_TYPES[modelTypes[i].index];
    }
    return NULL;
}

static UA_StatusCode
makeNodeId(const ModelDriver *md, const UA_String *child, UA_NodeId *out) {
    UA_String id = UA_STRING_NULL;
    UA_StatusCode res = UA_String_append(&id, md->drv.name);
    if(child) {
        res |= UA_String_append(&id, UA_STRING("."));
        res |= UA_String_append(&id, *child);
    }
    if(res != UA_STATUSCODE_GOOD) {
        UA_String_clear(&id);
        return res;
    }
    UA_NodeId_init(out);
    out->namespaceIndex = md->ns;
    out->identifierType = UA_NODEIDTYPE_STRING;
    out->identifier.string = id;
    return UA_STATUSCODE_GOOD;
}

/* UNECE codes of common units, see the namespace below */
static const struct {
    const char *symbol;
    const char *code;
} unitCodes[] = {
    {"°C", "CEL"}, {"%", "P1"}, {"hPa", "A97"}, {"mm", "MMT"}, {"km/h", "KMH"},
    {"m/s", "MTS"}, {"s", "SEC"}, {"min", "MIN"}, {"h", "HUR"}, {"W", "WTT"},
    {"kWh", "KWH"}, {"V", "VLT"}, {"A", "AMP"}
};

/* The code letters as a number, -1 for an unknown unit */
static UA_Int32
unitId(const UA_String *unit) {
    for(size_t i = 0; i < sizeof(unitCodes) / sizeof(unitCodes[0]); i++) {
        UA_String symbol = UA_STRING((char *)(uintptr_t)unitCodes[i].symbol);
        if(!UA_String_equal(&symbol, unit))
            continue;
        UA_Int32 id = 0;
        for(const char *c = unitCodes[i].code; *c; c++)
            id = (id << 8) | (UA_Byte)*c;
        return id;
    }
    return -1;
}

static UA_StatusCode
addEngineeringUnits(ModelDriver *md, const UA_NodeId variable, const UA_String unit) {
    UA_EUInformation eu;
    UA_EUInformation_init(&eu);
    eu.namespaceUri = UA_STRING("http://www.opcfoundation.org/UA/units/un/cefact");
    eu.unitId = unitId(&unit);
    eu.displayName.text = unit;
    eu.description.text = unit;
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    attr.displayName.text = UA_STRING("EngineeringUnits");
    attr.dataType = UA_TYPES[UA_TYPES_EUINFORMATION].typeId;
    attr.valueRank = UA_VALUERANK_SCALAR;
    UA_Variant_setScalar(&attr.value, &eu, &UA_TYPES[UA_TYPES_EUINFORMATION]);
    return UA_Server_addVariableNode(md->drv.server, UA_NODEID_NULL, variable,
                                     UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY),
                                     UA_QUALIFIEDNAME(0, "EngineeringUnits"),
                                     UA_NODEID_NUMERIC(0, UA_NS0ID_PROPERTYTYPE),
                                     attr, NULL, NULL);
}

/*****************/
/* Configuration */
/*****************/

/* Without a call, node->call is NULL */
static UA_StatusCode
parseNode(ModelDriver *md, const UA_KeyValuePair *def, UA_Boolean needsCall,
          ModelNode *node) {
    UA_KeyValueMap map = driverParamsMap(&def->value);
    const UA_String *call = driverParamsString(&map, "call");
    node->md = md;
    node->name = def->key.name;
    if(!call && needsCall) {
        UA_LOG_ERROR(getLogger(md), UA_LOGCATEGORY_SERVER,
                     "REST driver \"%S\": \"%S\" needs a call",
                     md->drv.name, node->name);
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }
    node->call = call ? driverCString(call) : NULL;
    if(call && !node->call)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    node->defaults =
        driverParamsMap(UA_KeyValueMap_get(&map, UA_QUALIFIEDNAME(0, "defaults")));
    return UA_STATUSCODE_GOOD;
}

static void
clearNode(ModelNode *node) {
    UA_free(node->call);
    UA_NodeId_clear(&node->nodeId);
}

static UA_KeyValueMap
getParamsMap(const UA_KeyValueMap *map, const char *key) {
    UA_QualifiedName qn = UA_QUALIFIEDNAME(0, (char *)(uintptr_t)key);
    return driverParamsMap(UA_KeyValueMap_get(map, qn));
}

static UA_StatusCode
typeError(ModelDriver *md, const UA_String *owner, const UA_String *name) {
    UA_LOG_ERROR(getLogger(md), UA_LOGCATEGORY_SERVER,
                 "REST driver \"%S\": \"%S\" of \"%S\" needs a known type",
                 md->drv.name, *name, *owner);
    return UA_STATUSCODE_BADCONFIGURATIONERROR;
}

static UA_StatusCode
parseArguments(ModelDriver *md, const UA_KeyValuePair *method, const char *key,
               UA_Boolean outputs, size_t *size, ModelArgument **args) {
    UA_KeyValueMap def = driverParamsMap(&method->value);
    UA_KeyValueMap list = getParamsMap(&def, key);
    if(list.mapSize == 0)
        return UA_STATUSCODE_GOOD;
    *args = (ModelArgument *)UA_calloc(list.mapSize, sizeof(ModelArgument));
    if(!*args)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    *size = list.mapSize;
    for(size_t i = 0; i < list.mapSize; i++) {
        ModelArgument *arg = &(*args)[i];
        const UA_Variant *v = &list.map[i].value;
        arg->name = list.map[i].key.name;
        arg->from = arg->name;
        if(UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_STRING])) {
            arg->type = findType((const UA_String *)v->data);
        } else if(outputs) {
            UA_KeyValueMap out = driverParamsMap(v);
            arg->type = findType(driverParamsString(&out, "type"));
            const UA_String *from = driverParamsString(&out, "from");
            if(from)
                arg->from = *from;
        }
        arg->array = restPathHasWildcard(arg->from);
        if(!arg->type)
            return typeError(md, &method->key.name, &arg->name);
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
optionError(ModelDriver *md, const char *option, const UA_String *key,
            const char *expected) {
    UA_LOG_ERROR(getLogger(md), UA_LOGCATEGORY_SERVER,
                 "REST driver \"%S\": The %s of \"%S\" must be a %s",
                 md->drv.name, option, *key, expected);
    return UA_STATUSCODE_BADCONFIGURATIONERROR;
}

/* The values of scale are numbers, those of units strings */
static UA_StatusCode
checkNodesOptions(ModelDriver *md) {
    const UA_KeyValueMap *scale = &md->autoNodes.scale;
    const UA_KeyValueMap *units = &md->autoNodes.units;
    UA_Double factor;
    for(size_t i = 0; i < scale->mapSize; i++) {
        if(!driverNumber(&scale->map[i].value, &factor))
            return optionError(md, "scale", &scale->map[i].key.name, "number");
    }
    for(size_t i = 0; i < units->mapSize; i++) {
        if(!UA_Variant_hasScalarType(&units->map[i].value, &UA_TYPES[UA_TYPES_STRING]))
            return optionError(md, "unit", &units->map[i].key.name, "string");
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
parseConfig(ModelDriver *md) {
    /* The place in the address space */
    md->ns = 1;
    md->parent = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    const UA_String *ns = driverParamsString(&md->drv.params, "namespace");
    if(ns) {
        char *uri = driverCString(ns);
        if(!uri)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        md->ns = UA_Server_addNamespace(md->drv.server, uri);
        UA_free(uri);
    }
    const UA_String *parent = driverParamsString(&md->drv.params, "parent");
    if(parent && UA_NodeId_parse(&md->parent, *parent) != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(getLogger(md), UA_LOGCATEGORY_SERVER,
                     "REST driver \"%S\": The parent \"%S\" is not a NodeId",
                     md->drv.name, *parent);
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }

    UA_KeyValueMap methods = getParamsMap(&md->drv.params, "methods");
    UA_KeyValueMap variables = getParamsMap(&md->drv.params, "variables");
    if(methods.mapSize > 0) {
        md->methods = (ModelMethod *)UA_calloc(methods.mapSize, sizeof(ModelMethod));
        if(!md->methods)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        md->methodsSize = methods.mapSize;
    }
    if(variables.mapSize > 0) {
        md->variables = (ModelVariable *)
            UA_calloc(variables.mapSize, sizeof(ModelVariable));
        if(!md->variables)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        md->variablesSize = variables.mapSize;
    }

    UA_StatusCode res = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < methods.mapSize && res == UA_STATUSCODE_GOOD; i++) {
        ModelMethod *m = &md->methods[i];
        const UA_KeyValuePair *def = &methods.map[i];
        res = parseNode(md, def, true, &m->node);
        if(res == UA_STATUSCODE_GOOD)
            res = parseArguments(md, def, "inputs", false, &m->inputsSize, &m->inputs);
        if(res == UA_STATUSCODE_GOOD)
            res = parseArguments(md, def, "outputs", true, &m->outputsSize, &m->outputs);
    }

    for(size_t i = 0; i < variables.mapSize && res == UA_STATUSCODE_GOOD; i++) {
        ModelVariable *v = &md->variables[i];
        const UA_KeyValuePair *def = &variables.map[i];
        UA_KeyValueMap map = driverParamsMap(&def->value);
        v->value.name = def->key.name;
        v->interval = MODEL_DEFAULT_INTERVAL_MS;
        res = parseNode(md, def, false, &v->node);
        if(res != UA_STATUSCODE_GOOD)
            break;
        v->value.type = findType(driverParamsString(&map, "type"));
        if(!v->value.type) {
            res = typeError(md, &md->drv.name, &v->node.name);
            break;
        }
        const UA_String *from = driverParamsString(&map, "from");
        if(!from) {
            UA_LOG_ERROR(getLogger(md), UA_LOGCATEGORY_SERVER,
                         "REST driver \"%S\": The variable \"%S\" needs a path "
                         "in \"from\"", md->drv.name, v->node.name);
            res = UA_STATUSCODE_BADCONFIGURATIONERROR;
            break;
        }
        v->value.from = *from;
        v->value.array = restPathHasWildcard(*from);
        const UA_String *unit = driverParamsString(&map, "unit");
        v->unit = unit ? *unit : UA_STRING_NULL;
        const UA_Variant *scale = UA_KeyValueMap_get(&map, UA_QUALIFIEDNAME(0, "scale"));
        if(scale && (!driverNumber(scale, &v->scale) ||
                     v->value.type != &UA_TYPES[UA_TYPES_DOUBLE])) {
            UA_LOG_ERROR(getLogger(md), UA_LOGCATEGORY_SERVER,
                         "REST driver \"%S\": The scale of the variable \"%S\" "
                         "must be a number, with the type Double", md->drv.name,
                         v->node.name);
            res = UA_STATUSCODE_BADCONFIGURATIONERROR;
            break;
        }
        res = driverParamsInterval(&map, &v->interval);
        if(res != UA_STATUSCODE_GOOD)
            UA_LOG_ERROR(getLogger(md), UA_LOGCATEGORY_SERVER,
                         "REST driver \"%S\": The interval of the variable "
                         "\"%S\" must be a positive number",
                         md->drv.name, v->node.name);
    }

    if(res == UA_STATUSCODE_GOOD &&
       UA_KeyValueMap_contains(&md->drv.params, UA_QUALIFIEDNAME(0, "nodes"))) {
        UA_KeyValueMap config = getParamsMap(&md->drv.params, "nodes");
        const UA_String *from = driverParamsString(&config, "from");
        md->autoNodes.enabled = true;
        md->autoNodes.from = from ? *from : UA_STRING_NULL;
        md->autoNodes.scale = getParamsMap(&config, "scale");
        md->autoNodes.units = getParamsMap(&config, "units");
        if(restPathHasWildcard(md->autoNodes.from)) {
            UA_LOG_ERROR(getLogger(md), UA_LOGCATEGORY_SERVER,
                         "REST driver \"%S\": The path of the nodes in \"from\" "
                         "cannot have wildcards", md->drv.name);
            res = UA_STATUSCODE_BADCONFIGURATIONERROR;
        }
        if(res == UA_STATUSCODE_GOOD)
            res = checkNodesOptions(md);
    }
    return res;
}

static void
clearAutoNodes(AutoNodes *m) {
    for(size_t i = 0; i < m->nodesSize; i++) {
        UA_String_clear(&m->nodes[i].path);
        UA_NodeId_clear(&m->nodes[i].nodeId);
    }
    UA_free(m->nodes);
    memset(m, 0, sizeof(AutoNodes));
}

static void
clearConfig(ModelDriver *md) {
    UA_NodeId_clear(&md->parent);
    clearAutoNodes(&md->autoNodes);
    for(size_t i = 0; i < md->methodsSize; i++) {
        clearNode(&md->methods[i].node);
        UA_free(md->methods[i].inputs);
        UA_free(md->methods[i].outputs);
    }
    for(size_t i = 0; i < md->variablesSize; i++)
        clearNode(&md->variables[i].node);
    UA_free(md->methods);
    UA_free(md->variables);
    md->methods = NULL;
    md->variables = NULL;
    md->methodsSize = 0;
    md->variablesSize = 0;
    UA_NodeId_clear(&md->objectId);
}

/***********/
/* Results */
/***********/

/* A factor of 0 writes the value unscaled */
static UA_StatusCode
writeScaled(UA_Server *server, const UA_NodeId nodeId, const UA_Variant *v,
            UA_Double factor) {
    if(factor == 0.0)
        return UA_Server_writeValue(server, nodeId, *v);
    UA_Variant scaled;
    UA_Variant_init(&scaled);
    UA_StatusCode res = restScale(v, factor, &scaled);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_Server_writeValue(server, nodeId, scaled);
    UA_Variant_clear(&scaled);
    return res;
}

/***********/
/* Methods */
/***********/

static void
finishStopIfDrained(ModelDriver *md);

static UA_StatusCode
fillOutputs(ModelMethod *m, const UA_Variant *result, UA_Variant *output) {
    for(size_t i = 0; i < m->outputsSize; i++) {
        UA_StatusCode res = restSelect(result, m->outputs[i].from, m->outputs[i].type,
                                       &output[i]);
        if(res == UA_STATUSCODE_GOOD)
            continue;
        UA_LOG_WARNING(getLogger(m->node.md), UA_LOGCATEGORY_SERVER,
                       "REST driver \"%S\": The output \"%S\" of \"%S\" was "
                       "not found in the result (%s)", m->node.md->drv.name,
                       m->outputs[i].name, m->node.name, UA_StatusCode_name(res));
        for(size_t j = 0; j < i; j++)
            UA_Variant_clear(&output[j]);
        return res;
    }
    return UA_STATUSCODE_GOOD;
}

static void
methodDone(void *context, const RestData *data) {
    PendingCall *pc = (PendingCall *)context;
    ModelMethod *m = pc->method;
    ModelDriver *md = m->node.md;
    UA_StatusCode status = restDataStatus(data);
    if(data->errorStatus != 0)
        UA_LOG_WARNING(getLogger(md), UA_LOGCATEGORY_SERVER,
                       "REST driver \"%S\": The method \"%S\" got the "
                       "status %u", md->drv.name, m->node.name,
                       (unsigned)data->errorStatus);
    if(status == UA_STATUSCODE_GOOD)
        status = fillOutputs(m, &data->result, pc->output);
    if(pc->inCallback) {
        pc->done = true;
        pc->status = status;
        return;
    }
    /* Also after a cancellation: the output stays valid until the result is
     * set, and the server waits for it */
    UA_Server_setAsyncCallMethodResult(md->drv.server, pc->output, status);
    LIST_REMOVE(pc, next);
    UA_free(pc);
    finishStopIfDrained(md);
}

static UA_StatusCode
methodCallback(UA_Server *server,
               const UA_NodeId *sessionId, void *sessionContext,
               const UA_NodeId *methodId, void *methodContext,
               const UA_NodeId *objectId, void *objectContext,
               size_t inputSize, const UA_Variant *input,
               size_t outputSize, UA_Variant *output) {
    (void)server, (void)sessionId, (void)sessionContext, (void)methodId;
    (void)objectId, (void)objectContext;
    ModelMethod *m = (ModelMethod *)methodContext;
    ModelDriver *md = m->node.md;
    if(md->drv.state != UA_LIFECYCLESTATE_STARTED)
        return UA_STATUSCODE_BADINVALIDSTATE;
    if(outputSize < m->outputsSize)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_KeyValueMap in = UA_KEYVALUEMAP_NULL;
    UA_StatusCode res = UA_KeyValueMap_copy(&m->node.defaults, &in);
    for(size_t i = 0; i < inputSize && i < m->inputsSize &&
            res == UA_STATUSCODE_GOOD; i++) {
        UA_QualifiedName key = {0, m->inputs[i].name};
        res = UA_KeyValueMap_set(&in, key, &input[i]);
    }

    PendingCall *pc = NULL;
    if(res == UA_STATUSCODE_GOOD) {
        pc = (PendingCall *)UA_calloc(1, sizeof(PendingCall));
        if(!pc)
            res = UA_STATUSCODE_BADOUTOFMEMORY;
    }
    if(res != UA_STATUSCODE_GOOD) {
        UA_KeyValueMap_clear(&in);
        return res;
    }
    pc->method = m;
    pc->output = output;
    pc->inCallback = true;
    LIST_INSERT_HEAD(&md->calls, pc, next);

    res = restExtractCall(md->rd, m->node.call, &in, methodDone, pc);
    UA_KeyValueMap_clear(&in);
    pc->inCallback = false;
    if(res == UA_STATUSCODE_GOOD && !pc->done)
        return UA_STATUSCODE_GOODCOMPLETESASYNCHRONOUSLY;

    if(res == UA_STATUSCODE_GOOD)
        res = pc->status;
    else
        UA_LOG_WARNING(getLogger(md), UA_LOGCATEGORY_SERVER,
                       "REST driver \"%S\": The call \"%s\" failed (%s)",
                       md->drv.name, m->node.call, UA_StatusCode_name(res));
    LIST_REMOVE(pc, next);
    UA_free(pc);
    return res;
}

/*************/
/* Variables */
/*************/

static void
writeStatus(UA_Server *server, const UA_NodeId nodeId, UA_StatusCode status) {
    UA_DataValue dv;
    UA_DataValue_init(&dv);
    dv.hasStatus = true;
    dv.status = status;
    UA_Server_writeDataValue(server, nodeId, dv);
}

/* Every failure is logged, or with log-only-changes only a changed status */
static UA_Boolean
shouldLogFailure(ModelDriver *md, UA_StatusCode status, UA_StatusCode lastStatus) {
    return status != lastStatus ||
        !driverParamsBoolean(&md->drv.params, "log-only-changes");
}

static void
setVariableStatus(ModelVariable *v, UA_StatusCode status, UA_UInt16 errorStatus) {
    ModelDriver *md = v->node.md;
    if(shouldLogFailure(md, status, v->lastStatus)) {
        if(errorStatus != 0)
            UA_LOG_WARNING(getLogger(md), UA_LOGCATEGORY_SERVER,
                           "REST driver \"%S\": The variable \"%S\" could not be "
                           "updated (status %u)", md->drv.name, v->node.name,
                           (unsigned)errorStatus);
        else
            UA_LOG_WARNING(getLogger(md), UA_LOGCATEGORY_SERVER,
                           "REST driver \"%S\": The variable \"%S\" could not be "
                           "updated (%s)", md->drv.name, v->node.name,
                           UA_StatusCode_name(status));
    }
    v->lastStatus = status;
    writeStatus(md->drv.server, v->node.nodeId, status);
}

/* The paths of variables with a call start at the result, the others at the
 * polled data */
static void
updateVariable(ModelVariable *v, UA_StatusCode status, UA_UInt16 errorStatus,
               const UA_Variant *root) {
    ModelDriver *md = v->node.md;
    UA_Variant value;
    UA_Variant_init(&value);
    if(status == UA_STATUSCODE_GOOD)
        status = restSelect(root, v->value.from, v->value.type, &value);
    if(status == UA_STATUSCODE_GOOD)
        status = writeScaled(md->drv.server, v->node.nodeId, &value, v->scale);
    if(status == UA_STATUSCODE_GOOD) {
        if(v->lastStatus != UA_STATUSCODE_GOOD &&
           v->lastStatus != UA_STATUSCODE_BADWAITINGFORINITIALDATA)
            UA_LOG_INFO(getLogger(md), UA_LOGCATEGORY_SERVER,
                        "REST driver \"%S\": The variable \"%S\" is "
                        "updated again", md->drv.name, v->node.name);
        v->lastStatus = UA_STATUSCODE_GOOD;
    } else {
        setVariableStatus(v, status, errorStatus);
    }
    UA_Variant_clear(&value);
}

static void
variableCallDone(void *context, const RestData *data) {
    ModelVariable *v = (ModelVariable *)context;
    ModelDriver *md = v->node.md;
    v->busy = false;
    md->polls--;
    if(md->drv.state == UA_LIFECYCLESTATE_STARTED)
        updateVariable(v, restDataStatus(data), data->errorStatus, &data->result);
    finishStopIfDrained(md);
}

static void
variableCallback(UA_Server *server, void *data) {
    (void)server;
    ModelVariable *v = (ModelVariable *)data;
    ModelDriver *md = v->node.md;
    if(v->busy || md->drv.state != UA_LIFECYCLESTATE_STARTED)
        return;
    v->busy = true;
    md->polls++;
    UA_StatusCode res = restExtractCall(md->rd, v->node.call, &v->node.defaults,
                                        variableCallDone, v);
    if(res != UA_STATUSCODE_GOOD) {
        v->busy = false;
        md->polls--;
        setVariableStatus(v, res, 0);
    }
}

/**********/
/* Nodes from the data */
/**********/

/* Objects and arrays that contain objects or arrays become Object nodes */
static UA_Boolean
isAutoObject(const UA_Variant *v) {
    if(UA_Variant_hasArrayType(v, &UA_TYPES[UA_TYPES_KEYVALUEPAIR]))
        return true;
    if(!UA_Variant_hasArrayType(v, &UA_TYPES[UA_TYPES_VARIANT]))
        return false;
    const UA_Variant *items = (const UA_Variant *)v->data;
    for(size_t i = 0; i < v->arrayLength; i++) {
        if(items[i].type && !UA_Variant_isScalar(&items[i]))
            return true;
    }
    return false;
}

/* Numbers can change between Int64 and Double. Null and arrays can be followed
 * by any value. */
static UA_NodeId
autoDataType(const UA_Variant *v, UA_Int32 *valueRank) {
    *valueRank = UA_VALUERANK_SCALAR;
    if(UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_INT64]) ||
       UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_DOUBLE]))
        return UA_NODEID_NUMERIC(0, UA_NS0ID_NUMBER);
    if(UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_BOOLEAN]) ||
       UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_STRING]))
        return v->type->typeId;
    *valueRank = UA_VALUERANK_ANY;
    return UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATATYPE);
}

static UA_StatusCode
writeAutoValue(ModelDriver *md, const AutoNode *node, const UA_String name,
               const UA_Variant *v) {
    UA_Double factor = 0.0;
    driverNumber(restOption(&md->autoNodes.scale, name, node->path), &factor);
    return writeScaled(md->drv.server, node->nodeId, v, factor);
}

/* Starts at the cursor, so results in the same order find each node first */
static AutoNode *
findAutoNode(AutoNodes *m, const UA_String *path) {
    for(size_t n = 0; n < m->nodesSize; n++) {
        size_t i = (m->cursor + n) % m->nodesSize;
        if(UA_String_equal(&m->nodes[i].path, path)) {
            m->cursor = i + 1;
            return &m->nodes[i];
        }
    }
    return NULL;
}

static AutoNode *
addAutoNode(ModelDriver *md, const UA_NodeId parent, const UA_String *path,
            const UA_String name, UA_Boolean object, const UA_Variant *v) {
    AutoNodes *m = &md->autoNodes;
    AutoNode *nodes = (AutoNode *)
        UA_realloc(m->nodes, sizeof(AutoNode) * (m->nodesSize + 1));
    if(!nodes)
        return NULL;
    m->nodes = nodes;
    AutoNode *node = &nodes[m->nodesSize];
    memset(node, 0, sizeof(AutoNode));
    node->variable = !object;

    UA_QualifiedName browseName = {md->ns, name};
    UA_StatusCode res = UA_String_copy(path, &node->path);
    if(res == UA_STATUSCODE_GOOD)
        res = makeNodeId(md, path, &node->nodeId);
    if(res == UA_STATUSCODE_GOOD && node->variable) {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        attr.displayName.text = name;
        attr.dataType = autoDataType(v, &attr.valueRank);
        attr.accessLevel = UA_ACCESSLEVELMASK_READ;
        attr.userAccessLevel = UA_ACCESSLEVELMASK_READ;
        res = UA_Server_addVariableNode(md->drv.server, node->nodeId, parent,
                                        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                        browseName,
                                        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                                        attr, NULL, NULL);
        const UA_Variant *unit = restOption(&m->units, name, *path);
        if(res == UA_STATUSCODE_GOOD && unit &&
           UA_Variant_hasScalarType(unit, &UA_TYPES[UA_TYPES_STRING]))
            res = addEngineeringUnits(md, node->nodeId, *(const UA_String *)unit->data);
    } else if(res == UA_STATUSCODE_GOOD) {
        UA_ObjectAttributes attr = UA_ObjectAttributes_default;
        attr.displayName.text = name;
        res = UA_Server_addObjectNode(md->drv.server, node->nodeId, parent,
                                      UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                      browseName,
                                      UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE),
                                      attr, NULL, NULL);
    }
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(getLogger(md), UA_LOGCATEGORY_SERVER,
                       "REST driver \"%S\": The node \"%S\" could not be added (%s)",
                       md->drv.name, *path, UA_StatusCode_name(res));
        UA_String_clear(&node->path);
        UA_NodeId_clear(&node->nodeId);
        return NULL;
    }
    m->nodesSize++;
    return node;
}

static void
autoNodesChild(ModelDriver *md, const UA_NodeId parent, const UA_String parentPath,
               const UA_String name, const UA_Variant *v);

static void
autoNodesChildren(ModelDriver *md, const UA_NodeId parent, const UA_String parentPath,
                  const UA_Variant *v) {
    if(UA_Variant_hasArrayType(v, &UA_TYPES[UA_TYPES_KEYVALUEPAIR])) {
        const UA_KeyValuePair *pairs = (const UA_KeyValuePair *)v->data;
        for(size_t i = 0; i < v->arrayLength; i++)
            autoNodesChild(md, parent, parentPath, pairs[i].key.name, &pairs[i].value);
    } else if(UA_Variant_hasArrayType(v, &UA_TYPES[UA_TYPES_VARIANT])) {
        const UA_Variant *items = (const UA_Variant *)v->data;
        for(size_t i = 0; i < v->arrayLength; i++) {
            UA_Byte buf[24];
            UA_String index = {sizeof(buf), buf};
            UA_String_format(&index, "%lu", (unsigned long)i);
            autoNodesChild(md, parent, parentPath, index, &items[i]);
        }
    }
}

static void
autoNodesChild(ModelDriver *md, const UA_NodeId parent, const UA_String parentPath,
               const UA_String name, const UA_Variant *v) {
    UA_Byte buf[AUTO_MAX_PATH];
    UA_String path = {sizeof(buf), buf};
    UA_StatusCode res = (parentPath.length > 0) ?
        UA_String_format(&path, "%S.%S", parentPath, name) :
        UA_String_format(&path, "%S", name);
    if(res != UA_STATUSCODE_GOOD)
        return;

    AutoNodes *m = &md->autoNodes;
    UA_Boolean object = isAutoObject(v);
    AutoNode *node = findAutoNode(m, &path);
    if(!node)
        node = addAutoNode(md, parent, &path, name, object, v);
    if(!node)
        return;
    node->seen = m->generation;
    if(node->variable && object) {
        writeStatus(md->drv.server, node->nodeId, UA_STATUSCODE_BADTYPEMISMATCH);
    } else if(node->variable) {
        res = writeAutoValue(md, node, name, v);
        if(res != UA_STATUSCODE_GOOD)
            writeStatus(md->drv.server, node->nodeId,
                        UA_Variant_isEmpty(v) ? UA_STATUSCODE_BADNODATA : res);
    } else if(object) {
        /* The node array can grow, the strings of the node stay */
        autoNodesChildren(md, node->nodeId, node->path, v);
    }
}

static void
setAutoNodesStatus(ModelDriver *md, UA_StatusCode status, UA_Boolean onlyUnseen) {
    AutoNodes *m = &md->autoNodes;
    for(size_t i = 0; i < m->nodesSize; i++) {
        if(m->nodes[i].variable && (!onlyUnseen || m->nodes[i].seen != m->generation))
            writeStatus(md->drv.server, m->nodes[i].nodeId, status);
    }
}

/* A failed poll is logged by the REST driver, a missing "from" here */
static void
updateAutoNodes(ModelDriver *md, UA_StatusCode status, const UA_Variant *data) {
    AutoNodes *m = &md->autoNodes;
    UA_Boolean pollFailed = (status != UA_STATUSCODE_GOOD);
    const UA_Variant *root = NULL;
    UA_Variant element;
    if(status == UA_STATUSCODE_GOOD) {
        UA_String from = m->from;
        root = restPathFind(data, &from, &element);
        if(!root || from.length > 0)
            status = UA_STATUSCODE_BADNOTFOUND;
    }
    if(status != UA_STATUSCODE_GOOD) {
        if(!pollFailed && shouldLogFailure(md, status, m->lastStatus))
            UA_LOG_WARNING(getLogger(md), UA_LOGCATEGORY_SERVER,
                           "REST driver \"%S\": \"%S\" of the nodes is not in the "
                           "data", md->drv.name, m->from);
        m->lastStatus = status;
        setAutoNodesStatus(md, status, false);
        return;
    }
    if(m->lastStatus == UA_STATUSCODE_BADNOTFOUND) /* Else the REST driver logs it */
        UA_LOG_INFO(getLogger(md), UA_LOGCATEGORY_SERVER,
                    "REST driver \"%S\": The nodes are updated again", md->drv.name);
    m->lastStatus = UA_STATUSCODE_GOOD;

    m->generation++;
    autoNodesChildren(md, md->objectId, UA_STRING_NULL, root);
    setAutoNodesStatus(md, UA_STATUSCODE_BADNODATA, true);
}

/*********/
/* Nodes */
/*********/

static void
toArguments(const ModelArgument *args, size_t size, UA_Argument *out) {
    for(size_t i = 0; i < size; i++) {
        UA_Argument_init(&out[i]);
        out[i].name = args[i].name;
        out[i].dataType = args[i].type->typeId;
        out[i].valueRank = args[i].array ?
            UA_VALUERANK_ONE_DIMENSION : UA_VALUERANK_SCALAR;
    }
}

static UA_StatusCode
addMethod(ModelDriver *md, ModelMethod *m) {
    UA_StatusCode res = makeNodeId(md, &m->node.name, &m->node.nodeId);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    UA_STACKARRAY(UA_Argument, inputs, m->inputsSize);
    UA_STACKARRAY(UA_Argument, outputs, m->outputsSize);
    toArguments(m->inputs, m->inputsSize, inputs);
    toArguments(m->outputs, m->outputsSize, outputs);
    UA_MethodAttributes attr = UA_MethodAttributes_default;
    attr.displayName.text = m->node.name;
    attr.executable = true;
    attr.userExecutable = true;
    UA_QualifiedName browseName = {md->ns, m->node.name};
    return UA_Server_addMethodNode(md->drv.server, m->node.nodeId, md->objectId,
                                   UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                   browseName, attr, methodCallback,
                                   m->inputsSize, inputs, m->outputsSize, outputs,
                                   m, NULL);
}

static UA_StatusCode
addVariable(ModelDriver *md, ModelVariable *v) {
    UA_StatusCode res = makeNodeId(md, &v->node.name, &v->node.nodeId);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    attr.displayName.text = v->node.name;
    attr.dataType = v->value.type->typeId;
    UA_UInt32 anyLength = 0;
    if(v->value.array) {
        attr.valueRank = UA_VALUERANK_ONE_DIMENSION;
        attr.arrayDimensionsSize = 1;
        attr.arrayDimensions = &anyLength;
    } else {
        attr.valueRank = UA_VALUERANK_SCALAR;
    }
    attr.accessLevel = UA_ACCESSLEVELMASK_READ;
    attr.userAccessLevel = UA_ACCESSLEVELMASK_READ;
    UA_QualifiedName browseName = {md->ns, v->node.name};
    res = UA_Server_addVariableNode(md->drv.server, v->node.nodeId, md->objectId,
                                    UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                    browseName,
                                    UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                                    attr, v, NULL);
    if(res == UA_STATUSCODE_GOOD && v->unit.length > 0)
        res = addEngineeringUnits(md, v->node.nodeId, v->unit);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    v->lastStatus = UA_STATUSCODE_BADWAITINGFORINITIALDATA; /* Not a failure */
    writeStatus(md->drv.server, v->node.nodeId, v->lastStatus);
    if(!v->node.call)
        return UA_STATUSCODE_GOOD; /* Updated by the polls */
    /* The first call in the next iteration, then every interval */
    res = UA_Server_addTimedCallback(md->drv.server, variableCallback, v, 0,
                                     &v->firstCallbackId);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_Server_addRepeatedCallback(md->drv.server, variableCallback, v,
                                            v->interval, &v->callbackId);
    return res;
}

static void
removeNodes(ModelDriver *md) {
    for(size_t i = md->autoNodes.nodesSize; i > 0; i--) /* Children first */
        UA_Server_deleteNode(md->drv.server, md->autoNodes.nodes[i - 1].nodeId, true);
    for(size_t i = 0; i < md->variablesSize; i++) {
        ModelVariable *v = &md->variables[i];
        if(v->firstCallbackId != 0)
            UA_Server_removeCallback(md->drv.server, v->firstCallbackId);
        if(v->callbackId != 0)
            UA_Server_removeCallback(md->drv.server, v->callbackId);
        v->firstCallbackId = 0;
        v->callbackId = 0;
        if(!UA_NodeId_isNull(&v->node.nodeId))
            UA_Server_deleteNode(md->drv.server, v->node.nodeId, true);
    }
    for(size_t i = 0; i < md->methodsSize; i++) {
        if(!UA_NodeId_isNull(&md->methods[i].node.nodeId))
            UA_Server_deleteNode(md->drv.server, md->methods[i].node.nodeId, true);
    }
    if(!UA_NodeId_isNull(&md->objectId))
        UA_Server_deleteNode(md->drv.server, md->objectId, true);
}

static UA_StatusCode
addNodes(ModelDriver *md) {
    UA_StatusCode res = makeNodeId(md, NULL, &md->objectId);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    UA_String shortName = md->drv.name;
    for(size_t i = shortName.length; i > 0; i--) {
        if(shortName.data[i - 1] == '/') {
            shortName.data += i;
            shortName.length -= i;
            break;
        }
    }
    UA_ObjectAttributes attr = UA_ObjectAttributes_default;
    attr.displayName.text = shortName;
    UA_QualifiedName browseName = {md->ns, shortName};
    res = UA_Server_addObjectNode(md->drv.server, md->objectId,
                                  md->parent,
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), browseName,
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE),
                                  attr, NULL, NULL);
    for(size_t i = 0; i < md->methodsSize && res == UA_STATUSCODE_GOOD; i++)
        res = addMethod(md, &md->methods[i]);
    for(size_t i = 0; i < md->variablesSize && res == UA_STATUSCODE_GOOD; i++)
        res = addVariable(md, &md->variables[i]);
    if(res != UA_STATUSCODE_GOOD)
        UA_LOG_ERROR(getLogger(md), UA_LOGCATEGORY_SERVER,
                     "REST driver \"%S\": The nodes could not be added (%s)",
                     md->drv.name, UA_StatusCode_name(res));
    return res;
}

/*************/
/* Lifecycle */
/*************/

static void
finishStopIfDrained(ModelDriver *md) {
    if(md->drv.state != UA_LIFECYCLESTATE_STOPPING ||
       !LIST_EMPTY(&md->calls) || md->polls > 0)
        return;
    clearConfig(md);
    md->drv.state = UA_LIFECYCLESTATE_STOPPED;
}

static UA_StatusCode
modelStart(UA_Driver *drv) {
    ModelDriver *md = (ModelDriver *)drv;
    if(drv->state != UA_LIFECYCLESTATE_STOPPED)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_StatusCode res = parseConfig(md);
    if(res == UA_STATUSCODE_GOOD)
        res = addNodes(md);
    if(res != UA_STATUSCODE_GOOD) {
        removeNodes(md);
        clearConfig(md);
        return res;
    }
    drv->state = UA_LIFECYCLESTATE_STARTED;
    return UA_STATUSCODE_GOOD;
}

static void
modelStop(UA_Driver *drv) {
    ModelDriver *md = (ModelDriver *)drv;
    if(drv->state != UA_LIFECYCLESTATE_STARTED)
        return;
    drv->state = UA_LIFECYCLESTATE_STOPPING;
    removeNodes(md);
    finishStopIfDrained(md);
}

static UA_StatusCode
modelFree(UA_Driver *drv) {
    if(drv->state != UA_LIFECYCLESTATE_STOPPED)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_KeyValueMap_clear(&drv->params);
    UA_free(drv);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
modelNew(RestDriver *rd, const UA_KeyValueMap params, UA_Driver **outDriver) {
    ModelDriver *md = (ModelDriver *)UA_calloc(1, sizeof(ModelDriver));
    if(!md)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode res = UA_KeyValueMap_copy(&params, &md->drv.params);
    if(res != UA_STATUSCODE_GOOD) {
        UA_free(md);
        return res;
    }
    LIST_INIT(&md->calls);
    md->rd = rd;
    md->drv.name = rd->drv.name;
    md->drv.server = rd->drv.server;
    md->drv.start = modelStart;
    md->drv.stop = modelStop;
    md->drv.free = modelFree;
    *outDriver = &md->drv;
    return UA_STATUSCODE_GOOD;
}

/********************************/
/* The model of the REST driver */
/********************************/

/* Is the polled data shown as nodes? On by default, except for nested REST
 * drivers: Their parent decides what is shown. "nodes" is false, true or an
 * object with options. */
static UA_StatusCode
nodesSetting(RestDriver *rd, UA_Boolean *on, UA_KeyValueMap *options) {
    const UA_Variant *nodes = UA_KeyValueMap_get(&rd->drv.params,
                                                 UA_QUALIFIEDNAME(0, "nodes"));
    /* Without polling, there is nothing to show */
    *on = !memchr(rd->drv.name.data, '/', rd->drv.name.length) && rd->pollId != 0;
    *options = UA_KEYVALUEMAP_NULL;
    if(!nodes)
        return UA_STATUSCODE_GOOD;
    if(UA_Variant_hasScalarType(nodes, &UA_TYPES[UA_TYPES_BOOLEAN])) {
        *on = *(const UA_Boolean *)nodes->data;
    } else if(UA_Variant_isEmpty(nodes) ||
              UA_Variant_hasArrayType(nodes, &UA_TYPES[UA_TYPES_KEYVALUEPAIR])) {
        *on = true;
        *options = driverParamsMap(nodes);
    } else {
        UA_LOG_ERROR(restLogger(rd), UA_LOGCATEGORY_SERVER,
                     "REST driver \"%S\": \"nodes\" must be true, false or an "
                     "object", rd->drv.name);
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }
    if(*on && rd->pollId == 0) {
        UA_LOG_ERROR(restLogger(rd), UA_LOGCATEGORY_SERVER,
                     "REST driver \"%S\": The nodes need polling", rd->drv.name);
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }
    return UA_STATUSCODE_GOOD;
}

/* Methods and variables call a known call. Variables without call need the
 * polling. */
static UA_StatusCode
checkModelCalls(RestDriver *rd, const char *key, UA_Boolean polled) {
    UA_KeyValueMap defs = driverParamsMap(UA_KeyValueMap_get(
        &rd->drv.params, UA_QUALIFIEDNAME(0, (char *)(uintptr_t)key)));
    for(size_t i = 0; i < defs.mapSize; i++) {
        UA_KeyValueMap def = driverParamsMap(&defs.map[i].value);
        const UA_String *call = driverParamsString(&def, "call");
        if(call ? restFindCall(rd, call) != NULL : (polled && rd->pollId != 0))
            continue;
        UA_LOG_ERROR(restLogger(rd), UA_LOGCATEGORY_SERVER,
                     "REST driver \"%S\": \"%S\" needs a call from \"calls\"%s",
                     rd->drv.name, defs.map[i].key.name,
                     polled ? " or the polling" : "");
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
restLoadStart(RestDriver *rd) {
#ifndef REST_ALARMS
    if(driverParamsBoolean(&rd->drv.params, "alarms"))
        UA_LOG_WARNING(restLogger(rd), UA_LOGCATEGORY_SERVER,
                       "REST driver \"%S\": Alarms need events and the full "
                       "namespace zero. Failures are reported as events.",
                       rd->drv.name);
#endif
    UA_Boolean nodes;
    UA_KeyValueMap options;
    UA_StatusCode res = nodesSetting(rd, &nodes, &options);
    if(res == UA_STATUSCODE_GOOD)
        res = checkModelCalls(rd, "methods", false);
    if(res == UA_STATUSCODE_GOOD)
        res = checkModelCalls(rd, "variables", true);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    const UA_Variant *methods = UA_KeyValueMap_get(&rd->drv.params,
                                                   UA_QUALIFIEDNAME(0, "methods"));
    const UA_Variant *variables = UA_KeyValueMap_get(&rd->drv.params,
                                                     UA_QUALIFIEDNAME(0, "variables"));
    if(!nodes && !methods && !variables)
        return UA_STATUSCODE_GOOD;

    if(!rd->model) {
        UA_KeyValueMap params = UA_KEYVALUEMAP_NULL;
        if(methods)
            res |= UA_KeyValueMap_set(&params, UA_QUALIFIEDNAME(0, "methods"), methods);
        if(variables)
            res |= UA_KeyValueMap_set(&params, UA_QUALIFIEDNAME(0, "variables"), variables);
        if(nodes) {
            UA_Variant v;
            UA_Variant_setArray(&v, options.map ? (void *)options.map :
                                UA_EMPTY_ARRAY_SENTINEL, options.mapSize,
                                &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
            res |= UA_KeyValueMap_set(&params, UA_QUALIFIEDNAME(0, "nodes"), &v);
        }
        static const char *place[] = {"namespace", "parent"};
        for(size_t i = 0; i < sizeof(place) / sizeof(place[0]); i++) {
            UA_QualifiedName key = UA_QUALIFIEDNAME(0, (char *)(uintptr_t)place[i]);
            const UA_Variant *v = UA_KeyValueMap_get(&rd->drv.params, key);
            if(v)
                res |= UA_KeyValueMap_set(&params, key, v);
        }
        UA_Boolean quiet = driverParamsBoolean(&rd->drv.params, "log-only-changes");
        res |= UA_KeyValueMap_setScalar(&params, UA_QUALIFIEDNAME(0, "log-only-changes"),
                                        &quiet, &UA_TYPES[UA_TYPES_BOOLEAN]);
        if(res == UA_STATUSCODE_GOOD)
            res = modelNew(rd, params, &rd->model);
        UA_KeyValueMap_clear(&params);
        if(res != UA_STATUSCODE_GOOD)
            return res;
    }
    return rd->model->start(rd->model);
}

void
restLoadUpdate(RestDriver *rd, UA_StatusCode status, const RestData *data) {
    ModelDriver *md = (ModelDriver *)rd->model;
    if(!md || md->drv.state != UA_LIFECYCLESTATE_STARTED)
        return;
    if(md->autoNodes.enabled)
        updateAutoNodes(md, status, data->data);
    for(size_t i = 0; i < md->variablesSize; i++) {
        if(!md->variables[i].node.call)
            updateVariable(&md->variables[i], status, data->errorStatus, data->data);
    }
}

/*********************/
/* Events and alarms */
/*********************/

/* The object of the model, else the Server object */
static UA_NodeId
eventSource(const RestDriver *rd) {
    if(rd->model && rd->model->state == UA_LIFECYCLESTATE_STARTED)
        return ((const ModelDriver *)rd->model)->objectId;
    return UA_NS0ID(SERVER);
}


#ifdef REST_ALARMS

/* The namespace of the model, else 1 */
static UA_UInt16
modelNamespace(const RestDriver *rd) {
    if(rd->model && rd->model->state == UA_LIFECYCLESTATE_STARTED)
        return ((const ModelDriver *)rd->model)->ns;
    return 1;
}

static UA_StatusCode
setAlarmField(RestDriver *rd, const char *field, const void *value,
              const UA_DataType *type) {
    UA_Variant v;
    UA_Variant_setScalar(&v, (void *)(uintptr_t)value, type);
    return rd->ac->setConditionField(rd->ac, rd->alarm, &v,
                                     UA_QUALIFIEDNAME(0, (char *)(uintptr_t)field));
}

static UA_StatusCode
setAlarmState(RestDriver *rd, const char *state, UA_Boolean id) {
    UA_Variant v;
    UA_Variant_setScalar(&v, &id, &UA_TYPES[UA_TYPES_BOOLEAN]);
    return rd->ac->setConditionVariableFieldProperty(
        rd->ac, rd->alarm, &v, UA_QUALIFIEDNAME(0, (char *)(uintptr_t)state),
        UA_QUALIFIEDNAME(0, "Id"));
}

/* The Alarms & Conditions driver of the server. Added if there is none. */
static UA_AlarmConditionsDriver *
getAlarmsDriver(RestDriver *rd) {
    UA_Driver *drv = UA_Server_getDriver(rd->drv.server, NULL, "alarms-conditions");
    if(!drv) {
        UA_AlarmConditionsDriver *ac = UA_AlarmsConditionsDriver(UA_KEYVALUEMAP_NULL);
        if(!ac)
            return NULL;
        if(UA_Server_addDriver(rd->drv.server, &ac->drv) != UA_STATUSCODE_GOOD) {
            ac->drv.free(&ac->drv);
            return NULL;
        }
        drv = &ac->drv;
    }
    return (drv->state == UA_LIFECYCLESTATE_STARTED) ?
        (UA_AlarmConditionsDriver *)drv : NULL;
}

/* An OffNormalAlarm below the object of the model, else unexposed with the
 * Server object as its source */
static UA_StatusCode
createAlarm(RestDriver *rd) {
    UA_AlarmConditionsDriver *ac = getAlarmsDriver(rd);
    if(!ac)
        return UA_STATUSCODE_BADNOTFOUND;
    UA_NodeId source = eventSource(rd);
    UA_NodeId server = UA_NS0ID(SERVER);
    UA_NodeId alarm;
    UA_StatusCode res =
        ac->createCondition(ac, UA_NODEID_NUMERIC(modelNamespace(rd), 0),
                            UA_NS0ID(OFFNORMALALARMTYPE),
                            UA_QUALIFIEDNAME(modelNamespace(rd), "CommunicationError"),
                            source,
                            UA_NodeId_equal(&source, &server) ?
                            UA_NODEID_NULL : UA_NS0ID(HASCOMPONENT), &alarm);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    rd->ac = ac;
    rd->alarm = alarm;
    res = UA_NodeId_copy(&source, &rd->alarmSource);
    UA_Boolean retain = true;
    if(res == UA_STATUSCODE_GOOD)
        res = setAlarmField(rd, "Retain", &retain, &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(res == UA_STATUSCODE_GOOD)
        res = setAlarmState(rd, "EnabledState", true);
    return res;
}

static void
deleteAlarm(RestDriver *rd) {
    if(!rd->ac)
        return;
    /* A stopped driver cleans up its conditions when it is freed */
    if(rd->ac->drv.state == UA_LIFECYCLESTATE_STARTED)
        rd->ac->deleteCondition(rd->ac, rd->alarm, rd->alarmSource);
    UA_NodeId_clear(&rd->alarm);
    UA_NodeId_clear(&rd->alarmSource);
    rd->ac = NULL;
    rd->alarmActive = false;
}

/* Active while the polls fail. Setting ActiveState triggers the event of the
 * activation, the other changes are triggered here. */
static UA_StatusCode
setAlarm(RestDriver *rd, UA_StatusCode status, const UA_String *message) {
    UA_Boolean active = (status != UA_STATUSCODE_GOOD);
    if(!rd->ac && !active)
        return UA_STATUSCODE_GOOD;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(!rd->ac)
        res = createAlarm(rd);
    if(res == UA_STATUSCODE_GOOD && rd->ac->drv.state != UA_LIFECYCLESTATE_STARTED)
        res = UA_STATUSCODE_BADINVALIDSTATE;
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_UInt16 severity = active ? REST_FAILURE_SEVERITY : REST_RECOVERY_SEVERITY;
    UA_LocalizedText text = {UA_STRING("en"), *message};
    UA_Boolean retain = active;
    res |= setAlarmField(rd, "Severity", &severity, &UA_TYPES[UA_TYPES_UINT16]);
    res |= setAlarmField(rd, "Message", &text, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    res |= setAlarmField(rd, "Retain", &retain, &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    if(active && !rd->alarmActive) {
        res = setAlarmState(rd, "AckedState", false);
        if(res == UA_STATUSCODE_GOOD)
            res = setAlarmState(rd, "ActiveState", true);
    } else {
        if(!active)
            res = setAlarmState(rd, "ActiveState", false);
        if(res == UA_STATUSCODE_GOOD)
            res = rd->ac->triggerConditionEvent(rd->ac, rd->alarm, rd->alarmSource, NULL);
    }
    if(res == UA_STATUSCODE_GOOD)
        rd->alarmActive = active;
    return res;
}

#endif /* REST_ALARMS */

void
restLoadReport(RestDriver *rd, UA_StatusCode status, const UA_String *message) {
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    UA_StatusCode res;
# ifdef REST_ALARMS
    if(driverParamsBoolean(&rd->drv.params, "alarms")) {
        res = setAlarm(rd, status, message);
        if(res != UA_STATUSCODE_GOOD)
            UA_LOG_WARNING(restLogger(rd), UA_LOGCATEGORY_SERVER,
                           "REST driver \"%S\": The alarm could not be set (%s)",
                           rd->drv.name, UA_StatusCode_name(res));
        return;
    }
# endif

    UA_NodeId type = UA_NS0ID(BASEEVENTTYPE);
# ifdef UA_GENERATED_NAMESPACE_ZERO_FULL
    if(status != UA_STATUSCODE_GOOD)
        type = UA_NS0ID(DEVICEFAILUREEVENTTYPE);
# endif
    UA_LocalizedText text = {UA_STRING("en"), *message};
    res = UA_Server_createEvent(rd->drv.server, eventSource(rd), type,
                                (status == UA_STATUSCODE_GOOD) ?
                                REST_RECOVERY_SEVERITY : REST_FAILURE_SEVERITY,
                                text, NULL, NULL, NULL);
    if(res != UA_STATUSCODE_GOOD)
        UA_LOG_WARNING(restLogger(rd), UA_LOGCATEGORY_SERVER,
                       "REST driver \"%S\": The event could not be created (%s)",
                       rd->drv.name, UA_StatusCode_name(res));
#else
    (void)rd, (void)status, (void)message;
#endif
}

/*************/
/* Lifecycle */
/*************/

/* The model stops when its calls are done (runs of the REST driver) */
void
restLoadStop(RestDriver *rd) {
#ifdef REST_ALARMS
    deleteAlarm(rd);
#endif
    if(rd->model)
        rd->model->stop(rd->model);
}

void
restLoadFree(RestDriver *rd) {
    if(rd->model)
        rd->model->free(rd->model);
    rd->model = NULL;
}

#endif /* UA_ENABLE_DRIVER_REST */
