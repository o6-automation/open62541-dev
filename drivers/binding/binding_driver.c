/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

#include <open62541/driver/binding.h>
#include <open62541/driver/rest.h>

#include "open62541_queue.h"
#include "../driver_params.h"

#ifdef UA_ENABLE_DRIVER_REST

#define BINDING_DEFAULT_INTERVAL_MS 1000.0
#define AUTO_MAX_PATH 512

typedef struct BindingDriver BindingDriver;

typedef struct {
    UA_String name;
    const UA_DataType *type;
    UA_String from;
    UA_Boolean array; /* The path has wildcards */
} BindingArgument;

typedef struct {
    BindingDriver *bd;
    UA_String name;
    char *driver;
    char *call;
    UA_KeyValueMap defaults;
    UA_NodeId nodeId;
} BindingNode;

typedef struct {
    BindingNode node;
    size_t inputsSize;
    BindingArgument *inputs;
    size_t outputsSize;
    BindingArgument *outputs;
} BindingMethod;

typedef struct {
    BindingNode node;
    BindingArgument value;
    UA_Double interval;
    UA_UInt64 callbackId;
    UA_Boolean busy;
    UA_StatusCode lastStatus;
    UA_Driver *rest; /* The polling REST driver, for a variable without call */
    UA_UInt64 restCallbackId;
    UA_String unit; /* Empty without engineering units */
    UA_Double scale; /* 0 without scaling */
} BindingVariable;

typedef struct PendingCall {
    LIST_ENTRY(PendingCall) next;
    BindingMethod *method;
    UA_Variant *output;
    UA_Boolean inCallback;
    UA_Boolean done;
    UA_StatusCode status;
} PendingCall;

typedef struct {
    UA_String path; /* Below the object, e.g. "days.0.dayDate" */
    UA_NodeId nodeId;
    UA_Boolean variable;
    UA_UInt32 seen; /* Generation of the last result that contained it */
} AutoNode;

/* The data of a polling REST driver as nodes */
typedef struct {
    UA_Boolean enabled;
    char *driver;
    UA_String from;
    UA_KeyValueMap scale; /* Factor by key name or path pattern */
    UA_KeyValueMap units; /* Unit by key name or path pattern */
    UA_Driver *rest;
    UA_StatusCode lastStatus;
    UA_UInt64 callbackId;
    UA_UInt32 generation;
    size_t cursor; /* The next node in the usual order of the results */
    size_t nodesSize;
    AutoNode *nodes;
} AutoNodes;

struct BindingDriver {
    UA_Driver drv;
    UA_NodeId objectId;
    size_t methodsSize;
    BindingMethod *methods;
    size_t variablesSize;
    BindingVariable *variables;
    AutoNodes autoNodes;
    LIST_HEAD(, PendingCall) calls;
    size_t polls;
};

static const UA_DriverParameter bindingParameters[] = {
    {"methods", UA_TYPES_KEYVALUEPAIR, true, false},
    {"variables", UA_TYPES_KEYVALUEPAIR, true, false},
    {"nodes", UA_TYPES_KEYVALUEPAIR, true, false},
    {"log-only-changes", UA_TYPES_BOOLEAN, false, false}
};

static UA_StatusCode
bindingCreate(UA_Server *server, const UA_KeyValueMap params, UA_Driver **outDriver) {
    (void)server;
    return UA_BindingDriver_new(params, outDriver);
}

const UA_DriverRegistration UA_BindingDriver_registration = {
    "binding", bindingParameters,
    sizeof(bindingParameters) / sizeof(bindingParameters[0]),
    bindingCreate
};

/***********/
/* Helpers */
/***********/

static UA_Logger *
getLogger(BindingDriver *bd) {
    return UA_Server_getConfig(bd->drv.server)->logging;
}

static const struct {
    const char *name;
    UA_UInt16 index;
} bindingTypes[] = {
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
    for(size_t i = 0; i < sizeof(bindingTypes) / sizeof(bindingTypes[0]); i++) {
        UA_String n = UA_STRING((char *)(uintptr_t)bindingTypes[i].name);
        if(UA_String_equal(&n, name))
            return &UA_TYPES[bindingTypes[i].index];
    }
    return NULL;
}

static UA_StatusCode
makeNodeId(const BindingDriver *bd, const UA_String *child, UA_NodeId *out) {
    UA_String id = UA_STRING_NULL;
    UA_StatusCode res = UA_String_append(&id, bd->drv.name);
    if(child) {
        res |= UA_String_append(&id, UA_STRING("."));
        res |= UA_String_append(&id, *child);
    }
    if(res != UA_STATUSCODE_GOOD) {
        UA_String_clear(&id);
        return res;
    }
    UA_NodeId_init(out);
    out->namespaceIndex = 1;
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
addEngineeringUnits(BindingDriver *bd, const UA_NodeId variable, const UA_String unit) {
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
    return UA_Server_addVariableNode(bd->drv.server, UA_NODEID_NULL, variable,
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
parseNode(BindingDriver *bd, const UA_KeyValuePair *def, UA_Boolean needsCall,
          BindingNode *node) {
    UA_KeyValueMap map = driverParamsMap(&def->value);
    const UA_String *call = driverParamsString(&map, "call");
    node->bd = bd;
    node->name = def->key.name;
    if(!call && needsCall) {
        UA_LOG_ERROR(getLogger(bd), UA_LOGCATEGORY_SERVER,
                     "Binding driver \"%S\": \"%S\" needs a call",
                     bd->drv.name, node->name);
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }
    node->driver = driverCString(driverParamsString(&map, "driver"));
    node->call = call ? driverCString(call) : NULL;
    if(!node->driver || (call && !node->call))
        return UA_STATUSCODE_BADOUTOFMEMORY;
    node->defaults =
        driverParamsMap(UA_KeyValueMap_get(&map, UA_QUALIFIEDNAME(0, "defaults")));
    return UA_STATUSCODE_GOOD;
}

static void
clearNode(BindingNode *node) {
    UA_free(node->driver);
    UA_free(node->call);
    UA_NodeId_clear(&node->nodeId);
}

static UA_KeyValueMap
getParamsMap(const UA_KeyValueMap *map, const char *key) {
    UA_QualifiedName qn = UA_QUALIFIEDNAME(0, (char *)(uintptr_t)key);
    return driverParamsMap(UA_KeyValueMap_get(map, qn));
}

static UA_StatusCode
typeError(BindingDriver *bd, const UA_String *owner, const UA_String *name) {
    UA_LOG_ERROR(getLogger(bd), UA_LOGCATEGORY_SERVER,
                 "Binding driver \"%S\": \"%S\" of \"%S\" needs a known type",
                 bd->drv.name, *name, *owner);
    return UA_STATUSCODE_BADCONFIGURATIONERROR;
}

static UA_StatusCode
parseArguments(BindingDriver *bd, const UA_KeyValuePair *method, const char *key,
               UA_Boolean outputs, size_t *size, BindingArgument **args) {
    UA_KeyValueMap def = driverParamsMap(&method->value);
    UA_KeyValueMap list = getParamsMap(&def, key);
    if(list.mapSize == 0)
        return UA_STATUSCODE_GOOD;
    *args = (BindingArgument *)UA_calloc(list.mapSize, sizeof(BindingArgument));
    if(!*args)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    *size = list.mapSize;
    for(size_t i = 0; i < list.mapSize; i++) {
        BindingArgument *arg = &(*args)[i];
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
        arg->array = driverPathHasWildcard(arg->from);
        if(!arg->type)
            return typeError(bd, &method->key.name, &arg->name);
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
optionError(BindingDriver *bd, const char *option, const UA_String *key,
            const char *expected) {
    UA_LOG_ERROR(getLogger(bd), UA_LOGCATEGORY_SERVER,
                 "Binding driver \"%S\": The %s of \"%S\" must be a %s",
                 bd->drv.name, option, *key, expected);
    return UA_STATUSCODE_BADCONFIGURATIONERROR;
}

/* The values of scale are numbers, those of units strings */
static UA_StatusCode
checkNodesOptions(BindingDriver *bd) {
    const UA_KeyValueMap *scale = &bd->autoNodes.scale;
    const UA_KeyValueMap *units = &bd->autoNodes.units;
    UA_Double factor;
    for(size_t i = 0; i < scale->mapSize; i++) {
        if(!driverNumber(&scale->map[i].value, &factor))
            return optionError(bd, "scale", &scale->map[i].key.name, "number");
    }
    for(size_t i = 0; i < units->mapSize; i++) {
        if(!UA_Variant_hasScalarType(&units->map[i].value, &UA_TYPES[UA_TYPES_STRING]))
            return optionError(bd, "unit", &units->map[i].key.name, "string");
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
parseConfig(BindingDriver *bd) {
    UA_KeyValueMap methods = getParamsMap(&bd->drv.params, "methods");
    UA_KeyValueMap variables = getParamsMap(&bd->drv.params, "variables");
    if(methods.mapSize > 0) {
        bd->methods = (BindingMethod *)UA_calloc(methods.mapSize, sizeof(BindingMethod));
        if(!bd->methods)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        bd->methodsSize = methods.mapSize;
    }
    if(variables.mapSize > 0) {
        bd->variables = (BindingVariable *)
            UA_calloc(variables.mapSize, sizeof(BindingVariable));
        if(!bd->variables)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        bd->variablesSize = variables.mapSize;
    }

    UA_StatusCode res = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < methods.mapSize && res == UA_STATUSCODE_GOOD; i++) {
        BindingMethod *m = &bd->methods[i];
        const UA_KeyValuePair *def = &methods.map[i];
        res = parseNode(bd, def, true, &m->node);
        if(res == UA_STATUSCODE_GOOD)
            res = parseArguments(bd, def, "inputs", false, &m->inputsSize, &m->inputs);
        if(res == UA_STATUSCODE_GOOD)
            res = parseArguments(bd, def, "outputs", true, &m->outputsSize, &m->outputs);
    }

    for(size_t i = 0; i < variables.mapSize && res == UA_STATUSCODE_GOOD; i++) {
        BindingVariable *v = &bd->variables[i];
        const UA_KeyValuePair *def = &variables.map[i];
        UA_KeyValueMap map = driverParamsMap(&def->value);
        v->value.name = def->key.name;
        v->interval = BINDING_DEFAULT_INTERVAL_MS;
        res = parseNode(bd, def, false, &v->node);
        if(res != UA_STATUSCODE_GOOD)
            break;
        v->value.type = findType(driverParamsString(&map, "type"));
        if(!v->value.type) {
            res = typeError(bd, &bd->drv.name, &v->node.name);
            break;
        }
        const UA_String *from = driverParamsString(&map, "from");
        if(!from) {
            UA_LOG_ERROR(getLogger(bd), UA_LOGCATEGORY_SERVER,
                         "Binding driver \"%S\": The variable \"%S\" needs a path "
                         "in \"from\"", bd->drv.name, v->node.name);
            res = UA_STATUSCODE_BADCONFIGURATIONERROR;
            break;
        }
        v->value.from = *from;
        v->value.array = driverPathHasWildcard(*from);
        const UA_String *unit = driverParamsString(&map, "unit");
        v->unit = unit ? *unit : UA_STRING_NULL;
        const UA_Variant *scale = UA_KeyValueMap_get(&map, UA_QUALIFIEDNAME(0, "scale"));
        if(scale && (!driverNumber(scale, &v->scale) ||
                     v->value.type != &UA_TYPES[UA_TYPES_DOUBLE])) {
            UA_LOG_ERROR(getLogger(bd), UA_LOGCATEGORY_SERVER,
                         "Binding driver \"%S\": The scale of the variable \"%S\" "
                         "must be a number, with the type Double", bd->drv.name,
                         v->node.name);
            res = UA_STATUSCODE_BADCONFIGURATIONERROR;
            break;
        }
        res = driverParamsInterval(&map, &v->interval);
        if(res != UA_STATUSCODE_GOOD)
            UA_LOG_ERROR(getLogger(bd), UA_LOGCATEGORY_SERVER,
                         "Binding driver \"%S\": The interval of the variable "
                         "\"%S\" must be a positive number",
                         bd->drv.name, v->node.name);
    }

    if(res == UA_STATUSCODE_GOOD &&
       UA_KeyValueMap_contains(&bd->drv.params, UA_QUALIFIEDNAME(0, "nodes"))) {
        UA_KeyValueMap config = getParamsMap(&bd->drv.params, "nodes");
        const UA_String *from = driverParamsString(&config, "from");
        bd->autoNodes.enabled = true;
        bd->autoNodes.from = from ? *from : UA_STRING_NULL;
        bd->autoNodes.scale = getParamsMap(&config, "scale");
        bd->autoNodes.units = getParamsMap(&config, "units");
        bd->autoNodes.driver = driverCString(driverParamsString(&config, "driver"));
        if(!bd->autoNodes.driver)
            res = UA_STATUSCODE_BADOUTOFMEMORY;
        if(res == UA_STATUSCODE_GOOD && driverPathHasWildcard(bd->autoNodes.from)) {
            UA_LOG_ERROR(getLogger(bd), UA_LOGCATEGORY_SERVER,
                         "Binding driver \"%S\": The path of the nodes in \"from\" "
                         "cannot have wildcards", bd->drv.name);
            res = UA_STATUSCODE_BADCONFIGURATIONERROR;
        }
        if(res == UA_STATUSCODE_GOOD)
            res = checkNodesOptions(bd);
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
    UA_free(m->driver);
    memset(m, 0, sizeof(AutoNodes));
}

static void
clearConfig(BindingDriver *bd) {
    clearAutoNodes(&bd->autoNodes);
    for(size_t i = 0; i < bd->methodsSize; i++) {
        clearNode(&bd->methods[i].node);
        UA_free(bd->methods[i].inputs);
        UA_free(bd->methods[i].outputs);
    }
    for(size_t i = 0; i < bd->variablesSize; i++)
        clearNode(&bd->variables[i].node);
    UA_free(bd->methods);
    UA_free(bd->variables);
    bd->methods = NULL;
    bd->variables = NULL;
    bd->methodsSize = 0;
    bd->variablesSize = 0;
    UA_NodeId_clear(&bd->objectId);
}

/***********/
/* Results */
/***********/

static UA_StatusCode
checkResult(UA_StatusCode status, const UA_KeyValueMap *result,
            UA_UInt16 *errorStatus) {
    *errorStatus = 0;
    if(status != UA_STATUSCODE_GOOD)
        return status;
    *errorStatus = driverErrorStatus(result);
    return (*errorStatus != 0) ? UA_STATUSCODE_BADCOMMUNICATIONERROR : UA_STATUSCODE_GOOD;
}

/* The paths of methods and polled variables start at the result */
static UA_Variant
resultRoot(const UA_KeyValueMap *result) {
    UA_Variant root;
    UA_Variant_setArray(&root, result->map, result->mapSize,
                        &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
    return root;
}

/* The text form of a value in the type. Strings take over the text. */
static UA_StatusCode
textToValue(UA_String *text, const UA_DataType *type, void *data) {
    if(type == &UA_TYPES[UA_TYPES_STRING] || type == &UA_TYPES[UA_TYPES_BYTESTRING]) {
        *(UA_String *)data = *text;
        UA_String_init(text);
        return UA_STATUSCODE_GOOD;
    }
    if(UA_decodeJson(text, data, type, NULL) == UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_GOOD;
    /* JSON strings (e.g. DateTime) lost their quotes in the path lookup */
    UA_clear(data, type);
    UA_String quoted = UA_STRING_NULL;
    UA_StatusCode res = UA_String_format(&quoted, "\"%S\"", *text);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_decodeJson(&quoted, data, type, NULL);
    UA_String_clear(&quoted);
    return (res == UA_STATUSCODE_GOOD) ? res : UA_STATUSCODE_BADDECODINGERROR;
}

/* All matches of a path with wildcards as an array of the type */
static UA_StatusCode
extractArray(const UA_Variant *root, const BindingArgument *arg, UA_Variant *out) {
    UA_Variant matches;
    UA_StatusCode res = driverPathCollect(root, arg->from, &matches);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    size_t size = matches.arrayLength;
    void *array = UA_Array_new(size, arg->type);
    if(!array)
        res = UA_STATUSCODE_BADOUTOFMEMORY;
    for(size_t i = 0; i < size && res == UA_STATUSCODE_GOOD; i++) {
        UA_String text = UA_STRING_NULL;
        res = driverPathAppend(&((UA_Variant *)matches.data)[i], UA_STRING_NULL, &text);
        void *element = (UA_Byte *)array + i * arg->type->memSize;
        if(res == UA_STATUSCODE_GOOD)
            res = textToValue(&text, arg->type, element);
        UA_String_clear(&text);
    }
    UA_Variant_clear(&matches);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Array_delete(array, size, arg->type);
        return res;
    }
    UA_Variant_setArray(out, array, size, arg->type);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
extractValue(const UA_Variant *root, const BindingArgument *arg, UA_Variant *out) {
    if(arg->array)
        return extractArray(root, arg, out);
    UA_String text = UA_STRING_NULL;
    UA_StatusCode res = driverPathAppend(root, arg->from, &text);
    void *data = NULL;
    if(res == UA_STATUSCODE_GOOD) {
        data = UA_new(arg->type);
        if(!data)
            res = UA_STATUSCODE_BADOUTOFMEMORY;
    }
    if(res == UA_STATUSCODE_GOOD)
        res = textToValue(&text, arg->type, data);
    UA_String_clear(&text);
    if(res != UA_STATUSCODE_GOOD) {
        if(data)
            UA_delete(data, arg->type);
        return res;
    }
    UA_Variant_setScalar(out, data, arg->type);
    return UA_STATUSCODE_GOOD;
}

/* Dividing by 10 gives 5.3 where multiplying by 0.1 gives 5.300000000000001 */
static UA_Double
applyScale(UA_Double value, UA_Double factor) {
    UA_Double inverse = 1.0 / factor;
    if(inverse == (UA_Double)(UA_Int64)inverse)
        return value / inverse;
    return value * factor;
}

/* Numbers times the factor, as Double. Arrays element by element, other
 * values unchanged. */
static UA_StatusCode
scaleValue(const UA_Variant *v, UA_Double factor, UA_Variant *out) {
    UA_Double d;
    if(driverNumber(v, &d)) {
        d = applyScale(d, factor);
        return UA_Variant_setScalarCopy(out, &d, &UA_TYPES[UA_TYPES_DOUBLE]);
    }
    if(UA_Variant_isScalar(v) || !v->type || !(v->type == &UA_TYPES[UA_TYPES_VARIANT] ||
                                               UA_DataType_isNumeric(v->type)))
        return UA_Variant_copy(v, out);

    /* Variant arrays stay Variant arrays, e.g. with nulls in between */
    const UA_DataType *type = (v->type == &UA_TYPES[UA_TYPES_VARIANT]) ?
        v->type : &UA_TYPES[UA_TYPES_DOUBLE];
    void *array = UA_Array_new(v->arrayLength, type);
    if(!array)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < v->arrayLength && res == UA_STATUSCODE_GOOD; i++) {
        if(type == &UA_TYPES[UA_TYPES_VARIANT]) {
            res = scaleValue(&((const UA_Variant *)v->data)[i], factor,
                             &((UA_Variant *)array)[i]);
            continue;
        }
        UA_Variant element;
        UA_Variant_setScalar(&element, (UA_Byte *)v->data + i * v->type->memSize,
                             v->type);
        driverNumber(&element, &((UA_Double *)array)[i]);
        ((UA_Double *)array)[i] = applyScale(((UA_Double *)array)[i], factor);
    }
    if(res != UA_STATUSCODE_GOOD) {
        UA_Array_delete(array, v->arrayLength, type);
        return res;
    }
    UA_Variant_setArray(out, array, v->arrayLength, type);
    return UA_STATUSCODE_GOOD;
}

/* A factor of 0 writes the value unscaled */
static UA_StatusCode
writeScaled(UA_Server *server, const UA_NodeId nodeId, const UA_Variant *v,
            UA_Double factor) {
    if(factor == 0.0)
        return UA_Server_writeValue(server, nodeId, *v);
    UA_Variant scaled;
    UA_Variant_init(&scaled);
    UA_StatusCode res = scaleValue(v, factor, &scaled);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_Server_writeValue(server, nodeId, scaled);
    UA_Variant_clear(&scaled);
    return res;
}

/***********/
/* Methods */
/***********/

static void
finishStopIfDrained(BindingDriver *bd);

static UA_StatusCode
fillOutputs(BindingMethod *m, const UA_KeyValueMap *result, UA_Variant *output) {
    UA_Variant root = resultRoot(result);
    for(size_t i = 0; i < m->outputsSize; i++) {
        UA_StatusCode res = extractValue(&root, &m->outputs[i], &output[i]);
        if(res == UA_STATUSCODE_GOOD)
            continue;
        UA_LOG_WARNING(getLogger(m->node.bd), UA_LOGCATEGORY_SERVER,
                       "Binding driver \"%S\": The output \"%S\" of \"%S\" was "
                       "not found in the result (%s)", m->node.bd->drv.name,
                       m->outputs[i].name, m->node.name, UA_StatusCode_name(res));
        for(size_t j = 0; j < i; j++)
            UA_Variant_clear(&output[j]);
        return res;
    }
    return UA_STATUSCODE_GOOD;
}

static void
methodDone(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    PendingCall *pc = (PendingCall *)context;
    BindingMethod *m = pc->method;
    BindingDriver *bd = m->node.bd;
    UA_UInt16 errorStatus;
    status = checkResult(status, result, &errorStatus);
    if(errorStatus != 0)
        UA_LOG_WARNING(getLogger(bd), UA_LOGCATEGORY_SERVER,
                       "Binding driver \"%S\": The method \"%S\" got the "
                       "status %u", bd->drv.name, m->node.name,
                       (unsigned)errorStatus);
    if(status == UA_STATUSCODE_GOOD)
        status = fillOutputs(m, result, pc->output);
    if(pc->inCallback) {
        pc->done = true;
        pc->status = status;
        return;
    }
    /* Also after a cancellation: the output stays valid until the result is
     * set, and the server waits for it */
    UA_Server_setAsyncCallMethodResult(bd->drv.server, pc->output, status);
    LIST_REMOVE(pc, next);
    UA_free(pc);
    finishStopIfDrained(bd);
}

static UA_StatusCode
methodCallback(UA_Server *server,
               const UA_NodeId *sessionId, void *sessionContext,
               const UA_NodeId *methodId, void *methodContext,
               const UA_NodeId *objectId, void *objectContext,
               size_t inputSize, const UA_Variant *input,
               size_t outputSize, UA_Variant *output) {
    (void)sessionId, (void)sessionContext, (void)methodId;
    (void)objectId, (void)objectContext;
    BindingMethod *m = (BindingMethod *)methodContext;
    BindingDriver *bd = m->node.bd;
    if(bd->drv.state != UA_LIFECYCLESTATE_STARTED)
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
    LIST_INSERT_HEAD(&bd->calls, pc, next);

    res = UA_Server_callDriverFrom(server, &bd->drv, m->node.driver, m->node.call, &in,
                                   methodDone, pc);
    UA_KeyValueMap_clear(&in);
    pc->inCallback = false;
    if(res == UA_STATUSCODE_GOOD && !pc->done)
        return UA_STATUSCODE_GOODCOMPLETESASYNCHRONOUSLY;

    if(res == UA_STATUSCODE_GOOD)
        res = pc->status;
    else
        UA_LOG_WARNING(getLogger(bd), UA_LOGCATEGORY_SERVER,
                       "Binding driver \"%S\": The call \"%s\" of the driver \"%s\" "
                       "failed (%s)", bd->drv.name, m->node.call, m->node.driver,
                       UA_StatusCode_name(res));
    LIST_REMOVE(pc, next);
    UA_free(pc);
    return res;
}

/**************/
/* Polling */
/**************/

/* The REST driver is resolved again when unsubscribing. It can be gone by then. */
static UA_StatusCode
subscribe(BindingDriver *bd, const char *driver, UA_DriverCallCallback callback,
          void *context, UA_Driver **rest, UA_UInt64 *callbackId) {
    *rest = UA_Server_getDriver(bd->drv.server, &bd->drv, driver);
    UA_StatusCode res = !*rest ? UA_STATUSCODE_BADNOTFOUND :
        UA_RestDriver_addCallback(*rest, callback, context, callbackId);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(getLogger(bd), UA_LOGCATEGORY_SERVER,
                     "Binding driver \"%S\": Needs the REST driver \"%s\" (%s)",
                     bd->drv.name, driver, UA_StatusCode_name(res));
        *rest = NULL;
    }
    return res;
}

static void
unsubscribe(BindingDriver *bd, const char *driver, UA_Driver **rest,
            UA_UInt64 callbackId) {
    if(*rest && UA_Server_getDriver(bd->drv.server, &bd->drv, driver) == *rest)
        UA_RestDriver_removeCallback(*rest, callbackId);
    *rest = NULL;
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
shouldLogFailure(BindingDriver *bd, UA_StatusCode status, UA_StatusCode lastStatus) {
    return status != lastStatus ||
        !driverParamsBoolean(&bd->drv.params, "log-only-changes");
}

static void
setVariableStatus(BindingVariable *v, UA_StatusCode status, UA_UInt16 errorStatus) {
    BindingDriver *bd = v->node.bd;
    if(shouldLogFailure(bd, status, v->lastStatus)) {
        if(errorStatus != 0)
            UA_LOG_WARNING(getLogger(bd), UA_LOGCATEGORY_SERVER,
                           "Binding driver \"%S\": The variable \"%S\" could not be "
                           "updated (status %u)", bd->drv.name, v->node.name,
                           (unsigned)errorStatus);
        else
            UA_LOG_WARNING(getLogger(bd), UA_LOGCATEGORY_SERVER,
                           "Binding driver \"%S\": The variable \"%S\" could not be "
                           "updated (%s)", bd->drv.name, v->node.name,
                           UA_StatusCode_name(status));
    }
    v->lastStatus = status;
    writeStatus(bd->drv.server, v->node.nodeId, status);
}

/* The paths of variables fed by polling start at the parsed data */
static void
updateVariable(BindingVariable *v, UA_StatusCode status, const UA_KeyValueMap *result) {
    BindingDriver *bd = v->node.bd;
    UA_Variant value;
    UA_Variant_init(&value);
    UA_UInt16 errorStatus;
    status = checkResult(status, result, &errorStatus);
    if(status == UA_STATUSCODE_GOOD) {
        UA_Variant root = resultRoot(result);
        const UA_Variant *start = v->node.call ? &root :
            UA_KeyValueMap_get(result, UA_QUALIFIEDNAME(0, "data"));
        status = extractValue(start, &v->value, &value);
    }
    if(status == UA_STATUSCODE_GOOD)
        status = writeScaled(bd->drv.server, v->node.nodeId, &value, v->scale);
    if(status == UA_STATUSCODE_GOOD) {
        if(v->lastStatus != UA_STATUSCODE_GOOD &&
           v->lastStatus != UA_STATUSCODE_BADWAITINGFORINITIALDATA)
            UA_LOG_INFO(getLogger(bd), UA_LOGCATEGORY_SERVER,
                        "Binding driver \"%S\": The variable \"%S\" is "
                        "updated again", bd->drv.name, v->node.name);
        v->lastStatus = UA_STATUSCODE_GOOD;
    } else {
        setVariableStatus(v, status, errorStatus);
    }
    UA_Variant_clear(&value);
}

static void
pollDone(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    BindingVariable *v = (BindingVariable *)context;
    BindingDriver *bd = v->node.bd;
    v->busy = false;
    bd->polls--;
    if(bd->drv.state == UA_LIFECYCLESTATE_STARTED)
        updateVariable(v, status, result);
    finishStopIfDrained(bd);
}

static void
polledResult(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    BindingVariable *v = (BindingVariable *)context;
    if(v->node.bd->drv.state == UA_LIFECYCLESTATE_STARTED)
        updateVariable(v, status, result);
}

static void
pollCallback(UA_Server *server, void *data) {
    BindingVariable *v = (BindingVariable *)data;
    BindingDriver *bd = v->node.bd;
    if(v->busy || bd->drv.state != UA_LIFECYCLESTATE_STARTED)
        return;
    v->busy = true;
    bd->polls++;
    UA_StatusCode res = UA_Server_callDriverFrom(server, &bd->drv, v->node.driver,
                                                 v->node.call, &v->node.defaults,
                                                 pollDone, v);
    if(res != UA_STATUSCODE_GOOD) {
        v->busy = false;
        bd->polls--;
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

/* The entry for a node: by its key name, or a JSONPath pattern ($...) that
 * matches its path below nodes.from */
static const UA_Variant *
findByKeyOrPath(const UA_KeyValueMap *map, const UA_String name, const UA_String path) {
    for(size_t i = 0; i < map->mapSize; i++) {
        const UA_String *key = &map->map[i].key.name;
        UA_Boolean pattern = key->length > 0 && key->data[0] == '$';
        if(pattern ? driverPathMatches(*key, path) : UA_String_equal(key, &name))
            return &map->map[i].value;
    }
    return NULL;
}

static UA_StatusCode
writeAutoValue(BindingDriver *bd, const AutoNode *node, const UA_String name,
               const UA_Variant *v) {
    UA_Double factor = 0.0;
    driverNumber(findByKeyOrPath(&bd->autoNodes.scale, name, node->path), &factor);
    return writeScaled(bd->drv.server, node->nodeId, v, factor);
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
addAutoNode(BindingDriver *bd, const UA_NodeId parent, const UA_String *path,
            const UA_String name, UA_Boolean object, const UA_Variant *v) {
    AutoNodes *m = &bd->autoNodes;
    AutoNode *nodes = (AutoNode *)
        UA_realloc(m->nodes, sizeof(AutoNode) * (m->nodesSize + 1));
    if(!nodes)
        return NULL;
    m->nodes = nodes;
    AutoNode *node = &nodes[m->nodesSize];
    memset(node, 0, sizeof(AutoNode));
    node->variable = !object;

    UA_QualifiedName browseName = {1, name};
    UA_StatusCode res = UA_String_copy(path, &node->path);
    if(res == UA_STATUSCODE_GOOD)
        res = makeNodeId(bd, path, &node->nodeId);
    if(res == UA_STATUSCODE_GOOD && node->variable) {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        attr.displayName.text = name;
        attr.dataType = autoDataType(v, &attr.valueRank);
        attr.accessLevel = UA_ACCESSLEVELMASK_READ;
        attr.userAccessLevel = UA_ACCESSLEVELMASK_READ;
        res = UA_Server_addVariableNode(bd->drv.server, node->nodeId, parent,
                                        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                        browseName,
                                        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                                        attr, NULL, NULL);
        const UA_Variant *unit = findByKeyOrPath(&m->units, name, *path);
        if(res == UA_STATUSCODE_GOOD && unit &&
           UA_Variant_hasScalarType(unit, &UA_TYPES[UA_TYPES_STRING]))
            res = addEngineeringUnits(bd, node->nodeId, *(const UA_String *)unit->data);
    } else if(res == UA_STATUSCODE_GOOD) {
        UA_ObjectAttributes attr = UA_ObjectAttributes_default;
        attr.displayName.text = name;
        res = UA_Server_addObjectNode(bd->drv.server, node->nodeId, parent,
                                      UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                      browseName,
                                      UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE),
                                      attr, NULL, NULL);
    }
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(getLogger(bd), UA_LOGCATEGORY_SERVER,
                       "Binding driver \"%S\": The node \"%S\" could not be added (%s)",
                       bd->drv.name, *path, UA_StatusCode_name(res));
        UA_String_clear(&node->path);
        UA_NodeId_clear(&node->nodeId);
        return NULL;
    }
    m->nodesSize++;
    return node;
}

static void
autoNodesChild(BindingDriver *bd, const UA_NodeId parent, const UA_String parentPath,
               const UA_String name, const UA_Variant *v);

static void
autoNodesChildren(BindingDriver *bd, const UA_NodeId parent, const UA_String parentPath,
                  const UA_Variant *v) {
    if(UA_Variant_hasArrayType(v, &UA_TYPES[UA_TYPES_KEYVALUEPAIR])) {
        const UA_KeyValuePair *pairs = (const UA_KeyValuePair *)v->data;
        for(size_t i = 0; i < v->arrayLength; i++)
            autoNodesChild(bd, parent, parentPath, pairs[i].key.name, &pairs[i].value);
    } else if(UA_Variant_hasArrayType(v, &UA_TYPES[UA_TYPES_VARIANT])) {
        const UA_Variant *items = (const UA_Variant *)v->data;
        for(size_t i = 0; i < v->arrayLength; i++) {
            UA_Byte buf[24];
            UA_String index = {sizeof(buf), buf};
            UA_String_format(&index, "%lu", (unsigned long)i);
            autoNodesChild(bd, parent, parentPath, index, &items[i]);
        }
    }
}

static void
autoNodesChild(BindingDriver *bd, const UA_NodeId parent, const UA_String parentPath,
               const UA_String name, const UA_Variant *v) {
    UA_Byte buf[AUTO_MAX_PATH];
    UA_String path = {sizeof(buf), buf};
    UA_StatusCode res = (parentPath.length > 0) ?
        UA_String_format(&path, "%S.%S", parentPath, name) :
        UA_String_format(&path, "%S", name);
    if(res != UA_STATUSCODE_GOOD)
        return;

    AutoNodes *m = &bd->autoNodes;
    UA_Boolean object = isAutoObject(v);
    AutoNode *node = findAutoNode(m, &path);
    if(!node)
        node = addAutoNode(bd, parent, &path, name, object, v);
    if(!node)
        return;
    node->seen = m->generation;
    if(node->variable && object) {
        writeStatus(bd->drv.server, node->nodeId, UA_STATUSCODE_BADTYPEMISMATCH);
    } else if(node->variable) {
        res = writeAutoValue(bd, node, name, v);
        if(res != UA_STATUSCODE_GOOD)
            writeStatus(bd->drv.server, node->nodeId,
                        UA_Variant_isEmpty(v) ? UA_STATUSCODE_BADNODATA : res);
    } else if(object) {
        /* The node array can grow, the strings of the node stay */
        autoNodesChildren(bd, node->nodeId, node->path, v);
    }
}

static void
setAutoNodesStatus(BindingDriver *bd, UA_StatusCode status, UA_Boolean onlyUnseen) {
    AutoNodes *m = &bd->autoNodes;
    for(size_t i = 0; i < m->nodesSize; i++) {
        if(m->nodes[i].variable && (!onlyUnseen || m->nodes[i].seen != m->generation))
            writeStatus(bd->drv.server, m->nodes[i].nodeId, status);
    }
}

static void
autoNodesResult(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    BindingDriver *bd = (BindingDriver *)context;
    AutoNodes *m = &bd->autoNodes;
    if(bd->drv.state != UA_LIFECYCLESTATE_STARTED)
        return;

    UA_UInt16 errorStatus;
    status = checkResult(status, result, &errorStatus);
    const UA_Variant *root = NULL;
    UA_Variant element;
    if(status == UA_STATUSCODE_GOOD) {
        UA_String from = m->from;
        root = driverPathFind(UA_KeyValueMap_get(result, UA_QUALIFIEDNAME(0, "data")),
                              &from, &element);
        if(!root || from.length > 0)
            status = UA_STATUSCODE_BADNOTFOUND;
    }
    if(status != UA_STATUSCODE_GOOD) {
        if(shouldLogFailure(bd, status, m->lastStatus))
            UA_LOG_WARNING(getLogger(bd), UA_LOGCATEGORY_SERVER,
                           "Binding driver \"%S\": The nodes could not be updated "
                           "(%s, status %u)", bd->drv.name, UA_StatusCode_name(status),
                           (unsigned)errorStatus);
        m->lastStatus = status;
        setAutoNodesStatus(bd, status, false);
        return;
    }
    if(m->lastStatus != UA_STATUSCODE_GOOD)
        UA_LOG_INFO(getLogger(bd), UA_LOGCATEGORY_SERVER,
                    "Binding driver \"%S\": The nodes are updated again", bd->drv.name);
    m->lastStatus = UA_STATUSCODE_GOOD;

    m->generation++;
    autoNodesChildren(bd, bd->objectId, UA_STRING_NULL, root);
    setAutoNodesStatus(bd, UA_STATUSCODE_BADNODATA, true);
}

static UA_StatusCode
startAutoNodes(BindingDriver *bd) {
    AutoNodes *m = &bd->autoNodes;
    if(!m->enabled)
        return UA_STATUSCODE_GOOD;
    return subscribe(bd, m->driver, autoNodesResult, bd, &m->rest, &m->callbackId);
}

static void
stopAutoNodes(BindingDriver *bd) {
    unsubscribe(bd, bd->autoNodes.driver, &bd->autoNodes.rest, bd->autoNodes.callbackId);
}

/*********/
/* Nodes */
/*********/

static void
toArguments(const BindingArgument *args, size_t size, UA_Argument *out) {
    for(size_t i = 0; i < size; i++) {
        UA_Argument_init(&out[i]);
        out[i].name = args[i].name;
        out[i].dataType = args[i].type->typeId;
        out[i].valueRank = args[i].array ?
            UA_VALUERANK_ONE_DIMENSION : UA_VALUERANK_SCALAR;
    }
}

static UA_StatusCode
addMethod(BindingDriver *bd, BindingMethod *m) {
    UA_StatusCode res = makeNodeId(bd, &m->node.name, &m->node.nodeId);
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
    UA_QualifiedName browseName = {1, m->node.name};
    return UA_Server_addMethodNode(bd->drv.server, m->node.nodeId, bd->objectId,
                                   UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                   browseName, attr, methodCallback,
                                   m->inputsSize, inputs, m->outputsSize, outputs,
                                   m, NULL);
}

static UA_StatusCode
addVariable(BindingDriver *bd, BindingVariable *v) {
    UA_StatusCode res = makeNodeId(bd, &v->node.name, &v->node.nodeId);
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
    UA_QualifiedName browseName = {1, v->node.name};
    res = UA_Server_addVariableNode(bd->drv.server, v->node.nodeId, bd->objectId,
                                    UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                    browseName,
                                    UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                                    attr, v, NULL);
    if(res == UA_STATUSCODE_GOOD && v->unit.length > 0)
        res = addEngineeringUnits(bd, v->node.nodeId, v->unit);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    v->lastStatus = UA_STATUSCODE_BADWAITINGFORINITIALDATA; /* Not a failure */
    writeStatus(bd->drv.server, v->node.nodeId, v->lastStatus);
    if(!v->node.call)
        return subscribe(bd, v->node.driver, polledResult, v, &v->rest,
                         &v->restCallbackId);
    return UA_Server_addRepeatedCallback(bd->drv.server, pollCallback, v,
                                         v->interval, &v->callbackId);
}

static void
removeNodes(BindingDriver *bd) {
    for(size_t i = bd->autoNodes.nodesSize; i > 0; i--) /* Children first */
        UA_Server_deleteNode(bd->drv.server, bd->autoNodes.nodes[i - 1].nodeId, true);
    for(size_t i = 0; i < bd->variablesSize; i++) {
        BindingVariable *v = &bd->variables[i];
        if(v->callbackId != 0)
            UA_Server_removeCallback(bd->drv.server, v->callbackId);
        v->callbackId = 0;
        unsubscribe(bd, v->node.driver, &v->rest, v->restCallbackId);
        if(!UA_NodeId_isNull(&v->node.nodeId))
            UA_Server_deleteNode(bd->drv.server, v->node.nodeId, true);
    }
    for(size_t i = 0; i < bd->methodsSize; i++) {
        if(!UA_NodeId_isNull(&bd->methods[i].node.nodeId))
            UA_Server_deleteNode(bd->drv.server, bd->methods[i].node.nodeId, true);
    }
    if(!UA_NodeId_isNull(&bd->objectId))
        UA_Server_deleteNode(bd->drv.server, bd->objectId, true);
}

static UA_StatusCode
addNodes(BindingDriver *bd) {
    UA_StatusCode res = makeNodeId(bd, NULL, &bd->objectId);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    UA_String shortName = bd->drv.name;
    for(size_t i = shortName.length; i > 0; i--) {
        if(shortName.data[i - 1] == '/') {
            shortName.data += i;
            shortName.length -= i;
            break;
        }
    }
    UA_ObjectAttributes attr = UA_ObjectAttributes_default;
    attr.displayName.text = shortName;
    UA_QualifiedName browseName = {1, shortName};
    res = UA_Server_addObjectNode(bd->drv.server, bd->objectId,
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), browseName,
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE),
                                  attr, NULL, NULL);
    for(size_t i = 0; i < bd->methodsSize && res == UA_STATUSCODE_GOOD; i++)
        res = addMethod(bd, &bd->methods[i]);
    for(size_t i = 0; i < bd->variablesSize && res == UA_STATUSCODE_GOOD; i++)
        res = addVariable(bd, &bd->variables[i]);
    if(res != UA_STATUSCODE_GOOD)
        UA_LOG_ERROR(getLogger(bd), UA_LOGCATEGORY_SERVER,
                     "Binding driver \"%S\": The nodes could not be added (%s)",
                     bd->drv.name, UA_StatusCode_name(res));
    return res;
}

/*************/
/* Lifecycle */
/*************/

static void
finishStopIfDrained(BindingDriver *bd) {
    if(bd->drv.state != UA_LIFECYCLESTATE_STOPPING ||
       !LIST_EMPTY(&bd->calls) || bd->polls > 0)
        return;
    clearConfig(bd);
    bd->drv.state = UA_LIFECYCLESTATE_STOPPED;
}

static UA_StatusCode
bindingStart(UA_Driver *drv) {
    BindingDriver *bd = (BindingDriver *)drv;
    if(drv->state != UA_LIFECYCLESTATE_STOPPED)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_StatusCode res = parseConfig(bd);
    if(res == UA_STATUSCODE_GOOD)
        res = addNodes(bd);
    if(res == UA_STATUSCODE_GOOD)
        res = startAutoNodes(bd);
    if(res != UA_STATUSCODE_GOOD) {
        removeNodes(bd);
        clearConfig(bd);
        return res;
    }
    drv->state = UA_LIFECYCLESTATE_STARTED;
    return UA_STATUSCODE_GOOD;
}

static void
bindingStop(UA_Driver *drv) {
    BindingDriver *bd = (BindingDriver *)drv;
    if(drv->state != UA_LIFECYCLESTATE_STARTED)
        return;
    drv->state = UA_LIFECYCLESTATE_STOPPING;
    stopAutoNodes(bd);
    removeNodes(bd);
    finishStopIfDrained(bd);
}

static UA_StatusCode
bindingFree(UA_Driver *drv) {
    if(drv->state != UA_LIFECYCLESTATE_STOPPED)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_KeyValueMap_clear(&drv->params);
    UA_free(drv);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_BindingDriver_new(const UA_KeyValueMap params, UA_Driver **outDriver) {
    BindingDriver *bd = (BindingDriver *)UA_calloc(1, sizeof(BindingDriver));
    if(!bd)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode res = UA_KeyValueMap_copy(&params, &bd->drv.params);
    if(res != UA_STATUSCODE_GOOD) {
        UA_free(bd);
        return res;
    }
    LIST_INIT(&bd->calls);
    bd->drv.name = UA_STRING("binding");
    bd->drv.start = bindingStart;
    bd->drv.stop = bindingStop;
    bd->drv.free = bindingFree;
    *outDriver = &bd->drv;
    return UA_STATUSCODE_GOOD;
}

#endif /* UA_ENABLE_DRIVER_REST */
