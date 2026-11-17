/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

#include <open62541/driver/binding.h>

#include "open62541_queue.h"
#include "../driver_params.h"

#ifdef UA_ENABLE_DRIVER_REST

#define BINDING_DEFAULT_INTERVAL_MS 1000.0

typedef struct BindingDriver BindingDriver;

typedef struct {
    UA_String name;
    const UA_DataType *type;
    UA_String from;
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
} BindingVariable;

typedef struct PendingCall {
    LIST_ENTRY(PendingCall) next;
    BindingMethod *method;
    UA_Variant *output;
    UA_Boolean inCallback;
    UA_Boolean done;
    UA_Boolean cancelled;
    UA_StatusCode status;
} PendingCall;

struct BindingDriver {
    UA_Driver drv;
    UA_NodeId objectId;
    size_t methodsSize;
    BindingMethod *methods;
    size_t variablesSize;
    BindingVariable *variables;
    LIST_HEAD(, PendingCall) calls;
    size_t polls;

    UA_Boolean hooked;
    void (*prevCancel)(UA_Server *server, const void *out);
};

static const UA_DriverParameter bindingParameters[] = {
    {"methods", UA_TYPES_KEYVALUEPAIR, true, false},
    {"variables", UA_TYPES_KEYVALUEPAIR, true, false}
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

static UA_StatusCode bindingStart(UA_Driver *drv);

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

/*****************/
/* Configuration */
/*****************/

static UA_StatusCode
parseNode(BindingDriver *bd, const UA_KeyValuePair *def, BindingNode *node) {
    UA_KeyValueMap map = driverParamsMap(&def->value);
    const UA_String *call = driverParamsString(&map, "call");
    node->bd = bd;
    node->name = def->key.name;
    if(!call) {
        UA_LOG_ERROR(getLogger(bd), UA_LOGCATEGORY_SERVER,
                     "Binding driver \"%S\": \"%S\" needs a call",
                     bd->drv.name, node->name);
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }
    node->driver = driverCString(driverParamsString(&map, "driver"));
    node->call = driverCString(call);
    if(!node->driver || !node->call)
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
        if(!arg->type)
            return typeError(bd, &method->key.name, &arg->name);
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
        res = parseNode(bd, def, &m->node);
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
        res = parseNode(bd, def, &v->node);
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
        const UA_Variant *interval =
            UA_KeyValueMap_get(&map, UA_QUALIFIEDNAME(0, "interval"));
        if(interval) {
            UA_Variant d;
            UA_Variant_init(&d);
            if(UA_Variant_isScalar(interval) && UA_DataType_isNumeric(interval->type))
                UA_castNumerical(interval, &UA_TYPES[UA_TYPES_DOUBLE], &d);
            if(UA_Variant_isEmpty(&d) || *(UA_Double *)d.data <= 0.0) {
                UA_Variant_clear(&d);
                UA_LOG_ERROR(getLogger(bd), UA_LOGCATEGORY_SERVER,
                             "Binding driver \"%S\": The interval of the variable "
                             "\"%S\" must be a positive number",
                             bd->drv.name, v->node.name);
                res = UA_STATUSCODE_BADCONFIGURATIONERROR;
                break;
            }
            v->interval = *(UA_Double *)d.data;
            UA_Variant_clear(&d);
        }
    }
    return res;
}

static void
clearConfig(BindingDriver *bd) {
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
    const UA_UInt16 *s = (const UA_UInt16 *)UA_KeyValueMap_getScalar(
        result, UA_QUALIFIEDNAME(0, "status"), &UA_TYPES[UA_TYPES_UINT16]);
    if(!s || *s < 400)
        return UA_STATUSCODE_GOOD;
    *errorStatus = *s;
    return UA_STATUSCODE_BADCOMMUNICATIONERROR;
}

static UA_StatusCode
extractValue(const UA_KeyValueMap *result, const BindingArgument *arg,
             UA_Variant *out) {
    UA_Variant all;
    UA_Variant_setArray(&all, result->map, result->mapSize,
                        &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
    UA_String text = UA_STRING_NULL;
    UA_StatusCode res = driverPathAppend(&all, arg->from, &text);
    if(res != UA_STATUSCODE_GOOD) {
        UA_String_clear(&text);
        return res;
    }

    void *data = UA_new(arg->type);
    if(!data) {
        UA_String_clear(&text);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    if(arg->type == &UA_TYPES[UA_TYPES_STRING] ||
       arg->type == &UA_TYPES[UA_TYPES_BYTESTRING]) {
        *(UA_String *)data = text;
        UA_String_init(&text);
    } else {
        /* JSON strings (e.g. DateTime) lost their quotes in the path lookup */
        res = UA_decodeJson(&text, data, arg->type, NULL);
        if(res != UA_STATUSCODE_GOOD) {
            UA_clear(data, arg->type);
            UA_String quoted = UA_STRING_NULL;
            res = UA_String_append(&quoted, UA_STRING("\""));
            res |= UA_String_append(&quoted, text);
            res |= UA_String_append(&quoted, UA_STRING("\""));
            if(res == UA_STATUSCODE_GOOD)
                res = UA_decodeJson(&quoted, data, arg->type, NULL);
            UA_String_clear(&quoted);
        }
    }
    UA_String_clear(&text);
    if(res != UA_STATUSCODE_GOOD) {
        UA_delete(data, arg->type);
        return UA_STATUSCODE_BADDECODINGERROR;
    }
    UA_Variant_setScalar(out, data, arg->type);
    return UA_STATUSCODE_GOOD;
}

/***********/
/* Methods */
/***********/

static void
finishStopIfDrained(BindingDriver *bd);

static UA_StatusCode
fillOutputs(BindingMethod *m, const UA_KeyValueMap *result, UA_Variant *output) {
    for(size_t i = 0; i < m->outputsSize; i++) {
        UA_StatusCode res = extractValue(result, &m->outputs[i], &output[i]);
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
    if(!pc->cancelled) {
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
        UA_Server_setAsyncCallMethodResult(bd->drv.server, pc->output, status);
    }
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

static void
cancelCallback(UA_Server *server, const void *out) {
    void (*prev)(UA_Server *server, const void *out) = NULL;
    for(UA_Driver *drv = UA_Server_getDrivers(server); drv; drv = drv->next) {
        if(drv->start != bindingStart)
            continue;
        BindingDriver *bd = (BindingDriver *)drv;
        if(bd->hooked)
            prev = bd->prevCancel;
        PendingCall *pc;
        LIST_FOREACH(pc, &bd->calls, next) {
            if(pc->output == out)
                pc->cancelled = true;
        }
    }
    if(prev)
        prev(server, out);
}

static BindingDriver *
otherHookedDriver(BindingDriver *bd) {
    for(UA_Driver *drv = UA_Server_getDrivers(bd->drv.server); drv; drv = drv->next) {
        if(drv != &bd->drv && drv->start == bindingStart &&
           ((BindingDriver *)drv)->hooked)
            return (BindingDriver *)drv;
    }
    return NULL;
}

static void
hookCancel(BindingDriver *bd) {
    UA_ServerConfig *config = UA_Server_getConfig(bd->drv.server);
    BindingDriver *other = otherHookedDriver(bd);
    if(other && config->asyncOperationCancelCallback == cancelCallback) {
        bd->prevCancel = other->prevCancel;
    } else {
        bd->prevCancel = config->asyncOperationCancelCallback;
        config->asyncOperationCancelCallback = cancelCallback;
    }
    bd->hooked = true;
}

static void
unhookCancel(BindingDriver *bd) {
    if(!bd->hooked)
        return;
    bd->hooked = false;
    UA_ServerConfig *config = UA_Server_getConfig(bd->drv.server);
    if(!otherHookedDriver(bd) && config->asyncOperationCancelCallback == cancelCallback)
        config->asyncOperationCancelCallback = bd->prevCancel;
}

/*************/
/* Variables */
/*************/

static void
setVariableStatus(BindingVariable *v, UA_StatusCode status, UA_UInt16 errorStatus) {
    if(status != v->lastStatus && errorStatus != 0)
        UA_LOG_WARNING(getLogger(v->node.bd), UA_LOGCATEGORY_SERVER,
                       "Binding driver \"%S\": The variable \"%S\" could not be "
                       "updated (status %u)", v->node.bd->drv.name, v->node.name,
                       (unsigned)errorStatus);
    else if(status != v->lastStatus)
        UA_LOG_WARNING(getLogger(v->node.bd), UA_LOGCATEGORY_SERVER,
                       "Binding driver \"%S\": The variable \"%S\" could not be "
                       "updated (%s)", v->node.bd->drv.name, v->node.name,
                       UA_StatusCode_name(status));
    v->lastStatus = status;
    UA_DataValue dv;
    UA_DataValue_init(&dv);
    dv.hasStatus = true;
    dv.status = status;
    UA_Server_writeDataValue(v->node.bd->drv.server, v->node.nodeId, dv);
}

static void
pollDone(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    BindingVariable *v = (BindingVariable *)context;
    BindingDriver *bd = v->node.bd;
    v->busy = false;
    bd->polls--;
    if(bd->drv.state == UA_LIFECYCLESTATE_STARTED) {
        UA_Variant value;
        UA_Variant_init(&value);
        UA_UInt16 errorStatus;
        status = checkResult(status, result, &errorStatus);
        if(status == UA_STATUSCODE_GOOD)
            status = extractValue(result, &v->value, &value);
        if(status == UA_STATUSCODE_GOOD)
            status = UA_Server_writeValue(bd->drv.server, v->node.nodeId, value);
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
    finishStopIfDrained(bd);
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

/*********/
/* Nodes */
/*********/

static void
toArguments(const BindingArgument *args, size_t size, UA_Argument *out) {
    for(size_t i = 0; i < size; i++) {
        UA_Argument_init(&out[i]);
        out[i].name = args[i].name;
        out[i].dataType = args[i].type->typeId;
        out[i].valueRank = UA_VALUERANK_SCALAR;
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
    attr.valueRank = UA_VALUERANK_SCALAR;
    attr.accessLevel = UA_ACCESSLEVELMASK_READ;
    attr.userAccessLevel = UA_ACCESSLEVELMASK_READ;
    UA_QualifiedName browseName = {1, v->node.name};
    res = UA_Server_addVariableNode(bd->drv.server, v->node.nodeId, bd->objectId,
                                    UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                    browseName,
                                    UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                                    attr, v, NULL);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    v->lastStatus = UA_STATUSCODE_BADWAITINGFORINITIALDATA;
    setVariableStatus(v, UA_STATUSCODE_BADWAITINGFORINITIALDATA, 0);
    return UA_Server_addRepeatedCallback(bd->drv.server, pollCallback, v,
                                         v->interval, &v->callbackId);
}

static void
removeNodes(BindingDriver *bd) {
    for(size_t i = 0; i < bd->variablesSize; i++) {
        BindingVariable *v = &bd->variables[i];
        if(v->callbackId != 0)
            UA_Server_removeCallback(bd->drv.server, v->callbackId);
        v->callbackId = 0;
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
    unhookCancel(bd);
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
    if(res != UA_STATUSCODE_GOOD) {
        removeNodes(bd);
        clearConfig(bd);
        return res;
    }
    hookCancel(bd);
    drv->state = UA_LIFECYCLESTATE_STARTED;
    return UA_STATUSCODE_GOOD;
}

static void
bindingStop(UA_Driver *drv) {
    BindingDriver *bd = (BindingDriver *)drv;
    if(drv->state != UA_LIFECYCLESTATE_STARTED)
        return;
    drv->state = UA_LIFECYCLESTATE_STOPPING;
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
