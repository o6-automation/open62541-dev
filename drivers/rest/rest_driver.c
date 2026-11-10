/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

#include <open62541/driver/rest.h>

#include "../driver_params.h"

#ifdef UA_ENABLE_DRIVER_REST

#define REST_MAX_CHAIN 16

typedef struct {
    UA_Driver drv;
    size_t runs;
} RestDriver;

typedef struct {
    RestDriver *rd;
    UA_KeyValueMap input;
    UA_KeyValueMap results;
    const UA_KeyValuePair *chain[REST_MAX_CHAIN];
    size_t chainSize;
    size_t current;
    UA_DriverCallCallback callback;
    void *context;
} RestRun;

static const UA_DriverParameter restParameters[] = {
    {"calls", UA_TYPES_KEYVALUEPAIR, true, true},
    {"defaults", UA_TYPES_KEYVALUEPAIR, true, false}
};

static UA_StatusCode
restCreate(UA_Server *server, const UA_KeyValueMap params, UA_Driver **outDriver) {
    (void)server;
    return UA_RestDriver_new(params, outDriver);
}

const UA_DriverRegistration UA_RestDriver_registration = {
    "rest", restParameters,
    sizeof(restParameters) / sizeof(restParameters[0]),
    restCreate
};

/***********/
/* Helpers */
/***********/

static UA_Boolean
equalsChars(const UA_String *s, const char *chars) {
    UA_String c = UA_STRING((char *)(uintptr_t)chars);
    return UA_String_equal(s, &c);
}

static const UA_KeyValuePair *
findCall(const RestDriver *rd, const UA_String *name) {
    UA_KeyValueMap calls = driverParamsMap(UA_KeyValueMap_get(&rd->drv.params,
                                                    UA_QUALIFIEDNAME(0, "calls")));
    for(size_t i = 0; i < calls.mapSize; i++) {
        if(UA_String_equal(&calls.map[i].key.name, name))
            return &calls.map[i];
    }
    return NULL;
}

/****************/
/* Placeholders */
/****************/

static UA_StatusCode
appendExpression(const RestRun *run, UA_String expr, UA_String *out) {
    UA_String head = driverPathSegment(&expr);
    if(equalsChars(&head, "input")) {
        UA_Variant input;
        UA_Variant_setArray(&input, run->input.map, run->input.mapSize,
                            &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
        return driverPathAppend(&input, expr, out);
    }
    UA_QualifiedName callName = {0, head};
    return driverPathAppend(UA_KeyValueMap_get(&run->results, callName), expr, out);
}

static UA_StatusCode
resolve(const RestRun *run, const UA_String *tmpl, UA_String *out) {
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    size_t pos = 0;
    while(res == UA_STATUSCODE_GOOD && pos < tmpl->length) {
        size_t start = pos;
        while(pos + 1 < tmpl->length &&
              !(tmpl->data[pos] == '$' && tmpl->data[pos + 1] == '{'))
            pos++;
        if(pos + 1 >= tmpl->length) {
            UA_String rest = {tmpl->length - start, &tmpl->data[start]};
            return UA_String_append(out, rest);
        }
        UA_String literal = {pos - start, &tmpl->data[start]};
        res = UA_String_append(out, literal);
        size_t end = pos + 2;
        while(end < tmpl->length && tmpl->data[end] != '}')
            end++;
        if(end == tmpl->length)
            return UA_STATUSCODE_BADINVALIDARGUMENT;
        UA_String expr = {end - pos - 2, &tmpl->data[pos + 2]};
        if(res == UA_STATUSCODE_GOOD)
            res = appendExpression(run, expr, out);
        pos = end + 1;
    }
    return res;
}

/*********/
/* Calls */
/*********/

static void
callDone(void *context, UA_StatusCode status, const UA_KeyValueMap *result);

static void
finishStopIfDrained(RestDriver *rd) {
    if(rd->drv.state == UA_LIFECYCLESTATE_STOPPING && rd->runs == 0)
        rd->drv.state = UA_LIFECYCLESTATE_STOPPED;
}

static void
deleteRun(RestRun *run) {
    RestDriver *rd = run->rd;
    UA_KeyValueMap_clear(&run->input);
    UA_KeyValueMap_clear(&run->results);
    UA_free(run);
    rd->runs--;
    finishStopIfDrained(rd);
}

static UA_StatusCode
resolveValue(const RestRun *run, UA_Variant *v) {
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    size_t size = UA_Variant_isScalar(v) ? 1 : v->arrayLength;
    for(size_t i = 0; i < size && res == UA_STATUSCODE_GOOD; i++) {
        if(v->type == &UA_TYPES[UA_TYPES_STRING]) {
            UA_String *s = &((UA_String *)v->data)[i];
            UA_String resolved = UA_STRING_NULL;
            res = resolve(run, s, &resolved);
            UA_String_clear(s);
            *s = resolved;
        } else if(v->type == &UA_TYPES[UA_TYPES_KEYVALUEPAIR]) {
            res = resolveValue(run, &((UA_KeyValuePair *)v->data)[i].value);
        } else if(v->type == &UA_TYPES[UA_TYPES_VARIANT]) {
            res = resolveValue(run, &((UA_Variant *)v->data)[i]);
        }
    }
    return res;
}

static UA_Boolean
isCallKey(const UA_String *key) {
    return equalsChars(key, "endpoint") || equalsChars(key, "method") ||
        equalsChars(key, "after");
}

static UA_StatusCode
sendCall(RestRun *run) {
    const UA_KeyValuePair *call = run->chain[run->current];
    UA_KeyValueMap def = driverParamsMap(&call->value);
    UA_KeyValueMap request = UA_KEYVALUEMAP_NULL;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < def.mapSize && res == UA_STATUSCODE_GOOD; i++) {
        if(isCallKey(&def.map[i].key.name))
            continue;
        UA_Variant value;
        res = UA_Variant_copy(&def.map[i].value, &value);
        if(res == UA_STATUSCODE_GOOD)
            res = resolveValue(run, &value);
        if(res == UA_STATUSCODE_GOOD)
            res = UA_KeyValueMap_set(&request, def.map[i].key, &value);
        UA_Variant_clear(&value);
    }

    char *endpoint = driverCString(driverParamsString(&def, "endpoint"));
    char *method = driverCString(driverParamsString(&def, "method"));
    if(res == UA_STATUSCODE_GOOD && (!endpoint || !method))
        res = UA_STATUSCODE_BADOUTOFMEMORY;
    if(res == UA_STATUSCODE_GOOD)
        res = UA_Server_callDriverFrom(run->rd->drv.server, &run->rd->drv, endpoint,
                                       method, &request, callDone, run);
    else
        UA_LOG_WARNING(UA_Server_getConfig(run->rd->drv.server)->logging,
                       UA_LOGCATEGORY_SERVER, "REST driver \"%S\": Call \"%S\" "
                       "could not be prepared (%s)", run->rd->drv.name, call->key.name,
                       UA_StatusCode_name(res));
    UA_free(endpoint);
    UA_free(method);
    UA_KeyValueMap_clear(&request);
    return res;
}

static void
finishRun(RestRun *run, UA_StatusCode status, const UA_KeyValueMap *result) {
    const UA_KeyValuePair *call = run->chain[run->current];
    UA_STACKARRAY(UA_KeyValuePair, pairs, result->mapSize + 1);
    memcpy(pairs, result->map, sizeof(UA_KeyValuePair) * result->mapSize);
    pairs[result->mapSize].key = UA_QUALIFIEDNAME(0, "call");
    UA_Variant_setScalar(&pairs[result->mapSize].value,
                         (void *)(uintptr_t)&call->key.name,
                         &UA_TYPES[UA_TYPES_STRING]);
    UA_KeyValueMap map = {result->mapSize + 1, pairs};
    run->callback(run->context, status, &map);
    deleteRun(run);
}

static void
callDone(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    RestRun *run = (RestRun *)context;

    const UA_KeyValuePair *call = run->chain[run->current];
    UA_Variant v;
    UA_Variant_setArray(&v, result->map, result->mapSize,
                        &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
    UA_StatusCode res = UA_KeyValueMap_set(&run->results, call->key, &v);
    if(res != UA_STATUSCODE_GOOD)
        status = res;

    const UA_UInt16 *httpStatus = (const UA_UInt16 *)UA_KeyValueMap_getScalar(
        result, UA_QUALIFIEDNAME(0, "status"), &UA_TYPES[UA_TYPES_UINT16]);
    if(status != UA_STATUSCODE_GOOD || (httpStatus && *httpStatus >= 400) ||
       run->current + 1 == run->chainSize) {
        finishRun(run, status, result);
        return;
    }

    run->current++;
    res = sendCall(run);
    if(res != UA_STATUSCODE_GOOD) {
        run->current--;
        finishRun(run, res, result);
    }
}

static UA_StatusCode
restCall(UA_Driver *drv, const UA_String call, const UA_KeyValueMap *input,
         UA_DriverCallCallback callback, void *context) {
    RestDriver *rd = (RestDriver *)drv;
    const UA_KeyValuePair *target = findCall(rd, &call);
    if(!target)
        return UA_STATUSCODE_BADNOTFOUND;

    RestRun *run = (RestRun *)UA_calloc(1, sizeof(RestRun));
    if(!run)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    run->rd = rd;
    run->callback = callback;
    run->context = context;
    rd->runs++;

    for(const UA_KeyValuePair *c = target; c; run->chainSize++) {
        memmove(&run->chain[1], &run->chain[0],
                sizeof(UA_KeyValuePair *) * run->chainSize);
        run->chain[0] = c;
        UA_KeyValueMap def = driverParamsMap(&c->value);
        const UA_String *after = driverParamsString(&def, "after");
        c = after ? findCall(rd, after) : NULL;
    }

    UA_KeyValueMap defaults = driverParamsMap(UA_KeyValueMap_get(&rd->drv.params,
                                                       UA_QUALIFIEDNAME(0, "defaults")));
    UA_StatusCode res = UA_KeyValueMap_copy(&defaults, &run->input);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_KeyValueMap_merge(&run->input, input);
    if(res == UA_STATUSCODE_GOOD)
        res = sendCall(run);
    if(res != UA_STATUSCODE_GOOD)
        deleteRun(run);
    return res;
}

/*************/
/* Lifecycle */
/*************/

static UA_StatusCode
validateCalls(RestDriver *rd) {
    UA_Logger *logger = UA_Server_getConfig(rd->drv.server)->logging;
    UA_KeyValueMap calls = driverParamsMap(UA_KeyValueMap_get(&rd->drv.params,
                                                    UA_QUALIFIEDNAME(0, "calls")));
    for(size_t i = 0; i < calls.mapSize; i++) {
        const UA_KeyValuePair *call = &calls.map[i];
        size_t length = 0;
        for(const UA_KeyValuePair *c = call; c; length++) {
            UA_KeyValueMap def = driverParamsMap(&c->value);
            const UA_String *after = driverParamsString(&def, "after");
            if(!driverParamsString(&def, "method") || length == REST_MAX_CHAIN ||
               (after && !findCall(rd, after))) {
                UA_LOG_ERROR(logger, UA_LOGCATEGORY_SERVER,
                             "REST driver \"%S\": The call \"%S\" needs a method "
                             "and a known \"after\" call without cycles",
                             rd->drv.name, c->key.name);
                return UA_STATUSCODE_BADCONFIGURATIONERROR;
            }
            c = after ? findCall(rd, after) : NULL;
        }
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
restStart(UA_Driver *drv) {
    if(drv->state != UA_LIFECYCLESTATE_STOPPED)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_StatusCode res = validateCalls((RestDriver *)drv);
    if(res == UA_STATUSCODE_GOOD)
        drv->state = UA_LIFECYCLESTATE_STARTED;
    return res;
}

static void
restStop(UA_Driver *drv) {
    if(drv->state != UA_LIFECYCLESTATE_STARTED)
        return;
    drv->state = UA_LIFECYCLESTATE_STOPPING;
    finishStopIfDrained((RestDriver *)drv);
}

static UA_StatusCode
restFree(UA_Driver *drv) {
    if(drv->state != UA_LIFECYCLESTATE_STOPPED)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_KeyValueMap_clear(&drv->params);
    UA_free(drv);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_RestDriver_new(const UA_KeyValueMap params, UA_Driver **outDriver) {
    RestDriver *rd = (RestDriver *)UA_calloc(1, sizeof(RestDriver));
    if(!rd)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode res = UA_KeyValueMap_copy(&params, &rd->drv.params);
    if(res != UA_STATUSCODE_GOOD) {
        UA_free(rd);
        return res;
    }
    rd->drv.name = UA_STRING("rest");
    rd->drv.start = restStart;
    rd->drv.stop = restStop;
    rd->drv.free = restFree;
    rd->drv.call = restCall;
    *outDriver = &rd->drv;
    return UA_STATUSCODE_GOOD;
}

#endif /* UA_ENABLE_DRIVER_REST */
