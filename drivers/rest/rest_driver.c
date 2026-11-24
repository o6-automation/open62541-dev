/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

#include <open62541/driver/rest.h>

#include "open62541_queue.h"
#include "../driver_params.h"

#ifdef UA_ENABLE_DRIVER_REST

#define REST_MAX_CHAIN 16
#define REST_DEFAULT_INTERVAL_MS 1000.0

typedef struct RestCallback {
    LIST_ENTRY(RestCallback) next;
    UA_UInt64 id;
    UA_DriverCallCallback callback;
    void *context;
} RestCallback;

typedef struct {
    UA_Driver drv;
    size_t runs;

    /* Polling */
    UA_UInt64 firstPollId;
    UA_UInt64 pollId;
    UA_Boolean polling;
    UA_StatusCode lastStatus; /* Of the last poll, for logging only changes */
    UA_UInt64 lastCallbackId;
    LIST_HEAD(, RestCallback) callbacks;
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
    {"calls", UA_TYPES_KEYVALUEPAIR, true, false},
    {"defaults", UA_TYPES_KEYVALUEPAIR, true, false},
    {"endpoint", UA_TYPES_STRING, false, false},
    {"path", UA_TYPES_STRING, false, false},
    {"poll", UA_TYPES_STRING, false, false},
    {"interval", UA_TYPES_DOUBLE, false, false},
    {"log-only-changes", UA_TYPES_BOOLEAN, false, false}
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

static UA_Logger *
getLogger(const RestDriver *rd) {
    return UA_Server_getConfig(rd->drv.server)->logging;
}

/* Pass the result with one more key on, without copying it */
static void
callbackWithKey(UA_DriverCallCallback callback, void *context, UA_StatusCode status,
                const UA_KeyValueMap *result, const char *key, const UA_Variant *value) {
    UA_STACKARRAY(UA_KeyValuePair, pairs, result->mapSize + 1);
    memcpy(pairs, result->map, sizeof(UA_KeyValuePair) * result->mapSize);
    pairs[result->mapSize].key = UA_QUALIFIEDNAME(0, (char *)(uintptr_t)key);
    pairs[result->mapSize].value = *value;
    UA_KeyValueMap map = {result->mapSize + 1, pairs};
    callback(context, status, &map);
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
    UA_String head = driverPathSegment(&expr, NULL);
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
        UA_LOG_WARNING(getLogger(run->rd), UA_LOGCATEGORY_SERVER,
                       "REST driver \"%S\": Call \"%S\" could not be prepared (%s)",
                       run->rd->drv.name, call->key.name, UA_StatusCode_name(res));
    UA_free(endpoint);
    UA_free(method);
    UA_KeyValueMap_clear(&request);
    return res;
}

static void
finishRun(RestRun *run, UA_StatusCode status, const UA_KeyValueMap *result) {
    UA_Variant call;
    UA_Variant_setScalar(&call, (void *)(uintptr_t)&run->chain[run->current]->key.name,
                         &UA_TYPES[UA_TYPES_STRING]);
    callbackWithKey(run->callback, run->context, status, result, "call", &call);
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

    if(status != UA_STATUSCODE_GOOD || driverErrorStatus(result) != 0 ||
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

/***********/
/* Polling */
/***********/

static UA_StatusCode restStart(UA_Driver *drv);

static void
notifyCallbacks(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    RestDriver *rd = (RestDriver *)context;
    RestCallback *cb, *tmp;
    LIST_FOREACH_SAFE(cb, &rd->callbacks, next, tmp)
        cb->callback(cb->context, status, result);
}

/* Logs every failed poll, or with log-only-changes when the failure starts
 * or changes. The end of a failure is logged once. An HTTP error status
 * counts as BadCommunicationError. */
static void
logPollStatus(RestDriver *rd, UA_StatusCode status, UA_UInt16 errorStatus) {
    if(status == UA_STATUSCODE_GOOD && errorStatus != 0)
        status = UA_STATUSCODE_BADCOMMUNICATIONERROR;
    UA_Boolean changed = (status != rd->lastStatus);
    rd->lastStatus = status;
    if(status == UA_STATUSCODE_GOOD) {
        if(changed)
            UA_LOG_INFO(getLogger(rd), UA_LOGCATEGORY_SERVER,
                        "REST driver \"%S\": Polls again", rd->drv.name);
        return;
    }
    if(!changed && driverParamsBoolean(&rd->drv.params, "log-only-changes"))
        return;
    if(errorStatus != 0)
        UA_LOG_WARNING(getLogger(rd), UA_LOGCATEGORY_SERVER,
                       "REST driver \"%S\": The poll failed (HTTP status %u)",
                       rd->drv.name, (unsigned)errorStatus);
    else
        UA_LOG_WARNING(getLogger(rd), UA_LOGCATEGORY_SERVER,
                       "REST driver \"%S\": The poll failed (%s)", rd->drv.name,
                       UA_StatusCode_name(status));
}

/* The result of the endpoint plus "data", the parsed body */
static void
pollDone(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    RestDriver *rd = (RestDriver *)context;
    rd->polling = false;
    if(rd->drv.state == UA_LIFECYCLESTATE_STARTED) {
        UA_Variant data;
        UA_Variant_init(&data);
        const UA_ByteString *body = driverParamsText(result, "body");
        UA_UInt16 errorStatus = driverErrorStatus(result);
        if(status == UA_STATUSCODE_GOOD && errorStatus == 0 && body && body->length > 0)
            status = driverJsonParse(body, &data);
        logPollStatus(rd, status, errorStatus);
        callbackWithKey(notifyCallbacks, rd, status, result, "data", &data);
        UA_Variant_clear(&data);
    }
    rd->runs--;
    finishStopIfDrained(rd);
}

static void
pollCallback(UA_Server *server, void *data) {
    RestDriver *rd = (RestDriver *)data;
    if(rd->polling || rd->drv.state != UA_LIFECYCLESTATE_STARTED)
        return;
    rd->polling = true;
    rd->runs++;

    UA_StatusCode res;
    const UA_String *poll = driverParamsString(&rd->drv.params, "poll");
    if(poll) {
        res = restCall(&rd->drv, *poll, NULL, pollDone, rd);
    } else {
        UA_KeyValuePair path;
        path.key = UA_QUALIFIEDNAME(0, "path");
        UA_Variant_setScalar(&path.value, (void *)(uintptr_t)
                             driverParamsString(&rd->drv.params, "path"),
                             &UA_TYPES[UA_TYPES_STRING]);
        UA_KeyValueMap input = {1, &path};
        char *endpoint = driverCString(driverParamsString(&rd->drv.params, "endpoint"));
        res = endpoint ? UA_Server_callDriverFrom(server, &rd->drv, endpoint, "GET",
                                                  &input, pollDone, rd)
                       : UA_STATUSCODE_BADOUTOFMEMORY;
        UA_free(endpoint);
    }
    if(res == UA_STATUSCODE_GOOD)
        return;
    rd->polling = false;
    rd->runs--;
    logPollStatus(rd, res, 0);
    notifyCallbacks(rd, res, &UA_KEYVALUEMAP_NULL);
}

/* The first poll is in the next iteration, when the endpoint has started */
static UA_StatusCode
startPolling(RestDriver *rd) {
    const UA_String *path = driverParamsString(&rd->drv.params, "path");
    const UA_String *poll = driverParamsString(&rd->drv.params, "poll");
    if(!path && !poll &&
       UA_KeyValueMap_contains(&rd->drv.params, UA_QUALIFIEDNAME(0, "calls")))
        return UA_STATUSCODE_GOOD; /* Only calls, no polling */
    UA_Double interval = REST_DEFAULT_INTERVAL_MS;
    UA_StatusCode res = driverParamsInterval(&rd->drv.params, &interval);
    if(res != UA_STATUSCODE_GOOD || (path && poll) || (!path && !poll) ||
       (poll && !findCall(rd, poll))) {
        UA_LOG_ERROR(getLogger(rd), UA_LOGCATEGORY_SERVER,
                     "REST driver \"%S\": Needs calls, or polls either a path or "
                     "a known call with a positive interval", rd->drv.name);
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }
    res = UA_Server_addTimedCallback(rd->drv.server, pollCallback, rd, 0,
                                     &rd->firstPollId);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_Server_addRepeatedCallback(rd->drv.server, pollCallback, rd,
                                            interval, &rd->pollId);
    return res;
}

static void
stopPolling(RestDriver *rd) {
    UA_Server_removeCallback(rd->drv.server, rd->firstPollId);
    UA_Server_removeCallback(rd->drv.server, rd->pollId);
    rd->firstPollId = 0;
    rd->pollId = 0;
}

UA_StatusCode
UA_RestDriver_addCallback(UA_Driver *drv, UA_DriverCallCallback callback,
                          void *context, UA_UInt64 *callbackId) {
    if(!drv || !callback)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(drv->start != restStart)
        return UA_STATUSCODE_BADTYPEMISMATCH;
    RestDriver *rd = (RestDriver *)drv;
    RestCallback *cb = (RestCallback *)UA_calloc(1, sizeof(RestCallback));
    if(!cb)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    cb->id = ++rd->lastCallbackId;
    cb->callback = callback;
    cb->context = context;
    LIST_INSERT_HEAD(&rd->callbacks, cb, next);
    if(callbackId)
        *callbackId = cb->id;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_RestDriver_removeCallback(UA_Driver *drv, UA_UInt64 callbackId) {
    if(!drv)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(drv->start != restStart)
        return UA_STATUSCODE_BADTYPEMISMATCH;
    RestCallback *cb;
    LIST_FOREACH(cb, &((RestDriver *)drv)->callbacks, next) {
        if(cb->id == callbackId) {
            LIST_REMOVE(cb, next);
            UA_free(cb);
            return UA_STATUSCODE_GOOD;
        }
    }
    return UA_STATUSCODE_BADNOTFOUND;
}

UA_StatusCode
UA_RestDriver_getValue(const UA_KeyValueMap *result, const char *path,
                       UA_Variant *out) {
    if(!result || !path || !out)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_String p = UA_STRING((char *)(uintptr_t)path);
    const UA_Variant *data = UA_KeyValueMap_get(result, UA_QUALIFIEDNAME(0, "data"));
    if(driverPathHasWildcard(p))
        return driverPathCollect(data, p, out);
    UA_Variant element;
    const UA_Variant *v = driverPathFind(data, &p, &element);
    if(!v || p.length > 0)
        return UA_STATUSCODE_BADNOTFOUND;
    return UA_Variant_copy(v, out);
}

UA_StatusCode
UA_RestDriver_getNumber(const UA_KeyValueMap *result, const char *path,
                        UA_Double *out) {
    UA_Variant v;
    UA_StatusCode res = UA_RestDriver_getValue(result, path, &v);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    res = driverNumber(&v, out) ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADTYPEMISMATCH;
    UA_Variant_clear(&v);
    return res;
}

/*************/
/* Lifecycle */
/*************/

static UA_StatusCode
validateCalls(RestDriver *rd) {
    UA_Logger *logger = getLogger(rd);
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
    RestDriver *rd = (RestDriver *)drv;
    if(drv->state != UA_LIFECYCLESTATE_STOPPED)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_StatusCode res = validateCalls(rd);
    if(res == UA_STATUSCODE_GOOD)
        res = startPolling(rd);
    if(res != UA_STATUSCODE_GOOD) {
        stopPolling(rd);
        return res;
    }
    drv->state = UA_LIFECYCLESTATE_STARTED;
    return UA_STATUSCODE_GOOD;
}

static void
restStop(UA_Driver *drv) {
    if(drv->state != UA_LIFECYCLESTATE_STARTED)
        return;
    drv->state = UA_LIFECYCLESTATE_STOPPING;
    stopPolling((RestDriver *)drv);
    finishStopIfDrained((RestDriver *)drv);
}

/* The remaining callbacks are told that the driver is gone */
static UA_StatusCode
restFree(UA_Driver *drv) {
    if(drv->state != UA_LIFECYCLESTATE_STOPPED)
        return UA_STATUSCODE_BADINTERNALERROR;
    RestDriver *rd = (RestDriver *)drv;
    RestCallback *cb, *tmp;
    LIST_FOREACH_SAFE(cb, &rd->callbacks, next, tmp) {
        LIST_REMOVE(cb, next);
        cb->callback(cb->context, UA_STATUSCODE_BADSHUTDOWN, &UA_KEYVALUEMAP_NULL);
        UA_free(cb);
    }
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
    LIST_INIT(&rd->callbacks);
    rd->drv.name = UA_STRING("rest");
    rd->drv.start = restStart;
    rd->drv.stop = restStop;
    rd->drv.free = restFree;
    rd->drv.call = restCall;
    *outDriver = &rd->drv;
    return UA_STATUSCODE_GOOD;
}

#endif /* UA_ENABLE_DRIVER_REST */
