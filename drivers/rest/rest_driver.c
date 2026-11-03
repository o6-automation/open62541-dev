/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

#include <open62541/driver/rest.h>

#include "cj5.h"
#include "../../src/util/ua_util_internal.h"

#ifdef UA_ENABLE_DRIVER_REST

#define REST_MAX_CHAIN 16

typedef struct {
    UA_Driver drv;
    size_t runs; /* Calls in progress */
} RestDriver;

/* A call in progress with its chain of calls */
typedef struct {
    RestDriver *rd;
    UA_KeyValueMap input;
    UA_KeyValueMap results; /* Call name -> result (KeyValuePair array) */
    const UA_KeyValuePair *chain[REST_MAX_CHAIN];
    size_t chainSize;
    size_t current;
    UA_DriverCallCallback callback;
    void *context;
} RestRun;

static const UA_DriverParameter restParameters[] = {
    {"calls", UA_TYPES_KEYVALUEPAIR, true, true}
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

/* View a KeyValuePair array as a map. Empty for other values. */
static UA_KeyValueMap
asMap(const UA_Variant *v) {
    UA_KeyValueMap map = {0, NULL};
    if(v && UA_Variant_hasArrayType(v, &UA_TYPES[UA_TYPES_KEYVALUEPAIR])) {
        map.mapSize = v->arrayLength;
        map.map = (UA_KeyValuePair *)v->data;
    }
    return map;
}

static const UA_Variant *
mapGet(const UA_KeyValueMap *map, const UA_String *key) {
    for(size_t i = 0; i < map->mapSize; i++) {
        if(UA_String_equal(&map->map[i].key.name, key))
            return &map->map[i].value;
    }
    return NULL;
}

static const UA_String *
mapGetString(const UA_KeyValueMap *map, const char *key) {
    UA_String k = UA_STRING((char *)(uintptr_t)key);
    const UA_Variant *v = mapGet(map, &k);
    if(!v || !UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_STRING]))
        return NULL;
    return (const UA_String *)v->data;
}

static const UA_KeyValuePair *
findCall(const RestDriver *rd, const UA_String *name) {
    UA_KeyValueMap calls = asMap(UA_KeyValueMap_get(&rd->drv.params,
                                                    UA_QUALIFIEDNAME(0, "calls")));
    for(size_t i = 0; i < calls.mapSize; i++) {
        if(UA_String_equal(&calls.map[i].key.name, name))
            return &calls.map[i];
    }
    return NULL;
}

/* Split off the part up to the next dot */
static UA_String
nextSegment(UA_String *path) {
    UA_String segment = *path;
    for(size_t i = 0; i < path->length; i++) {
        if(path->data[i] == '.') {
            segment.length = i;
            path->data += i + 1;
            path->length -= i + 1;
            return segment;
        }
    }
    path->length = 0;
    return segment;
}

static char *
toCString(const UA_String *s) {
    char *c = (char *)UA_malloc(s->length + 1);
    if(c) {
        memcpy(c, s->data, s->length);
        c[s->length] = '\0';
    }
    return c;
}

/****************/
/* Placeholders */
/****************/

/* Strings are inserted as they are, numbers and booleans as JSON */
static UA_StatusCode
appendValue(const UA_Variant *v, UA_String *out) {
    if(!v || !UA_Variant_isScalar(v))
        return UA_STATUSCODE_BADNOTFOUND;
    if(v->type == &UA_TYPES[UA_TYPES_STRING] ||
       v->type == &UA_TYPES[UA_TYPES_BYTESTRING])
        return UA_String_append(out, *(const UA_String *)v->data);
    UA_ByteString json = UA_BYTESTRING_NULL;
    UA_StatusCode res = UA_encodeJson(v->data, v->type, &json, NULL);
    UA_String text = json;
    if(text.length >= 2 && text.data[0] == '"') { /* Int64 is a JSON string */
        text.data++;
        text.length -= 2;
    }
    if(res == UA_STATUSCODE_GOOD)
        res = UA_String_append(out, text);
    UA_ByteString_clear(&json);
    return res;
}

/* Insert a field of a JSON document. Strings without quotes, other values as
 * JSON. */
static UA_StatusCode
appendJsonField(const UA_ByteString *doc, UA_String path, UA_String *out) {
    cj5_token small[64];
    cj5_token *tokens = small;
    cj5_result r = cj5_parse((const char *)doc->data, (unsigned int)doc->length,
                             small, 64, NULL);
    if(r.error == CJ5_ERROR_OVERFLOW) {
        unsigned int count = r.num_tokens;
        tokens = (cj5_token *)UA_malloc(sizeof(cj5_token) * count);
        if(!tokens)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        r = cj5_parse((const char *)doc->data, (unsigned int)doc->length,
                      tokens, count, NULL);
    }
    UA_StatusCode res = (r.error == CJ5_ERROR_NONE) ?
        UA_STATUSCODE_GOOD : UA_STATUSCODE_BADDECODINGERROR;

    /* Follow the path through objects and arrays */
    unsigned int idx = 0;
    while(res == UA_STATUSCODE_GOOD && path.length > 0) {
        UA_String segment = nextSegment(&path);
        const cj5_token *tok = &r.tokens[idx];
        unsigned int child = idx + 1;
        res = UA_STATUSCODE_BADNOTFOUND;
        if(tok->type == CJ5_TOKEN_OBJECT) {
            for(unsigned int i = 0; i < tok->size / 2; i++) {
                const cj5_token *key = &r.tokens[child];
                UA_String keyName = {key->end + 1 - key->start,
                                     (UA_Byte *)(uintptr_t)&r.json5[key->start]};
                child++;
                if(UA_String_equal(&keyName, &segment)) {
                    idx = child;
                    res = UA_STATUSCODE_GOOD;
                    break;
                }
                cj5_skip(&r, &child);
            }
        } else if(tok->type == CJ5_TOKEN_ARRAY) {
            UA_UInt32 index = 0;
            if(segment.length > 0 &&
               UA_readNumber(segment.data, segment.length, &index) == segment.length &&
               index < tok->size) {
                for(UA_UInt32 i = 0; i < index; i++)
                    cj5_skip(&r, &child);
                idx = child;
                res = UA_STATUSCODE_GOOD;
            }
        }
    }

    if(res == UA_STATUSCODE_GOOD) {
        const cj5_token *tok = &r.tokens[idx];
        if(tok->type == CJ5_TOKEN_STRING) {
            char *buf = (char *)UA_malloc(tok->size + 1);
            unsigned int len = 0;
            if(!buf || cj5_get_str(&r, idx, buf, &len) != CJ5_ERROR_NONE)
                res = UA_STATUSCODE_BADDECODINGERROR;
            else
                res = UA_String_append(out, UA_STRING(buf));
            UA_free(buf);
        } else {
            UA_String raw = {tok->end + 1 - tok->start,
                             (UA_Byte *)(uintptr_t)&r.json5[tok->start]};
            res = UA_String_append(out, raw);
        }
    }
    if(tokens != small)
        UA_free(tokens);
    return res;
}

/* Insert the value of an expression like input.job or login.body.token */
static UA_StatusCode
appendExpression(const RestRun *run, UA_String expr, UA_String *out) {
    UA_String head = nextSegment(&expr);
    if(equalsChars(&head, "input")) {
        UA_QualifiedName key = {0, expr};
        return appendValue(UA_KeyValueMap_get(&run->input, key), out);
    }

    UA_QualifiedName callName = {0, head};
    UA_KeyValueMap result = asMap(UA_KeyValueMap_get(&run->results, callName));
    UA_String field = nextSegment(&expr);
    if(equalsChars(&field, "status"))
        return appendValue(UA_KeyValueMap_get(&result, UA_QUALIFIEDNAME(0, "status")), out);
    if(equalsChars(&field, "body")) {
        const UA_ByteString *body = (const UA_ByteString *)UA_KeyValueMap_getScalar(
            &result, UA_QUALIFIEDNAME(0, "body"), &UA_TYPES[UA_TYPES_BYTESTRING]);
        if(!body)
            return UA_STATUSCODE_BADNOTFOUND;
        if(expr.length == 0)
            return UA_String_append(out, *body);
        return appendJsonField(body, expr, out);
    }
    if(equalsChars(&field, "headers")) {
        UA_KeyValueMap headers = asMap(UA_KeyValueMap_get(&result,
                                                          UA_QUALIFIEDNAME(0, "headers")));
        for(size_t i = 0; i < headers.mapSize; i++) {
            if(UA_String_equal_ignorecase(&headers.map[i].key.name, &expr))
                return appendValue(&headers.map[i].value, out);
        }
    }
    return UA_STATUSCODE_BADNOTFOUND;
}

/* Fill in the ${...} placeholders of a template */
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

/* Fill in the placeholders and send the current call of the chain */
static UA_StatusCode
sendCall(RestRun *run) {
    const UA_KeyValuePair *call = run->chain[run->current];
    UA_KeyValueMap def = asMap(&call->value);
    const UA_String *endpoint = mapGetString(&def, "endpoint");
    const UA_String *method = mapGetString(&def, "method");
    UA_String get = UA_STRING("GET");

    UA_KeyValueMap request = UA_KEYVALUEMAP_NULL;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    const char *fields[2] = {"path", "body"};
    for(size_t i = 0; i < 2 && res == UA_STATUSCODE_GOOD; i++) {
        const UA_String *tmpl = mapGetString(&def, fields[i]);
        if(!tmpl)
            continue;
        UA_String value = UA_STRING_NULL;
        res = resolve(run, tmpl, &value);
        if(res == UA_STATUSCODE_GOOD)
            res = UA_KeyValueMap_setScalar(&request,
                                           UA_QUALIFIEDNAME(0, (char *)(uintptr_t)fields[i]),
                                           &value, &UA_TYPES[UA_TYPES_STRING]);
        UA_String_clear(&value);
    }

    /* Headers with placeholders in the values */
    UA_String headersKey = UA_STRING("headers");
    UA_KeyValueMap headers = asMap(mapGet(&def, &headersKey));
    UA_KeyValueMap resolved = UA_KEYVALUEMAP_NULL;
    for(size_t i = 0; i < headers.mapSize && res == UA_STATUSCODE_GOOD; i++) {
        if(!UA_Variant_hasScalarType(&headers.map[i].value, &UA_TYPES[UA_TYPES_STRING]))
            continue;
        UA_String value = UA_STRING_NULL;
        res = resolve(run, (const UA_String *)headers.map[i].value.data, &value);
        if(res == UA_STATUSCODE_GOOD)
            res = UA_KeyValueMap_setScalar(&resolved, headers.map[i].key, &value,
                                           &UA_TYPES[UA_TYPES_STRING]);
        UA_String_clear(&value);
    }
    if(res == UA_STATUSCODE_GOOD && resolved.mapSize > 0) {
        UA_Variant v;
        UA_Variant_setArray(&v, resolved.map, resolved.mapSize,
                            &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
        res = UA_KeyValueMap_set(&request, UA_QUALIFIEDNAME(0, "headers"), &v);
    }
    UA_KeyValueMap_clear(&resolved);

    char *endpointName = toCString(endpoint);
    char *methodName = toCString(method ? method : &get);
    if(res == UA_STATUSCODE_GOOD && (!endpointName || !methodName))
        res = UA_STATUSCODE_BADOUTOFMEMORY;
    if(res == UA_STATUSCODE_GOOD)
        res = UA_Server_callDriver(run->rd->drv.server, endpointName, methodName,
                                   &request, callDone, run);
    else
        UA_LOG_WARNING(UA_Server_getConfig(run->rd->drv.server)->logging,
                       UA_LOGCATEGORY_SERVER, "REST driver \"%S\": Call \"%S\" "
                       "could not be prepared (%s)", run->rd->drv.name, call->key.name,
                       UA_StatusCode_name(res));
    UA_free(endpointName);
    UA_free(methodName);
    UA_KeyValueMap_clear(&request);
    return res;
}

/* The result of the call is the result of the run, together with the name of
 * the call */
static void
finishRun(RestRun *run, UA_StatusCode status, const UA_KeyValueMap *result) {
    const UA_KeyValuePair *call = run->chain[run->current];
    UA_STACKARRAY(UA_KeyValuePair, pairs, result->mapSize + 1);
    memcpy(pairs, result->map, sizeof(UA_KeyValuePair) * result->mapSize);
    pairs[result->mapSize].key = UA_QUALIFIEDNAME(0, "call");
    UA_Variant_setScalar(&pairs[result->mapSize].value, (void *)(uintptr_t)&call->key.name,
                         &UA_TYPES[UA_TYPES_STRING]);
    UA_KeyValueMap map = {result->mapSize + 1, pairs};
    run->callback(run->context, status, &map);
    deleteRun(run);
}

static void
callDone(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    RestRun *run = (RestRun *)context;

    /* Keep the result for the placeholders of the next calls */
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

    /* The chain from the first call to the target. The calls were validated
     * during the start. */
    for(const UA_KeyValuePair *c = target; c; run->chainSize++) {
        memmove(&run->chain[1], &run->chain[0],
                sizeof(UA_KeyValuePair *) * run->chainSize);
        run->chain[0] = c;
        UA_KeyValueMap def = asMap(&c->value);
        const UA_String *after = mapGetString(&def, "after");
        c = after ? findCall(rd, after) : NULL;
    }

    UA_StatusCode res = UA_KeyValueMap_copy(input, &run->input);
    if(res == UA_STATUSCODE_GOOD)
        res = sendCall(run);
    if(res != UA_STATUSCODE_GOOD)
        deleteRun(run);
    return res;
}

/*************/
/* Lifecycle */
/*************/

/* Every call needs an endpoint, and the chains must be finite */
static UA_StatusCode
validateCalls(RestDriver *rd) {
    UA_Logger *logger = UA_Server_getConfig(rd->drv.server)->logging;
    UA_KeyValueMap calls = asMap(UA_KeyValueMap_get(&rd->drv.params,
                                                    UA_QUALIFIEDNAME(0, "calls")));
    for(size_t i = 0; i < calls.mapSize; i++) {
        const UA_KeyValuePair *call = &calls.map[i];
        size_t length = 0;
        for(const UA_KeyValuePair *c = call; c; length++) {
            UA_KeyValueMap def = asMap(&c->value);
            const UA_String *after = mapGetString(&def, "after");
            if(!mapGetString(&def, "endpoint") || length == REST_MAX_CHAIN ||
               (after && !findCall(rd, after))) {
                UA_LOG_ERROR(logger, UA_LOGCATEGORY_SERVER,
                             "REST driver \"%S\": The call \"%S\" needs an endpoint "
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

/* Stopping waits for the calls in progress. Their endpoint drivers stop as
 * well and complete them. */
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
