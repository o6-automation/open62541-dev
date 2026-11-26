/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

/* Extract: calls, chains, placeholders, polling and the endpoint. The endpoint
 * is any driver with calls: one by its name, or an own driver from an inline
 * definition such as { driver: "http", url: "https://..." }. The conventions
 * of the results, status and body, are read in extractResult only. */

#include "rest_internal.h"

#ifdef UA_ENABLE_DRIVER_REST

#define REST_MAX_CHAIN 16
#define REST_DEFAULT_INTERVAL_MS 1000.0

typedef struct {
    RestDriver *rd;
    UA_KeyValueMap input;
    UA_KeyValueMap results; /* Of the calls so far, with parsed bodies */
    const UA_KeyValuePair *chain[REST_MAX_CHAIN];
    size_t chainSize;
    size_t current;
    UA_DriverCallCallback callback; /* For the application, or */
    RestDataCallback dataCallback;  /* for the stages */
    void *context;
} RestRun;

static UA_Boolean
equalsChars(const UA_String *s, const char *chars) {
    UA_String c = UA_STRING((char *)(uintptr_t)chars);
    return UA_String_equal(s, &c);
}

/******************/
/* Answers        */
/******************/

/* The status and the body of the endpoint result. A JSON body is parsed once,
 * a result without a body is the data itself (e.g. of a field device). */
static UA_StatusCode
extractResult(UA_StatusCode status, const UA_KeyValueMap *raw, const UA_String *call,
              RestData *d) {
    memset(d, 0, sizeof(RestData));
    d->status = status;
    d->raw = raw;
    d->call = call;
    d->errorStatus = driverErrorStatus(raw);
    UA_KeyValuePair *pairs = NULL;
    UA_StatusCode res = UA_Array_copy(raw->map, raw->mapSize, (void **)&pairs,
                                      &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    UA_Variant_setArray(&d->result, pairs, raw->mapSize,
                        &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
    if(status != UA_STATUSCODE_GOOD || d->errorStatus != 0)
        return UA_STATUSCODE_GOOD;

    UA_Variant *body = NULL;
    for(size_t i = 0; i < raw->mapSize && !body; i++) {
        if(equalsChars(&pairs[i].key.name, "body"))
            body = &pairs[i].value;
    }
    if(!body) {
        d->data = &d->result;
        return UA_STATUSCODE_GOOD;
    }
    if(!UA_Variant_isScalar(body) || (body->type != &UA_TYPES[UA_TYPES_STRING] &&
                                      body->type != &UA_TYPES[UA_TYPES_BYTESTRING]) ||
       ((const UA_ByteString *)body->data)->length == 0)
        return UA_STATUSCODE_GOOD;
    UA_Variant tree;
    d->decodeStatus = restJsonDecode((const UA_ByteString *)body->data, &tree);
    if(d->decodeStatus != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_GOOD; /* Not JSON: the body stays text */
    UA_Variant_clear(body);
    *body = tree;
    d->data = body;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
restDataStatus(const RestData *data) {
    if(data->status != UA_STATUSCODE_GOOD)
        return data->status;
    return (data->errorStatus != 0) ?
        UA_STATUSCODE_BADCOMMUNICATIONERROR : UA_STATUSCODE_GOOD;
}

/************/
/* Endpoint */
/************/

/* The endpoint of a call, else the one of the driver. NULL for the own driver
 * or for the only nested driver. */
static const UA_String *
endpointOf(const RestDriver *rd, const UA_KeyValueMap *def) {
    const UA_String *endpoint = driverParamsString(def, "endpoint");
    if(endpoint || rd->endpoint)
        return endpoint;
    return driverParamsString(&rd->drv.params, "endpoint");
}

/* Without an endpoint, the own driver. Else the driver with the name, resolved
 * like nested drivers. */
static UA_StatusCode
callEndpoint(RestDriver *rd, const UA_String *endpoint, const char *method,
             const UA_KeyValueMap *input, UA_DriverCallCallback callback,
             void *context) {
    if(rd->endpoint && (!endpoint || endpoint->length == 0)) {
        if(rd->endpoint->state != UA_LIFECYCLESTATE_STARTED)
            return UA_STATUSCODE_BADINVALIDSTATE;
        return rd->endpoint->call(rd->endpoint, UA_STRING((char *)(uintptr_t)method),
                                  input, callback, context);
    }
    char *name = driverCString(endpoint);
    if(!name)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode res = UA_Server_callDriverFrom(rd->drv.server, &rd->drv, name,
                                                 method, input, callback, context);
    UA_free(name);
    return res;
}

const UA_KeyValuePair *
restFindCall(const RestDriver *rd, const UA_String *name) {
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

/* The input or the result of a call, by the first segment of the expression.
 * The input is set up in the variant. */
static const UA_Variant *
expressionStart(const RestRun *run, UA_String *expr, UA_Variant *input) {
    UA_String head = restPathSegment(expr, NULL);
    if(equalsChars(&head, "input")) {
        UA_Variant_setArray(input, run->input.map, run->input.mapSize,
                            &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
        return input;
    }
    UA_QualifiedName callName = {0, head};
    return UA_KeyValueMap_get(&run->results, callName);
}

/* The place of a placeholder decides how its value is escaped, so that a
 * value cannot change the request around it */
typedef enum {
    PLACE_TEXT,   /* As it is, e.g. for the input of a field device */
    PLACE_PATH,   /* Percent-encoded (RFC 3986) */
    PLACE_JSON,   /* JSON text (RFC 8259): escaped in strings, else a JSON value */
    PLACE_HEADER  /* Without line breaks (RFC 9110) */
} RestPlace;

static RestPlace
placeOf(const UA_String *key) {
    if(equalsChars(key, "path"))
        return PLACE_PATH;
    if(equalsChars(key, "body"))
        return PLACE_JSON; /* If the template is JSON, see resolve */
    if(equalsChars(key, "headers"))
        return PLACE_HEADER;
    return PLACE_TEXT;
}

/* A template that is only one placeholder, e.g. "${input.speed}". Its value is
 * the whole field and is not escaped. */
static UA_Boolean
isWholePlaceholder(const UA_String *s) {
    return s->length >= 4 && s->data[0] == '$' && s->data[1] == '{' &&
        s->data[s->length - 1] == '}' && !memchr(&s->data[2], '}', s->length - 3);
}

static UA_Boolean
isJsonTemplate(const UA_String *s) {
    for(size_t i = 0; i < s->length; i++) {
        UA_Byte c = s->data[i];
        if(c != ' ' && c != '\t' && c != '\r' && c != '\n')
            return c == '{' || c == '[';
    }
    return false;
}

/* Percent-encoding for a path (RFC 3986) or escaping inside a JSON string
 * (RFC 8259), into one buffer: at most 6 bytes per byte (\u00XX) */
static UA_StatusCode
appendEscaped(const UA_String *text, RestPlace place, UA_String *out) {
    static const char hex[] = "0123456789ABCDEF";
    UA_ByteString buf;
    UA_StatusCode res = UA_ByteString_allocBuffer(&buf, text->length * 6);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    size_t n = 0;
    for(size_t i = 0; i < text->length; i++) {
        UA_Byte c = text->data[i];
        if(place == PLACE_PATH) {
            if((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~') {
                buf.data[n++] = c;
            } else {
                buf.data[n++] = '%';
                buf.data[n++] = (UA_Byte)hex[c >> 4];
                buf.data[n++] = (UA_Byte)hex[c & 0x0f];
            }
        } else if(c == '"' || c == '\\') {
            buf.data[n++] = '\\';
            buf.data[n++] = c;
        } else if(c < 0x20) {
            memcpy(&buf.data[n], "\\u00", 4);
            buf.data[n + 4] = (UA_Byte)hex[c >> 4];
            buf.data[n + 5] = (UA_Byte)hex[c & 0x0f];
            n += 6;
        } else {
            buf.data[n++] = c;
        }
    }
    buf.length = n;
    res = UA_String_append(out, buf);
    UA_ByteString_clear(&buf);
    return res;
}

/* The value of a placeholder, escaped for its place */
static UA_StatusCode
appendValue(const UA_Variant *v, RestPlace place, UA_Boolean inString,
            UA_String *out) {
    UA_Boolean text = UA_Variant_isScalar(v) &&
        (v->type == &UA_TYPES[UA_TYPES_STRING] ||
         v->type == &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(place == PLACE_JSON && !inString && UA_Variant_isEmpty(v))
        return UA_String_append(out, UA_STRING("null"));
    if(place == PLACE_TEXT || (place == PLACE_JSON && !inString && !text))
        return restValueText(v, out);

    UA_String plain = UA_STRING_NULL;
    UA_StatusCode res = restValueText(v, &plain);
    if(res == UA_STATUSCODE_GOOD && place == PLACE_HEADER) {
        if(memchr(plain.data, '\r', plain.length) || memchr(plain.data, '\n', plain.length))
            res = UA_STATUSCODE_BADINVALIDARGUMENT;
        else
            res = UA_String_append(out, plain);
    } else if(res == UA_STATUSCODE_GOOD) {
        /* A path, a JSON string, or a string as a JSON value in quotes */
        UA_Boolean quote = (place == PLACE_JSON && !inString);
        if(quote)
            res = UA_String_append(out, UA_STRING("\""));
        if(res == UA_STATUSCODE_GOOD)
            res = appendEscaped(&plain, place, out);
        if(res == UA_STATUSCODE_GOOD && quote)
            res = UA_String_append(out, UA_STRING("\""));
    }
    UA_String_clear(&plain);
    return res;
}

/* Does the JSON text end inside a string? Follows quotes and escapes. */
static UA_Boolean
endsInString(const UA_String *literal, UA_Boolean inString) {
    for(size_t i = 0; i < literal->length; i++) {
        if(inString && literal->data[i] == '\\')
            i++;
        else if(literal->data[i] == '"')
            inString = !inString;
    }
    return inString;
}

static UA_StatusCode
resolve(const RestRun *run, const UA_String *tmpl, RestPlace place, UA_String *out) {
    if(isWholePlaceholder(tmpl) || (place == PLACE_JSON && !isJsonTemplate(tmpl)))
        place = PLACE_TEXT;
    UA_Boolean inString = false;
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
        inString = endsInString(&literal, inString);
        res = UA_String_append(out, literal);
        size_t end = pos + 2;
        while(end < tmpl->length && tmpl->data[end] != '}')
            end++;
        if(end == tmpl->length)
            return UA_STATUSCODE_BADINVALIDARGUMENT;
        UA_String expr = {end - pos - 2, &tmpl->data[pos + 2]};
        UA_Variant input, element;
        const UA_Variant *v = expressionStart(run, &expr, &input);
        v = restPathFind(v, &expr, &element);
        if(res == UA_STATUSCODE_GOOD)
            res = (v && expr.length == 0) ? appendValue(v, place, inString, out) :
                UA_STATUSCODE_BADNOTFOUND;
        pos = end + 1;
    }
    return res;
}

/* A string that is only one placeholder, e.g. "${input.speed}", keeps the
 * type of a number or a boolean */
static UA_Boolean
resolveTyped(const RestRun *run, UA_Variant *v) {
    const UA_String *s = (const UA_String *)v->data;
    if(!isWholePlaceholder(s))
        return false;
    UA_String expr = {s->length - 3, &s->data[2]};
    UA_Variant input, element;
    const UA_Variant *start = expressionStart(run, &expr, &input);
    const UA_Variant *found = restPathFind(start, &expr, &element);
    if(!found || expr.length > 0 || !UA_Variant_isScalar(found) ||
       !(found->type == &UA_TYPES[UA_TYPES_BOOLEAN] ||
         UA_DataType_isNumeric(found->type)))
        return false;
    UA_Variant copy;
    if(UA_Variant_copy(found, &copy) != UA_STATUSCODE_GOOD)
        return false;
    UA_Variant_clear(v);
    *v = copy;
    return true;
}

static UA_StatusCode
resolveValue(const RestRun *run, UA_Variant *v, RestPlace place) {
    if(UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_STRING]) && resolveTyped(run, v))
        return UA_STATUSCODE_GOOD;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    size_t size = UA_Variant_isScalar(v) ? 1 : v->arrayLength;
    for(size_t i = 0; i < size && res == UA_STATUSCODE_GOOD; i++) {
        if(v->type == &UA_TYPES[UA_TYPES_STRING]) {
            UA_String *s = &((UA_String *)v->data)[i];
            UA_String resolved = UA_STRING_NULL;
            res = resolve(run, s, place, &resolved);
            UA_String_clear(s);
            *s = resolved;
        } else if(v->type == &UA_TYPES[UA_TYPES_KEYVALUEPAIR]) {
            res = resolveValue(run, &((UA_KeyValuePair *)v->data)[i].value, place);
        } else if(v->type == &UA_TYPES[UA_TYPES_VARIANT]) {
            res = resolveValue(run, &((UA_Variant *)v->data)[i], place);
        }
    }
    return res;
}

/*********/
/* Calls */
/*********/

static void
callDone(void *context, UA_StatusCode status, const UA_KeyValueMap *result);

static void
deleteRun(RestRun *run) {
    RestDriver *rd = run->rd;
    UA_KeyValueMap_clear(&run->input);
    UA_KeyValueMap_clear(&run->results);
    UA_free(run);
    rd->runs--;
    restFinishStopIfDrained(rd);
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
            res = resolveValue(run, &value, placeOf(&def.map[i].key.name));
        if(res == UA_STATUSCODE_GOOD)
            res = UA_KeyValueMap_set(&request, def.map[i].key, &value);
        UA_Variant_clear(&value);
    }

    char *method = driverCString(driverParamsString(&def, "method"));
    if(res == UA_STATUSCODE_GOOD && !method)
        res = UA_STATUSCODE_BADOUTOFMEMORY;
    if(res == UA_STATUSCODE_GOOD)
        res = callEndpoint(run->rd, endpointOf(run->rd, &def), method,
                           &request, callDone, run);
    else
        UA_LOG_WARNING(restLogger(run->rd), UA_LOGCATEGORY_SERVER,
                       "REST driver \"%S\": Call \"%S\" could not be prepared (%s)",
                       run->rd->drv.name, call->key.name, UA_StatusCode_name(res));
    UA_free(method);
    UA_KeyValueMap_clear(&request);
    return res;
}

/* The application gets the endpoint result plus "call", the stages the
 * parsed answer */
static void
finishRun(RestRun *run, const RestData *data) {
    if(run->dataCallback) {
        run->dataCallback(run->context, data);
    } else {
        UA_Variant call;
        UA_Variant_setScalar(&call, (void *)(uintptr_t)data->call,
                             &UA_TYPES[UA_TYPES_STRING]);
        restCallbackWithKey(run->callback, run->context, data->status, data->raw,
                            "call", &call);
    }
    deleteRun(run);
}

static void
callDone(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    RestRun *run = (RestRun *)context;
    const UA_KeyValuePair *call = run->chain[run->current];
    RestData data;
    UA_StatusCode res = extractResult(status, result, &call->key.name, &data);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_KeyValueMap_set(&run->results, call->key, &data.result);
    if(res != UA_STATUSCODE_GOOD)
        data.status = res;

    if(restDataStatus(&data) != UA_STATUSCODE_GOOD ||
       run->current + 1 == run->chainSize) {
        finishRun(run, &data);
    } else {
        run->current++;
        res = sendCall(run);
        if(res != UA_STATUSCODE_GOOD) {
            run->current--;
            data.status = res;
            finishRun(run, &data);
        }
    }
    UA_Variant_clear(&data.result);
}

static UA_StatusCode
startRun(RestDriver *rd, const UA_String call, const UA_KeyValueMap *input,
         UA_DriverCallCallback callback, RestDataCallback dataCallback,
         void *context) {
    const UA_KeyValuePair *target = restFindCall(rd, &call);
    if(!target)
        return UA_STATUSCODE_BADNOTFOUND;

    RestRun *run = (RestRun *)UA_calloc(1, sizeof(RestRun));
    if(!run)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    run->rd = rd;
    run->callback = callback;
    run->dataCallback = dataCallback;
    run->context = context;
    rd->runs++;

    for(const UA_KeyValuePair *c = target; c; run->chainSize++) {
        memmove(&run->chain[1], &run->chain[0],
                sizeof(UA_KeyValuePair *) * run->chainSize);
        run->chain[0] = c;
        UA_KeyValueMap def = driverParamsMap(&c->value);
        const UA_String *after = driverParamsString(&def, "after");
        c = after ? restFindCall(rd, after) : NULL;
    }

    UA_KeyValueMap defaults = driverParamsMap(UA_KeyValueMap_get(&rd->drv.params,
                                                       UA_QUALIFIEDNAME(0, "defaults")));
    UA_StatusCode res = UA_KeyValueMap_copy(&defaults, &run->input);
    if(res == UA_STATUSCODE_GOOD && input)
        res = UA_KeyValueMap_merge(&run->input, input);
    if(res == UA_STATUSCODE_GOOD)
        res = sendCall(run);
    if(res != UA_STATUSCODE_GOOD)
        deleteRun(run);
    return res;
}

UA_StatusCode
restCall(UA_Driver *drv, const UA_String call, const UA_KeyValueMap *input,
         UA_DriverCallCallback callback, void *context) {
    return startRun((RestDriver *)drv, call, input, callback, NULL, context);
}

UA_StatusCode
restExtractCall(RestDriver *rd, const char *call, const UA_KeyValueMap *input,
                RestDataCallback callback, void *context) {
    if(rd->drv.state != UA_LIFECYCLESTATE_STARTED)
        return UA_STATUSCODE_BADINVALIDSTATE;
    return startRun(rd, UA_STRING((char *)(uintptr_t)call), input, NULL,
                    callback, context);
}

/***********/
/* Polling */
/***********/

static void
pollFinished(RestDriver *rd, const RestData *data) {
    rd->polling = false;
    restPolled(rd, data);
    rd->runs--;
    restFinishStopIfDrained(rd);
}

static void
pollPathDone(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    RestData data;
    UA_StatusCode res = extractResult(status, result, NULL, &data);
    if(res != UA_STATUSCODE_GOOD)
        data.status = res;
    pollFinished((RestDriver *)context, &data);
    UA_Variant_clear(&data.result);
}

static void
pollCallDone(void *context, const RestData *data) {
    pollFinished((RestDriver *)context, data);
}

static void
pollCallback(UA_Server *server, void *context) {
    (void)server;
    RestDriver *rd = (RestDriver *)context;
    if(rd->polling || rd->drv.state != UA_LIFECYCLESTATE_STARTED)
        return;
    rd->polling = true;
    rd->runs++;

    UA_StatusCode res;
    const UA_String *poll = driverParamsString(&rd->drv.params, "poll");
    if(poll) {
        res = startRun(rd, *poll, NULL, NULL, pollCallDone, rd);
    } else {
        /* Without a path, the endpoint itself. The call is "method", by default
         * GET. */
        const UA_String *p = driverParamsString(&rd->drv.params, "path");
        UA_KeyValuePair path;
        path.key = UA_QUALIFIEDNAME(0, "path");
        UA_Variant_setScalar(&path.value, (void *)(uintptr_t)p,
                             &UA_TYPES[UA_TYPES_STRING]);
        UA_KeyValueMap input = {p ? 1 : 0, &path};
        static const UA_String get = UA_STRING_STATIC("GET");
        const UA_String *m = driverParamsString(&rd->drv.params, "method");
        char *method = driverCString(m ? m : &get);
        res = method ? callEndpoint(rd, endpointOf(rd, &UA_KEYVALUEMAP_NULL), method,
                                    &input, pollPathDone, rd) :
            UA_STATUSCODE_BADOUTOFMEMORY;
        UA_free(method);
    }
    if(res == UA_STATUSCODE_GOOD)
        return;
    RestData failed;
    memset(&failed, 0, sizeof(RestData));
    failed.status = res;
    failed.raw = &UA_KEYVALUEMAP_NULL;
    pollFinished(rd, &failed);
}

/* The first poll is in the next iteration, when the endpoint has started. An
 * endpoint URL without path, poll and calls is polled itself. */
static UA_StatusCode
startPolling(RestDriver *rd) {
    const UA_String *path = driverParamsString(&rd->drv.params, "path");
    const UA_String *poll = driverParamsString(&rd->drv.params, "poll");
    if(!path && !poll &&
       UA_KeyValueMap_contains(&rd->drv.params, UA_QUALIFIEDNAME(0, "calls")))
        return UA_STATUSCODE_GOOD; /* Only calls, no polling */
    UA_Double interval = REST_DEFAULT_INTERVAL_MS;
    UA_StatusCode res = driverParamsInterval(&rd->drv.params, &interval);
    if(res != UA_STATUSCODE_GOOD || (path && poll) || (!path && !poll && !rd->endpoint) ||
       (poll && !restFindCall(rd, poll))) {
        UA_LOG_ERROR(restLogger(rd), UA_LOGCATEGORY_SERVER,
                     "REST driver \"%S\": Needs calls, or polls its own endpoint, "
                     "a path or a known call with a positive interval", rd->drv.name);
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

/*************/
/* Lifecycle */
/*************/

static UA_StatusCode
validateCalls(RestDriver *rd) {
    UA_KeyValueMap calls = driverParamsMap(UA_KeyValueMap_get(&rd->drv.params,
                                                    UA_QUALIFIEDNAME(0, "calls")));
    for(size_t i = 0; i < calls.mapSize; i++) {
        size_t length = 0;
        for(const UA_KeyValuePair *c = &calls.map[i]; c; length++) {
            UA_KeyValueMap def = driverParamsMap(&c->value);
            const UA_String *after = driverParamsString(&def, "after");
            if(!driverParamsString(&def, "method") || length == REST_MAX_CHAIN ||
               (after && !restFindCall(rd, after))) {
                UA_LOG_ERROR(restLogger(rd), UA_LOGCATEGORY_SERVER,
                             "REST driver \"%S\": The call \"%S\" needs a method "
                             "and a known \"after\" call without cycles",
                             rd->drv.name, c->key.name);
                return UA_STATUSCODE_BADCONFIGURATIONERROR;
            }
            c = after ? restFindCall(rd, after) : NULL;
        }
    }
    return UA_STATUSCODE_GOOD;
}

/* An inline endpoint, e.g. { driver: "http", url: "https://..." }: a driver
 * of its own, created from the registration with the other keys as its
 * parameters. It is not added to the server. */
static UA_StatusCode
startEndpoint(RestDriver *rd) {
    const UA_Variant *endpoint = UA_KeyValueMap_get(&rd->drv.params,
                                                    UA_QUALIFIEDNAME(0, "endpoint"));
    if(!endpoint || UA_Variant_hasScalarType(endpoint, &UA_TYPES[UA_TYPES_STRING]))
        return UA_STATUSCODE_GOOD; /* A driver by its name */
    UA_KeyValueMap def = driverParamsMap(endpoint);
    const UA_String *type = driverParamsString(&def, "driver");
    if(!type) {
        UA_LOG_ERROR(restLogger(rd), UA_LOGCATEGORY_SERVER,
                     "REST driver \"%S\": The endpoint is the name of a driver or "
                     "an object with \"driver\"", rd->drv.name);
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }
    if(!rd->endpoint) {
        UA_KeyValueMap params = UA_KEYVALUEMAP_NULL;
        UA_StatusCode res = UA_KeyValueMap_copy(&def, &params);
        UA_KeyValueMap_remove(&params, UA_QUALIFIEDNAME(0, "driver"));
        char *driver = driverCString(type);
        if(res == UA_STATUSCODE_GOOD && !driver)
            res = UA_STATUSCODE_BADOUTOFMEMORY;
        if(res == UA_STATUSCODE_GOOD)
            res = UA_Server_createDriver(rd->drv.server, driver, params, &rd->endpoint);
        if(res == UA_STATUSCODE_GOOD)
            res = UA_String_format(&rd->endpointName, "%S/%S", rd->drv.name, *type);
        UA_free(driver);
        UA_KeyValueMap_clear(&params);
        if(res != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR(restLogger(rd), UA_LOGCATEGORY_SERVER,
                         "REST driver \"%S\": The endpoint driver \"%S\" could not "
                         "be created (%s)", rd->drv.name, *type, UA_StatusCode_name(res));
            if(rd->endpoint)
                rd->endpoint->free(rd->endpoint);
            rd->endpoint = NULL;
            return res;
        }
        rd->endpoint->name = rd->endpointName;
        rd->endpoint->server = rd->drv.server;
    }
    return rd->endpoint->start(rd->endpoint);
}

UA_StatusCode
restExtractStart(RestDriver *rd) {
    UA_StatusCode res = validateCalls(rd);
    if(res == UA_STATUSCODE_GOOD)
        res = startEndpoint(rd);
    if(res == UA_STATUSCODE_GOOD)
        res = startPolling(rd);
    return res;
}

static void
endpointStopCheck(UA_Server *server, void *context) {
    (void)server;
    restFinishStopIfDrained((RestDriver *)context);
}

/* The own endpoint driver can finish its stop later, e.g. when its
 * connection is closed. Until then, the stop is checked regularly. */
void
restExtractStop(RestDriver *rd) {
    stopPolling(rd);
    if(!rd->endpoint)
        return;
    rd->endpoint->stop(rd->endpoint);
    if(rd->endpoint->state != UA_LIFECYCLESTATE_STOPPED && rd->stopCheckId == 0)
        UA_Server_addRepeatedCallback(rd->drv.server, endpointStopCheck, rd, 10.0,
                                      &rd->stopCheckId);
}

void
restExtractFree(RestDriver *rd) {
    if(rd->endpoint)
        rd->endpoint->free(rd->endpoint);
    rd->endpoint = NULL;
    UA_String_clear(&rd->endpointName);
}

#endif /* UA_ENABLE_DRIVER_REST */
