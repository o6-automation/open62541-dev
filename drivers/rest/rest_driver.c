/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

/* The REST driver: parameters, lifecycle and the wiring of the stages
 * Extract, Transform and Load (see rest_internal.h) */

#include "rest_internal.h"

#ifdef UA_ENABLE_DRIVER_REST

static const UA_DriverParameter restParameters[] = {
    {"endpoint", UA_TYPES_VARIANT, false, false}, /* A name or a driver */
    {"calls", UA_TYPES_KEYVALUEPAIR, true, false},
    {"defaults", UA_TYPES_KEYVALUEPAIR, true, false},
    {"path", UA_TYPES_STRING, false, false},
    {"poll", UA_TYPES_STRING, false, false},
    {"method", UA_TYPES_STRING, false, false},
    {"interval", UA_TYPES_DOUBLE, false, false},
    /* Transform and Load */
    {"nodes", UA_TYPES_VARIANT, false, false}, /* Boolean or options */
    {"methods", UA_TYPES_KEYVALUEPAIR, true, false},
    {"variables", UA_TYPES_KEYVALUEPAIR, true, false},
    {"namespace", UA_TYPES_STRING, false, false},
    {"parent", UA_TYPES_STRING, false, false},
    {"alarms", UA_TYPES_BOOLEAN, false, false},
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

UA_Logger *
restLogger(const RestDriver *rd) {
    return UA_Server_getConfig(rd->drv.server)->logging;
}

void
restCallbackWithKey(UA_DriverCallCallback callback, void *context, UA_StatusCode status,
                    const UA_KeyValueMap *result, const char *key,
                    const UA_Variant *value) {
    UA_STACKARRAY(UA_KeyValuePair, pairs, result->mapSize + 1);
    if(result->mapSize > 0)
        memcpy(pairs, result->map, sizeof(UA_KeyValuePair) * result->mapSize);
    pairs[result->mapSize].key = UA_QUALIFIEDNAME(0, (char *)(uintptr_t)key);
    pairs[result->mapSize].value = *value;
    UA_KeyValueMap map = {result->mapSize + 1, pairs};
    callback(context, status, &map);
}

/***********/
/* Polling */
/***********/

static void
notifyCallbacks(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    RestDriver *rd = (RestDriver *)context;
    RestCallback *cb, *tmp;
    LIST_FOREACH_SAFE(cb, &rd->callbacks, next, tmp)
        cb->callback(cb->context, status, result);
}

/* Logs every failed poll, or with log-only-changes when the failure starts
 * or changes. The end of a failure is logged once. A change is also reported
 * as an event or an alarm. */
static void
logPollStatus(RestDriver *rd, UA_StatusCode status, UA_UInt16 errorStatus) {
    if(status == UA_STATUSCODE_GOOD && errorStatus != 0)
        status = UA_STATUSCODE_BADCOMMUNICATIONERROR;
    UA_Boolean changed = (status != rd->lastStatus);
    rd->lastStatus = status;
    if(!changed && (status == UA_STATUSCODE_GOOD ||
                    driverParamsBoolean(&rd->drv.params, "log-only-changes")))
        return;

    UA_String message = UA_STRING_NULL;
    if(status == UA_STATUSCODE_GOOD)
        UA_String_format(&message, "REST driver \"%S\": Polls again", rd->drv.name);
    else if(errorStatus != 0)
        UA_String_format(&message, "REST driver \"%S\": The poll failed (status %u)",
                         rd->drv.name, (unsigned)errorStatus);
    else
        UA_String_format(&message, "REST driver \"%S\": The poll failed (%s)",
                         rd->drv.name, UA_StatusCode_name(status));
    if(status == UA_STATUSCODE_GOOD)
        UA_LOG_INFO(restLogger(rd), UA_LOGCATEGORY_SERVER, "%S", message);
    else
        UA_LOG_WARNING(restLogger(rd), UA_LOGCATEGORY_SERVER, "%S", message);
    if(changed)
        restLoadReport(rd, status, &message);
    UA_String_clear(&message);
}

/* Every poll: log and report, update the model, then the application gets
 * the endpoint result plus "data" */
void
restPolled(RestDriver *rd, const RestData *data) {
    if(rd->drv.state != UA_LIFECYCLESTATE_STARTED)
        return;
    UA_StatusCode status = restDataStatus(data);
    if(status == UA_STATUSCODE_GOOD)
        status = data->decodeStatus;
    logPollStatus(rd, status, data->errorStatus);
    restLoadUpdate(rd, status, data);

    /* The endpoint result plus "data", and "call" for a polled call. An error
     * status in the result is a valid result for the application. */
    const UA_KeyValueMap *raw = data->raw;
    UA_STACKARRAY(UA_KeyValuePair, pairs, raw->mapSize + 2);
    if(raw->mapSize > 0)
        memcpy(pairs, raw->map, sizeof(UA_KeyValuePair) * raw->mapSize);
    UA_KeyValueMap result = {raw->mapSize, pairs};
    pairs[result.mapSize].key = UA_QUALIFIEDNAME(0, "data");
    UA_Variant_init(&pairs[result.mapSize].value);
    if(data->data)
        pairs[result.mapSize].value = *data->data;
    result.mapSize++;
    if(data->call) {
        pairs[result.mapSize].key = UA_QUALIFIEDNAME(0, "call");
        UA_Variant_setScalar(&pairs[result.mapSize].value,
                             (void *)(uintptr_t)data->call, &UA_TYPES[UA_TYPES_STRING]);
        result.mapSize++;
    }
    notifyCallbacks(rd, (data->errorStatus != 0) ? data->status : status, &result);
}

/*************/
/* Lifecycle */
/*************/

/* The own endpoint driver can stop later, e.g. when its connection is closed.
 * The model stops when its calls (runs of this driver) are done. */
void
restFinishStopIfDrained(RestDriver *rd) {
    if(rd->drv.state != UA_LIFECYCLESTATE_STOPPING || rd->runs > 0 ||
       (rd->endpoint && rd->endpoint->state != UA_LIFECYCLESTATE_STOPPED) ||
       (rd->model && rd->model->state != UA_LIFECYCLESTATE_STOPPED))
        return;
    if(rd->stopCheckId != 0)
        UA_Server_removeCallback(rd->drv.server, rd->stopCheckId);
    rd->stopCheckId = 0;
    rd->drv.state = UA_LIFECYCLESTATE_STOPPED;
}

static UA_StatusCode
restStart(UA_Driver *drv) {
    RestDriver *rd = (RestDriver *)drv;
    if(drv->state != UA_LIFECYCLESTATE_STOPPED)
        return UA_STATUSCODE_BADINTERNALERROR;
    rd->lastStatus = UA_STATUSCODE_GOOD;
    UA_StatusCode res = restExtractStart(rd);
    if(res == UA_STATUSCODE_GOOD)
        res = restLoadStart(rd);
    if(res != UA_STATUSCODE_GOOD) {
        restLoadStop(rd);
        restExtractStop(rd);
        return res;
    }
    drv->state = UA_LIFECYCLESTATE_STARTED;
    return UA_STATUSCODE_GOOD;
}

static void
restStop(UA_Driver *drv) {
    RestDriver *rd = (RestDriver *)drv;
    if(drv->state != UA_LIFECYCLESTATE_STARTED)
        return;
    drv->state = UA_LIFECYCLESTATE_STOPPING;
    restLoadStop(rd);
    restExtractStop(rd);
    restFinishStopIfDrained(rd);
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
    restLoadFree(rd);
    restExtractFree(rd);
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

/**************/
/* Public API */
/**************/

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
    if(restPathHasWildcard(p))
        return restPathCollect(data, p, out);
    UA_Variant element;
    const UA_Variant *v = restPathFind(data, &p, &element);
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

#endif /* UA_ENABLE_DRIVER_REST */
