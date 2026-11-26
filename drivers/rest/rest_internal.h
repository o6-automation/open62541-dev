/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

#ifndef UA_REST_INTERNAL_H_
#define UA_REST_INTERNAL_H_

/* The REST driver is a pipeline of three stages:
 *
 *   Extract (rest_extract.c)     calls, chains, placeholders, polling, the
 *                                endpoint (a driver by name, or an own
 *                                driver from an inline definition)
 *   Transform (rest_transform.c) pure functions: JSON into a value tree,
 *                                paths, conversion into OPC UA types, scale
 *   Load (rest_load.c)           the information model, events and alarms
 *
 * rest_driver.c is the driver itself: parameters, lifecycle and the wiring.
 * No stage knows a protocol. Extract hands every answer on as RestData. */

#include <open62541/driver/rest.h>

#include "open62541_queue.h"
#include "../driver_params.h"

#ifdef UA_ENABLE_DRIVER_REST

#if defined(UA_ENABLE_SUBSCRIPTIONS_EVENTS) && defined(UA_GENERATED_NAMESPACE_ZERO_FULL)
# include <open62541/driver/alarms_conditions.h>
# define REST_ALARMS
#endif

_UA_BEGIN_DECLS

typedef struct RestCallback {
    LIST_ENTRY(RestCallback) next;
    UA_UInt64 id;
    UA_DriverCallCallback callback;
    void *context;
} RestCallback;

typedef struct {
    UA_Driver drv;
    size_t runs; /* Open calls and polls */

    /* Extract */
    UA_UInt64 firstPollId;
    UA_UInt64 pollId;
    UA_Boolean polling;
    UA_Driver *endpoint; /* Own driver of the endpoint, not in the server */
    UA_String endpointName;
    UA_UInt64 stopCheckId; /* Waits for the stop of the endpoint */

    /* Load */
    UA_Driver *model; /* Not in the server */
    UA_StatusCode lastStatus; /* Of the last poll, for logs and events */
#ifdef REST_ALARMS
    UA_AlarmConditionsDriver *ac; /* The alarm is created at the first failure */
    UA_NodeId alarm;
    UA_NodeId alarmSource;
    UA_Boolean alarmActive;
#endif

    /* Callbacks of the application */
    UA_UInt64 lastCallbackId;
    LIST_HEAD(, RestCallback) callbacks;
} RestDriver;

/* An answer of the endpoint, parsed once */
typedef struct {
    UA_StatusCode status;       /* Of the endpoint driver */
    UA_UInt16 errorStatus;      /* A status of 400 or higher, else 0 */
    UA_StatusCode decodeStatus; /* BadDecodingError for a body that is not JSON */
    const UA_KeyValueMap *raw;  /* The result as the endpoint sent it */
    const UA_String *call;      /* The name of the call, NULL for a poll of a path */
    UA_Variant result;          /* The result, with a JSON body as a value tree */
    const UA_Variant *data;     /* The parsed body, or the result without a body.
                                 * NULL without data. Points into result. */
} RestData;

typedef void (*RestDataCallback)(void *context, const RestData *data);

/* The status for the user of the data: the endpoint status, then
 * BadCommunicationError for an error status */
UA_StatusCode restDataStatus(const RestData *data);

UA_Logger *restLogger(const RestDriver *rd);

/* Pass the result with one more key on, without copying it */
void restCallbackWithKey(UA_DriverCallCallback callback, void *context,
                         UA_StatusCode status, const UA_KeyValueMap *result,
                         const char *key, const UA_Variant *value);

/***********/
/* Extract */
/***********/

UA_StatusCode restExtractStart(RestDriver *rd);
void restExtractStop(RestDriver *rd);
void restExtractFree(RestDriver *rd);
const UA_KeyValuePair *restFindCall(const RestDriver *rd, const UA_String *name);

/* The call function of the driver, with the endpoint result plus "call" */
UA_StatusCode restCall(UA_Driver *drv, const UA_String call,
                       const UA_KeyValueMap *input,
                       UA_DriverCallCallback callback, void *context);

/* A call for the stages, with the parsed answer */
UA_StatusCode restExtractCall(RestDriver *rd, const char *call,
                              const UA_KeyValueMap *input,
                              RestDataCallback callback, void *context);

/* Called by Extract for every poll (rest_driver.c) */
void restPolled(RestDriver *rd, const RestData *data);
void restFinishStopIfDrained(RestDriver *rd);

/*************/
/* Transform */
/*************/

/* JSON (RFC 8259) into a value tree: objects are KeyValuePair arrays, arrays
 * of one scalar type are typed arrays (Double for mixed numbers), other arrays
 * Variant arrays. Integers in the range of Int64 are Int64, other numbers
 * Double. null is an empty Variant. */
UA_StatusCode restJsonDecode(const UA_ByteString *doc, UA_Variant *out);

/* Paths: JSONPath (RFC 9535) with $, .name, ['name'], [index], [*] and .*, and
 * the dotted form items.0.id. Keys are case-sensitive, except below
 * "headers". */
UA_String restPathSegment(UA_String *path, UA_Boolean *wildcard);
const UA_Variant *restPathFind(const UA_Variant *v, UA_String *path, UA_Variant *element);
UA_Boolean restPathHasWildcard(UA_String path);
UA_StatusCode restPathCollect(const UA_Variant *v, UA_String path, UA_Variant *out);
UA_Boolean restPathMatches(UA_String pattern, UA_String path);

/* A scalar as text: strings without quotes, others as JSON */
UA_StatusCode restValueText(const UA_Variant *v, UA_String *out);

/* The value at the path as text */
UA_StatusCode restPathText(const UA_Variant *v, UA_String path, UA_String *out);

/* A value in an OPC UA type, like the JSON encoding of OPC UA (Part 6, 5.4).
 * Numbers are converted exactly with a range check. */
UA_StatusCode restConvert(const UA_Variant *v, const UA_DataType *type, UA_Variant *out);

/* The value at the path in the type. With wildcards, an array of all matches. */
UA_StatusCode restSelect(const UA_Variant *root, UA_String path,
                         const UA_DataType *type, UA_Variant *out);

/* Numbers times the factor as Double, also in arrays */
UA_StatusCode restScale(const UA_Variant *v, UA_Double factor, UA_Variant *out);

/* The option for a key name, or for a $ pattern that matches the path */
const UA_Variant *restOption(const UA_KeyValueMap *options, UA_String name,
                             UA_String path);

/********/
/* Load */
/********/

UA_StatusCode restLoadStart(RestDriver *rd);
void restLoadStop(RestDriver *rd);
void restLoadFree(RestDriver *rd);

/* The nodes and the variables without call get the data of every poll */
void restLoadUpdate(RestDriver *rd, UA_StatusCode status, const RestData *data);

/* An event, or with the parameter alarms the alarm, for a changed poll status */
void restLoadReport(RestDriver *rd, UA_StatusCode status, const UA_String *message);

_UA_END_DECLS

#endif /* UA_ENABLE_DRIVER_REST */

#endif /* UA_REST_INTERNAL_H_ */
