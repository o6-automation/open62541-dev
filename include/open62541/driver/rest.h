/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

#ifndef UA_DRIVER_REST_H_
#define UA_DRIVER_REST_H_

#include <open62541/server.h>

_UA_BEGIN_DECLS

#ifdef UA_ENABLE_DRIVER_REST

/**
 * REST Driver
 * -----------
 * The REST driver describes the calls of an API in the configuration. It does
 * not communicate itself: Each call is sent by another driver, the endpoint,
 * that is referenced by its name. The endpoint can be any driver that offers
 * calls (see ``UA_Server_callDriver``), for example an HTTP driver (see
 * ``UA_HttpDriver_registration``). Calls can build on each other: values from
 * the input and from the results of earlier calls are filled in with
 * placeholders. The default server configuration registers the driver under
 * the name ``rest``:
 *
 * .. code-block:: json5
 *
 *    drivers: [
 *      { driver: "http", name: "machine", url: "http://192.168.0.10:8000/api" },
 *      { driver: "rest", name: "machine-api",
 *        defaults: { user: "opcua" }, calls: {
 *          login: { endpoint: "machine", method: "POST", path: "/login",
 *                   headers: { "content-type": "application/json" },
 *                   body: "{\"user\":\"${input.user}\"}" },
 *          getJob: { endpoint: "machine", method: "GET",
 *                    path: "/jobs/${input.job}",
 *                    headers: { authorization: "Bearer ${login.body.token}" },
 *                    after: "login" } } }
 *    ]
 *
 * ``UA_Server_callDriver(server, "machine-api", "getJob", input, ...)`` then
 * sends ``login`` and afterwards ``getJob``.
 *
 * Parameters:
 *
 * 0:calls [KeyValuePair array]
 *    The calls by name. Each call has these keys:
 *
 *    - ``endpoint`` [string]: Name of the driver that sends the call (see the
 *      references of nested drivers). If the REST driver contains exactly one
 *      nested driver, it can be left out.
 *    - ``method`` [string]: The call of the endpoint driver, for HTTP the
 *      method. Required.
 *    - ``after`` [string]: A call that is sent before. Its result can be used
 *      in the placeholders.
 *    - All other keys are the input of the endpoint driver, for HTTP ``path``,
 *      ``headers`` and ``body``. Placeholders in strings are filled in, also
 *      inside objects and arrays.
 *
 * 0:defaults [KeyValuePair array]
 *    Default values for ``${input...}``, e.g. the login or the machine. The
 *    input of a call overrides them.
 *
 * Placeholders
 * ~~~~~~~~~~~~
 * - ``${input.<path>}``: Value from the input of the call.
 * - ``${<call>.<path>}``: Value from the result of an earlier call, e.g.
 *   ``${login.status}`` or ``${login.body.token}`` for HTTP.
 *
 * The path follows the keys of objects (ignoring case), the indices of arrays
 * (``items.0``) and the fields of JSON text, e.g. of an HTTP body. Strings are
 * inserted without quotes, other values as JSON.
 *
 * All paths of the drivers can also be written in the JSONPath notation (RFC
 * 9535): ``$`` for the start, ``.name``, ``['name']`` and ``[index]``, e.g.
 * ``body.items[1].id``. The wildcard ``[*]`` (or ``.*``) selects all elements
 * of an array or all values of an object, e.g. ``$.days[*].temperatureMax``.
 * Wildcards are possible where several values are expected (see the variables
 * of the binding driver and ``UA_RestDriver_getValue``), not in placeholders.
 * Filters and ``..`` are not supported.
 *
 * Result
 * ~~~~~~
 * The result of the endpoint driver for the last call (for HTTP ``status``,
 * ``headers`` and ``body``) and ``call`` [string] with the name of that call.
 * The chain stops at the first call that fails, or that has a ``status`` of
 * 400 or higher in its result (as HTTP reports errors).
 *
 * Polling
 * ~~~~~~~
 * The REST driver can also poll an endpoint by itself and parse the JSON
 * response. The application gets every result with a callback, the binding
 * driver puts it into the information model (see ``nodes`` and the variables
 * without ``call`` of the binding driver):
 *
 * .. code-block:: json5
 *
 *    drivers: [
 *      { driver: "rest", name: "weather",
 *        path: "/stationOverviewExtended?stationIds=10865", interval: 60000,
 *        drivers: [ { driver: "http",
 *                     url: "https://app-prod-ws.warnwetter.de/v30" } ] }
 *    ]
 *
 * Parameters:
 *
 * 0:path [string]
 *    The driver sends ``GET`` with this path to the endpoint.
 *
 * 0:poll [string]
 *    Instead of ``path``, the name of a call in ``calls`` that is polled, e.g.
 *    one that logs in first.
 *
 * 0:endpoint [string]
 *    The endpoint driver for ``path``. If the REST driver contains exactly one
 *    nested driver, it can be left out.
 *
 * 0:interval [double]
 *    Interval of the polls in milliseconds. Default 1000. The first poll is
 *    sent right after the start.
 *
 * 0:log-only-changes [boolean]
 *    A failed poll is logged every time (default). With true, only when the
 *    failure starts or changes. The end of a failure is logged once.
 *
 * The result of a poll is the result of the endpoint plus ``data``, the body
 * parsed as JSON: Objects become KeyValuePair arrays, strings String, booleans
 * Boolean, integers Int64 and other numbers Double. Arrays of one scalar type
 * become an array of that type (Double for mixed numbers), other arrays a
 * Variant array. ``null`` is an empty Variant. A body that is not JSON gives
 * the status ``BadDecodingError``. The body is not parsed for a ``status`` of
 * 400 or higher. */

extern UA_EXPORT const UA_DriverRegistration UA_RestDriver_registration;

UA_EXPORT UA_StatusCode
UA_RestDriver_new(const UA_KeyValueMap params, UA_Driver **outDriver);

/* Get the result of every poll. The driver can be found with
 * ``UA_Server_getDriver``. Callbacks can be added before the driver starts. A
 * callback can remove itself while it runs. When the driver is freed, the
 * remaining callbacks are called a last time with ``BadShutdown``.
 *
 * Use these functions from the thread of the server, e.g. before it runs or
 * in a callback. Returns ``BadTypeMismatch`` if the driver is not a REST
 * driver. */
UA_EXPORT UA_StatusCode
UA_RestDriver_addCallback(UA_Driver *rest, UA_DriverCallCallback callback,
                          void *context, UA_UInt64 *callbackId);

UA_EXPORT UA_StatusCode
UA_RestDriver_removeCallback(UA_Driver *rest, UA_UInt64 callbackId);

/* A value of ``data`` in the result of a poll, by its JSONPath, e.g.
 * ``$.days[0].dayDate`` or ``$['10865'].days[0]``. With wildcards, e.g.
 * ``$.days[*].temperatureMax``, the output is a Variant array of all matches.
 * The output is a copy, clear it with ``UA_Variant_clear``. Returns
 * ``BadNotFound`` if the path does not exist. */
UA_EXPORT UA_StatusCode
UA_RestDriver_getValue(const UA_KeyValueMap *result, const char *path,
                       UA_Variant *out);

/* A number in ``data`` as a Double, whether it was an integer or not in the
 * JSON. ``BadTypeMismatch`` if the value is not a number. */
UA_EXPORT UA_StatusCode
UA_RestDriver_getNumber(const UA_KeyValueMap *result, const char *path,
                        UA_Double *out);

#endif /* UA_ENABLE_DRIVER_REST */

_UA_END_DECLS

#endif /* UA_DRIVER_REST_H_ */
