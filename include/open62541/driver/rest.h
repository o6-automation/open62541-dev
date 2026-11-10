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
 * Result
 * ~~~~~~
 * The result of the endpoint driver for the last call (for HTTP ``status``,
 * ``headers`` and ``body``) and ``call`` [string] with the name of that call.
 * The chain stops at the first call that fails, or that has a ``status`` of
 * 400 or higher in its result (as HTTP reports errors). */

extern UA_EXPORT const UA_DriverRegistration UA_RestDriver_registration;

UA_EXPORT UA_StatusCode
UA_RestDriver_new(const UA_KeyValueMap params, UA_Driver **outDriver);

#endif /* UA_ENABLE_DRIVER_REST */

_UA_END_DECLS

#endif /* UA_DRIVER_REST_H_ */
