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
 * The REST driver describes the calls of a REST API in the configuration. A
 * call is sent by another driver, usually an HTTP driver (see
 * ``UA_HttpDriver_registration``), that is referenced by its name. Calls can
 * build on each other: values from the input and from the responses of
 * earlier calls are filled in with placeholders. The default server
 * configuration registers the driver under the name ``rest``:
 *
 * .. code-block:: json5
 *
 *    drivers: [
 *      { driver: "http", name: "machine", url: "http://192.168.0.10:8000/api" },
 *      { driver: "rest", name: "machine-api", calls: {
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
 *    - ``endpoint`` [string]: Name of the driver that sends the call. Required.
 *    - ``method`` [string]: Call of the endpoint driver, for HTTP the method.
 *      Defaults to ``GET``.
 *    - ``path``, ``body`` [string], ``headers`` [KeyValuePair array]: The input
 *      of the endpoint driver. Placeholders are filled in.
 *    - ``after`` [string]: A call that is sent before. Its result can be used
 *      in the placeholders.
 *
 * Placeholders
 * ~~~~~~~~~~~~
 * - ``${input.<key>}``: Value from the input of the call.
 * - ``${<call>.status}``: HTTP status of an earlier call.
 * - ``${<call>.body}``: Body of an earlier call.
 * - ``${<call>.body.<path>}``: Field in the JSON body of an earlier call. The
 *   path consists of object keys and array indices, e.g. ``items.0.id``.
 * - ``${<call>.headers.<name>}``: Header of an earlier call.
 *
 * Result
 * ~~~~~~
 * The result of the endpoint driver for the last call (for HTTP ``status``,
 * ``headers`` and ``body``) and ``call`` [string] with the name of that call.
 * The chain stops at the first call that fails or returns an HTTP status of
 * 400 or higher. */

extern UA_EXPORT const UA_DriverRegistration UA_RestDriver_registration;

UA_EXPORT UA_StatusCode
UA_RestDriver_new(const UA_KeyValueMap params, UA_Driver **outDriver);

#endif /* UA_ENABLE_DRIVER_REST */

_UA_END_DECLS

#endif /* UA_DRIVER_REST_H_ */
