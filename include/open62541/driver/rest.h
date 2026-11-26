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
 * The shortest configuration is the endpoint, here an HTTP driver with the URL
 * of a JSON API. The driver polls it every second and shows the data as nodes
 * below ``Objects/<name>``:
 *
 * .. code-block:: json5
 *
 *    drivers: [
 *      { driver: "rest", name: "Weather",
 *        endpoint: { driver: "http",
 *                    url: "https://app-prod-ws.warnwetter.de/v30/stationOverviewExtended?stationIds=10865" } }
 *    ]
 *
 * All other parameters are optional, see below and the endpoint. The driver is
 * built with ``UA_ENABLE_DRIVER_REST`` (needs ``UA_ENABLE_JSON_ENCODING``). An
 * HTTP endpoint also needs ``UA_ENABLE_DRIVER_HTTP``.
 *
 * The REST driver can also describe the calls of an API in the configuration.
 * It does not communicate itself: Each call is sent by another driver, the
 * endpoint, that is referenced by its name. The endpoint can be any driver that offers
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
 *      references of nested drivers). Default is the ``endpoint`` of the REST
 *      driver, else the only nested driver.
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
 * The path follows the keys of objects, the indices of arrays (``items.0``)
 * and a JSON body, which is parsed once per answer. Keys are case-sensitive,
 * header names below ``headers`` are not (RFC 9110). Strings are
 * inserted without quotes, other values as JSON. A value that is only one
 * placeholder, e.g. ``speed: "${input.speed}"``, keeps the type of a number or
 * a boolean, for endpoint drivers that are not HTTP.
 *
 * Values are escaped for their place, so that a value, e.g. a method argument
 * of a client, cannot change the request around it:
 *
 * - In ``path``: percent-encoded (RFC 3986), all but ``A-Z a-z 0-9 - . _ ~``.
 *   ``/items/${input.id}`` with ``a/b c`` becomes ``/items/a%2Fb%20c``.
 * - In a ``body`` that is JSON (starts with ``{`` or ``[``): inside a JSON
 *   string escaped (``"`` becomes ``\"``), outside a string as a JSON value
 *   (strings in quotes, null for no value). ``{"speed":${input.speed}}`` stays
 *   a number for a number.
 * - In ``headers``: a value with a line break fails the call (RFC 9110).
 * - Elsewhere, e.g. in the input of a field device, and in a field that is
 *   only one placeholder: as it is.
 *
 * All paths of the drivers can also be written in the JSONPath notation (RFC
 * 9535): ``$`` for the start, ``.name``, ``['name']`` and ``[index]``, e.g.
 * ``body.items[1].id``. The wildcard ``[*]`` (or ``.*``) selects all elements
 * of an array or all values of an object, e.g. ``$.days[*].temperatureMax``.
 * Wildcards are possible where several values are expected (see the variables
 * and ``UA_RestDriver_getValue``), not in placeholders.
 * Filters, slices and ``..`` are not supported.
 *
 * Extract, Transform, Load
 * ~~~~~~~~~~~~~~~~~~~~~~~~
 * Internally, the driver is a pipeline of three stages. The configuration
 * stays flat, the parameters belong to the stages like this:
 *
 * - Extract, getting the data: ``endpoint``, ``calls``, ``defaults``,
 *   ``path``, ``poll``, ``method`` and ``interval``. The stage knows no
 *   protocol: the endpoint is any driver, named in the configuration.
 * - Transform, turning the answer into values: the JSON body is parsed once
 *   (RFC 8259: integers in the range of Int64 are Int64, other numbers
 *   Double, the last of duplicate keys counts), paths follow JSONPath (RFC
 *   9535), and values are converted like the JSON encoding of OPC UA (Part 6,
 *   5.4): numbers exactly with a range check (7.5 is no Int32), text such as
 *   ``"6"`` or ``"2026-11-19T08:00:00Z"`` into the type, text taken over for
 *   String and ByteString. ``scale`` and ``units`` belong here.
 * - Load, putting it into OPC UA: ``nodes``, ``methods``, ``variables``,
 *   ``alarms`` and the events.
 *
 * A result without ``body``, e.g. of a field device driver, is the data
 * itself. So polling and the nodes also work for endpoints that are not HTTP.
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
 * response. The data is put into the information model (see ``nodes``) and
 * the application gets every result with a callback. For typed values of your
 * own, see the variables without ``call``:
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
 * 0:endpoint [string or KeyValuePair array]
 *    The endpoint driver for ``path`` and the calls without an endpoint: the
 *    name of a driver, or a driver of its own, see below. If the REST driver
 *    contains exactly one nested driver, it can be left out.
 *
 * 0:method [string]
 *    The call that is sent with ``path``, for HTTP the method. Default
 *    ``GET``.
 *
 * 0:interval [double]
 *    Interval of the polls in milliseconds. Default 1000. The first poll is
 *    sent right after the start.
 *
 * 0:log-only-changes [boolean]
 *    A failed poll is logged every time (default). With true, only when the
 *    failure starts or changes. The end of a failure is logged once.
 *
 * 0:nodes [boolean or KeyValuePair array]
 *    The polled data as nodes below ``Objects/<name>``, with the object
 *    ``ns=1;s=<name>``. On by default, ``false`` switches it off. Nested REST
 *    drivers are off by default: The driver that contains them decides what
 *    is shown. An object switches it on with options:
 *
 *    - ``from`` [string]: Path of the part of the data that becomes nodes,
 *      e.g. ``10865`` or ``$['10865']``. Default is all data. No wildcards.
 *    - ``scale`` [KeyValuePair array]: Factors by key name, e.g.
 *      ``{ temperatureMax: 0.1 }`` for an API that sends 0.1 °C. The values of
 *      these keys are multiplied wherever they are in the data, also the
 *      numbers in arrays. Scaled numbers are Double. A key that starts with
 *      ``$`` is a path below ``from`` instead, with wildcards for any key or
 *      index, e.g. ``{ "$.days[*].temperatureMax": 0.1 }``.
 *    - ``units`` [KeyValuePair array]: Engineering units, with the same keys
 *      as ``scale``, e.g. ``{ temperatureMax: "°C" }`` (see ``unit`` of the
 *      variables).
 *
 *    Objects, and arrays that contain objects or arrays, become Object nodes
 *    with a child per key or index. Other values become Variable nodes:
 *    Numbers have the DataType Number (Int64 or Double), booleans and strings
 *    Boolean and String. Null and arrays have the DataType BaseDataType with
 *    any ValueRank. The NodeIds contain the path, e.g.
 *    ``Weather.days.0.dayDate``. The nodes are added when their key first
 *    appears and are kept. A value that is missing in a later result has the
 *    status ``BadNoData``. A failed poll sets its status on all these
 *    variables.
 *
 * 0:namespace [string]
 *    The URI of the namespace of the NodeIds and BrowseNames of the object
 *    and its nodes. It is added to the server if needed. Default is the
 *    namespace 1.
 *
 * 0:parent [string]
 *    The NodeId of the node that organizes the object, e.g. ``ns=2;i=5001``.
 *    Default is the Objects folder.
 *
 * 0:alarms [boolean]
 *    Report the failures as an alarm instead of events, see below.
 *
 * The result of a poll is the result of the endpoint plus ``data``, the body
 * parsed as JSON: Objects become KeyValuePair arrays, strings String, booleans
 * Boolean, integers Int64 and other numbers Double. Arrays of one scalar type
 * become an array of that type (Double for mixed numbers), other arrays a
 * Variant array. ``null`` is an empty Variant. A body that is not JSON gives
 * the status ``BadDecodingError``. The body is not parsed for a ``status`` of
 * 400 or higher.
 *
 * Methods and Variables
 * ~~~~~~~~~~~~~~~~~~~~~
 * The calls can also be made available to OPC UA clients, as Method and
 * Variable nodes of the object ``Objects/<name>``:
 *
 * .. code-block:: json5
 *
 *    drivers: [
 *      { driver: "rest", name: "Press1",
 *        endpoint: { driver: "http", url: "http://192.168.0.11:8000/api" },
 *        calls: { readMachine: { method: "GET", path: "/machine" },
 *                 setSpeed: { method: "PUT", path: "/speed",
 *                             body: "{\"speed\":${input.speed}}" } },
 *        methods: { SetSpeed: { call: "setSpeed", inputs: { speed: "Double" },
 *                               outputs: { status: "UInt16" } } },
 *        variables: { Speed: { call: "readMachine", type: "Double",
 *                              from: "body.speed", unit: "m/s" } } }
 *    ]
 *
 * The NodeIds are ``ns=1;s=<name>.<method>`` and ``ns=1;s=<name>.<variable>``,
 * in the namespace of ``namespace``.
 * The nodes are removed when the driver stops.
 *
 * 0:methods [KeyValuePair array]
 *    The methods by name. Calling a method sends a call; the input arguments
 *    become the input of the call, the output arguments are taken from the
 *    result. Each method has these keys:
 *
 *    - ``call`` [string]: Name of a call in ``calls``. Required.
 *    - ``defaults`` [KeyValuePair array]: Input of the call. The input
 *      arguments override it.
 *    - ``inputs`` [KeyValuePair array]: The input arguments by name, with the
 *      name of their type as the value. They become ``${input.<name>}``.
 *    - ``outputs`` [KeyValuePair array]: The output arguments by name. The
 *      value is either the name of the type, then the output argument is taken
 *      from the result key with the same name, or an object with ``type`` and
 *      ``from``, the path in the result (e.g. ``body.job.id``).
 *
 *    A method fails with the bad status of the call, with
 *    ``BadCommunicationError`` for a ``status`` of 400 or higher, or if an
 *    output is not found. Methods return asynchronously when the endpoint
 *    answers later.
 *
 * 0:variables [KeyValuePair array]
 *    The variables by name. Each variable has these keys:
 *
 *    - ``call``, ``defaults``: As for the methods. Without ``call``, the
 *      variable is updated on each poll and ``from`` is a path in the polled
 *      data, e.g. ``$.departureList[0].countdown``.
 *    - ``type`` [string]: Name of the type of the value. Required.
 *    - ``from`` [string]: Path of the value in the result. Required. With
 *      wildcards (e.g. ``$.days[*].temperatureMax``), an array of all matches.
 *    - ``interval`` [double]: Interval of the calls in milliseconds. Default
 *      1000. The first call is sent right after the start.
 *    - ``scale`` [double]: Factor for the value, e.g. ``0.1`` for an API that
 *      sends 0.1 °C. Needs the type Double.
 *    - ``unit`` [string]: Engineering unit, e.g. ``°C``. The variable gets the
 *      property EngineeringUnits. Common symbols (°C, %, hPa, mm, km/h, m/s,
 *      s, min, h, W, kWh, V, A) also get their UNECE code as the unitId.
 *
 *    A failed call sets the status of the variable value. Text such as ``"6"``
 *    is converted to the type.
 *
 * The types are the names of the builtin scalar types: Boolean, SByte, Byte,
 * Int16, UInt16, Int32, UInt32, Int64, UInt64, Float, Double, String,
 * DateTime and ByteString. Methods and variables are shown also for a nested
 * REST driver.
 *
 * Own Endpoint
 * ~~~~~~~~~~~~
 * ``endpoint`` can also define a driver of its own, in the same form as the
 * entries of ``drivers``: ``driver`` is the registration, the other keys are
 * its parameters, checked against its schema (see ``UA_Server_createDriver``).
 * The REST driver creates, starts and stops it with itself. It is not added
 * to the server. The REST driver knows no protocol, any registered driver
 * works, e.g. ``http`` or your own ``modbus``.
 *
 * - Without ``path``, ``poll`` and ``calls``, the endpoint itself is polled. A
 *   ``path`` is the input of the poll (for HTTP appended to the URL). The poll
 *   sends the call ``method``, default ``GET``.
 * - Calls without ``endpoint`` are sent to it.
 *
 * .. code-block:: json5
 *
 *    drivers: [
 *      { driver: "rest", name: "Weather", interval: 60000,
 *        endpoint: { driver: "http", url: "https://app-prod-ws.warnwetter.de/v30",
 *                    headers: { accept: "application/json" } },
 *        path: "/stationOverviewExtended?stationIds=10865",
 *        nodes: { from: "10865", scale: { temperatureMax: 0.1 } },
 *        alarms: true }
 *    ]
 *
 * Events and Alarms
 * ~~~~~~~~~~~~~~~~~
 * When the polls start to fail, fail differently (e.g. HTTP status 404 after a
 * timeout) or work again, the driver creates an event. Failures have the
 * severity 500 (DeviceFailureEventType with the full namespace zero, else
 * BaseEventType), the recovery 100 (BaseEventType). The message is the text of
 * the log. The source is the object of the nodes, else the Server object.
 *
 * With ``alarms: true``, an OffNormalAlarm ``CommunicationError`` takes the
 * place of the events (needs the full namespace zero, else the driver warns
 * and creates events). It is active while the
 * polls fail. The alarm is a component of the object of the nodes, else it
 * is not exposed and has the Server object as its source. The server gets an
 * Alarms & Conditions driver if it has none. Without event support in the
 * build, nothing is reported. */

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
