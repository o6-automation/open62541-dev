/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

#ifndef UA_DRIVER_BINDING_H_
#define UA_DRIVER_BINDING_H_

#include <open62541/server.h>

_UA_BEGIN_DECLS

#ifdef UA_ENABLE_DRIVER_REST

/**
 * Binding Driver
 * --------------
 * The binding driver makes the calls of other drivers (see
 * ``UA_Server_callDriver``) available to OPC UA clients. It creates an object
 * with the name of the driver below the Objects folder. The object contains a
 * Method node for every configured method and a Variable node for every
 * configured variable:
 *
 * - Calling a method sends a call to a driver. The input arguments become
 *   the input of the call, and the output arguments are taken from the
 *   result.
 * - A variable sends a call periodically and takes its value from the
 *   result.
 *
 * The default server configuration registers the driver under the name
 * ``binding``:
 *
 * .. code-block:: json5
 *
 *    drivers: [
 *      { driver: "http", name: "machine", url: "http://192.168.0.10:8000/api" },
 *      { driver: "rest", name: "machine-api", calls: {
 *          setSpeed: { endpoint: "machine", method: "PUT", path: "/speed",
 *                      body: "{\"speed\":${input.speed}}" },
 *          readMachine: { endpoint: "machine", method: "GET", path: "/machine" } } },
 *      { driver: "binding", name: "Machine",
 *        methods: {
 *          SetSpeed: { driver: "machine-api", call: "setSpeed",
 *                      inputs: { speed: "Double" },
 *                      outputs: { status: "UInt16" } } },
 *        variables: {
 *          Speed: { driver: "machine-api", call: "readMachine",
 *                   type: "Double", from: "body.speed", interval: 1000 } } }
 *    ]
 *
 * The nodes are created in namespace 1 with string NodeIds: ``Machine`` for
 * the object and ``Machine.SetSpeed`` or ``Machine.Speed`` for its methods and
 * variables. They are removed when the driver stops. If the binding is nested
 * in another driver, the NodeIds contain the full name (e.g.
 * ``plant/Machine.Speed``), the object is shown with its own name.
 *
 * The drivers the binding uses can also be nested in it (see the section on
 * nested drivers), then ``driver`` can be left out:
 *
 * .. code-block:: json5
 *
 *    drivers: [
 *      { driver: "binding", name: "Machine",
 *        variables: { Speed: { call: "GET", type: "Double", from: "body.speed" } },
 *        drivers: [ { driver: "http", url: "http://192.168.0.10:8000/api" } ] }
 *    ]
 *
 * Parameters:
 *
 * 0:methods [KeyValuePair array]
 *    The methods by name. Each method has these keys:
 *
 *    - ``driver`` [string]: Name of the driver that is called (see the
 *      references of nested drivers). If the binding contains exactly one
 *      nested driver, it can be left out.
 *    - ``call`` [string]: Name of the call. Required.
 *    - ``defaults`` [KeyValuePair array]: Input of the call. The input
 *      arguments override it.
 *    - ``inputs`` [KeyValuePair array]: The input arguments by name, with the
 *      name of their type as the value. They become the input of the call
 *      under their name, e.g. ``${input.speed}`` for the REST driver.
 *    - ``outputs`` [KeyValuePair array]: The output arguments by name. The
 *      value is either the name of the type, then the output argument is taken
 *      from the result key with the same name, or an object with ``type`` and
 *      ``from``, the path in the result (e.g. ``body.job.id``).
 *
 * 0:variables [KeyValuePair array]
 *    The variables by name. Each variable has these keys:
 *
 *    - ``driver``, ``call``, ``defaults``: As for the methods.
 *    - ``type`` [string]: Name of the type of the value. Required.
 *    - ``from`` [string]: Path of the value in the result. Required.
 *    - ``interval`` [double]: Interval of the calls in milliseconds. Default
 *      1000.
 *    - ``scale`` [double]: Factor for the value, e.g. ``0.1`` for an API that
 *      sends 0.1 °C. Needs the type Double.
 *    - ``unit`` [string]: Engineering unit, e.g. ``°C``. The variable gets the
 *      property EngineeringUnits. Common symbols (°C, %, hPa, mm, km/h, m/s, s,
 *      min, h, W, kWh, V, A) also get their UNECE code as the unitId.
 *
 *    A ``from`` with wildcards (e.g. ``$.days[*].temperatureMax``) gives an
 *    array of the type, from all matches.
 *
 *    Without ``call``, ``driver`` is a polling REST driver (see the polling
 *    of the REST driver). The variable is updated on each of its polls, and
 *    ``from`` is a path in its parsed data, e.g.
 *    ``$.departureList[0].countdown``. Text such as ``"6"`` is converted to
 *    the type, e.g. Int32.
 *
 * The types are the names of the builtin scalar types: Boolean, SByte, Byte,
 * Int16, UInt16, Int32, UInt32, Int64, UInt64, Float, Double, String,
 * DateTime and ByteString. Paths work like the placeholders of the REST driver:
 * They follow keys (ignoring case), array indices and the fields of JSON text,
 * e.g. of an HTTP body. Values are converted from their text form.
 *
 * Results
 * ~~~~~~~
 * A call fails if the driver returns a bad status, if the result contains a
 * ``status`` of 400 or higher (as HTTP reports errors) or if a value cannot be
 * found or converted. A failed method call returns the bad status
 * (``BadCommunicationError`` for a status of 400 or higher). A failed variable
 * call sets the status of the variable value.
 *
 * A variable or the nodes from the data that cannot be updated are logged
 * every time. With the parameter ``log-only-changes`` [boolean] set to true,
 * only when the status changes. The end of a failure is logged once.
 *
 * Methods return asynchronously when the driver answers later. The result is
 * also set after the server cancelled the call (e.g. after a timeout), so the
 * server does not wait for it at the shutdown.
 *
 * Nodes from the Data
 * ~~~~~~~~~~~~~~~~~~~
 * The binding can create the nodes for all data of a polling REST driver (see
 * the polling of the REST driver) without a description of the values. Every
 * poll updates the nodes below the object:
 *
 * .. code-block:: json5
 *
 *    drivers: [
 *      { driver: "binding", name: "Weather", nodes: { from: "10865" },
 *        drivers: [ { driver: "rest",
 *                     path: "/stationOverviewExtended?stationIds=10865",
 *                     drivers: [ { driver: "http",
 *                                  url: "https://app-prod-ws.warnwetter.de/v30" } ] } ] }
 *    ]
 *
 * 0:nodes [KeyValuePair array]
 *    - ``driver`` [string]: Name of the REST driver. If the binding contains
 *      exactly one nested driver, it can be left out.
 *    - ``from`` [string]: Path of the part of the data that becomes nodes, e.g.
 *      ``10865`` or ``$['10865']``. Default is all data.
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
 * Objects, and arrays that contain objects or arrays, become Object nodes
 * with a child per key or index. Other values become Variable nodes: Numbers
 * have the DataType Number (Int64 or Double), booleans and strings Boolean and
 * String. Null and arrays have the DataType BaseDataType with any ValueRank.
 * The NodeIds contain the path, e.g. ``Weather.days.0.dayDate``.
 *
 * The nodes are added when their key first appears and are kept. A value that
 * is missing in a later result has the status ``BadNoData``. A failed poll
 * sets its status on all these variables. */

extern UA_EXPORT const UA_DriverRegistration UA_BindingDriver_registration;

UA_EXPORT UA_StatusCode
UA_BindingDriver_new(const UA_KeyValueMap params, UA_Driver **outDriver);

#endif /* UA_ENABLE_DRIVER_REST */

_UA_END_DECLS

#endif /* UA_DRIVER_BINDING_H_ */
