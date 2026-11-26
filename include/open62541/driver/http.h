/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

#ifndef UA_DRIVER_HTTP_H_
#define UA_DRIVER_HTTP_H_

#include <open62541/server.h>

_UA_BEGIN_DECLS

#ifdef UA_ENABLE_DRIVER_HTTP

/**
 * HTTP Driver
 * -----------
 * The HTTP driver sends HTTP requests to one endpoint, e.g. the REST API of a
 * machine. It uses an HTTP ConnectionManager of the EventLoop (libwebsockets
 * or a third-party implementation). Like the other users of HTTP, the driver
 * does not create one: Register it explicitly before the server starts, e.g.
 * with ``UA_ConnectionManager_new_HTTP``. Other drivers and the application send
 * requests with ``UA_Server_callDriver``. The driver is built with
 * ``UA_ENABLE_DRIVER_HTTP``. The default server configuration registers it
 * under the name ``http``:
 *
 * .. code-block:: json5
 *
 *    drivers: [{ driver: "http", name: "machine",
 *                url: "http://192.168.0.10:8000/api",
 *                headers: { accept: "application/json" } }]
 *
 * Parameters:
 *
 * 0:url [string]
 *    Base URL of the endpoint, ``http://`` or ``https://``. The path of the
 *    URL is prepended to the path of every request. Required.
 *
 * 0:headers [KeyValuePair array]
 *    Headers sent with every request (String values).
 *
 * 0:timeout [uint16]
 *    Request timeout in seconds.
 *
 * 0:connection-manager [string]
 *    EventSource name of the HTTP ConnectionManager. If not set, the first
 *    ConnectionManager for the ``http`` protocol is used.
 *
 * The trust for ``https`` (CA certificates) and a client certificate are part
 * of the ConnectionManager, see the ``tlsConfig`` of
 * ``UA_ConnectionManager_new_HTTP``. Without them, the system trust store is
 * used. For an endpoint with its own CA, use a ConnectionManager with that
 * configuration and select it with ``connection-manager``.
 *
 * Calls
 * ~~~~~
 * The name of the call is the HTTP method, e.g. ``GET``, ``POST`` or ``PUT``.
 *
 * Input: ``path`` [string] (appended to the path of the URL), ``headers``
 * [KeyValuePair array] (added to the default headers), ``body`` [string or
 * bytestring].
 *
 * Result: ``status`` [uint16] (HTTP status), ``headers`` [KeyValuePair array],
 * ``body`` [bytestring]. An HTTP error status is a valid result. The status
 * of the callback is bad only if the request could not be completed. */

extern UA_EXPORT const UA_DriverRegistration UA_HttpDriver_registration;

UA_EXPORT UA_StatusCode
UA_HttpDriver_new(const UA_KeyValueMap params, UA_Driver **outDriver);

#endif /* UA_ENABLE_DRIVER_HTTP */

_UA_END_DECLS

#endif /* UA_DRIVER_HTTP_H_ */
