/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 * OPC UA WebSocket Client Example
 * --------------------------------
 * Demonstrates an OPC UA client connecting via opc.wss:// using the WebSocket
 * ConnectionManager (libwebsockets). The client reads the server's current
 * time over the WebSocket transport.
 *
 * Build with: -DUA_ENABLE_LWS=ON
 * Run:        ./bin/examples/client_wss
 *
 * Requires a server listening on opc.wss://localhost:4843, for instance the
 * server_wss example from this directory.
 */

#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/eventloop.h>
#include <open62541/plugin/log_stdout.h>

int main(void) {
    UA_Client *client = UA_Client_new();
    UA_ClientConfig *config = UA_Client_getConfig(client);
    UA_ClientConfig_setDefault(config);

    /* Register a WebSocket ConnectionManager so the client can reach
     * opc.wss:// endpoints. */
    UA_ConnectionManager *wsCM =
        UA_ConnectionManager_new_POSIX_WS(UA_STRING("ws connection manager"));
    if(wsCM)
        config->eventLoop->registerEventSource(config->eventLoop,
                                               &wsCM->eventSource);

    /* Connect over WebSocket to the server */
    UA_StatusCode retval =
        UA_Client_connect(client, "opc.wss://localhost:4843");
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                    "Connection failed: %s", UA_StatusCode_name(retval));
        UA_Client_delete(client);
        return 1;
    }

    /* Read the server's current time */
    UA_Variant value;
    UA_Variant_init(&value);
    const UA_NodeId nodeId = UA_NS0ID(SERVER_SERVERSTATUS_CURRENTTIME);
    retval = UA_Client_readValueAttribute(client, nodeId, &value);

    if(retval == UA_STATUSCODE_GOOD &&
       UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_DATETIME])) {
        UA_DateTime raw_date = *(UA_DateTime *)value.data;
        UA_DateTimeStruct dts = UA_DateTime_toStruct(raw_date);
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                    "Server date is: %02u-%02u-%04u %02u:%02u:%02u.%03u",
                    dts.day, dts.month, dts.year,
                    dts.hour, dts.min, dts.sec, dts.milliSec);
    }

    UA_Variant_clear(&value);

    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return 0;
}
