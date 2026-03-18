/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 * Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 *
 * OPC UA Multi-Transport Client Example
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * Demonstrates connecting to an OPC UA server via different transports:
 *   opc.tcp://localhost:4840  — Standard TCP
 *   opc.ws://localhost:4843   — Plain WebSocket
 *
 * Reads the server's current time over each transport.
 * Requires a server listening on both endpoints (e.g. the server_wss example).
 *
 * Build with: -DUA_ENABLE_LWS=ON
 */

#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/eventloop.h>
#include <open62541/plugin/log_stdout.h>

static UA_StatusCode
readServerTime(const char *url) {
    UA_Client *client = UA_Client_new();
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    UA_ClientConfig_setDefault(cc);

    /* Register the WebSocket ConnectionManager so the client can reach
     * opc.ws(s):// endpoints. For opc.tcp:// the default TCP CM is used. */
    UA_ConnectionManager *wsCM =
        UA_ConnectionManager_new_POSIX_WS(UA_STRING("ws connection manager"));
    if(wsCM)
        cc->eventLoop->registerEventSource(cc->eventLoop, &wsCM->eventSource);

    UA_StatusCode retval = UA_Client_connect(client, url);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                     "%s — connect failed: %s", url, UA_StatusCode_name(retval));
        UA_Client_delete(client);
        return retval;
    }

    UA_Variant value;
    UA_Variant_init(&value);
    const UA_NodeId nodeId = UA_NS0ID(SERVER_SERVERSTATUS_CURRENTTIME);
    retval = UA_Client_readValueAttribute(client, nodeId, &value);

    if(retval == UA_STATUSCODE_GOOD &&
       UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_DATETIME])) {
        UA_DateTime raw_date = *(UA_DateTime *)value.data;
        UA_DateTimeStruct dts = UA_DateTime_toStruct(raw_date);
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                    "%s — Server time: %02u-%02u-%04u %02u:%02u:%02u.%03u",
                    url,
                    dts.day, dts.month, dts.year,
                    dts.hour, dts.min, dts.sec, dts.milliSec);
    }
    UA_Variant_clear(&value);

    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return retval;
}

int main(void) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                "--- Connecting via opc.tcp ---");
    readServerTime("opc.tcp://localhost:4840");

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                "--- Connecting via opc.ws ---");
    readServerTime("opc.ws://localhost:4843");

    return 0;
}
