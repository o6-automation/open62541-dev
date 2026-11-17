/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 * Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

/* An HTTP endpoint as OPC UA nodes. Start tools/lws/httpServer.py first. */

#include <open62541/server.h>

#include <stdlib.h>

int main(void) {
    UA_Server *server = UA_Server_newFromFile(UA_STRING(
        "{ drivers: [{"
        "    driver: 'binding', name: 'Web',"
        "    variables: { Page: { call: 'GET', type: 'String', from: 'body' } },"
        "    methods: { Get: { call: 'GET', outputs: { status: 'UInt16' } } },"
        "    drivers: [{ driver: 'http', url: 'http://localhost:8000' }]"
        "}] }"));
    if(!server)
        return EXIT_FAILURE;
    UA_StatusCode res = UA_Server_runUntilInterrupt(server);
    UA_Server_delete(server);
    return (res == UA_STATUSCODE_GOOD) ? EXIT_SUCCESS : EXIT_FAILURE;
}
