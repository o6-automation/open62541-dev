/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 * Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

/* One GET with the http driver. Start tools/lws/httpServer.py first. */

#include <open62541/server.h>

#include <stdio.h>
#include <stdlib.h>

static UA_Boolean done;

static void
onResponse(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    (void)context;
    const UA_ByteString *body = (const UA_ByteString *)UA_KeyValueMap_getScalar(
        result, UA_QUALIFIEDNAME(0, "body"), &UA_TYPES[UA_TYPES_BYTESTRING]);
    printf("%s: %.*s\n", UA_StatusCode_name(status),
           body ? (int)body->length : 0, body ? (const char *)body->data : "");
    done = true;
}

int main(void) {
    UA_Server *server = UA_Server_newFromFile(UA_STRING(
        "{ drivers: [{ driver: 'http', name: 'web', url: 'http://localhost:8000' }] }"));
    if(!server || UA_Server_run_startup(server) != UA_STATUSCODE_GOOD)
        return EXIT_FAILURE;

    if(UA_Server_callDriver(server, "web", "GET", NULL, onResponse, NULL) ==
       UA_STATUSCODE_GOOD) {
        while(!done)
            UA_Server_run_iterate(server, true);
    }

    UA_Server_run_shutdown(server);
    UA_Server_delete(server);
    return done ? EXIT_SUCCESS : EXIT_FAILURE;
}
