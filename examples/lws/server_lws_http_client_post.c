/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 * Copyright 2026 (c) o6 Automation GmbH (Author: Julius Pfrommer)
 * Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

/* Sends a form twice at once with HTTP POST to tools/lws/httpServer.py. Each
 * request gets its own connection. */

#include <open62541/server.h>
#include <open62541/plugin/log_stdout.h>

#include <stdlib.h>

#include "common.h"

#define COUNT 2

static size_t responses;

static void
onResponse(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    const UA_ByteString *body = (const UA_ByteString *)UA_KeyValueMap_getScalar(
        result, UA_QUALIFIEDNAME(0, "body"), &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Response (%s): %S",
                UA_StatusCode_name(status), body ? *body : UA_STRING_NULL);
    responses++;
}

int main(void) {
    UA_Server *server = UA_Server_newFromFile(UA_STRING(
        "{ drivers: [{"
        "    driver: 'rest', name: 'test',"
        "    calls: { post: { method: 'POST', path: '/post',"
        "                     body: 'text=hallo&send=data' } },"
        "    drivers: [{ driver: 'http', url: 'http://localhost:8000' }]"
        "}] }"));
    if(!server || addHttpConnectionManager(server) != UA_STATUSCODE_GOOD ||
       UA_Server_run_startup(server) != UA_STATUSCODE_GOOD) {
        UA_Server_delete(server);
        return EXIT_FAILURE;
    }

    size_t sent = 0;
    for(size_t i = 0; i < COUNT; i++) {
        if(UA_Server_callDriver(server, "test", "post", NULL, onResponse, NULL) ==
           UA_STATUSCODE_GOOD)
            sent++;
    }
    while(responses < sent)
        UA_Server_run_iterate(server, true);

    UA_Server_run_shutdown(server);
    UA_Server_delete(server);
    return (sent == COUNT) ? EXIT_SUCCESS : EXIT_FAILURE;
}
