/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 * Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

/* Calls of a REST API from server_lws_rest_client.json5.
 * Start tools/lws/restServer.py first. */

#include <open62541/server.h>
#include <open62541/plugin/log_stdout.h>

#include <stdlib.h>

#include "common.h"

#ifndef REST_CLIENT_CONFIG
#define REST_CLIENT_CONFIG "server_lws_rest_client.json5"
#endif

static UA_Boolean done;
static UA_Boolean success;

static void
onResult(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    const char *call = (const char *)context;
    const UA_UInt16 *httpStatus = (const UA_UInt16 *)UA_KeyValueMap_getScalar(
        result, UA_QUALIFIEDNAME(0, "status"), &UA_TYPES[UA_TYPES_UINT16]);
    const UA_ByteString *body = (const UA_ByteString *)UA_KeyValueMap_getScalar(
        result, UA_QUALIFIEDNAME(0, "body"), &UA_TYPES[UA_TYPES_BYTESTRING]);
    const UA_String *lastCall = (const UA_String *)UA_KeyValueMap_getScalar(
        result, UA_QUALIFIEDNAME(0, "call"), &UA_TYPES[UA_TYPES_STRING]);
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "%s (%s, last call %S): HTTP %u %S", call,
                UA_StatusCode_name(status), lastCall ? *lastCall : UA_STRING_NULL,
                httpStatus ? (unsigned)*httpStatus : 0u,
                body ? *body : UA_STRING_NULL);
    success = (status == UA_STATUSCODE_GOOD && httpStatus && *httpStatus < 400);
    done = true;
}

static UA_Boolean
call(UA_Server *server, const char *name, const UA_KeyValueMap *input) {
    done = false;
    success = false;
    UA_StatusCode res = UA_Server_callDriver(server, "press-api", name, input,
                                             onResult, (void *)(uintptr_t)name);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "%s could not be sent (%s)", name, UA_StatusCode_name(res));
        return false;
    }
    UA_DateTime deadline = UA_DateTime_nowMonotonic() + 10 * UA_DATETIME_SEC;
    while(!done && UA_DateTime_nowMonotonic() < deadline)
        UA_Server_run_iterate(server, true);
    return success;
}

int main(int argc, char **argv) {
    UA_ByteString json = loadFile(argc > 1 ? argv[1] : REST_CLIENT_CONFIG);
    if(json.length == 0) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Could not load the configuration");
        return EXIT_FAILURE;
    }
    UA_Server *server = UA_Server_newFromFile(json);
    UA_ByteString_clear(&json);
    if(!server || UA_Server_run_startup(server) != UA_STATUSCODE_GOOD) {
        UA_Server_delete(server);
        return EXIT_FAILURE;
    }

    UA_KeyValueMap input = UA_KEYVALUEMAP_NULL;
    UA_Int64 speed = 1500;
    UA_KeyValueMap_setScalar(&input, UA_QUALIFIEDNAME(0, "speed"), &speed,
                             &UA_TYPES[UA_TYPES_INT64]);

    UA_Boolean ok = call(server, "readMachine", NULL) &&
                    call(server, "setSpeed", &input) &&
                    call(server, "readMachine", NULL) &&
                    call(server, "currentJob", NULL);
    UA_KeyValueMap_clear(&input);

    UA_Server_run_shutdown(server);
    UA_Server_delete(server);
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
