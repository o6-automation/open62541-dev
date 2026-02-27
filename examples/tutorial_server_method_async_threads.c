/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 * Async Method Call with Thread-Based Processing and Context Retrieval
 * ====================================================================
 *
 * This example demonstrates how to implement an async OPC UA method that
 * offloads work to a separate thread. When the method callback is called,
 * it returns UA_STATUSCODE_GOODCOMPLETESASYNCHRONOUSLY to signal the server
 * that the result will be provided later.
 *
 * A worker thread is spawned to perform the actual work. The thread uses
 * UA_Server_getAsyncMethodCallContext() to retrieve the full context of
 * the original method call:
 *
 *   - asyncId         unique numeric operation ID
 *   - sessionId       the calling session
 *   - methodId        the method node
 *   - methodContext    the method node's user context pointer
 *   - objectId        the parent object node
 *   - objectContext    the object node's user context pointer
 *   - inputArguments   deep copy of the input arguments
 *   - outputArguments  direct pointer to write results into
 *
 * Multiple async operations can be in flight simultaneously. Each gets its
 * own unique asyncId. The worker can also complete the operation using
 * UA_Server_setAsyncCallMethodResultById() with the asyncId.
 *
 * Build requirement: UA_MULTITHREADING >= 100 and UA_ENABLE_METHODCALLS */

#include <open62541/server.h>
#include <open62541/plugin/log.h>

#include <pthread.h>
#include <unistd.h>
#include <string.h>

/* Context passed to the worker thread */
typedef struct {
    UA_Server *server;
    UA_Variant *output; /* The async operation handle (output pointer) */
} WorkerContext;

static void *
workerThread(void *arg) {
    WorkerContext *wctx = (WorkerContext*)arg;
    UA_Server *server = wctx->server;
    UA_Variant *output = wctx->output;
    const UA_Logger *logger = UA_Server_getConfig(server)->logging;

    UA_LOG_INFO(logger, UA_LOGCATEGORY_APPLICATION,
                "[Worker] Thread started, retrieving call context...");

    /* Retrieve the full method call context from the server. This is
     * thread-safe and returns a struct mirroring the MethodCallback
     * parameters: sessionId, sessionContext, methodId, methodContext,
     * objectId, objectContext, inputArguments, outputArguments, and
     * the unique asyncId. */
    UA_AsyncMethodCallContext ctx;
    UA_StatusCode res = UA_Server_getAsyncMethodCallContext(server, output, &ctx);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_APPLICATION,
                     "[Worker] Failed to get call context: %s",
                     UA_StatusCode_name(res));
        UA_Server_setAsyncCallMethodResult(server, output,
                                           UA_STATUSCODE_BADINTERNALERROR);
        free(wctx);
        return NULL;
    }

    /* Log the unique async operation ID */
    UA_LOG_INFO(logger, UA_LOGCATEGORY_APPLICATION,
                "[Worker] Async operation ID: %lu", (unsigned long)ctx.asyncId);

    /* Log the session information */
    UA_String sessionStr = UA_STRING_NULL;
    UA_NodeId_print(&ctx.sessionId, &sessionStr);
    UA_LOG_INFO(logger, UA_LOGCATEGORY_APPLICATION,
                "[Worker] Session: %.*s (context=%p)",
                (int)sessionStr.length, sessionStr.data, ctx.sessionContext);
    UA_String_clear(&sessionStr);

    /* Log the method and object node IDs with their context pointers */
    UA_String methodStr = UA_STRING_NULL, objectStr = UA_STRING_NULL;
    UA_NodeId_print(&ctx.methodId, &methodStr);
    UA_NodeId_print(&ctx.objectId, &objectStr);
    UA_LOG_INFO(logger, UA_LOGCATEGORY_APPLICATION,
                "[Worker] Method: %.*s (context=%p)\n"
                "         Object: %.*s (context=%p)",
                (int)methodStr.length, methodStr.data, ctx.methodContext,
                (int)objectStr.length, objectStr.data, ctx.objectContext);
    UA_String_clear(&methodStr);
    UA_String_clear(&objectStr);

    /* Access the original input arguments */
    UA_String processName = UA_STRING_NULL;
    UA_UInt32 timeoutSec = 1;

    if(ctx.inputArgumentsSize >= 1 &&
       ctx.inputArguments[0].type == &UA_TYPES[UA_TYPES_STRING]) {
        processName = *(UA_String*)ctx.inputArguments[0].data;
    }
    if(ctx.inputArgumentsSize >= 2 &&
       ctx.inputArguments[1].type == &UA_TYPES[UA_TYPES_UINT32]) {
        timeoutSec = *(UA_UInt32*)ctx.inputArguments[1].data;
    }

    UA_LOG_INFO(logger, UA_LOGCATEGORY_APPLICATION,
                "[Worker] Input: ProcessName='%.*s', TimeoutSec=%u",
                (int)processName.length, processName.data, (unsigned)timeoutSec);

    /* Simulate long-running work */
    if(timeoutSec > 10)
        timeoutSec = 10; /* Cap for safety */
    UA_LOG_INFO(logger, UA_LOGCATEGORY_APPLICATION,
                "[Worker] Simulating %u seconds of work...", (unsigned)timeoutSec);
    sleep(timeoutSec);

    /* Write the output result using the outputArguments pointer from the
     * context. This writes directly into server-internal memory. */
    UA_String resultMsg = UA_STRING_NULL;
    UA_String_format(&resultMsg, "Process '%.*s' completed (asyncId=%lu)",
                     (int)processName.length, processName.data,
                     (unsigned long)ctx.asyncId);
    UA_Variant_setScalarCopy(ctx.outputArguments, &resultMsg,
                             &UA_TYPES[UA_TYPES_STRING]);
    UA_String_clear(&resultMsg);

    /* Clean up the deep-copied context */
    UA_AsyncMethodCallContext_clear(&ctx);

    /* Signal completion using the asyncId (alternative: use output pointer) */
    UA_LOG_INFO(logger, UA_LOGCATEGORY_APPLICATION,
                "[Worker] Work completed, signaling result.");
    UA_Server_setAsyncCallMethodResult(server, output, UA_STATUSCODE_GOOD);

    free(wctx);
    return NULL;
}

/* The async method callback. This is called by the server when a client
 * invokes the method. It spawns a worker thread and returns
 * UA_STATUSCODE_GOODCOMPLETESASYNCHRONOUSLY so the server holds the
 * response until the worker finishes. */
static UA_StatusCode
openProcessCallback(UA_Server *server,
                    const UA_NodeId *sessionId, void *sessionContext,
                    const UA_NodeId *methodId, void *methodContext,
                    const UA_NodeId *objectId, void *objectContext,
                    size_t inputSize, const UA_Variant *input,
                    size_t outputSize, UA_Variant *output) {
    UA_LOG_INFO(UA_Server_getConfig(server)->logging, UA_LOGCATEGORY_APPLICATION,
                "OpenProcess called - spawning worker thread");

    /* Allocate context for the worker thread.
     * We pass the server pointer and the output pointer (which serves as
     * the handle for the async operation). */
    WorkerContext *wctx = (WorkerContext*)malloc(sizeof(WorkerContext));
    if(!wctx)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    wctx->server = server;
    wctx->output = output;

    /* Spawn a detached worker thread */
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&thread, &attr, workerThread, wctx);
    pthread_attr_destroy(&attr);
    if(rc != 0) {
        free(wctx);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Tell the server to hold the response */
    return UA_STATUSCODE_GOODCOMPLETESASYNCHRONOUSLY;
}

int main(void) {
    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);

    /* Set a generous async operation timeout (60 seconds) */
    config->asyncOperationTimeout = 60000;

    /* Define input arguments: processName (String) and timeoutSec (UInt32) */
    UA_Argument inputArgs[2];

    UA_Argument_init(&inputArgs[0]);
    inputArgs[0].description = UA_LOCALIZEDTEXT("en-US", "Name of the process to open");
    inputArgs[0].name = UA_STRING("ProcessName");
    inputArgs[0].dataType = UA_TYPES[UA_TYPES_STRING].typeId;
    inputArgs[0].valueRank = UA_VALUERANK_SCALAR;

    UA_Argument_init(&inputArgs[1]);
    inputArgs[1].description = UA_LOCALIZEDTEXT("en-US",
                                                "Simulated processing time in seconds");
    inputArgs[1].name = UA_STRING("TimeoutSec");
    inputArgs[1].dataType = UA_TYPES[UA_TYPES_UINT32].typeId;
    inputArgs[1].valueRank = UA_VALUERANK_SCALAR;

    /* Define output argument: result message (String) */
    UA_Argument outputArg;
    UA_Argument_init(&outputArg);
    outputArg.description = UA_LOCALIZEDTEXT("en-US", "Result status message");
    outputArg.name = UA_STRING("Result");
    outputArg.dataType = UA_TYPES[UA_TYPES_STRING].typeId;
    outputArg.valueRank = UA_VALUERANK_SCALAR;

    /* Add the method node */
    UA_MethodAttributes methAttr = UA_MethodAttributes_default;
    methAttr.description = UA_LOCALIZEDTEXT("en-US",
        "Opens a process asynchronously. The method returns immediately "
        "while a worker thread performs the actual work. The worker retrieves "
        "the full call context (asyncId, session, method/object nodes and "
        "contexts, input arguments) via UA_Server_getAsyncMethodCallContext().");
    methAttr.displayName = UA_LOCALIZEDTEXT("en-US", "OpenProcess");
    methAttr.executable = true;
    methAttr.userExecutable = true;

    UA_Server_addMethodNode(server, UA_NODEID_NUMERIC(1, 62542),
                            UA_NS0ID(OBJECTSFOLDER), UA_NS0ID(HASCOMPONENT),
                            UA_QUALIFIEDNAME(1, "OpenProcess"),
                            methAttr, &openProcessCallback,
                            2, inputArgs, 1, &outputArg, NULL, NULL);

    UA_LOG_INFO(config->logging, UA_LOGCATEGORY_APPLICATION,
                "Async threaded method server started. "
                "Call method ns=1;i=62542 with arguments: "
                "ProcessName (String), TimeoutSec (UInt32)");

    UA_Server_runUntilInterrupt(server);
    UA_Server_delete(server);
    return 0;
}
