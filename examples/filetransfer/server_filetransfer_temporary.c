/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */

/* This example exposes a TemporaryFileTransferType Object for handshake-based
 * transfers (OPC UA Part 20, 4.4). It demonstrates both directions:
 *
 *  - GenerateFileForWrite + Write + CloseAndCommit: the client uploads a
 *    firmware image; the applyWrite callback receives the complete content.
 *  - GenerateFileForRead + Read + Close: the client downloads a generated
 *    status report produced by the generateForRead callback.
 *
 * Transfers complete synchronously, so the completionStateMachine output is
 * always null and no FileTransferStateMachineType is instantiated. Temporary
 * files are held in the driver's internal in-memory store. */

#include <open62541/plugin/log_stdout.h>
#include <open62541/driver/file_transfer.h>
#include <open62541/server.h>

#include <stdlib.h>
#include <string.h>

/* Apply an uploaded firmware image. A real device would validate and flash it;
 * here we just log the size. */
static UA_StatusCode
applyFirmware(UA_Server *server, const UA_NodeId *sessionId,
              const UA_Variant *generateOptions, void *context,
              const UA_ByteString content) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "Firmware update received: %lu bytes",
                (unsigned long)content.length);
    return UA_STATUSCODE_GOOD;
}

/* Produce a status report the client can download */
static UA_StatusCode
generateReport(UA_Server *server, const UA_NodeId *sessionId,
               const UA_Variant *generateOptions, void *context,
               UA_ByteString *outContent) {
    *outContent = UA_BYTESTRING_ALLOC("device=example\nstatus=OK\nuptime=42h\n");
    return (outContent->data != NULL) ?
        UA_STATUSCODE_GOOD : UA_STATUSCODE_BADOUTOFMEMORY;
}

int main(void) {
    UA_Server *server = UA_Server_new();

    UA_FileTransferDriver *ftd = UA_FileTransferDriver_new(UA_KEYVALUEMAP_NULL);
    if(!ftd) {
        UA_Server_delete(server);
        return EXIT_FAILURE;
    }
    UA_Server_addDriver(server, &ftd->drv);
    ftd->drv.start(&ftd->drv);

    /* A read+write temporary transfer object for firmware upload and report
     * download. The default in-memory temp store is used. */
    UA_FileTransferTemporaryOptions options;
    memset(&options, 0, sizeof(options));
    options.generateForRead = generateReport;
    options.applyWrite = applyFirmware;
    options.clientProcessingTimeoutMs = 30000.0; /* 30 s handshake timeout */

    UA_NodeId transferId;
    UA_StatusCode res = ftd->addTemporaryFileTransfer(
        ftd, UA_NODEID_NULL, UA_NS0ID(OBJECTSFOLDER),
        UA_QUALIFIEDNAME(0, "FirmwareUpdate"), &options, &transferId);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Could not add the temporary file transfer object");
        UA_Server_delete(server);
        return EXIT_FAILURE;
    }
    UA_NodeId_clear(&transferId);

    UA_Server_runUntilInterrupt(server);
    UA_Server_delete(server); /* Stops and frees the driver as well */
    return EXIT_SUCCESS;
}
