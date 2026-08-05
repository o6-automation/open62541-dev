/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/server_config_default.h>
#include <open62541/driver/file_transfer.h>

#include <check.h>
#include <stdlib.h>

#include "test_helpers.h"
#include "testing_clock.h"
#include "thread_wrapper.h"

#ifdef _WIN32
# include <windows.h>
# define shortSleep() Sleep(10)
#else
# include <unistd.h>
# define shortSleep() usleep(10000)
#endif

#if defined(UA_ENABLE_METHODCALLS) && defined(UA_GENERATED_NAMESPACE_ZERO_FULL)
# define UA_TEST_ENABLE_FILETRANSFER
#endif

UA_Server *server;
UA_Boolean running;
THREAD_HANDLE server_thread;

#ifdef UA_TEST_ENABLE_FILETRANSFER

static UA_FileTransferDriver *ftDriver;
static UA_NodeId fileNodeId;
static UA_NodeId openCountId;

/* Temporary file transfer objects (default and short-timeout) */
static UA_NodeId tempObjId;
static UA_NodeId tempTimeoutObjId;
static UA_Boolean tempApplyCalled;
static UA_ByteString tempApplied;

/* Simple single-file in-memory backend for the test */
static UA_ByteString fileContent;

typedef struct {
    size_t pos;
} SingleFileHandle;

static UA_StatusCode
sfOpen(UA_FileTransferBackend *b, const UA_String path, UA_Byte mode,
       void **fileContext) {
    SingleFileHandle *h = (SingleFileHandle*)UA_calloc(1, sizeof(SingleFileHandle));
    if(!h)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    if(mode & UA_OPENFILEMODE_ERASEEXISTING)
        fileContent.length = 0;
    if(mode & UA_OPENFILEMODE_APPEND)
        h->pos = fileContent.length;
    *fileContext = h;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
sfClose(UA_FileTransferBackend *b, void *fileContext) {
    UA_free(fileContext);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
sfRead(UA_FileTransferBackend *b, void *fileContext, UA_Int32 length,
       UA_ByteString *out) {
    SingleFileHandle *h = (SingleFileHandle*)fileContext;
    size_t remaining = (h->pos < fileContent.length) ?
        fileContent.length - h->pos : 0;
    size_t toRead = ((size_t)length < remaining) ? (size_t)length : remaining;
    if(toRead == 0) {
        UA_ByteString_init(out);
        return UA_STATUSCODE_GOOD;
    }
    UA_StatusCode res = UA_ByteString_allocBuffer(out, toRead);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    memcpy(out->data, fileContent.data + h->pos, toRead);
    h->pos += toRead;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
sfWrite(UA_FileTransferBackend *b, void *fileContext, const UA_ByteString data) {
    return UA_STATUSCODE_BADNOTWRITABLE;
}

static UA_StatusCode
sfGetPosition(UA_FileTransferBackend *b, void *fileContext, UA_UInt64 *outPos) {
    *outPos = ((SingleFileHandle*)fileContext)->pos;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
sfSetPosition(UA_FileTransferBackend *b, void *fileContext, UA_UInt64 pos) {
    SingleFileHandle *h = (SingleFileHandle*)fileContext;
    h->pos = (pos < fileContent.length) ? (size_t)pos : fileContent.length;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
sfGetAttributes(UA_FileTransferBackend *b, const UA_String path,
                UA_FileTransferFileInfo *outInfo) {
    memset(outInfo, 0, sizeof(UA_FileTransferFileInfo));
    outInfo->size = fileContent.length;
    outInfo->lastModified = UA_DateTime_now();
    outInfo->writable = true;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
sfUnsupported(UA_FileTransferBackend *b, const UA_String path) {
    return UA_STATUSCODE_BADNOTSUPPORTED;
}

static UA_StatusCode
sfListDirectory(UA_FileTransferBackend *b, const UA_String path,
                UA_FileTransferListCallback cb, void *listContext) {
    return UA_STATUSCODE_BADNOTSUPPORTED;
}

static UA_StatusCode
sfRename(UA_FileTransferBackend *b, const UA_String fromPath,
         const UA_String toPath) {
    return UA_STATUSCODE_BADNOTSUPPORTED;
}

static UA_FileTransferBackend
singleFileBackend(void) {
    UA_FileTransferBackend b;
    memset(&b, 0, sizeof(UA_FileTransferBackend));
    b.openFile = sfOpen;
    b.closeFile = sfClose;
    b.read = sfRead;
    b.write = sfWrite;
    b.getPosition = sfGetPosition;
    b.setPosition = sfSetPosition;
    b.getAttributes = sfGetAttributes;
    b.listDirectory = sfListDirectory;
    b.createFile = sfUnsupported;
    b.createDirectory = sfUnsupported;
    b.remove = sfUnsupported;
    b.rename = sfRename;
    return b;
}

static UA_StatusCode
tfApplyWrite(UA_Server *s, const UA_NodeId *sessionId,
             const UA_Variant *generateOptions, void *ctx,
             const UA_ByteString content) {
    tempApplyCalled = true;
    UA_ByteString_clear(&tempApplied);
    return UA_ByteString_copy(&content, &tempApplied);
}

#endif /* UA_TEST_ENABLE_FILETRANSFER */

THREAD_CALLBACK(serverloop) {
    while(running)
        UA_Server_run_iterate(server, true);
    return 0;
}

static void setup(void) {
    running = true;
    server = UA_Server_newForUnitTest();
    ck_assert(server != NULL);

#ifdef UA_TEST_ENABLE_FILETRANSFER
    fileContent = UA_BYTESTRING_ALLOC("Hello File Transfer");

    ftDriver = UA_FileTransferDriver_new(UA_KEYVALUEMAP_NULL);
    ck_assert_ptr_nonnull(ftDriver);
    ck_assert_uint_eq(UA_Server_addDriver(server, &ftDriver->drv),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(ftDriver->drv.start(&ftDriver->drv), UA_STATUSCODE_GOOD);

    fileNodeId = UA_NODEID_NULL;
    ck_assert_uint_eq(
        ftDriver->addFile(ftDriver, UA_NODEID_NULL, UA_NS0ID(OBJECTSFOLDER),
                          UA_QUALIFIEDNAME(0, "TestFile"), singleFileBackend(),
                          UA_STRING("file"), NULL, &fileNodeId),
        UA_STATUSCODE_GOOD);

    /* Resolve the OpenCount Property for server-side observation */
    UA_QualifiedName qn = UA_QUALIFIEDNAME(0, "OpenCount");
    UA_BrowsePathResult bpr =
        UA_Server_browseSimplifiedBrowsePath(server, fileNodeId, 1, &qn);
    ck_assert_uint_eq(bpr.statusCode, UA_STATUSCODE_GOOD);
    UA_NodeId_copy(&bpr.targets[0].targetId.nodeId, &openCountId);
    UA_BrowsePathResult_clear(&bpr);

    /* Temporary transfer objects (created before the server thread starts) */
    tempApplyCalled = false;
    UA_ByteString_init(&tempApplied);

    UA_FileTransferTemporaryOptions topts;
    memset(&topts, 0, sizeof(topts));
    topts.applyWrite = tfApplyWrite;
    tempObjId = UA_NODEID_NULL;
    ck_assert_uint_eq(
        ftDriver->addTemporaryFileTransfer(ftDriver, UA_NODEID_NULL,
            UA_NS0ID(OBJECTSFOLDER), UA_QUALIFIEDNAME(0, "FirmwareUpdate"),
            &topts, &tempObjId), UA_STATUSCODE_GOOD);

    UA_FileTransferTemporaryOptions qopts;
    memset(&qopts, 0, sizeof(qopts));
    qopts.applyWrite = tfApplyWrite;
    qopts.clientProcessingTimeoutMs = 50.0;
    tempTimeoutObjId = UA_NODEID_NULL;
    ck_assert_uint_eq(
        ftDriver->addTemporaryFileTransfer(ftDriver, UA_NODEID_NULL,
            UA_NS0ID(OBJECTSFOLDER), UA_QUALIFIEDNAME(0, "QuickTimeout"),
            &qopts, &tempTimeoutObjId), UA_STATUSCODE_GOOD);
#endif

    UA_Server_run_startup(server);
    THREAD_CREATE(server_thread, serverloop);
}

static void teardown(void) {
    running = false;
    THREAD_JOIN(server_thread);
    UA_Server_run_shutdown(server);
#ifdef UA_TEST_ENABLE_FILETRANSFER
    ftDriver->drv.stop(&ftDriver->drv);
    ck_assert_uint_eq(UA_Server_removeDriver(server, &ftDriver->drv),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(ftDriver->drv.free(&ftDriver->drv), UA_STATUSCODE_GOOD);
    UA_NodeId_clear(&fileNodeId);
    UA_NodeId_clear(&openCountId);
    UA_NodeId_clear(&tempObjId);
    UA_NodeId_clear(&tempTimeoutObjId);
    UA_ByteString_clear(&tempApplied);
    UA_ByteString_clear(&fileContent);
#endif
    UA_Server_delete(server);
}

#ifdef UA_TEST_ENABLE_FILETRANSFER

static UA_UInt16
readOpenCount(void) {
    UA_Variant value;
    UA_Variant_init(&value);
    ck_assert_uint_eq(UA_Server_readValue(server, openCountId, &value),
                      UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_UINT16]));
    UA_UInt16 openCount = *(UA_UInt16*)value.data;
    UA_Variant_clear(&value);
    return openCount;
}

/* File handles are bound to the Session. Closing the Session releases all
 * handles the Session had open. */
START_TEST(sessionCloseReleasesHandles) {
    UA_Client *client = UA_Client_newForUnitTest();
    UA_StatusCode retval = UA_Client_connect(client, "opc.tcp://localhost:4840");
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);

    /* Open the file over the wire */
    UA_Byte mode = UA_OPENFILEMODE_READ;
    UA_Variant input;
    UA_Variant_setScalar(&input, &mode, &UA_TYPES[UA_TYPES_BYTE]);
    size_t outputSize = 0;
    UA_Variant *output = NULL;
    retval = UA_Client_call(client, fileNodeId,
                            UA_NODEID_NUMERIC(0, UA_NS0ID_FILETYPE_OPEN),
                            1, &input, &outputSize, &output);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(outputSize, 1);
    UA_UInt32 handle = *(UA_UInt32*)output[0].data;
    ck_assert_uint_ne(handle, 0);
    UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);

    ck_assert_uint_eq(readOpenCount(), 1);

    /* Read the file content over the wire */
    UA_Int32 length = 100;
    UA_Variant readInput[2];
    UA_Variant_setScalar(&readInput[0], &handle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&readInput[1], &length, &UA_TYPES[UA_TYPES_INT32]);
    retval = UA_Client_call(client, fileNodeId,
                            UA_NODEID_NUMERIC(0, UA_NS0ID_FILETYPE_READ),
                            2, readInput, &outputSize, &output);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
    UA_ByteString *data = (UA_ByteString*)output[0].data;
    ck_assert_uint_eq(data->length, strlen("Hello File Transfer"));
    UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);

    /* Disconnecting closes the Session and releases the handle */
    UA_Client_disconnect(client);
    UA_Client_delete(client);

    UA_UInt16 openCount = 1;
    for(int i = 0; i < 500 && openCount > 0; i++) {
        UA_fakeSleep(10);
        shortSleep();
        openCount = readOpenCount();
    }
    ck_assert_uint_eq(openCount, 0);
} END_TEST

/* Call a method over the wire; returns the StatusCode and (on Good) the
 * outputs, which the caller frees. */
static UA_StatusCode
clientCall(UA_Client *client, const UA_NodeId object, UA_UInt32 method,
           size_t inSize, UA_Variant *in, size_t *outSize, UA_Variant **out) {
    return UA_Client_call(client, object, UA_NODEID_NUMERIC(0, method),
                          inSize, in, outSize, out);
}

/* A full write transfer over the wire commits the content to the application */
START_TEST(tempWriteCommitOverWire) {
    UA_Client *client = UA_Client_newForUnitTest();
    ck_assert_uint_eq(UA_Client_connect(client, "opc.tcp://localhost:4840"),
                      UA_STATUSCODE_GOOD);

    /* GenerateFileForWrite */
    UA_Variant options;
    UA_Variant_init(&options);
    size_t outSize = 0;
    UA_Variant *out = NULL;
    ck_assert_uint_eq(clientCall(client, tempObjId,
        UA_NS0ID_TEMPORARYFILETRANSFERTYPE_GENERATEFILEFORWRITE, 1, &options,
        &outSize, &out), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(outSize, 2);
    UA_NodeId tmpFile;
    UA_NodeId_copy((UA_NodeId*)out[0].data, &tmpFile);
    UA_UInt32 handle = *(UA_UInt32*)out[1].data;
    UA_Array_delete(out, outSize, &UA_TYPES[UA_TYPES_VARIANT]);

    /* Write the content on the temporary FileType Object */
    UA_ByteString blob = UA_BYTESTRING("firmware-blob-v2");
    UA_Variant writeIn[2];
    UA_Variant_setScalar(&writeIn[0], &handle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&writeIn[1], &blob, &UA_TYPES[UA_TYPES_BYTESTRING]);
    ck_assert_uint_eq(clientCall(client, tmpFile, UA_NS0ID_FILETYPE_WRITE,
        2, writeIn, &outSize, &out), UA_STATUSCODE_GOOD);
    UA_Array_delete(out, outSize, &UA_TYPES[UA_TYPES_VARIANT]);

    /* CloseAndCommit applies the content */
    UA_Variant commitIn;
    UA_Variant_setScalar(&commitIn, &handle, &UA_TYPES[UA_TYPES_UINT32]);
    ck_assert_uint_eq(clientCall(client, tempObjId,
        UA_NS0ID_TEMPORARYFILETRANSFERTYPE_CLOSEANDCOMMIT, 1, &commitIn,
        &outSize, &out), UA_STATUSCODE_GOOD);
    UA_Array_delete(out, outSize, &UA_TYPES[UA_TYPES_VARIANT]);

    ck_assert(tempApplyCalled);
    UA_String expected = UA_STRING("firmware-blob-v2");
    ck_assert(UA_String_equal(&tempApplied, &expected));

    UA_NodeId_clear(&tmpFile);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
} END_TEST

/* Disconnecting mid-transfer aborts the write without applying it */
START_TEST(tempSessionCloseAborts) {
    UA_Client *client = UA_Client_newForUnitTest();
    ck_assert_uint_eq(UA_Client_connect(client, "opc.tcp://localhost:4840"),
                      UA_STATUSCODE_GOOD);

    UA_Variant options;
    UA_Variant_init(&options);
    size_t outSize = 0;
    UA_Variant *out = NULL;
    ck_assert_uint_eq(clientCall(client, tempObjId,
        UA_NS0ID_TEMPORARYFILETRANSFERTYPE_GENERATEFILEFORWRITE, 1, &options,
        &outSize, &out), UA_STATUSCODE_GOOD);
    UA_NodeId tmpFile;
    UA_NodeId_copy((UA_NodeId*)out[0].data, &tmpFile);
    UA_UInt32 handle = *(UA_UInt32*)out[1].data;
    UA_Array_delete(out, outSize, &UA_TYPES[UA_TYPES_VARIANT]);

    UA_ByteString blob = UA_BYTESTRING("partial-upload");
    UA_Variant writeIn[2];
    UA_Variant_setScalar(&writeIn[0], &handle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&writeIn[1], &blob, &UA_TYPES[UA_TYPES_BYTESTRING]);
    ck_assert_uint_eq(clientCall(client, tmpFile, UA_NS0ID_FILETYPE_WRITE,
        2, writeIn, &outSize, &out), UA_STATUSCODE_GOOD);
    UA_Array_delete(out, outSize, &UA_TYPES[UA_TYPES_VARIANT]);

    /* Disconnect without CloseAndCommit */
    UA_Client_disconnect(client);
    UA_Client_delete(client);

    /* The transaction was aborted: applyWrite must not have been called. Wait
     * until the temporary file is gone (the session-close handler deleted it). */
    UA_StatusCode existRes = UA_STATUSCODE_GOOD;
    for(int i = 0; i < 1000 && existRes == UA_STATUSCODE_GOOD; i++) {
        UA_fakeSleep(10);
        shortSleep();
        UA_QualifiedName bn;
        existRes = UA_Server_readBrowseName(server, tmpFile, &bn);
        if(existRes == UA_STATUSCODE_GOOD)
            UA_QualifiedName_clear(&bn);
    }
    ck_assert_uint_ne(existRes, UA_STATUSCODE_GOOD);
    ck_assert(!tempApplyCalled);

    /* The write lock is released: a fresh write transfer succeeds */
    UA_Client *client2 = UA_Client_newForUnitTest();
    ck_assert_uint_eq(UA_Client_connect(client2, "opc.tcp://localhost:4840"),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(clientCall(client2, tempObjId,
        UA_NS0ID_TEMPORARYFILETRANSFERTYPE_GENERATEFILEFORWRITE, 1, &options,
        &outSize, &out), UA_STATUSCODE_GOOD);
    UA_Array_delete(out, outSize, &UA_TYPES[UA_TYPES_VARIANT]);

    UA_NodeId_clear(&tmpFile);
    UA_Client_disconnect(client2);
    UA_Client_delete(client2);
} END_TEST

/* An idle transfer is cancelled after ClientProcessingTimeout */
START_TEST(tempWriteTimeout) {
    UA_Client *client = UA_Client_newForUnitTest();
    ck_assert_uint_eq(UA_Client_connect(client, "opc.tcp://localhost:4840"),
                      UA_STATUSCODE_GOOD);

    UA_Variant options;
    UA_Variant_init(&options);
    size_t outSize = 0;
    UA_Variant *out = NULL;
    ck_assert_uint_eq(clientCall(client, tempTimeoutObjId,
        UA_NS0ID_TEMPORARYFILETRANSFERTYPE_GENERATEFILEFORWRITE, 1, &options,
        &outSize, &out), UA_STATUSCODE_GOOD);
    UA_NodeId tmpFile;
    UA_NodeId_copy((UA_NodeId*)out[0].data, &tmpFile);
    UA_Array_delete(out, outSize, &UA_TYPES[UA_TYPES_VARIANT]);

    /* Idle past the 50 ms timeout and the 1000 ms sweep interval. Poll the
     * temporary file node server-side (this does not reset the idle timer, as
     * any Method call on the handle would) until the sweep deletes it. */
    UA_StatusCode existRes = UA_STATUSCODE_GOOD;
    for(int i = 0; i < 1000 && existRes == UA_STATUSCODE_GOOD; i++) {
        UA_fakeSleep(20);
        shortSleep();
        UA_QualifiedName bn;
        existRes = UA_Server_readBrowseName(server, tmpFile, &bn);
        if(existRes == UA_STATUSCODE_GOOD)
            UA_QualifiedName_clear(&bn);
    }
    ck_assert_uint_ne(existRes, UA_STATUSCODE_GOOD);
    ck_assert(!tempApplyCalled);

    UA_NodeId_clear(&tmpFile);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
} END_TEST

#endif /* UA_TEST_ENABLE_FILETRANSFER */

int main(void) {
    Suite *s = suite_create("client_filetransfer");

    TCase *tc = tcase_create("File Transfer Session Lifecycle");
#ifdef UA_TEST_ENABLE_FILETRANSFER
    tcase_add_test(tc, sessionCloseReleasesHandles);
    tcase_add_test(tc, tempWriteCommitOverWire);
    tcase_add_test(tc, tempSessionCloseAborts);
    tcase_add_test(tc, tempWriteTimeout);
#endif
    tcase_add_checked_fixture(tc, setup, teardown);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
