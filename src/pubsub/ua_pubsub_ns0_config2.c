/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2025 Fraunhofer IOSB (Author: Andreas Ebner)
 */

#include <open62541/server_pubsub.h>

#include "ua_pubsub_internal.h"
#include "../server/ua_server_internal.h"

#if defined(UA_ENABLE_PUBSUB) && defined(UA_ENABLE_PUBSUB_INFORMATIONMODEL) && \
    defined(UA_ENABLE_PUBSUB_FILE_CONFIG)

/* FileType front-end for the PubSubConfiguration object (Part 14 9.1.3.7).
 * The file content is the ExtensionObject-encoded UABinaryFileDataType with
 * a PubSubConfiguration2DataType body:
 *
 * - Open supports the modes Read (0x01), Read+Write (0x03) and
 *   Write+EraseExisting (0x06). The read snapshot is generated at open.
 *   Parallel readers are allowed, a writer requires exclusive access.
 * - Writes are buffered in the file handle. A plain Close discards them.
 * - CloseAndUpdate decodes the buffered content and applies the element
 *   operations through the incremental update engine.
 *
 * File handles are bound to the session. A repeated callback closes the
 * handles of sessions that have ended (pattern from the GDS TrustList). */

#define UA_PUBSUB_FILE_CHECKSESSIONINTERVAL 10000 /* 10s */

#define UA_PUBSUB_FILEMODE_WRITEBITS \
    ((UA_Byte)(UA_OPENFILEMODE_WRITE | UA_OPENFILEMODE_ERASEEXISTING))

static UA_PubSubFileContext *
getFileContext(UA_PubSubManager *psm, const UA_NodeId *sessionId,
               UA_UInt32 fileHandle) {
    UA_PubSubFileContext *ctx;
    LIST_FOREACH(ctx, &psm->configFileHandles, listEntry) {
        if(ctx->fileHandle == fileHandle &&
           UA_NodeId_equal(&ctx->sessionId, sessionId))
            return ctx;
    }
    return NULL;
}

static void
writeFileNs0Variable(UA_Server *server, UA_UInt32 id, void *v,
                     const UA_DataType *type) {
    UA_Variant var;
    UA_Variant_init(&var);
    UA_Variant_setScalar(&var, v, type);
    writeValueAttribute(server, UA_NODEID_NUMERIC(0, id), &var);
}

static void
updateOpenCountVariable(UA_Server *server, UA_PubSubManager *psm) {
    writeFileNs0Variable(server,
        UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_OPENCOUNT,
        &psm->configFileOpenCount, &UA_TYPES[UA_TYPES_UINT16]);
}

static void
updateSizeVariable(UA_Server *server, UA_UInt64 size) {
    writeFileNs0Variable(server,
        UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_SIZE,
        &size, &UA_TYPES[UA_TYPES_UINT64]);
}

/* Close the file handles of sessions that no longer exist */
static void
checkFileSessionsActive(UA_Server *server, void *data) {
    lockServer(server);
    UA_PubSubManager *psm = getPSM(server);
    if(!psm) {
        unlockServer(server);
        return;
    }

    UA_PubSubFileContext *ctx, *tmp;
    LIST_FOREACH_SAFE(ctx, &psm->configFileHandles, listEntry, tmp) {
        UA_Boolean foundSession = false;
        session_list_entry *session;
        LIST_FOREACH(session, &server->sessions, pointers) {
            if(UA_NodeId_equal(&session->session.sessionId, &ctx->sessionId)) {
                foundSession = true;
                break;
            }
        }
        if(foundSession)
            continue;
        UA_LOG_INFO(psm->logging, UA_LOGCATEGORY_PUBSUB,
                    "Session with an open PubSubConfiguration file handle has "
                    "ended. The handle is closed, buffered data is discarded.");
        UA_PubSubManager_removeConfigFileContext(psm, ctx);
    }

    if(psm->configFileOpenCount == 0 && psm->configFileCheckCallbackId != 0) {
        removeCallback(server, psm->configFileCheckCallbackId);
        psm->configFileCheckCallbackId = 0;
    }

    updateOpenCountVariable(server, psm);
    unlockServer(server);
}

/**********************/
/* Method callbacks   */
/**********************/

static UA_StatusCode
openPubSubConfigAction(UA_Server *server,
                       const UA_NodeId *sessionId, void *sessionContext,
                       const UA_NodeId *methodId, void *methodContext,
                       const UA_NodeId *objectId, void *objectContext,
                       size_t inputSize, const UA_Variant *input,
                       size_t outputSize, UA_Variant *output) {
    UA_LOCK_ASSERT(&server->serviceMutex);
    if(inputSize != 1 || !UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_BYTE]))
        return UA_STATUSCODE_BADTYPEMISMATCH;
    UA_Byte mode = *(UA_Byte*)input[0].data;

    UA_PubSubManager *psm = getPSM(server);
    if(!psm)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Only Read, Read+Write and Write+EraseExisting are supported */
    if(mode != UA_OPENFILEMODE_READ &&
       mode != (UA_OPENFILEMODE_READ | UA_OPENFILEMODE_WRITE) &&
       mode != (UA_OPENFILEMODE_WRITE | UA_OPENFILEMODE_ERASEEXISTING))
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* A writer requires exclusive access */
    if(mode & UA_PUBSUB_FILEMODE_WRITEBITS) {
        if(psm->configFileOpenCount != 0)
            return UA_STATUSCODE_BADNOTWRITABLE;
    } else if(psm->configFileWriterActive) {
        return UA_STATUSCODE_BADNOTREADABLE;
    }

    /* Generate the snapshot for the read modes */
    UA_ByteString snapshot = UA_BYTESTRING_NULL;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(mode & UA_OPENFILEMODE_READ) {
        res = UA_PubSubManager_encodeConfig2Blob(psm, &snapshot);
        if(res != UA_STATUSCODE_GOOD)
            return res;
    }

    UA_PubSubFileContext *ctx = (UA_PubSubFileContext*)
        UA_calloc(1, sizeof(UA_PubSubFileContext));
    if(!ctx) {
        UA_ByteString_clear(&snapshot);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    /* Assign a free handle id */
    UA_UInt32 handle = 0;
    for(UA_UInt32 id = 1; id != 0; id++) {
        UA_PubSubFileContext *iter;
        UA_Boolean isFree = true;
        LIST_FOREACH(iter, &psm->configFileHandles, listEntry) {
            if(iter->fileHandle == id) {
                isFree = false;
                break;
            }
        }
        if(isFree) {
            handle = id;
            break;
        }
    }

    ctx->fileHandle = handle;
    ctx->sessionId = *sessionId;
    ctx->openFileMode = mode;
    ctx->currentPos = 0;
    ctx->file = snapshot;
    ctx->dataToWrite = UA_BYTESTRING_NULL;
    LIST_INSERT_HEAD(&psm->configFileHandles, ctx, listEntry);
    psm->configFileOpenCount++;
    if(mode & UA_PUBSUB_FILEMODE_WRITEBITS)
        psm->configFileWriterActive = true;

    /* Watch for closed sessions while handles are open */
    if(psm->configFileCheckCallbackId == 0) {
        res = addRepeatedCallback(server, (UA_ServerCallback)checkFileSessionsActive,
                                  NULL, UA_PUBSUB_FILE_CHECKSESSIONINTERVAL,
                                  &psm->configFileCheckCallbackId);
        if(res != UA_STATUSCODE_GOOD) {
            UA_PubSubManager_removeConfigFileContext(psm, ctx);
            return res;
        }
    }

    updateOpenCountVariable(server, psm);
    updateSizeVariable(server, (UA_UInt64)ctx->file.length);
    return UA_Variant_setScalarCopy(output, &ctx->fileHandle,
                                    &UA_TYPES[UA_TYPES_UINT32]);
}

static UA_StatusCode
closePubSubConfigAction(UA_Server *server,
                        const UA_NodeId *sessionId, void *sessionContext,
                        const UA_NodeId *methodId, void *methodContext,
                        const UA_NodeId *objectId, void *objectContext,
                        size_t inputSize, const UA_Variant *input,
                        size_t outputSize, UA_Variant *output) {
    UA_LOCK_ASSERT(&server->serviceMutex);
    if(inputSize != 1 || !UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_UINT32]))
        return UA_STATUSCODE_BADTYPEMISMATCH;
    UA_UInt32 fileHandle = *(UA_UInt32*)input[0].data;

    UA_PubSubManager *psm = getPSM(server);
    if(!psm)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_PubSubFileContext *ctx = getFileContext(psm, sessionId, fileHandle);
    if(!ctx)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* A plain Close discards any buffered writes */
    UA_PubSubManager_removeConfigFileContext(psm, ctx);
    updateOpenCountVariable(server, psm);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
readPubSubConfigAction(UA_Server *server,
                       const UA_NodeId *sessionId, void *sessionContext,
                       const UA_NodeId *methodId, void *methodContext,
                       const UA_NodeId *objectId, void *objectContext,
                       size_t inputSize, const UA_Variant *input,
                       size_t outputSize, UA_Variant *output) {
    UA_LOCK_ASSERT(&server->serviceMutex);
    if(inputSize != 2 ||
       !UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_UINT32]) ||
       !UA_Variant_hasScalarType(&input[1], &UA_TYPES[UA_TYPES_INT32]))
        return UA_STATUSCODE_BADTYPEMISMATCH;
    UA_UInt32 fileHandle = *(UA_UInt32*)input[0].data;
    UA_Int32 length = *(UA_Int32*)input[1].data;
    if(length < 0)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_PubSubManager *psm = getPSM(server);
    if(!psm)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_PubSubFileContext *ctx = getFileContext(psm, sessionId, fileHandle);
    if(!ctx)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    if(!(ctx->openFileMode & UA_OPENFILEMODE_READ))
        return UA_STATUSCODE_BADINVALIDSTATE;

    /* Clamp to the remaining length */
    if((size_t)length > ctx->file.length - ctx->currentPos)
        length = (UA_Int32)(ctx->file.length - ctx->currentPos);

    UA_ByteString readBuffer = UA_BYTESTRING_NULL;
    if(length > 0) {
        readBuffer.length = (size_t)length;
        readBuffer.data = ctx->file.data + ctx->currentPos;
        ctx->currentPos += (UA_UInt64)length;
    }

    return UA_Variant_setScalarCopy(output, &readBuffer,
                                    &UA_TYPES[UA_TYPES_BYTESTRING]);
}

static UA_StatusCode
writePubSubConfigAction(UA_Server *server,
                        const UA_NodeId *sessionId, void *sessionContext,
                        const UA_NodeId *methodId, void *methodContext,
                        const UA_NodeId *objectId, void *objectContext,
                        size_t inputSize, const UA_Variant *input,
                        size_t outputSize, UA_Variant *output) {
    UA_LOCK_ASSERT(&server->serviceMutex);
    if(inputSize != 2 ||
       !UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_UINT32]) ||
       !UA_Variant_hasScalarType(&input[1], &UA_TYPES[UA_TYPES_BYTESTRING]))
        return UA_STATUSCODE_BADTYPEMISMATCH;
    UA_UInt32 fileHandle = *(UA_UInt32*)input[0].data;
    UA_ByteString data = *(UA_ByteString*)input[1].data;

    UA_PubSubManager *psm = getPSM(server);
    if(!psm)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_PubSubFileContext *ctx = getFileContext(psm, sessionId, fileHandle);
    if(!ctx)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    if(!(ctx->openFileMode & UA_OPENFILEMODE_WRITE))
        return UA_STATUSCODE_BADINVALIDSTATE;

    if(data.length == 0)
        return UA_STATUSCODE_GOOD;

    /* Append to the buffered writes */
    UA_ByteString merged = UA_BYTESTRING_NULL;
    UA_StatusCode res = UA_ByteString_allocBuffer(
        &merged, ctx->dataToWrite.length + data.length);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    if(ctx->dataToWrite.length)
        memcpy(merged.data, ctx->dataToWrite.data, ctx->dataToWrite.length);
    memcpy(merged.data + ctx->dataToWrite.length, data.data, data.length);
    UA_ByteString_clear(&ctx->dataToWrite);
    ctx->dataToWrite = merged;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
getPositionPubSubConfigAction(UA_Server *server,
                              const UA_NodeId *sessionId, void *sessionContext,
                              const UA_NodeId *methodId, void *methodContext,
                              const UA_NodeId *objectId, void *objectContext,
                              size_t inputSize, const UA_Variant *input,
                              size_t outputSize, UA_Variant *output) {
    UA_LOCK_ASSERT(&server->serviceMutex);
    if(inputSize != 1 || !UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_UINT32]))
        return UA_STATUSCODE_BADTYPEMISMATCH;
    UA_UInt32 fileHandle = *(UA_UInt32*)input[0].data;

    UA_PubSubManager *psm = getPSM(server);
    if(!psm)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_PubSubFileContext *ctx = getFileContext(psm, sessionId, fileHandle);
    if(!ctx)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    return UA_Variant_setScalarCopy(output, &ctx->currentPos,
                                    &UA_TYPES[UA_TYPES_UINT64]);
}

static UA_StatusCode
setPositionPubSubConfigAction(UA_Server *server,
                              const UA_NodeId *sessionId, void *sessionContext,
                              const UA_NodeId *methodId, void *methodContext,
                              const UA_NodeId *objectId, void *objectContext,
                              size_t inputSize, const UA_Variant *input,
                              size_t outputSize, UA_Variant *output) {
    UA_LOCK_ASSERT(&server->serviceMutex);
    if(inputSize != 2 ||
       !UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_UINT32]) ||
       !UA_Variant_hasScalarType(&input[1], &UA_TYPES[UA_TYPES_UINT64]))
        return UA_STATUSCODE_BADTYPEMISMATCH;
    UA_UInt32 fileHandle = *(UA_UInt32*)input[0].data;
    UA_UInt64 position = *(UA_UInt64*)input[1].data;

    UA_PubSubManager *psm = getPSM(server);
    if(!psm)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_PubSubFileContext *ctx = getFileContext(psm, sessionId, fileHandle);
    if(!ctx)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    ctx->currentPos = (position > ctx->file.length) ?
        ctx->file.length : position;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
closeAndUpdatePubSubConfigAction(UA_Server *server,
                                 const UA_NodeId *sessionId, void *sessionContext,
                                 const UA_NodeId *methodId, void *methodContext,
                                 const UA_NodeId *objectId, void *objectContext,
                                 size_t inputSize, const UA_Variant *input,
                                 size_t outputSize, UA_Variant *output) {
    UA_LOCK_ASSERT(&server->serviceMutex);
    if(inputSize != 3 ||
       !UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_UINT32]) ||
       !UA_Variant_hasScalarType(&input[1], &UA_TYPES[UA_TYPES_BOOLEAN]))
        return UA_STATUSCODE_BADTYPEMISMATCH;
    if(!UA_Variant_isEmpty(&input[2]) &&
       !UA_Variant_hasArrayType(&input[2],
           &UA_TYPES[UA_TYPES_PUBSUBCONFIGURATIONREFDATATYPE]))
        return UA_STATUSCODE_BADTYPEMISMATCH;

    UA_UInt32 fileHandle = *(UA_UInt32*)input[0].data;
    UA_Boolean requireCompleteUpdate = *(UA_Boolean*)input[1].data;
    size_t refsSize = input[2].arrayLength;
    const UA_PubSubConfigurationRefDataType *refs =
        (const UA_PubSubConfigurationRefDataType*)input[2].data;

    UA_PubSubManager *psm = getPSM(server);
    if(!psm)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_PubSubFileContext *ctx = getFileContext(psm, sessionId, fileHandle);
    if(!ctx)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    if(!(ctx->openFileMode & UA_OPENFILEMODE_WRITE))
        return UA_STATUSCODE_BADINVALIDSTATE;

    if(refsSize == 0)
        return UA_STATUSCODE_BADNOTHINGTODO;

    /* Decode the buffered file content */
    UA_ExtensionObject eo;
    UA_ExtensionObject_init(&eo);
    UA_PubSubConfiguration2DataType cfg;
    UA_StatusCode res =
        UA_PubSubManager_decodeConfig2Blob(psm, &ctx->dataToWrite, &eo, &cfg);
    if(res != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADTYPEMISMATCH;

    /* Apply the element operations */
    UA_PubSubConfigUpdateResult result;
    memset(&result, 0, sizeof(result));
    res = UA_PubSubManager_updateConfig2(psm, &cfg, refsSize, refs,
                                         requireCompleteUpdate, &result);
    UA_ExtensionObject_clear(&eo);
    if(res != UA_STATUSCODE_GOOD) {
        UA_PubSubConfigUpdateResult_clear(&result);
        return res;
    }

    /* Set the outputs: ChangesApplied, ReferencesResults,
     * ConfigurationValues, ConfigurationObjects */
    res = UA_Variant_setScalarCopy(&output[0], &result.changesApplied,
                                   &UA_TYPES[UA_TYPES_BOOLEAN]);
    res |= UA_Variant_setArrayCopy(&output[1], result.referencesResults,
                                   result.referencesResultsSize,
                                   &UA_TYPES[UA_TYPES_STATUSCODE]);
    res |= UA_Variant_setArrayCopy(&output[2], result.configurationValues,
                                   result.configurationValuesSize,
                                   &UA_TYPES[UA_TYPES_PUBSUBCONFIGURATIONVALUEDATATYPE]);
    res |= UA_Variant_setArrayCopy(&output[3], result.configurationObjects,
                                   result.configurationObjectsSize,
                                   &UA_TYPES[UA_TYPES_NODEID]);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* The file handle is closed on success */
    UA_PubSubManager_removeConfigFileContext(psm, ctx);
    updateOpenCountVariable(server, psm);
    return res;
}

UA_StatusCode
initPubSubConfig2FileType(UA_Server *server) {
    UA_StatusCode retVal = UA_STATUSCODE_GOOD;
    retVal |= setMethodNode_callback(server,
        UA_NS0ID(PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_OPEN),
        openPubSubConfigAction);
    retVal |= setMethodNode_callback(server,
        UA_NS0ID(PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_CLOSE),
        closePubSubConfigAction);
    retVal |= setMethodNode_callback(server,
        UA_NS0ID(PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_READ),
        readPubSubConfigAction);
    retVal |= setMethodNode_callback(server,
        UA_NS0ID(PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_WRITE),
        writePubSubConfigAction);
    retVal |= setMethodNode_callback(server,
        UA_NS0ID(PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_GETPOSITION),
        getPositionPubSubConfigAction);
    retVal |= setMethodNode_callback(server,
        UA_NS0ID(PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_SETPOSITION),
        setPositionPubSubConfigAction);
    retVal |= setMethodNode_callback(server,
        UA_NS0ID(PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_CLOSEANDUPDATE),
        closeAndUpdatePubSubConfigAction);

    /* Initial property values */
    UA_Boolean writable = true;
    writeFileNs0Variable(server,
        UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_WRITABLE,
        &writable, &UA_TYPES[UA_TYPES_BOOLEAN]);
    writeFileNs0Variable(server,
        UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_USERWRITABLE,
        &writable, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_UInt16 openCount = 0;
    writeFileNs0Variable(server,
        UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_OPENCOUNT,
        &openCount, &UA_TYPES[UA_TYPES_UINT16]);
    updateSizeVariable(server, 0);

    return retVal;
}

#endif /* UA_ENABLE_PUBSUB && UA_ENABLE_PUBSUB_INFORMATIONMODEL &&
          UA_ENABLE_PUBSUB_FILE_CONFIG */
