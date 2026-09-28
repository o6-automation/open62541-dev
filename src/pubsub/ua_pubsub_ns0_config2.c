/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#include <open62541/server_pubsub.h>
#include <open62541/driver/file_transfer.h>

#include "ua_pubsub_internal.h"

#if defined(UA_ENABLE_PUBSUB_INFORMATIONMODEL) && defined(UA_ENABLE_PUBSUB_FILE_CONFIG) && \
    defined(UA_ENABLE_METHODCALLS) && defined(UA_GENERATED_NAMESPACE_ZERO_FULL)

/* The PubSubConfiguration FileType object (Part 14 v1.05, 9.1.3.7) is served
 * by the file-transfer driver with the backend below:
 *
 * - Open supports the modes Read (0x01), Read+Write (0x03) and
 *   Write+EraseExisting (0x06). The file content is generated when the file
 *   is opened for reading. Written content stays in the file handle.
 * - A plain Close discards the written content. CloseAndUpdate applies the
 *   element operations of the references to it and closes the handle.
 * - The content is limited to UA_PUBSUB_CONFIGFILE_MAXSIZE bytes. */

#define UA_PUBSUB_CONFIGFILE_MAXSIZE (16u << 20) /* 16 MiB */

static const UA_String fileTransferDriverName = UA_STRING_STATIC("file-transfer");

typedef struct {
    UA_ByteString content;
    size_t position;
} UA_PubSubConfigFile;

static UA_StatusCode
configFileOpen(UA_FileTransferBackend *b, const UA_String path, UA_Byte mode,
               void **fileContext) {
    if(mode != UA_OPENFILEMODE_READ &&
       mode != (UA_OPENFILEMODE_READ | UA_OPENFILEMODE_WRITE) &&
       mode != (UA_OPENFILEMODE_WRITE | UA_OPENFILEMODE_ERASEEXISTING))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_PubSubConfigFile *f = (UA_PubSubConfigFile*)
        UA_calloc(1, sizeof(UA_PubSubConfigFile));
    if(!f)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    if(mode & UA_OPENFILEMODE_READ) {
        UA_StatusCode res = UA_PubSubManager_encodeConfig2Blob(
            (UA_PubSubManager*)b->context, &f->content);
        if(res != UA_STATUSCODE_GOOD) {
            UA_free(f);
            return res;
        }
    }
    *fileContext = f;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
configFileClose(UA_FileTransferBackend *b, void *fileContext) {
    UA_PubSubConfigFile *f = (UA_PubSubConfigFile*)fileContext;
    UA_ByteString_clear(&f->content);
    UA_free(f);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
configFileRead(UA_FileTransferBackend *b, void *fileContext, UA_Int32 length,
               UA_ByteString *out) {
    UA_PubSubConfigFile *f = (UA_PubSubConfigFile*)fileContext;
    size_t size = f->content.length - f->position;
    if(size > (size_t)length)
        size = (size_t)length;
    UA_ByteString_init(out);
    if(size == 0)
        return UA_STATUSCODE_GOOD; /* End of the file */
    UA_StatusCode res = UA_ByteString_allocBuffer(out, size);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    memcpy(out->data, &f->content.data[f->position], size);
    f->position += size;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
configFileWrite(UA_FileTransferBackend *b, void *fileContext,
                const UA_ByteString data) {
    UA_PubSubConfigFile *f = (UA_PubSubConfigFile*)fileContext;
    size_t end = f->position + data.length;
    if(end > UA_PUBSUB_CONFIGFILE_MAXSIZE)
        return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
    if(end > f->content.length) {
        UA_Byte *content = (UA_Byte*)UA_realloc(f->content.data, end);
        if(!content)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        f->content.data = content;
        f->content.length = end;
    }
    memcpy(&f->content.data[f->position], data.data, data.length);
    f->position = end;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
configFileGetPosition(UA_FileTransferBackend *b, void *fileContext,
                      UA_UInt64 *position) {
    *position = ((UA_PubSubConfigFile*)fileContext)->position;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
configFileSetPosition(UA_FileTransferBackend *b, void *fileContext,
                      UA_UInt64 position) {
    UA_PubSubConfigFile *f = (UA_PubSubConfigFile*)fileContext;
    f->position = (position < f->content.length) ?
        (size_t)position : f->content.length;
    return UA_STATUSCODE_GOOD;
}

/* The size of the current configuration and the time of the last update that
 * applied changes */
static UA_StatusCode
configFileGetAttributes(UA_FileTransferBackend *b, const UA_String path,
                        UA_FileTransferFileInfo *info) {
    UA_PubSubManager *psm = (UA_PubSubManager*)b->context;
    UA_ByteString content = UA_BYTESTRING_NULL;
    UA_StatusCode res = UA_PubSubManager_encodeConfig2Blob(psm, &content);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    memset(info, 0, sizeof(UA_FileTransferFileInfo));
    info->size = content.length;
    info->lastModified = psm->configFileLastModified;
    info->writable = true;
    UA_ByteString_clear(&content);
    return UA_STATUSCODE_GOOD;
}

static UA_FileTransferDriver *
findFileTransferDriver(UA_Server *server) {
    for(UA_Driver *drv = UA_Server_getDrivers(server); drv; drv = drv->next) {
        if(UA_String_equal(&drv->name, &fileTransferDriverName) &&
           drv->state == UA_LIFECYCLESTATE_STARTED)
            return (UA_FileTransferDriver*)drv;
    }
    return NULL;
}

static UA_StatusCode
closeAndUpdateAction(UA_Server *server,
                     const UA_NodeId *sessionId, void *sessionContext,
                     const UA_NodeId *methodId, void *methodContext,
                     const UA_NodeId *objectId, void *objectContext,
                     size_t inputSize, const UA_Variant *input,
                     size_t outputSize, UA_Variant *output) {
    UA_LOCK_ASSERT(&server->serviceMutex);
    if(inputSize != 3 || outputSize != 4 ||
       !UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_UINT32]) ||
       !UA_Variant_hasScalarType(&input[1], &UA_TYPES[UA_TYPES_BOOLEAN]))
        return UA_STATUSCODE_BADTYPEMISMATCH;
    if(!UA_Variant_isEmpty(&input[2]) &&
       !UA_Variant_hasArrayType(&input[2],
           &UA_TYPES[UA_TYPES_PUBSUBCONFIGURATIONREFDATATYPE]))
        return UA_STATUSCODE_BADTYPEMISMATCH;
    UA_UInt32 fileHandle = *(UA_UInt32*)input[0].data;

    /* The written content of the file handle */
    UA_PubSubManager *psm = getPSM(server);
    UA_FileTransferDriver *ftd = findFileTransferDriver(server);
    if(!psm || !ftd)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_Byte mode = 0;
    void *fileContext = NULL;
    UA_StatusCode res = ftd->getHandleContext(ftd, *objectId, sessionId,
                                              fileHandle, &mode, &fileContext);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    if(!(mode & UA_OPENFILEMODE_WRITE))
        return UA_STATUSCODE_BADINVALIDSTATE;

    UA_PubSubConfigurationUpdateResult result;
    res = UA_PubSubManager_updateConfigFile(
        psm, &((UA_PubSubConfigFile*)fileContext)->content, input[2].arrayLength,
        (const UA_PubSubConfigurationRefDataType*)input[2].data,
        *(UA_Boolean*)input[1].data, &result);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* ChangesApplied, ReferencesResults, ConfigurationValues and
     * ConfigurationObjects */
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
    UA_PubSubConfigurationUpdateResult_clear(&result);

    /* The file handle is closed when the update was processed */
    ftd->closeHandle(ftd, sessionId, fileHandle);
    return res;
}

void
UA_PubSubManager_attachConfigFile(UA_PubSubManager *psm) {
    UA_Server *server = psm->drv.server;
    UA_FileTransferDriver *ftd = findFileTransferDriver(server);
    if(!ftd) {
        UA_LOG_INFO(psm->logging, UA_LOGCATEGORY_PUBSUB,
                    "PubSubConfiguration file: Add the file-transfer driver "
                    "to serve the PubSubConfiguration object");
        return;
    }

    UA_FileTransferBackend backend;
    memset(&backend, 0, sizeof(UA_FileTransferBackend));
    backend.context = psm;
    backend.openFile = configFileOpen;
    backend.closeFile = configFileClose;
    backend.read = configFileRead;
    backend.write = configFileWrite;
    backend.getPosition = configFileGetPosition;
    backend.setPosition = configFileSetPosition;
    backend.getAttributes = configFileGetAttributes;
    UA_StatusCode res =
        ftd->attachFile(ftd, UA_NS0ID(PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION),
                        backend, UA_STRING_NULL, NULL);
    if(res == UA_STATUSCODE_BADNODEIDEXISTS)
        return; /* Attached at an earlier startup of the server */
    if(res == UA_STATUSCODE_GOOD)
        res = UA_Server_setMethodNodeCallback(server,
            UA_NS0ID(PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_CLOSEANDUPDATE),
            closeAndUpdateAction);
    if(res != UA_STATUSCODE_GOOD)
        UA_LOG_WARNING(psm->logging, UA_LOGCATEGORY_PUBSUB,
                       "PubSubConfiguration file: Attaching to the file-transfer "
                       "driver failed with %s", UA_StatusCode_name(res));
}

void
UA_PubSubManager_detachConfigFile(UA_PubSubManager *psm) {
    UA_Server *server = psm->drv.server;
    for(UA_Driver *drv = UA_Server_getDrivers(server); drv; drv = drv->next) {
        if(!UA_String_equal(&drv->name, &fileTransferDriverName))
            continue;
        UA_FileTransferDriver *ftd = (UA_FileTransferDriver*)drv;
        if(ftd->detachFile(ftd, UA_NS0ID(PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION)) ==
           UA_STATUSCODE_GOOD)
            UA_Server_setMethodNodeCallback(server,
                UA_NS0ID(PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_CLOSEANDUPDATE), NULL);
    }
}

#endif /* UA_ENABLE_PUBSUB_INFORMATIONMODEL && UA_ENABLE_PUBSUB_FILE_CONFIG &&
        * UA_ENABLE_METHODCALLS && UA_GENERATED_NAMESPACE_ZERO_FULL */
