/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#include "file_transfer_internal.h"

#if defined(UA_ENABLE_METHODCALLS) && defined(UA_GENERATED_NAMESPACE_ZERO_FULL)

/**************************************
 * Temporary File Transfer (Part 20, 4.4)
 **************************************/

/* Format "<prefix><id>" into buf (must hold >= 16 bytes) without depending on
 * stdio; returns a UA_String view over buf. */
static UA_String
tempPathName(char *buf, char prefix, UA_UInt32 id) {
    char digits[10];
    size_t n = 0;
    if(id == 0)
        digits[n++] = '0';
    while(id > 0) {
        digits[n++] = (char)('0' + (id % 10));
        id /= 10;
    }
    size_t len = 0;
    buf[len++] = prefix;
    while(n > 0)
        buf[len++] = digits[--n];
    UA_String s = {len, (UA_Byte*)buf};
    return s;
}

static FTTempTransfer *
findTempTransfer(FileTransferDriver *ftd, const UA_NodeId *objectId) {
    FTTempTransfer *t;
    LIST_FOREACH(t, &ftd->tempTransfers, listEntry) {
        if(UA_NodeId_equal(&t->objectNodeId, objectId))
            return t;
    }
    return NULL;
}

/* Read the entire content of a backend file into a single ByteString */
static UA_StatusCode
readWholeBackendFile(UA_FileTransferBackend *b, const UA_String path,
                     UA_ByteString *out) {
    void *ctx = NULL;
    UA_StatusCode res = b->openFile(b, path, UA_OPENFILEMODE_READ, &ctx);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_ByteString acc = UA_BYTESTRING_NULL;
    while(res == UA_STATUSCODE_GOOD) {
        UA_ByteString chunk = UA_BYTESTRING_NULL;
        res = b->read(b, ctx, UA_FILETRANSFER_COPYCHUNKSIZE, &chunk);
        if(res != UA_STATUSCODE_GOOD || chunk.length == 0) {
            UA_ByteString_clear(&chunk);
            break;
        }
        UA_Byte *grown = (UA_Byte*)UA_realloc(acc.data, acc.length + chunk.length);
        if(!grown) {
            UA_ByteString_clear(&chunk);
            res = UA_STATUSCODE_BADOUTOFMEMORY;
            break;
        }
        memcpy(grown + acc.length, chunk.data, chunk.length);
        acc.data = grown;
        acc.length += chunk.length;
        UA_ByteString_clear(&chunk);
    }

    b->closeFile(b, ctx);
    if(res != UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(&acc);
        return res;
    }
    *out = acc;
    return UA_STATUSCODE_GOOD;
}

/* Write the whole content into a freshly created backend file */
static UA_StatusCode
writeWholeBackendFile(UA_FileTransferBackend *b, const UA_String path,
                      const UA_ByteString content) {
    UA_StatusCode res = b->createFile(b, path);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    if(content.length > 0) {
        void *ctx = NULL;
        res = b->openFile(b, path, UA_OPENFILEMODE_WRITE, &ctx);
        if(res == UA_STATUSCODE_GOOD) {
            res = b->write(b, ctx, content);
            b->closeFile(b, ctx);
        }
    }
    /* If the staged file could not be fully written, remove it so a failed
     * generate does not leak a temp-store slot (or an on-disk file). */
    if(res != UA_STATUSCODE_GOOD)
        b->remove(b, path);
    return res;
}

/* Create a non-browsable temporary FileType Object (no hierarchical parent,
 * reachable only by NodeId) and register it as a temporary FTNode. */
static UA_StatusCode
createTempFileNode(UA_Server *server, FileTransferDriver *ftd,
                   FTTempTransfer *transfer, const UA_NodeId *sessionId,
                   UA_Boolean forWrite, const UA_String path, FTNode **outNode) {
    UA_ObjectAttributes attr = UA_ObjectAttributes_default;
    attr.displayName = UA_LOCALIZEDTEXT("", "TemporaryFile");

    /* Add the object without a hierarchical parent reference. The begin/finish
     * pair adds the HasTypeDefinition to FileType and instantiates the
     * mandatory children; with no parent the node is not browsable. */
    UA_NodeId newNodeId = UA_NODEID_NULL;
    UA_StatusCode res = UA_Server_addNode_begin(
        server, UA_NODECLASS_OBJECT, UA_NODEID_NULL, UA_NODEID_NULL,
        UA_NODEID_NULL, UA_QUALIFIEDNAME(0, "TemporaryFile"), UA_NS0ID(FILETYPE),
        &attr, &UA_TYPES[UA_TYPES_OBJECTATTRIBUTES], NULL, &newNodeId);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    res = UA_Server_addNode_finish(server, newNodeId);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Server_deleteNode(server, newNodeId, true);
        UA_NodeId_clear(&newNodeId);
        return res;
    }

    FTNode *node = newFTNode(ftd, transfer->mount, newNodeId, path, false);
    if(!node) {
        UA_Server_deleteNode(server, newNodeId, true);
        UA_NodeId_clear(&newNodeId);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    node->temporary = true;
    node->forWrite = forWrite;
    node->transfer = transfer;
    node->lastActivity = UA_DateTime_now();
    res = UA_NodeId_copy(sessionId, &node->creatorSession);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Server_deleteNode(server, newNodeId, true);
        removeFTNode(ftd, node);
        UA_NodeId_clear(&newNodeId);
        return res;
    }

    UA_FileTransferFileInfo info;
    UA_FileTransferBackend *b = &transfer->mount->backend;
    res = b->getAttributes(b, path, &info);
    if(res == UA_STATUSCODE_GOOD)
        res = setupFileNode(server, ftd, node, &info);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Server_deleteNode(server, newNodeId, true);
        removeFTNode(ftd, node);
        UA_NodeId_clear(&newNodeId);
        return res;
    }

    UA_NodeId_clear(&newNodeId);
    *outNode = node;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
generateFileForReadCallback(UA_Server *server, const UA_NodeId *sessionId,
                            void *sessionContext, const UA_NodeId *methodId,
                            void *methodContext, const UA_NodeId *objectId,
                            void *objectContext, size_t inputSize,
                            const UA_Variant *input, size_t outputSize,
                            UA_Variant *output) {
    FileTransferDriver *ftd = findFileTransferDriver(server);
    if(!ftd)
        return UA_STATUSCODE_BADNOTSUPPORTED;
    FTTempTransfer *transfer = findTempTransfer(ftd, objectId);
    if(!transfer)
        return UA_STATUSCODE_BADNOTSUPPORTED;
    if(!transfer->generateForRead)
        return UA_STATUSCODE_BADNOTREADABLE;

    /* At most one write transfer, and no read while a write is in progress */
    if(transfer->activeWrites > 0)
        return UA_STATUSCODE_BADNOTREADABLE;
    if(transfer->activeReads > 0 && !transfer->allowParallelReads)
        return UA_STATUSCODE_BADNOTREADABLE;

    const UA_Variant *generateOptions = (inputSize >= 1) ? &input[0] : NULL;

    /* Let the application produce the content */
    UA_ByteString content = UA_BYTESTRING_NULL;
    UA_StatusCode res = transfer->generateForRead(server, sessionId,
                                                  generateOptions,
                                                  transfer->transferContext,
                                                  &content);
    if(res != UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(&content);
        return res;
    }

    /* Stage the content in a unique temp file */
    char pathBuf[16];
    UA_String path = tempPathName(pathBuf, 'r', transfer->nextTempId++);
    UA_FileTransferBackend *b = &transfer->mount->backend;
    res = writeWholeBackendFile(b, path, content);
    UA_ByteString_clear(&content);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    FTNode *node = NULL;
    res = createTempFileNode(server, ftd, transfer, sessionId, false, path, &node);
    if(res != UA_STATUSCODE_GOOD) {
        b->remove(b, path);
        return res;
    }

    /* Count the read transaction before opening the handle: on any failure
     * below cleanupTempNode decrements the counter, so it must already be
     * incremented for the accounting to balance. */
    transfer->activeReads++;

    UA_UInt32 handle = 0;
    res = openFileHandle(server, ftd, node, sessionId, UA_OPENFILEMODE_READ,
                         &handle);
    if(res != UA_STATUSCODE_GOOD) {
        cleanupTempNode(server, ftd, node);
        return res;
    }

    /* Outputs: fileNodeId, fileHandle, completionStateMachine (always null) */
    UA_NodeId nullId = UA_NODEID_NULL;
    res = UA_Variant_setScalarCopy(&output[0], &node->nodeId,
                                   &UA_TYPES[UA_TYPES_NODEID]);
    res |= UA_Variant_setScalarCopy(&output[1], &handle,
                                    &UA_TYPES[UA_TYPES_UINT32]);
    res |= UA_Variant_setScalarCopy(&output[2], &nullId,
                                    &UA_TYPES[UA_TYPES_NODEID]);
    return res;
}

UA_StatusCode
generateFileForWriteCallback(UA_Server *server, const UA_NodeId *sessionId,
                             void *sessionContext, const UA_NodeId *methodId,
                             void *methodContext, const UA_NodeId *objectId,
                             void *objectContext, size_t inputSize,
                             const UA_Variant *input, size_t outputSize,
                             UA_Variant *output) {
    FileTransferDriver *ftd = findFileTransferDriver(server);
    if(!ftd)
        return UA_STATUSCODE_BADNOTSUPPORTED;
    FTTempTransfer *transfer = findTempTransfer(ftd, objectId);
    if(!transfer)
        return UA_STATUSCODE_BADNOTSUPPORTED;
    if(!transfer->applyWrite)
        return UA_STATUSCODE_BADNOTWRITABLE;

    /* A write transfer is exclusive (Part 20, 4.4.1) */
    if(transfer->activeWrites > 0 || transfer->activeReads > 0)
        return UA_STATUSCODE_BADNOTWRITABLE;

    /* Create an empty temp file */
    char pathBuf[16];
    UA_String path = tempPathName(pathBuf, 'w', transfer->nextTempId++);
    UA_FileTransferBackend *b = &transfer->mount->backend;
    UA_StatusCode res = b->createFile(b, path);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    FTNode *node = NULL;
    res = createTempFileNode(server, ftd, transfer, sessionId, true, path, &node);
    if(res != UA_STATUSCODE_GOOD) {
        b->remove(b, path);
        return res;
    }

    /* Capture the generateOptions for applyWrite at CloseAndCommit time */
    if(inputSize >= 1)
        UA_Variant_copy(&input[0], &node->generateOptions);

    /* Count the write transaction before opening the handle: cleanupTempNode
     * decrements it on any failure below, so it must already be incremented. */
    transfer->activeWrites++;

    UA_UInt32 handle = 0;
    res = openFileHandle(server, ftd, node, sessionId, UA_OPENFILEMODE_WRITE,
                         &handle);
    if(res != UA_STATUSCODE_GOOD) {
        cleanupTempNode(server, ftd, node);
        return res;
    }

    /* Outputs: fileNodeId, fileHandle (no completionStateMachine) */
    res = UA_Variant_setScalarCopy(&output[0], &node->nodeId,
                                   &UA_TYPES[UA_TYPES_NODEID]);
    res |= UA_Variant_setScalarCopy(&output[1], &handle,
                                    &UA_TYPES[UA_TYPES_UINT32]);
    return res;
}

UA_StatusCode
closeAndCommitCallback(UA_Server *server, const UA_NodeId *sessionId,
                       void *sessionContext, const UA_NodeId *methodId,
                       void *methodContext, const UA_NodeId *objectId,
                       void *objectContext, size_t inputSize,
                       const UA_Variant *input, size_t outputSize,
                       UA_Variant *output) {
    FileTransferDriver *ftd = findFileTransferDriver(server);
    if(!ftd)
        return UA_STATUSCODE_BADNOTSUPPORTED;
    FTTempTransfer *transfer = findTempTransfer(ftd, objectId);
    if(!transfer)
        return UA_STATUSCODE_BADNOTSUPPORTED;

    if(inputSize < 1 || !UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_UINT32]))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_UInt32 handleId = *(UA_UInt32*)input[0].data;
    FTHandle *h = findFTHandle(ftd, sessionId, handleId);
    if(!h || !h->file->temporary || !h->file->forWrite ||
       h->file->transfer != transfer)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    FTNode *node = h->file;
    UA_FileTransferBackend *b = &node->mount->backend;

    /* Flush the write handle without deleting the temp file yet */
    closeFTHandleEx(server, ftd, h, false);

    /* Read the full content and hand it to the application */
    UA_ByteString content = UA_BYTESTRING_NULL;
    UA_StatusCode res = readWholeBackendFile(b, node->path, &content);
    if(res == UA_STATUSCODE_GOOD) {
        res = transfer->applyWrite(server, sessionId, &node->generateOptions,
                                   transfer->transferContext, content);
    }
    UA_ByteString_clear(&content);

    /* Delete the temp file and node regardless of the apply result */
    cleanupTempNode(server, ftd, node);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* Output: completionStateMachine (always null) */
    UA_NodeId nullId = UA_NODEID_NULL;
    return UA_Variant_setScalarCopy(&output[0], &nullId,
                                    &UA_TYPES[UA_TYPES_NODEID]);
}

/* ClientProcessingTimeout sweep: cancel transactions idle beyond the timeout */
void
temporaryTimeoutSweep(UA_Server *server, void *data) {
    FileTransferDriver *ftd = (FileTransferDriver*)data;
    if(ftd->driver.drv.state != UA_LIFECYCLESTATE_STARTED)
        return;
    UA_DateTime now = UA_DateTime_now();

    FTNode *node, *tmp;
    LIST_FOREACH_SAFE(node, &ftd->nodes, listEntry, tmp) {
        if(!node->temporary || !node->transfer)
            continue;
        UA_Double idleMs =
            (UA_Double)(now - node->lastActivity) / (UA_Double)UA_DATETIME_MSEC;
        if(idleMs < node->transfer->timeoutMs)
            continue;
        /* Close any handles on the timed-out temp file, then delete it */
        FTHandle *h, *htmp;
        LIST_FOREACH_SAFE(h, &ftd->handles, listEntry, htmp) {
            if(h->file == node)
                closeFTHandleEx(server, ftd, h, false);
        }
        UA_LOG_WARNING(ftd->logging, UA_LOGCATEGORY_SERVER,
                       "FileTransfer: Temporary transfer timed out after %.0f ms",
                       node->transfer->timeoutMs);
        cleanupTempNode(server, ftd, node);
    }
}

static UA_StatusCode
addTemporaryFileTransfer(UA_FileTransferDriver *driver,
                         const UA_NodeId requestedNodeId,
                         const UA_NodeId parentNodeId,
                         const UA_QualifiedName browseName,
                         const UA_FileTransferTemporaryOptions *options,
                         UA_NodeId *outNodeId) {
    FileTransferDriver *ftd = (FileTransferDriver*)driver;
    UA_Driver *drv = &driver->drv;
    if(drv->state != UA_LIFECYCLESTATE_STARTED || !drv->server)
        return UA_STATUSCODE_BADINVALIDSTATE;
    if(!options || (!options->generateForRead && !options->applyWrite))
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* The temp store: app-provided backend or the internal in-memory store */
    UA_FileTransferBackend backend;
    if(options->hasBackend) {
        if(!backendComplete(&options->backend)) {
            if(options->backend.clear)
                backend = options->backend, backend.clear(&backend);
            return UA_STATUSCODE_BADINVALIDARGUMENT;
        }
        backend = options->backend;
    } else {
        UA_StatusCode memRes = UA_FileTransferBackend_inMemory(&backend);
        if(memRes != UA_STATUSCODE_GOOD)
            return memRes;
    }

    FTMount *mount = newMount(ftd, backend, NULL, false);
    if(!mount) {
        if(backend.clear)
            backend.clear(&backend);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    mount->temp = true;

    /* Create the browsable TemporaryFileTransferType Object */
    UA_ObjectAttributes attr = UA_ObjectAttributes_default;
    attr.displayName.text = browseName.name;
    UA_NodeId objId = UA_NODEID_NULL;
    UA_StatusCode res = UA_Server_addObjectNode(
        drv->server, requestedNodeId, parentNodeId, UA_NS0ID(HASCOMPONENT),
        browseName, UA_NS0ID(TEMPORARYFILETRANSFERTYPE), attr, NULL, &objId);
    if(res != UA_STATUSCODE_GOOD) {
        removeMount(ftd, mount);
        return res;
    }

    FTTempTransfer *transfer =
        (FTTempTransfer*)UA_calloc(1, sizeof(FTTempTransfer));
    if(!transfer) {
        UA_Server_deleteNode(drv->server, objId, true);
        removeMount(ftd, mount);
        UA_NodeId_clear(&objId);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    res = UA_NodeId_copy(&objId, &transfer->objectNodeId);
    if(res != UA_STATUSCODE_GOOD) {
        UA_free(transfer);
        UA_Server_deleteNode(drv->server, objId, true);
        removeMount(ftd, mount);
        UA_NodeId_clear(&objId);
        return res;
    }
    transfer->mount = mount;
    transfer->generateForRead = options->generateForRead;
    transfer->applyWrite = options->applyWrite;
    transfer->transferContext = options->transferContext;
    transfer->timeoutMs = (options->clientProcessingTimeoutMs > 0.0) ?
        options->clientProcessingTimeoutMs : ftd->defaultTimeoutMs;
    transfer->allowParallelReads = !options->disallowParallelReads;
    LIST_INSERT_HEAD(&ftd->tempTransfers, transfer, listEntry);

    /* Write the ClientProcessingTimeout Property */
    UA_NodeId timeoutId = UA_NODEID_NULL;
    if(getChildId(drv->server, objId, "ClientProcessingTimeout",
                  &timeoutId) == UA_STATUSCODE_GOOD) {
        UA_Duration timeout = transfer->timeoutMs;
        UA_Variant v;
        UA_Variant_setScalar(&v, &timeout, &UA_TYPES[UA_TYPES_DURATION]);
        UA_Server_writeValue(drv->server, timeoutId, v);
        UA_NodeId_clear(&timeoutId);
    }

    if(outNodeId)
        *outNodeId = objId;
    else
        UA_NodeId_clear(&objId);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
removeTemporaryFileTransfer(UA_FileTransferDriver *driver,
                            const UA_NodeId nodeId) {
    FileTransferDriver *ftd = (FileTransferDriver*)driver;
    UA_Driver *drv = &driver->drv;
    if(drv->state != UA_LIFECYCLESTATE_STARTED || !drv->server)
        return UA_STATUSCODE_BADINVALIDSTATE;

    FTTempTransfer *transfer = findTempTransfer(ftd, &nodeId);
    if(!transfer)
        return UA_STATUSCODE_BADNOTFOUND;

    /* Abort all in-flight transactions of this object */
    FTHandle *h, *htmp;
    LIST_FOREACH_SAFE(h, &ftd->handles, listEntry, htmp) {
        if(h->file->mount == transfer->mount)
            closeFTHandleEx(drv->server, ftd, h, false);
    }
    FTNode *node, *ntmp;
    LIST_FOREACH_SAFE(node, &ftd->nodes, listEntry, ntmp) {
        if(node->mount == transfer->mount)
            cleanupTempNode(drv->server, ftd, node);
    }

    UA_Server_deleteNode(drv->server, transfer->objectNodeId, true);
    UA_NodeId_clear(&transfer->objectNodeId);
    LIST_REMOVE(transfer, listEntry);
    removeMount(ftd, transfer->mount);
    UA_free(transfer);
    return UA_STATUSCODE_GOOD;
}

/* Expose the add/remove operations so the driver core can wire them up */
UA_StatusCode
fileTransferAddTemporary(UA_FileTransferDriver *driver,
                         const UA_NodeId requestedNodeId,
                         const UA_NodeId parentNodeId,
                         const UA_QualifiedName browseName,
                         const UA_FileTransferTemporaryOptions *options,
                         UA_NodeId *outNodeId) {
    return addTemporaryFileTransfer(driver, requestedNodeId, parentNodeId,
                                    browseName, options, outNodeId);
}

UA_StatusCode
fileTransferRemoveTemporary(UA_FileTransferDriver *driver,
                            const UA_NodeId nodeId) {
    return removeTemporaryFileTransfer(driver, nodeId);
}

#endif /* UA_ENABLE_METHODCALLS && UA_GENERATED_NAMESPACE_ZERO_FULL */
