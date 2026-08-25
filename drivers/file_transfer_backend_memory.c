/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#include "file_transfer_internal.h"

#if defined(UA_ENABLE_METHODCALLS) && defined(UA_GENERATED_NAMESPACE_ZERO_FULL)

/**************************************
 * Internal In-Memory Backend
 *
 * A flat in-memory store used as the default temp store for temporary file
 * transfers. It holds a small set of files (no directories) keyed by path.
 **************************************/

#define UA_FT_MEM_MAXFILES 32

typedef struct {
    UA_Boolean used;
    UA_String name;
    UA_ByteString content;
    UA_DateTime mtime;
} MemBackendFile;

typedef struct {
    MemBackendFile files[UA_FT_MEM_MAXFILES];
} MemBackendContext;

typedef struct {
    MemBackendFile *file;
    size_t pos;
} MemBackendOpenFile;

static MemBackendFile *
memBackendFind(MemBackendContext *ctx, const UA_String path) {
    for(size_t i = 0; i < UA_FT_MEM_MAXFILES; i++) {
        if(ctx->files[i].used && UA_String_equal(&ctx->files[i].name, &path))
            return &ctx->files[i];
    }
    return NULL;
}

static UA_StatusCode
memBackendOpen(UA_FileTransferBackend *b, const UA_String path, UA_Byte mode,
               void **fileContext) {
    MemBackendFile *file = memBackendFind((MemBackendContext*)b->context, path);
    if(!file)
        return UA_STATUSCODE_BADNOTFOUND;
    if(mode & UA_OPENFILEMODE_ERASEEXISTING) {
        UA_ByteString_clear(&file->content);
        file->mtime = UA_DateTime_now();
    }
    MemBackendOpenFile *of =
        (MemBackendOpenFile*)UA_calloc(1, sizeof(MemBackendOpenFile));
    if(!of)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    of->file = file;
    of->pos = (mode & UA_OPENFILEMODE_APPEND) ? file->content.length : 0;
    *fileContext = of;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
memBackendClose(UA_FileTransferBackend *b, void *fileContext) {
    UA_free(fileContext);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
memBackendRead(UA_FileTransferBackend *b, void *fileContext, UA_Int32 length,
               UA_ByteString *out) {
    if(length <= 0)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    MemBackendOpenFile *of = (MemBackendOpenFile*)fileContext;
    size_t remaining = (of->pos < of->file->content.length) ?
        of->file->content.length - of->pos : 0;
    size_t toRead = ((size_t)length < remaining) ? (size_t)length : remaining;
    if(toRead == 0) {
        UA_ByteString_init(out);
        return UA_STATUSCODE_GOOD;
    }
    UA_StatusCode res = UA_ByteString_allocBuffer(out, toRead);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    memcpy(out->data, of->file->content.data + of->pos, toRead);
    of->pos += toRead;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
memBackendWrite(UA_FileTransferBackend *b, void *fileContext,
                const UA_ByteString data) {
    if(data.length == 0)
        return UA_STATUSCODE_GOOD;
    MemBackendOpenFile *of = (MemBackendOpenFile*)fileContext;
    MemBackendFile *file = of->file;
    size_t newLength = of->pos + data.length;
    if(newLength > file->content.length) {
        UA_Byte *grown = (UA_Byte*)UA_realloc(file->content.data, newLength);
        if(!grown)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        if(of->pos > file->content.length)
            memset(grown + file->content.length, 0, of->pos - file->content.length);
        file->content.data = grown;
        file->content.length = newLength;
    }
    memcpy(file->content.data + of->pos, data.data, data.length);
    of->pos += data.length;
    file->mtime = UA_DateTime_now();
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
memBackendGetPosition(UA_FileTransferBackend *b, void *fileContext,
                      UA_UInt64 *outPosition) {
    *outPosition = ((MemBackendOpenFile*)fileContext)->pos;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
memBackendSetPosition(UA_FileTransferBackend *b, void *fileContext,
                      UA_UInt64 position) {
    MemBackendOpenFile *of = (MemBackendOpenFile*)fileContext;
    of->pos = (position < of->file->content.length) ?
        (size_t)position : of->file->content.length;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
memBackendGetAttributes(UA_FileTransferBackend *b, const UA_String path,
                        UA_FileTransferFileInfo *outInfo) {
    memset(outInfo, 0, sizeof(UA_FileTransferFileInfo));
    if(path.length == 0) { /* The mount root */
        outInfo->isDirectory = true;
        outInfo->writable = true;
        return UA_STATUSCODE_GOOD;
    }
    MemBackendFile *file = memBackendFind((MemBackendContext*)b->context, path);
    if(!file)
        return UA_STATUSCODE_BADNOTFOUND;
    outInfo->size = file->content.length;
    outInfo->lastModified = file->mtime;
    outInfo->writable = true;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
memBackendListDirectory(UA_FileTransferBackend *b, const UA_String path,
                        UA_FileTransferListCallback cb, void *listContext) {
    if(path.length > 0)
        return UA_STATUSCODE_BADNOTFOUND; /* Flat hierarchy */
    MemBackendContext *ctx = (MemBackendContext*)b->context;
    for(size_t i = 0; i < UA_FT_MEM_MAXFILES; i++) {
        if(ctx->files[i].used)
            cb(listContext, ctx->files[i].name, false);
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
memBackendCreateFile(UA_FileTransferBackend *b, const UA_String path) {
    MemBackendContext *ctx = (MemBackendContext*)b->context;
    if(memBackendFind(ctx, path))
        return UA_STATUSCODE_BADBROWSENAMEDUPLICATED;
    for(size_t i = 0; i < UA_FT_MEM_MAXFILES; i++) {
        MemBackendFile *file = &ctx->files[i];
        if(file->used)
            continue;
        if(UA_String_copy(&path, &file->name) != UA_STATUSCODE_GOOD)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        file->used = true;
        file->content = UA_BYTESTRING_NULL;
        file->mtime = UA_DateTime_now();
        return UA_STATUSCODE_GOOD;
    }
    return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
}

static UA_StatusCode
memBackendCreateDirectory(UA_FileTransferBackend *b, const UA_String path) {
    (void)b; (void)path;
    return UA_STATUSCODE_BADNOTSUPPORTED; /* Flat hierarchy */
}

static UA_StatusCode
memBackendRemove(UA_FileTransferBackend *b, const UA_String path) {
    MemBackendFile *file = memBackendFind((MemBackendContext*)b->context, path);
    if(!file)
        return UA_STATUSCODE_BADNOTFOUND;
    UA_String_clear(&file->name);
    UA_ByteString_clear(&file->content);
    file->used = false;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
memBackendRename(UA_FileTransferBackend *b, const UA_String fromPath,
                 const UA_String toPath) {
    MemBackendContext *ctx = (MemBackendContext*)b->context;
    MemBackendFile *file = memBackendFind(ctx, fromPath);
    if(!file)
        return UA_STATUSCODE_BADNOTFOUND;
    if(memBackendFind(ctx, toPath))
        return UA_STATUSCODE_BADBROWSENAMEDUPLICATED;
    UA_String newName = UA_STRING_NULL;
    if(UA_String_copy(&toPath, &newName) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_String_clear(&file->name);
    file->name = newName;
    return UA_STATUSCODE_GOOD;
}

static void
memBackendClear(UA_FileTransferBackend *b) {
    MemBackendContext *ctx = (MemBackendContext*)b->context;
    if(!ctx)
        return;
    for(size_t i = 0; i < UA_FT_MEM_MAXFILES; i++) {
        UA_String_clear(&ctx->files[i].name);
        UA_ByteString_clear(&ctx->files[i].content);
    }
    UA_free(ctx);
    b->context = NULL;
}

UA_StatusCode
UA_FileTransferBackend_inMemory(UA_FileTransferBackend *out) {
    MemBackendContext *ctx =
        (MemBackendContext*)UA_calloc(1, sizeof(MemBackendContext));
    if(!ctx)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    memset(out, 0, sizeof(UA_FileTransferBackend));
    out->context = ctx;
    out->openFile = memBackendOpen;
    out->closeFile = memBackendClose;
    out->read = memBackendRead;
    out->write = memBackendWrite;
    out->getPosition = memBackendGetPosition;
    out->setPosition = memBackendSetPosition;
    out->getAttributes = memBackendGetAttributes;
    out->listDirectory = memBackendListDirectory;
    out->createFile = memBackendCreateFile;
    out->createDirectory = memBackendCreateDirectory;
    out->remove = memBackendRemove;
    out->rename = memBackendRename;
    out->copy = NULL;
    out->clear = memBackendClear;
    return UA_STATUSCODE_GOOD;
}

#endif /* UA_ENABLE_METHODCALLS && UA_GENERATED_NAMESPACE_ZERO_FULL */
