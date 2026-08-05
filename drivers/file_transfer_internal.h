/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#ifndef UA_DRIVER_FILE_TRANSFER_INTERNAL_H_
#define UA_DRIVER_FILE_TRANSFER_INTERNAL_H_

#include <open62541/driver/file_transfer.h>

#include "open62541_queue.h"

#if defined(UA_ENABLE_METHODCALLS) && defined(UA_GENERATED_NAMESPACE_ZERO_FULL)

_UA_BEGIN_DECLS

#define UA_DRIVER_FILE_TRANSFER_NAME "file-transfer"

#define UA_FILETRANSFER_MAXHANDLESPERSESSION_DEFAULT 64
#define UA_FILETRANSFER_MAXHANDLESPERFILE_DEFAULT 16
#define UA_FILETRANSFER_MAXREADLENGTH_DEFAULT (1 << 20) /* 1 MByte */
#define UA_FILETRANSFER_TIMEOUT_DEFAULT_MS 60000.0
#define UA_FILETRANSFER_TIMEOUT_SWEEP_MS 1000.0

#define UA_FILETRANSFER_OPENMODE_ALLBITS                        \
    (UA_OPENFILEMODE_READ | UA_OPENFILEMODE_WRITE |             \
     UA_OPENFILEMODE_ERASEEXISTING | UA_OPENFILEMODE_APPEND)

#define UA_FILETRANSFER_COPYCHUNKSIZE 65536

typedef struct FTMount FTMount;
typedef struct FTNode FTNode;
typedef struct FTTempTransfer FTTempTransfer;

/* One entry per fileHandle returned by the Open Method. Handles are bound to
 * the Session that created them. */
typedef struct FTHandle {
    LIST_ENTRY(FTHandle) listEntry;
    UA_UInt32 handle; /* Globally unique, never 0 */
    UA_NodeId sessionId;
    FTNode *file;
    UA_Byte mode;
    void *backendFileContext;
} FTHandle;

/* One entry per driver-managed FileType/FileDirectoryType Object. The
 * registry is driver-owned so that the node context of the Objects remains
 * available to the application. */
struct FTNode {
    LIST_ENTRY(FTNode) listEntry;
    UA_NodeId nodeId;
    FTMount *mount;
    UA_String path; /* Relative to the mount root */
    UA_Boolean isDirectory;
    UA_Boolean zombie; /* Backend entry vanished; the node is removed when
                        * the last open handle is closed */
    UA_UInt16 openCount;
    UA_Boolean openForWrite;
    UA_NodeId openCountId; /* The OpenCount Property of a file node */

    /* Temporary file transfer transaction fields (only when temporary) */
    UA_Boolean temporary;      /* Transient temp-transfer file */
    UA_Boolean forWrite;       /* Write transaction (vs read) */
    FTTempTransfer *transfer;  /* Owning temporary-transfer object */
    UA_NodeId creatorSession;  /* Session that generated the temp file; only
                                * this Session may Open it */
    UA_Variant generateOptions;/* Captured for applyWrite (write only) */
    UA_DateTime lastActivity;  /* For the ClientProcessingTimeout sweep */
};

struct FTMount {
    LIST_ENTRY(FTMount) listEntry;
    UA_NodeId rootNodeId;
    UA_FileTransferBackend backend;
    UA_FileTransferMountOptions options;
    UA_Boolean standaloneFile; /* Created via addFile (no directory tree) */
    UA_Boolean temp;           /* Temp store of a temporary-transfer object */
};

/* One per addTemporaryFileTransfer object */
struct FTTempTransfer {
    LIST_ENTRY(FTTempTransfer) listEntry;
    UA_NodeId objectNodeId;
    FTMount *mount;            /* Temp-store mount (in-memory or app backend) */
    UA_FileTransferGenerateReadCallback generateForRead;
    UA_FileTransferApplyWriteCallback applyWrite;
    void *transferContext;
    UA_Double timeoutMs;
    UA_Boolean allowParallelReads;
    UA_UInt32 nextTempId;      /* For unique temp paths */
    size_t activeReads;
    size_t activeWrites;
};

typedef struct FileTransferDriver {
    UA_FileTransferDriver driver;
    UA_Logger *logging;
    LIST_HEAD(, FTMount) mounts;
    LIST_HEAD(, FTNode) nodes;
    LIST_HEAD(, FTHandle) handles;
    LIST_HEAD(, FTTempTransfer) tempTransfers;
    UA_UInt32 nextHandle;
    UA_UInt16 maxHandlesPerSession;
    UA_UInt16 maxHandlesPerFile;
    UA_UInt32 maxReadLength;
    UA_Double defaultTimeoutMs;
    UA_UInt64 timeoutCallbackId; /* Repeated callback for the timeout sweep */
} FileTransferDriver;

/* driver.c -- top-level helpers and lifecycle */
FileTransferDriver *findFileTransferDriver(UA_Server *server);
UA_Boolean backendComplete(const UA_FileTransferBackend *b);
UA_StatusCode registerFileTransferMethodCallbacks(UA_Server *server);

/* driver.c -- registry and handle primitives, used across all sub-files */
FTNode *findFTNode(FileTransferDriver *ftd, const UA_NodeId *nodeId);
FTHandle *findFTHandle(FileTransferDriver *ftd, const UA_NodeId *sessionId,
                       UA_UInt32 handle);
size_t countSessionHandles(FileTransferDriver *ftd,
                           const UA_NodeId *sessionId);
UA_UInt32 newHandleId(FileTransferDriver *ftd);
void updateOpenCount(UA_Server *server, FTNode *node);
void removeFTNode(FileTransferDriver *ftd, FTNode *node);
FTNode *newFTNode(FileTransferDriver *ftd, FTMount *mount,
                  const UA_NodeId nodeId, const UA_String path,
                  UA_Boolean isDirectory);
FTMount *newMount(FileTransferDriver *ftd, UA_FileTransferBackend backend,
                  const UA_FileTransferMountOptions *options,
                  UA_Boolean standaloneFile);
void removeMount(FileTransferDriver *ftd, FTMount *mount);
void removeMountNodes(FileTransferDriver *ftd, FTMount *mount);
void closeMountHandles(UA_Server *server, FileTransferDriver *ftd,
                       FTMount *mount);
UA_StatusCode closeFTHandle(UA_Server *server, FileTransferDriver *ftd,
                            FTHandle *h);
UA_StatusCode closeFTHandleEx(UA_Server *server, FileTransferDriver *ftd,
                              FTHandle *h, UA_Boolean cleanupTemp);
void cleanupTempNode(UA_Server *server, FileTransferDriver *ftd,
                     FTNode *node);

/* filetype.c -- property/source helpers and shared file-open helper */
UA_StatusCode getChildId(UA_Server *server, const UA_NodeId parent,
                         const char *name, UA_NodeId *out);
UA_Boolean userCanWrite(UA_Server *server, FTNode *node,
                        const UA_NodeId *sessionId);
UA_StatusCode setupFileNode(UA_Server *server, FileTransferDriver *ftd,
                            FTNode *node,
                            const UA_FileTransferFileInfo *info);
UA_StatusCode openFileHandle(UA_Server *server, FileTransferDriver *ftd,
                             FTNode *node, const UA_NodeId *sessionId,
                             UA_Byte mode, UA_UInt32 *outHandle);

/* FileType Method Callbacks (registered in driver.c) */
UA_StatusCode openMethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                                 void *sessionContext,
                                 const UA_NodeId *methodId,
                                 void *methodContext,
                                 const UA_NodeId *objectId,
                                 void *objectContext, size_t inputSize,
                                 const UA_Variant *input, size_t outputSize,
                                 UA_Variant *output);
UA_StatusCode closeMethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                                  void *sessionContext,
                                  const UA_NodeId *methodId,
                                  void *methodContext,
                                  const UA_NodeId *objectId,
                                  void *objectContext, size_t inputSize,
                                  const UA_Variant *input, size_t outputSize,
                                  UA_Variant *output);
UA_StatusCode readMethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                                 void *sessionContext,
                                 const UA_NodeId *methodId,
                                 void *methodContext,
                                 const UA_NodeId *objectId,
                                 void *objectContext, size_t inputSize,
                                 const UA_Variant *input, size_t outputSize,
                                 UA_Variant *output);
UA_StatusCode writeMethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                                  void *sessionContext,
                                  const UA_NodeId *methodId,
                                  void *methodContext,
                                  const UA_NodeId *objectId,
                                  void *objectContext, size_t inputSize,
                                  const UA_Variant *input, size_t outputSize,
                                  UA_Variant *output);
UA_StatusCode getPositionMethodCallback(UA_Server *server,
                                        const UA_NodeId *sessionId,
                                        void *sessionContext,
                                        const UA_NodeId *methodId,
                                        void *methodContext,
                                        const UA_NodeId *objectId,
                                        void *objectContext, size_t inputSize,
                                        const UA_Variant *input, size_t outputSize,
                                        UA_Variant *output);
UA_StatusCode setPositionMethodCallback(UA_Server *server,
                                        const UA_NodeId *sessionId,
                                        void *sessionContext,
                                        const UA_NodeId *methodId,
                                        void *methodContext,
                                        const UA_NodeId *objectId,
                                        void *objectContext, size_t inputSize,
                                        const UA_Variant *input, size_t outputSize,
                                        UA_Variant *output);

/* FileDirectoryType Method Callbacks (registered in driver.c) */
UA_StatusCode createDirectoryMethodCallback(UA_Server *server,
                                            const UA_NodeId *sessionId,
                                            void *sessionContext,
                                            const UA_NodeId *methodId,
                                            void *methodContext,
                                            const UA_NodeId *objectId,
                                            void *objectContext, size_t inputSize,
                                            const UA_Variant *input,
                                            size_t outputSize,
                                            UA_Variant *output);
UA_StatusCode createFileMethodCallback(UA_Server *server,
                                      const UA_NodeId *sessionId,
                                      void *sessionContext,
                                      const UA_NodeId *methodId,
                                      void *methodContext,
                                      const UA_NodeId *objectId,
                                      void *objectContext, size_t inputSize,
                                      const UA_Variant *input, size_t outputSize,
                                      UA_Variant *output);
UA_StatusCode deleteMethodCallback(UA_Server *server,
                                   const UA_NodeId *sessionId,
                                   void *sessionContext,
                                   const UA_NodeId *methodId,
                                   void *methodContext,
                                   const UA_NodeId *objectId,
                                   void *objectContext, size_t inputSize,
                                   const UA_Variant *input, size_t outputSize,
                                   UA_Variant *output);
UA_StatusCode moveOrCopyMethodCallback(UA_Server *server,
                                       const UA_NodeId *sessionId,
                                       void *sessionContext,
                                       const UA_NodeId *methodId,
                                       void *methodContext,
                                       const UA_NodeId *objectId,
                                       void *objectContext, size_t inputSize,
                                       const UA_Variant *input, size_t outputSize,
                                       UA_Variant *output);

/* directory.c -- tree mirroring entry points (used by driver.c addFileSystem /
 * addFile / refresh); countMountNodes is used by directory.c internally and
 * by driver.c refresh */
UA_StatusCode fileTransferMirrorTree(UA_Server *server,
                                     FileTransferDriver *ftd,
                                     FTNode *dirNode, UA_UInt32 depth,
                                     UA_UInt32 *nodeBudget);
UA_StatusCode fileTransferSyncTree(UA_Server *server,
                                   FileTransferDriver *ftd,
                                   FTNode *dirNode, UA_UInt32 depth,
                                   UA_UInt32 *nodeBudget);
UA_UInt32 countMountNodes(FileTransferDriver *ftd, FTMount *mount);
UA_UInt32 pathDepth(const UA_String path);
/* Reject a single path segment ('.', '..', separators, NUL, empty). Shared
 * with the localfs backend so the traversal-safety policy lives in one place. */
UA_Boolean validEntryName(const UA_String name);

/* backend_memory.c (used by temporary.c) */
UA_StatusCode inMemoryBackend(UA_FileTransferBackend *out);

/* temporary.c -- method callbacks (registered in driver.c) and sweep */
void temporaryTimeoutSweep(UA_Server *server, void *data);
UA_StatusCode fileTransferAddTemporary(UA_FileTransferDriver *driver,
                                       const UA_NodeId requestedNodeId,
                                       const UA_NodeId parentNodeId,
                                       const UA_QualifiedName browseName,
                                       const UA_FileTransferTemporaryOptions *options,
                                       UA_NodeId *outNodeId);
UA_StatusCode fileTransferRemoveTemporary(UA_FileTransferDriver *driver,
                                          const UA_NodeId nodeId);
UA_StatusCode generateFileForReadCallback(UA_Server *server,
                                          const UA_NodeId *sessionId,
                                          void *sessionContext,
                                          const UA_NodeId *methodId,
                                          void *methodContext,
                                          const UA_NodeId *objectId,
                                          void *objectContext,
                                          size_t inputSize,
                                          const UA_Variant *input,
                                          size_t outputSize,
                                          UA_Variant *output);
UA_StatusCode generateFileForWriteCallback(UA_Server *server,
                                           const UA_NodeId *sessionId,
                                           void *sessionContext,
                                           const UA_NodeId *methodId,
                                           void *methodContext,
                                           const UA_NodeId *objectId,
                                           void *objectContext,
                                           size_t inputSize,
                                           const UA_Variant *input,
                                           size_t outputSize,
                                           UA_Variant *output);
UA_StatusCode closeAndCommitCallback(UA_Server *server,
                                     const UA_NodeId *sessionId,
                                     void *sessionContext,
                                     const UA_NodeId *methodId,
                                     void *methodContext,
                                     const UA_NodeId *objectId,
                                     void *objectContext,
                                     size_t inputSize,
                                     const UA_Variant *input,
                                     size_t outputSize,
                                     UA_Variant *output);

_UA_END_DECLS

#endif /* UA_ENABLE_METHODCALLS && UA_GENERATED_NAMESPACE_ZERO_FULL */

#endif /* UA_DRIVER_FILE_TRANSFER_INTERNAL_H_ */