/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2024 (c) Fraunhofer IOSB (Author: Noel Graf)
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Julius Pfrommer)
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#include <open62541/plugin/certificategroup_default.h>
#include "gds_push_internal.h"

#ifdef UA_ENABLE_DRIVER_GDS_PUSH

#include "open62541_queue.h"

#define UA_SHA1_LENGTH 20
#define CHECKACTIVESESSIONINTERVAL 10000 /* 10sec */
#define STATIC_NS0ID(ID) {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_##ID}}

typedef enum {
    UA_GDSTRANSACTIONSTATE_FRESH,
    UA_GDSTRANSACTIONSTATE_PENDING,
} UA_GDSTransactionState;

typedef struct {
    UA_ByteString certificate;
    UA_ByteString privateKey;
    UA_NodeId certificateGroup;
    UA_NodeId certificateType;
} UA_GDSCertificateInfo;

typedef struct {
    UA_Server *server;
    UA_NodeId sessionId;
    UA_GDSTransactionState state;
    size_t certGroupSize;
    UA_CertificateGroup *certGroups;
    size_t certificateInfosSize;
    UA_GDSCertificateInfo *certificateInfos;
    UA_DelayedCallback dc;
    UA_Boolean applyChangesQueued;
} UA_GDSTransaction;

typedef struct UA_FileContext {
    LIST_ENTRY(UA_FileContext) listEntry;
    UA_ByteString file;
    UA_ByteString dataToWrite;
    UA_UInt32 fileHandle;
    UA_NodeId sessionId;
    UA_UInt64 currentPos;
    UA_Byte openFileMode;
} UA_FileContext;

typedef struct UA_FileInfo {
    struct UA_FileInfo *next;
    UA_NodeId certificateGroupId;
    UA_UInt16 openCount;
    UA_UtcTime lastUpdateTime;
    LIST_HEAD(, UA_FileContext) fileContext;
} UA_FileInfo;

struct UA_GDSPushContext {
    UA_Driver drv;
    UA_Boolean initialized;
    UA_GDSTransaction transaction;
    UA_FileInfo *fileInfos;
    UA_UInt64 checkSessionCallbackId;
    /* The certificate slots and SecureChannels of the server. Shared with the
     * GDS Pull driver. The slots are updated when the driver starts. */
    UA_GDSCore core;
};

typedef enum UA_GDSTransactionChanges {
    UA_GDSTRANSACTIONCHANGES_NOTHING = 0,
    UA_GDSTRANSACTIONCHANGES_TRUSTLIST,
    UA_GDSTRANSACTIONCHANGES_CERTIFICATE,
    UA_GDSTRANSACTIONCHANGES_BOTH,
} UA_GDSTransactionChanges;

UA_GDSCertificateSlot *
UA_GDSPush_serverSlots(UA_GDSPushContext *ctx, size_t *slotsSize) {
    *slotsSize = ctx->core.slotsSize;
    return ctx->core.slots;
}

UA_GDSCore *
UA_GDSPush_getCore(UA_Driver *drv) {
    UA_assert(drv->driverType == UA_DRIVERTYPE_GDS_PUSH);
    return &((UA_GDSPushContext*)drv)->core;
}

static UA_StatusCode
UA_GDSPush_applyChanges(UA_GDSPushContext *ctx);

static UA_FileContext*
getFileContext(UA_FileInfo *fileInfo, const UA_NodeId *sessionId,
               const UA_UInt32 fileHandle) {
    if(!fileInfo || !sessionId)
        return NULL;

    UA_FileContext *fileContext = NULL;
    LIST_FOREACH(fileContext, &fileInfo->fileContext, listEntry) {
        if(fileContext->fileHandle == fileHandle &&
           UA_NodeId_equal(&fileContext->sessionId, sessionId)){
            return fileContext;
        }
    }
    return NULL;
}

/********************/
/* GDS Transaction  */
/********************/

static UA_StatusCode
UA_GDSTransaction_init(UA_GDSTransaction *transaction, UA_Server *server,
                       const UA_NodeId sessionId) {
    if(!transaction || !server)
        return UA_STATUSCODE_BADINTERNALERROR;

    memset(transaction, 0, sizeof(UA_GDSTransaction));

    UA_StatusCode res = UA_NodeId_copy(&sessionId, &transaction->sessionId);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    transaction->state = UA_GDSTRANSACTIONSTATE_PENDING;
    transaction->server = server;
    transaction->applyChangesQueued = false;

    return UA_STATUSCODE_GOOD;
}

/* Copy a CertificateGroup into a Memorystore, optionally with an additional
 * trusted Certificate. With issuersTrusted, the issuer Certificates and CRLs
 * are also trusted in the copy. The copy has no size limit. The size of a
 * resulting TrustList is checked against the MaxTrustListSize by the caller. */
static UA_StatusCode
copyCertificateGroup(const UA_CertificateGroup *src,
                     const UA_ByteString *extraTrusted,
                     UA_Boolean issuersTrusted,
                     UA_CertificateGroup *dst) {
    if(!src->getTrustList)
        return UA_STATUSCODE_BADNOTSUPPORTED;

    UA_TrustListDataType trustList;
    UA_TrustListDataType_init(&trustList);
    trustList.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    UA_StatusCode res =
        src->getTrustList((UA_CertificateGroup*)(uintptr_t)src, &trustList);
    trustList.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    if(res == UA_STATUSCODE_GOOD && issuersTrusted) {
        UA_TrustListDataType issuers;
        UA_TrustListDataType_init(&issuers);
        issuers.specifiedLists =
            UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES | UA_TRUSTLISTMASKS_TRUSTEDCRLS;
        issuers.trustedCertificates = trustList.issuerCertificates;
        issuers.trustedCertificatesSize = trustList.issuerCertificatesSize;
        issuers.trustedCrls = trustList.issuerCrls;
        issuers.trustedCrlsSize = trustList.issuerCrlsSize;
        res = UA_TrustListDataType_add(&issuers, &trustList);
    }
    if(res == UA_STATUSCODE_GOOD && extraTrusted) {
        UA_TrustListDataType extra;
        UA_TrustListDataType_init(&extra);
        extra.specifiedLists = UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES;
        extra.trustedCertificates = (UA_ByteString*)(uintptr_t)extraTrusted;
        extra.trustedCertificatesSize = 1;
        res = UA_TrustListDataType_add(&extra, &trustList);
    }
    if(res == UA_STATUSCODE_GOOD) {
        UA_UInt32 unlimited = 0;
        UA_KeyValuePair param;
        param.key = UA_QUALIFIEDNAME(0, "max-trust-listsize");
        UA_Variant_setScalar(&param.value, &unlimited, &UA_TYPES[UA_TYPES_UINT32]);
        UA_KeyValueMap params = {1, &param};
        memset(dst, 0, sizeof(UA_CertificateGroup));
        res = UA_CertificateGroup_Memorystore(
            dst, (UA_NodeId*)(uintptr_t)&src->certificateGroupId, &trustList,
            src->logging, &params);
    }
    UA_TrustListDataType_clear(&trustList);
    return res;
}

/* The encoded size of the complete TrustList of a group */
static UA_StatusCode
trustListSize(UA_CertificateGroup *group, size_t *size) {
    UA_TrustListDataType trustList;
    UA_TrustListDataType_init(&trustList);
    trustList.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    UA_StatusCode res = group->getTrustList(group, &trustList);
    trustList.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    *size = UA_calcSizeBinary(&trustList, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL);
    UA_TrustListDataType_clear(&trustList);
    return res;
}

/* Returns the CertificateGroup staged in the transaction or NULL */
static UA_CertificateGroup *
UA_GDSTransaction_findCertificateGroup(UA_GDSTransaction *transaction,
                                       const UA_NodeId *certificateGroupId) {
    if(transaction->state != UA_GDSTRANSACTIONSTATE_PENDING)
        return NULL;
    for(size_t i = 0; i < transaction->certGroupSize; i++) {
        if(UA_NodeId_equal(&transaction->certGroups[i].certificateGroupId,
                           certificateGroupId))
            return &transaction->certGroups[i];
    }
    return NULL;
}

/* Move a CertificateGroup into the transaction. It replaces the staged group
 * with the same NodeId. */
static UA_StatusCode
UA_GDSTransaction_stageCertificateGroup(UA_GDSTransaction *transaction,
                                        UA_CertificateGroup *group) {
    UA_CertificateGroup *staged =
        UA_GDSTransaction_findCertificateGroup(transaction, &group->certificateGroupId);
    if(staged) {
        staged->clear(staged);
        *staged = *group;
        return UA_STATUSCODE_GOOD;
    }
    UA_CertificateGroup *newGroups = (UA_CertificateGroup*)
        UA_realloc(transaction->certGroups,
                   (transaction->certGroupSize + 1) * sizeof(UA_CertificateGroup));
    if(!newGroups)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    transaction->certGroups = newGroups;
    transaction->certGroups[transaction->certGroupSize] = *group;
    transaction->certGroupSize++;
    return UA_STATUSCODE_GOOD;
}

/* Returns the appropriate CertificateGroup from the transaction.
 * If the CertificateGroup does not exist in the transaction, it will be created. */
static UA_CertificateGroup*
UA_GDSTransaction_getCertificateGroup(UA_GDSTransaction *transaction,
                                      const UA_CertificateGroup *certGroup) {
    if(!transaction || !certGroup)
        return NULL;

    /* Check if transaction was initialized */
    if(transaction->state != UA_GDSTRANSACTIONSTATE_PENDING)
        return NULL;

    for(size_t i = 0; i < transaction->certGroupSize; i++) {
        UA_CertificateGroup *group = &transaction->certGroups[i];
        if(UA_NodeId_equal(&group->certificateGroupId, &certGroup->certificateGroupId))
            return group;
    }

    /* If the certGroup does not exist, create a new one */
    UA_CertificateGroup *newGroups = (UA_CertificateGroup*)
        UA_realloc(transaction->certGroups,
                   (transaction->certGroupSize + 1) * sizeof(UA_CertificateGroup));
    if(!newGroups)
        return NULL;
    transaction->certGroups = newGroups;

    transaction->certGroupSize++;

    UA_CertificateGroup* newGroup = (UA_CertificateGroup*)
        &transaction->certGroups[transaction->certGroupSize-1];
    if(copyCertificateGroup(certGroup, NULL, false, newGroup) != UA_STATUSCODE_GOOD) {
        transaction->certGroupSize--;
        return NULL;
    }
    return newGroup;
}

static UA_StatusCode
UA_GDSTransaction_addCertificateInfo(UA_GDSTransaction *transaction,
                                     const UA_NodeId certificateGroupId,
                                     const UA_NodeId certificateTypeId,
                                     const UA_ByteString *certificate,
                                     const UA_ByteString *privateKey) {
    if(!transaction || !certificate)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Check if transaction was initialized */
    if(transaction->state != UA_GDSTRANSACTIONSTATE_PENDING)
        return UA_STATUSCODE_BADINVALIDSTATE;

    /* Check if an entry with certificateGroupId and certificateTypeId already exists */
    for(size_t i = 0; i < transaction->certificateInfosSize; i++) {
        UA_GDSCertificateInfo *certInfo = &transaction->certificateInfos[i];
        if(!UA_NodeId_equal(&certInfo->certificateGroup, &certificateGroupId) ||
           !UA_NodeId_equal(&certInfo->certificateType, &certificateTypeId))
            continue;

        UA_ByteString newCertificate = UA_BYTESTRING_NULL;
        UA_ByteString newPrivateKey = UA_BYTESTRING_NULL;
        UA_StatusCode res = UA_ByteString_copy(certificate, &newCertificate);
        if(privateKey)
            res |= UA_ByteString_copy(privateKey, &newPrivateKey);
        if(res != UA_STATUSCODE_GOOD) {
            UA_ByteString_clear(&newCertificate);
            UA_ByteString_memZero(&newPrivateKey);
            UA_ByteString_clear(&newPrivateKey);
            return res;
        }
        UA_ByteString_clear(&certInfo->certificate);
        UA_ByteString_memZero(&certInfo->privateKey);
        UA_ByteString_clear(&certInfo->privateKey);
        certInfo->certificate = newCertificate;
        certInfo->privateKey = newPrivateKey;
        return UA_STATUSCODE_GOOD;
    }

    UA_GDSCertificateInfo stagedInfo;
    memset(&stagedInfo, 0, sizeof(stagedInfo));
    UA_StatusCode res = UA_ByteString_copy(certificate, &stagedInfo.certificate);
    res |= UA_NodeId_copy(&certificateGroupId, &stagedInfo.certificateGroup);
    res |= UA_NodeId_copy(&certificateTypeId, &stagedInfo.certificateType);
    if(privateKey)
        res |= UA_ByteString_copy(privateKey, &stagedInfo.privateKey);
    if(res != UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(&stagedInfo.certificate);
        UA_ByteString_memZero(&stagedInfo.privateKey);
        UA_ByteString_clear(&stagedInfo.privateKey);
        UA_NodeId_clear(&stagedInfo.certificateGroup);
        UA_NodeId_clear(&stagedInfo.certificateType);
        return res;
    }

    UA_GDSCertificateInfo *newCertInfos = (UA_GDSCertificateInfo *)
        UA_realloc(transaction->certificateInfos,
                   (transaction->certificateInfosSize + 1) * sizeof(UA_GDSCertificateInfo));
    if(!newCertInfos) {
        UA_ByteString_clear(&stagedInfo.certificate);
        UA_ByteString_memZero(&stagedInfo.privateKey);
        UA_ByteString_clear(&stagedInfo.privateKey);
        UA_NodeId_clear(&stagedInfo.certificateGroup);
        UA_NodeId_clear(&stagedInfo.certificateType);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    transaction->certificateInfos = newCertInfos;

    transaction->certificateInfos[transaction->certificateInfosSize] = stagedInfo;
    transaction->certificateInfosSize++;

    return UA_STATUSCODE_GOOD;
}

static void
UA_GDSTransaction_clear(UA_GDSTransaction *transaction) {
    if(!transaction)
        return;

    transaction->state = UA_GDSTRANSACTIONSTATE_FRESH;
    transaction->server = NULL;
    UA_NodeId_clear(&transaction->sessionId);

    if(transaction->certGroups) {
        for(size_t i = 0; i < transaction->certGroupSize; i++) {
            transaction->certGroups[i].clear(&transaction->certGroups[i]);
        }
        UA_free(transaction->certGroups);
        transaction->certGroupSize = 0;
        transaction->certGroups = NULL;
    }

    if(transaction->certificateInfos) {
        for(size_t i = 0; i < transaction->certificateInfosSize; i++) {
            UA_ByteString_clear(&transaction->certificateInfos[i].certificate);
            UA_ByteString_memZero(&transaction->certificateInfos[i].privateKey);
            UA_ByteString_clear(&transaction->certificateInfos[i].privateKey);
            UA_NodeId_clear(&transaction->certificateInfos[i].certificateGroup);
            UA_NodeId_clear(&transaction->certificateInfos[i].certificateType);
        }
        UA_free(transaction->certificateInfos);
        transaction->certificateInfosSize = 0;
        transaction->certificateInfos = NULL;
    }
}

/********************/
/*   GDS Manager    */
/********************/

static UA_FileInfo *
UA_GDSPush_getFileInfo(UA_GDSPushContext *ctx,
                          UA_NodeId certificateGroupId) {
    UA_FileInfo *fi = (UA_FileInfo*)ctx->fileInfos;
    while(fi) {
        if(UA_NodeId_equal(&fi->certificateGroupId, &certificateGroupId))
            return fi;
        fi = fi->next;
    }
    return NULL;
}

static void
UA_FileContext_delete(UA_FileInfo *fileInfo, UA_FileContext *fileContext) {
    LIST_REMOVE(fileContext, listEntry);
    fileInfo->openCount -= 1;
    UA_ByteString_clear(&fileContext->file);
    UA_ByteString_clear(&fileContext->dataToWrite);
    UA_free(fileContext);
}

static UA_Boolean
isWriteHandle(const UA_FileContext *fileContext) {
    return fileContext->openFileMode ==
        (UA_OPENFILEMODE_WRITE | UA_OPENFILEMODE_ERASEEXISTING);
}

/* Is a TrustList open for writing? A NULL fileInfo checks all TrustLists, a
 * NULL sessionId all Sessions. */
static UA_Boolean
hasWriteHandle(UA_GDSPushContext *ctx, const UA_FileInfo *fileInfo,
               const UA_NodeId *sessionId) {
    for(UA_FileInfo *fi = ctx->fileInfos; fi; fi = fi->next) {
        if(fileInfo && fi != fileInfo)
            continue;
        UA_FileContext *fileContext;
        LIST_FOREACH(fileContext, &fi->fileContext, listEntry) {
            if(isWriteHandle(fileContext) &&
               (!sessionId || UA_NodeId_equal(&fileContext->sessionId, sessionId)))
                return true;
        }
    }
    return false;
}

/* Close the write handles of a Session. Their data is discarded. */
static void
closeSessionWriteHandles(UA_GDSPushContext *ctx, const UA_NodeId *sessionId) {
    for(UA_FileInfo *fi = ctx->fileInfos; fi; fi = fi->next) {
        UA_Boolean closed = false;
        UA_FileContext *fileContext, *fileContextTmp;
        LIST_FOREACH_SAFE(fileContext, &fi->fileContext, listEntry, fileContextTmp) {
            if(!isWriteHandle(fileContext) ||
               !UA_NodeId_equal(&fileContext->sessionId, sessionId))
                continue;
            UA_FileContext_delete(fi, fileContext);
            closed = true;
        }
        UA_CertificateGroup *certGroup = UA_GDSPush_getCertGroup(ctx->drv.server,
                                                      &fi->certificateGroupId);
        if(closed && certGroup)
            UA_GDSPush_writeOpenCount(ctx, certGroup);
    }
}

/* Close a write handle and discard its data (Part 12, 7.8.2.5). A transaction
 * without staged changes and without other write handles is closed. */
static void
closeWriteHandle(UA_GDSPushContext *ctx, UA_CertificateGroup *certGroup,
                 UA_FileInfo *fileInfo, UA_FileContext *fileContext) {
    UA_NodeId sessionId;
    UA_StatusCode res = UA_NodeId_copy(&fileContext->sessionId, &sessionId);
    UA_FileContext_delete(fileInfo, fileContext);
    UA_GDSPush_writeOpenCount(ctx, certGroup);
    if(res != UA_STATUSCODE_GOOD)
        return;
    UA_GDSTransaction *transaction = &ctx->transaction;
    if(transaction->state == UA_GDSTRANSACTIONSTATE_PENDING &&
       !transaction->applyChangesQueued &&
       transaction->certGroupSize == 0 && transaction->certificateInfosSize == 0 &&
       UA_NodeId_equal(&transaction->sessionId, &sessionId) &&
       !hasWriteHandle(ctx, NULL, &sessionId))
        UA_GDSTransaction_clear(transaction);
    UA_NodeId_clear(&sessionId);
}

UA_StatusCode
UA_GDSPush_checkTransaction(UA_GDSPushContext *ctx,
                                const UA_NodeId *sessionId) {
    /* One transaction for one Session at a time (Part 12, 7.10.2) */
    UA_GDSTransaction *transaction = &ctx->transaction;
    if(transaction->state == UA_GDSTRANSACTIONSTATE_FRESH)
        return UA_STATUSCODE_GOOD;
    if(transaction->applyChangesQueued ||
       !UA_NodeId_equal(&transaction->sessionId, sessionId))
        return UA_STATUSCODE_BADTRANSACTIONPENDING;
    return UA_STATUSCODE_GOOD;
}

/* Verify a Certificate (Part 4, 6.1.3). Suppressible errors are ignored (Part
 * 12, 7.8.2.5 and 7.10.5). Of those, only the validity period can be ignored
 * safely. The plugins report RevocationUnknown and UseNotAllowed before the
 * trust in the Certificate is established. */
static UA_StatusCode
verifyCertificate(UA_GDSPushContext *ctx, UA_CertificateGroup *group,
                  const UA_ByteString *certificate) {
    UA_StatusCode res = group->verifyCertificate(group, certificate);
    if(res == UA_STATUSCODE_BADCERTIFICATETIMEINVALID ||
       res == UA_STATUSCODE_BADCERTIFICATEISSUERTIMEINVALID) {
        UA_ServerConfig *sc = UA_Server_getConfig(ctx->drv.server);
        UA_LOG_WARNING(sc->logging, UA_LOGCATEGORY_SERVER,
                       "Accepting a Certificate outside of its validity "
                       "period (%s)", UA_StatusCode_name(res));
        res = UA_STATUSCODE_GOOD;
    }
    return res;
}

UA_StatusCode
UA_GDSPush_validateCertificate(UA_GDSPushContext *ctx,
                                   const UA_NodeId *sessionId,
                                   UA_CertificateGroup *certGroup,
                                   const UA_ByteString *certificate) {
    /* Use the TrustList staged in the transaction of the Session. The
     * CertificateManager updates the TrustList first (Part 12, 7.7.2). */
    UA_GDSTransaction *transaction = &ctx->transaction;
    if(sessionId && UA_NodeId_equal(&transaction->sessionId, sessionId)) {
        UA_CertificateGroup *staged = UA_GDSTransaction_findCertificateGroup(
            transaction, &certGroup->certificateGroupId);
        if(staged)
            certGroup = staged;
    }

    /* Groups without a TrustList (e.g. AcceptAll) have no side effects */
    if(!certGroup->getTrustList)
        return verifyCertificate(ctx, certGroup, certificate);

    /* The TrustList must contain the issuers of the Certificate (Part 12,
     * 7.10.5). They do not have to be trusted, a CertificateManager may put
     * its CA in the issuer list only. Verify with a copy where the issuers are
     * trusted. The copy also keeps the plugins from adding the Certificate to
     * the rejected list of the group. */
    UA_CertificateGroup scratch;
    UA_StatusCode res = copyCertificateGroup(certGroup, NULL, true, &scratch);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    res = verifyCertificate(ctx, &scratch, certificate);
    scratch.clear(&scratch);
    return res;
}

/* Verify the trusted Certificates of a TrustList that are not CA
 * Certificates. CA Certificates cannot be verified with the plugin interface.
 * Issuer Certificates are not trusted by themselves. */
static UA_StatusCode
verifyTrustList(UA_GDSPushContext *ctx, UA_CertificateGroup *group) {
    UA_TrustListDataType trustList;
    UA_TrustListDataType_init(&trustList);
    trustList.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    UA_StatusCode res = group->getTrustList(group, &trustList);
    for(size_t i = 0; res == UA_STATUSCODE_GOOD &&
            i < trustList.trustedCertificatesSize; i++) {
        UA_ByteString *certificate = &trustList.trustedCertificates[i];
        if(UA_CertificateUtils_checkCA(certificate) == UA_STATUSCODE_GOOD)
            continue;
        res = verifyCertificate(ctx, group, certificate);
    }
    UA_TrustListDataType_clear(&trustList);
    return res;
}

/* Keep only the lists of the mask */
static void
filterTrustList(UA_TrustListDataType *trustList, UA_UInt32 mask) {
    if(!(mask & UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES)) {
        UA_Array_delete(trustList->trustedCertificates,
                        trustList->trustedCertificatesSize,
                        &UA_TYPES[UA_TYPES_BYTESTRING]);
        trustList->trustedCertificates = NULL;
        trustList->trustedCertificatesSize = 0;
    }
    if(!(mask & UA_TRUSTLISTMASKS_TRUSTEDCRLS)) {
        UA_Array_delete(trustList->trustedCrls, trustList->trustedCrlsSize,
                        &UA_TYPES[UA_TYPES_BYTESTRING]);
        trustList->trustedCrls = NULL;
        trustList->trustedCrlsSize = 0;
    }
    if(!(mask & UA_TRUSTLISTMASKS_ISSUERCERTIFICATES)) {
        UA_Array_delete(trustList->issuerCertificates,
                        trustList->issuerCertificatesSize,
                        &UA_TYPES[UA_TYPES_BYTESTRING]);
        trustList->issuerCertificates = NULL;
        trustList->issuerCertificatesSize = 0;
    }
    if(!(mask & UA_TRUSTLISTMASKS_ISSUERCRLS)) {
        UA_Array_delete(trustList->issuerCrls, trustList->issuerCrlsSize,
                        &UA_TYPES[UA_TYPES_BYTESTRING]);
        trustList->issuerCrls = NULL;
        trustList->issuerCrlsSize = 0;
    }
    trustList->specifiedLists = mask & UA_TRUSTLISTMASKS_ALL;
}

UA_StatusCode
UA_GDSPush_initFileInfos(UA_GDSPushContext *ctx, UA_UtcTime lastUpdateTime) {
    UA_FileInfo *fi = (UA_FileInfo*)UA_calloc(1, sizeof(UA_FileInfo));
    if(!fi)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_FileInfo *fi2 = (UA_FileInfo*)UA_calloc(1, sizeof(UA_FileInfo));
    if(!fi2) {
        UA_free(fi);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    fi->next = fi2;
    fi->certificateGroupId =
        UA_NS0ID(SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    LIST_INIT(&fi->fileContext);
    fi->lastUpdateTime = lastUpdateTime;
    fi2->certificateGroupId =
        UA_NS0ID(SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP);
    LIST_INIT(&fi2->fileContext);
    fi2->lastUpdateTime = lastUpdateTime;
    ctx->fileInfos = fi;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_GDSPush_getFileInfoMetadata(UA_GDSPushContext *ctx,
                                  const UA_NodeId certificateGroupId,
                                  UA_UInt16 *openCount,
                                  UA_UtcTime *lastUpdateTime) {
    UA_FileInfo *fi = UA_GDSPush_getFileInfo(ctx, certificateGroupId);
    if(!fi)
        return UA_STATUSCODE_BADNOTFOUND;
    *openCount = fi->openCount;
    *lastUpdateTime = fi->lastUpdateTime;
    return UA_STATUSCODE_GOOD;
}

UA_Boolean
UA_GDSPush_transactionPending(UA_GDSPushContext *ctx) {
    return ctx->transaction.state != UA_GDSTRANSACTIONSTATE_FRESH;
}

UA_StatusCode
UA_GDSPush_applyChangesForSession(UA_GDSPushContext *ctx,
                                     const UA_NodeId *sessionId) {
    /* Part 12, 7.10.9 */
    UA_GDSTransaction *transaction = &ctx->transaction;
    /* A fresh transaction has no owning session. Check the state first, so
     * that the session comparison does not hide Bad_NothingToDo. */
    if(transaction->state == UA_GDSTRANSACTIONSTATE_FRESH ||
       transaction->applyChangesQueued)
        return UA_STATUSCODE_BADNOTHINGTODO;
    if(!UA_NodeId_equal(&transaction->sessionId, sessionId))
        return UA_STATUSCODE_BADSESSIONIDINVALID;
    return UA_GDSPush_applyChanges(ctx);
}

UA_StatusCode
UA_GDSPush_cancelChangesForSession(UA_GDSPushContext *ctx,
                                      const UA_NodeId *sessionId) {
    /* Part 12, 7.10.11 */
    UA_GDSTransaction *transaction = &ctx->transaction;
    if(transaction->state == UA_GDSTRANSACTIONSTATE_FRESH ||
       transaction->applyChangesQueued)
        return UA_STATUSCODE_BADNOTHINGTODO;
    if(!UA_NodeId_equal(&transaction->sessionId, sessionId))
        return UA_STATUSCODE_BADSESSIONIDINVALID;
    closeSessionWriteHandles(ctx, sessionId);
    UA_GDSTransaction_clear(transaction);
    return UA_STATUSCODE_GOOD;
}

/* This callback is triggered at regular intervals as long as a transaction is ongoing
 * or a client has a TrustList open for reading or writing.
 * If the session is no longer active, the current transaction is cancelled,
 * and all open file handles are closed. */
static void
checkSessionActive(UA_Server *server, void *data) {
    UA_ServerConfig *sc = UA_Server_getConfig(server);
    UA_EventLoop *el = sc->eventLoop;
    el->lock(el);

    UA_GDSPushContext *ctx = (UA_GDSPushContext*)data;
    UA_GDSTransaction *transaction = &ctx->transaction;
    UA_Boolean removingCallback = false;
    if(transaction->state != UA_GDSTRANSACTIONSTATE_FRESH) {
        /* Check if the session is still active */
        UA_Variant tmp;
        UA_StatusCode res =
            UA_Server_getSessionAttribute(server, &transaction->sessionId,
                                          UA_QUALIFIEDNAME(0, "sessionName"), &tmp);
        if(res != UA_STATUSCODE_GOOD && !transaction->applyChangesQueued) {
            UA_LOG_INFO(sc->logging, UA_LOGCATEGORY_SERVER,
                "Session with an open transaction has ended. "
                "The transaction has been discarded.");
            UA_GDSTransaction_clear(transaction);
            removingCallback = true;
        }
    } else {
        removingCallback = true;
    }

    UA_FileInfo *fi = (UA_FileInfo*)ctx->fileInfos;
    for(; fi; fi = fi->next) {
        if(fi->openCount == 0)
            continue;

        removingCallback = false;

        UA_CertificateGroup *certGroup =
            UA_GDSPush_getCertGroup(server, &fi->certificateGroupId);
        if(!certGroup)
            continue;

        UA_FileContext *fileContext, *fileContextTmp;
        LIST_FOREACH_SAFE(fileContext, &fi->fileContext, listEntry, fileContextTmp) {
            UA_Variant tmp;
            UA_StatusCode res =
                UA_Server_getSessionAttribute(server, &fileContext->sessionId,
                                              UA_QUALIFIEDNAME(0, "sessionName"), &tmp);
            if(res == UA_STATUSCODE_GOOD)
                continue; /* Session still exists */

            UA_LOG_INFO(sc->logging, UA_LOGCATEGORY_SERVER,
                        "Session with an open trust list has ended. "
                        "All file handlers for the open trust lists have been closed.");

            LIST_REMOVE(fileContext, listEntry);
            fi->openCount -= 1;

            UA_ByteString_clear(&fileContext->file);
            UA_ByteString_clear(&fileContext->dataToWrite);
            UA_free(fileContext);

            /* Updating OpenCount Variable in the information model */
            UA_GDSPush_writeOpenCount(ctx, certGroup);
        }
    }

    if(removingCallback) {
        UA_Server_removeCallback(server, ctx->checkSessionCallbackId);
        ctx->checkSessionCallbackId = 0;
    }

    el->unlock(el);
}

UA_StatusCode
UA_GDSPush_getPositionTrustList(UA_GDSPushContext *ctx, UA_CertificateGroup *certGroup,
                                   const UA_NodeId *sessionId, UA_UInt32 fileHandle,
                                   UA_Variant *output) {
    UA_assert(certGroup != NULL);
    UA_FileInfo *fileInfo =
        UA_GDSPush_getFileInfo(ctx, certGroup->certificateGroupId);
    if(!fileInfo)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_FileContext *fileContext = getFileContext(fileInfo, sessionId, fileHandle);
    if(!fileContext)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    return UA_Variant_setScalarCopy(output, &fileContext->currentPos,
                                    &UA_TYPES[UA_TYPES_UINT64]);
}

UA_StatusCode
UA_GDSPush_setPositionTrustList(UA_GDSPushContext *ctx, UA_CertificateGroup *certGroup,
                                   const UA_NodeId *sessionId, UA_UInt32 fileHandle,
                                   UA_UInt64 position) {
    UA_assert(certGroup != NULL);
    UA_FileInfo *fileInfo =
        UA_GDSPush_getFileInfo(ctx, certGroup->certificateGroupId);
    if(!fileInfo)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_FileContext *fileContext = getFileContext(fileInfo, sessionId, fileHandle);
    if(!fileContext)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    if(fileContext->file.length < position) {
        fileContext->currentPos = fileContext->file.length;
    } else {
        fileContext->currentPos = position;
    }

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_GDSPush_writeTrustList(UA_GDSPushContext *ctx, UA_CertificateGroup *certGroup,
                             const UA_NodeId *sessionId, UA_UInt32 fileHandle,
                             const UA_ByteString data) {
    UA_assert(certGroup != NULL);
    UA_Server *server = ctx->drv.server;
    UA_ServerConfig *sc = UA_Server_getConfig(server);

    UA_FileInfo *fileInfo =
        UA_GDSPush_getFileInfo(ctx, certGroup->certificateGroupId);
    if(!fileInfo)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_FileContext *fileContext = getFileContext(fileInfo, sessionId, fileHandle);
    if(!fileContext)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    if(fileContext->openFileMode !=
       (UA_OPENFILEMODE_WRITE | UA_OPENFILEMODE_ERASEEXISTING))
        return UA_STATUSCODE_BADINVALIDSTATE;

    /* Abort when TrustList size would exceed the maximum allowed value (0 =
     * unlimited) */
    size_t newLen = fileContext->dataToWrite.length + data.length;
    if(sc->maxTrustListSize != 0 && newLen > sc->maxTrustListSize) {
        UA_LOG_WARNING(sc->logging, UA_LOGCATEGORY_SERVER,
                       "Write on trust list exceeds limit");
        return UA_STATUSCODE_BADREQUESTTOOLARGE;
    }

    return UA_String_append(&fileContext->dataToWrite, data);
}

UA_StatusCode
UA_GDSPush_closeAndUpdateTrustList(UA_GDSPushContext *ctx,
                                      UA_CertificateGroup *certGroup,
                                      const UA_NodeId *sessionId,
                                      UA_UInt32 fileHandle,
                                      UA_Variant *output) {
    UA_assert(certGroup != NULL);
    UA_ServerConfig *sc = UA_Server_getConfig(ctx->drv.server);

    UA_GDSTransaction *transaction = &ctx->transaction;
    UA_FileInfo *fileInfo =
        UA_GDSPush_getFileInfo(ctx, certGroup->certificateGroupId);
    if(!fileInfo)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_FileContext *fileContext = getFileContext(fileInfo, sessionId, fileHandle);
    if(!fileContext)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    if(!isWriteHandle(fileContext) ||
       transaction->state != UA_GDSTRANSACTIONSTATE_PENDING)
        return UA_STATUSCODE_BADINVALIDSTATE;

    /* Build the resulting TrustList in a scratch copy of the staged or the
     * active TrustList. A partial update keeps the other lists. */
    UA_CertificateGroup scratch;
    memset(&scratch, 0, sizeof(UA_CertificateGroup));
    UA_TrustListDataType trustList;
    UA_TrustListDataType_init(&trustList);
    UA_StatusCode retval = UA_STATUSCODE_BADNOTWRITABLE;
    if(!certGroup->setTrustList)
        goto discard;
    UA_CertificateGroup *staged = UA_GDSTransaction_findCertificateGroup(
        transaction, &certGroup->certificateGroupId);
    retval = copyCertificateGroup(staged ? staged : certGroup, NULL, false, &scratch);
    if(retval != UA_STATUSCODE_GOOD)
        goto discard;

    retval = UA_decodeBinary(&fileContext->dataToWrite, &trustList,
                             &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL);
    if(retval != UA_STATUSCODE_GOOD) {
        retval = UA_STATUSCODE_BADDECODINGERROR;
        goto discard;
    }
    retval = scratch.setTrustList(&scratch, &trustList);
    if(retval != UA_STATUSCODE_GOOD)
        goto discard;

    /* The limit applies to the resulting TrustList (Part 12, 7.8.2.5) */
    size_t size = 0;
    retval = trustListSize(&scratch, &size);
    if(retval != UA_STATUSCODE_GOOD)
        goto discard;
    if(sc->maxTrustListSize != 0 && size > sc->maxTrustListSize) {
        retval = UA_STATUSCODE_BADREQUESTTOOLARGE;
        goto discard;
    }

    /* Validate the Certificates of the resulting TrustList */
    retval = verifyTrustList(ctx, &scratch);
    if(retval != UA_STATUSCODE_GOOD)
        goto discard;

    retval = UA_GDSTransaction_stageCertificateGroup(transaction, &scratch);
    if(retval != UA_STATUSCODE_GOOD)
        goto discard;
    UA_TrustListDataType_clear(&trustList);

    UA_FileContext_delete(fileInfo, fileContext);
    UA_GDSPush_writeOpenCount(ctx, certGroup);

    /* Output arg, indicates that the ApplyChanges Method shall be called before
     * the new trust list will be used. */
    UA_Boolean applyChangesRequired = true;
    return UA_Variant_setScalarCopy(output, &applyChangesRequired,
                                    &UA_TYPES[UA_TYPES_BOOLEAN]);

 discard:
    /* The new TrustList is discarded. The transaction keeps its state. */
    UA_LOG_WARNING(sc->logging, UA_LOGCATEGORY_SERVER,
                   "The TrustList update was discarded (%s)",
                   UA_StatusCode_name(retval));
    UA_TrustListDataType_clear(&trustList);
    if(scratch.clear)
        scratch.clear(&scratch);
    closeWriteHandle(ctx, certGroup, fileInfo, fileContext);
    return retval;
}

UA_StatusCode
UA_GDSPush_closeTrustList(UA_GDSPushContext *ctx,
                             UA_CertificateGroup *certGroup,
                             const UA_NodeId *sessionId,
                             UA_UInt32 fileHandle) {
    UA_assert(certGroup != NULL);

    UA_FileInfo *fileInfo =
        UA_GDSPush_getFileInfo(ctx, certGroup->certificateGroupId);
    if(!fileInfo)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_FileContext *fileContext = getFileContext(fileInfo, sessionId, fileHandle);
    if(!fileContext)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* Close discards the data written to the handle. Other changes of the
     * transaction remain (Part 12, 7.8.2.5). */
    if(isWriteHandle(fileContext)) {
        closeWriteHandle(ctx, certGroup, fileInfo, fileContext);
        return UA_STATUSCODE_GOOD;
    }

    UA_FileContext_delete(fileInfo, fileContext);
    UA_GDSPush_writeOpenCount(ctx, certGroup);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_GDSPush_readTrustList(UA_GDSPushContext *ctx, UA_CertificateGroup *certGroup,
                            const UA_NodeId *sessionId, UA_UInt32 fileHandle,
                            UA_Int32 length, UA_Variant *output) {
    UA_assert(certGroup != NULL);

    UA_FileInfo *fileInfo =
        UA_GDSPush_getFileInfo(ctx, certGroup->certificateGroupId);
    if(!fileInfo)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_FileContext *fileContext = getFileContext(fileInfo, sessionId, fileHandle);
    if(!fileContext)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    if(fileContext->openFileMode != UA_OPENFILEMODE_READ)
        return UA_STATUSCODE_BADINVALIDSTATE;

    /* check boundaries */
    if((size_t)length >= fileContext->file.length)
        length = (UA_Int32)fileContext->file.length;

    if((size_t)length >= (fileContext->file.length - fileContext->currentPos))
        length = (UA_Int32)(fileContext->file.length - fileContext->currentPos);

    UA_ByteString readBuffer = UA_BYTESTRING_NULL;
    if(length > 0) {
        readBuffer.length = (size_t)length;
        readBuffer.data = fileContext->file.data+fileContext->currentPos;
    }

    UA_StatusCode res =
        UA_Variant_setScalarCopy(output, &readBuffer,
                                 &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(res == UA_STATUSCODE_GOOD)
        fileContext->currentPos += (UA_UInt64)length;
    return res;
}

/* TODO: Handle isTrustedCertificate */
UA_StatusCode
UA_GDSPush_addCertificate(UA_GDSPushContext *ctx,
                             UA_CertificateGroup *certGroup,
                             UA_ByteString *certificate,
                             const UA_Boolean *isTrustedCertificate) {
    UA_assert(certGroup != NULL);
    UA_Server *server = ctx->drv.server;
    UA_ServerConfig *sc = UA_Server_getConfig(server);

    /* CA certificates cannot be added using this method because it does not
     * support adding CRLs */
    if(UA_CertificateUtils_checkCA(certificate) == UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(sc->logging, UA_LOGCATEGORY_SERVER,
                     "The certificate could not be added because it is a CA certificate. "
                     "CA certificates must be added using the FileType methods.");
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    if(!certGroup->addToTrustList || !certGroup->getTrustList)
        return UA_STATUSCODE_BADNOTWRITABLE;

    /* This method cannot be called if the containing TrustList Object is open
     * (Part 12, 7.8.2.6) */
    UA_FileInfo *fileInfo =
        UA_GDSPush_getFileInfo(ctx, certGroup->certificateGroupId);
    if(!fileInfo)
        return UA_STATUSCODE_BADINTERNALERROR;
    if(hasWriteHandle(ctx, fileInfo, NULL))
        return UA_STATUSCODE_BADINVALIDSTATE;
    if(fileInfo->openCount > 0)
        return UA_STATUSCODE_BADNOTWRITABLE;

    /* Validate the Certificate in the resulting TrustList. A Certificate
     * issued by a CA requires the CA in the TrustList. */
    UA_CertificateGroup scratch;
    UA_StatusCode res = copyCertificateGroup(certGroup, certificate, false, &scratch);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    res = verifyCertificate(ctx, &scratch, certificate);
    size_t size = 0;
    if(res == UA_STATUSCODE_GOOD)
        res = trustListSize(&scratch, &size);
    scratch.clear(&scratch);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    if(sc->maxTrustListSize != 0 && size > sc->maxTrustListSize)
        return UA_STATUSCODE_BADREQUESTTOOLARGE;

    UA_TrustListDataType trustList;
    UA_TrustListDataType_init(&trustList);
    trustList.specifiedLists = UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES;
    trustList.trustedCertificates = certificate;
    trustList.trustedCertificatesSize = 1;

    res = certGroup->addToTrustList(certGroup, &trustList);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* Updating LastUpdateTime Variable in the information model */
    fileInfo->lastUpdateTime = UA_DateTime_now();
    UA_GDSPush_writeLastUpdateTime(ctx, certGroup);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_GDSPush_stageCertificateUpdate(UA_GDSPushContext *ctx,
                                const UA_NodeId *sessionId,
                                const UA_NodeId *certificateGroupId,
                                const UA_NodeId *certificateTypeId,
                                const UA_ByteString *certificate,
                                const UA_String *privateKeyFormat,
                                const UA_ByteString *privateKey) {
    UA_Server *server = ctx->drv.server;
    UA_ServerConfig *sc = UA_Server_getConfig(server);

    /* Another Session has a transaction (Part 12, 7.10.5) */
    UA_StatusCode retval = UA_GDSPush_checkTransaction(ctx, sessionId);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* The server currently only supports the DefaultApplicationGroup. A null
     * CertificateGroupId selects it (Part 12, 7.10.5). */
    static UA_NodeId defaultApplicationGroup =
        STATIC_NS0ID(SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    if(UA_NodeId_isNull(certificateGroupId))
        certificateGroupId = &defaultApplicationGroup;
    if(!UA_NodeId_equal(certificateGroupId, &defaultApplicationGroup))
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* The certificate type must be one of the CertificateTypes of the group,
     * the key must fit it and the certificate must belong to the private key
     * (or to the current key or the key of the pending signing request) */
    retval = UA_GDSCore_checkCertificate(&ctx->core, certificateTypeId,
                                         certificate, privateKey);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* The privateKey must be in a supported format */
    if(privateKey && privateKey->length > 0) {
        const UA_String pemFormat = UA_STRING("PEM");
        const UA_String derFormat = UA_STRING("DER");
        if(!privateKeyFormat || (!UA_String_equal(&pemFormat, privateKeyFormat) &&
                                 !UA_String_equal(&derFormat, privateKeyFormat)))
            return UA_STATUSCODE_BADNOTSUPPORTED;
    }

    /* The ApplicationUri is not suppressible (Part 4, 6.1.3) */
    if(UA_CertificateUtils_verifyApplicationUri(
           certificate, &sc->applicationDescription.applicationUri) !=
       UA_STATUSCODE_GOOD) {
        if(sc->allowAllCertificateUris <= UA_RULEHANDLING_WARN)
            UA_LOG_ERROR(sc->logging, UA_LOGCATEGORY_SERVER,
                         "UpdateCertificate: The ApplicationUri of the "
                         "Certificate is not %S",
                         sc->applicationDescription.applicationUri);
        if(sc->allowAllCertificateUris < UA_RULEHANDLING_WARN)
            return UA_STATUSCODE_BADCERTIFICATEURIINVALID;
    }

    /* Validate the Certificate with the TrustList (Part 12, 7.10.5) */
    UA_CertificateGroup *certGroup = UA_GDSPush_getCertGroup(server, certificateGroupId);
    if(!certGroup)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    retval = UA_GDSPush_validateCertificate(ctx, sessionId, certGroup,
                                                certificate);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* A queued ApplyChanges is refused by UA_GDSPush_checkTransaction
     * above, so the change cannot be dropped silently */
    UA_GDSTransaction *transaction = &ctx->transaction;
    UA_Boolean created = false;
    if(transaction->state == UA_GDSTRANSACTIONSTATE_FRESH) {
        retval = UA_GDSTransaction_init(transaction, server, *sessionId);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
        created = true;
    }

    if(ctx->checkSessionCallbackId == 0) {
        retval = UA_Server_addRepeatedCallback(server, checkSessionActive,
                                               ctx, CHECKACTIVESESSIONINTERVAL,
                                               &ctx->checkSessionCallbackId);
        if(retval != UA_STATUSCODE_GOOD)
            goto errout;
    }

    retval = UA_GDSTransaction_addCertificateInfo(transaction, *certificateGroupId,
                                                  *certificateTypeId, certificate,
                                                  privateKey);
    if(retval == UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_GOOD;

 errout:
    /* A failed call does not change the transaction state (Part 12, 7.10.2) */
    if(created)
        UA_GDSTransaction_clear(transaction);
    return retval;
}

/* TODO: Expose implementation in core open62541 */

static UA_Byte
lc(UA_Byte c) {
    if(((int)c) - 'A' < 26) return c | 32;
    return c;
}
static int
case_cmp(const UA_Byte *l, const UA_Byte *r, size_t n) {
    if(!n--) return 0;
    for(; *l && *r && n && (*l == *r || lc(*l) == lc(*r)); l++, r++, n--);
    return lc(*l) - lc(*r);
}
static UA_Boolean
String_equal_ignorecase(const UA_String *s1, const UA_String *s2) {
    if(s1->length != s2->length)
        return false;
    if(s1->length == 0)
        return true;
    if(s2->data == NULL)
        return false;
    return case_cmp(s1->data, s2->data, s1->length) == 0;
}

UA_StatusCode
UA_GDSPush_removeCertificate(UA_GDSPushContext *ctx,
                                UA_CertificateGroup *certGroup,
                                const UA_NodeId *sessionId,
                                const UA_String *thumbprint,
                                const UA_Boolean *isTrustedCertificate) {
    UA_assert(certGroup != NULL);
    UA_Server *server = ctx->drv.server;
    UA_ServerConfig *sc = UA_Server_getConfig(server);

    UA_GDSTransaction *transaction = &ctx->transaction;
    if(transaction->state != UA_GDSTRANSACTIONSTATE_FRESH)
        return UA_STATUSCODE_BADTRANSACTIONPENDING;

    if(!certGroup->getTrustList || !certGroup->setTrustList ||
       !certGroup->getCertificateCrls)
        return UA_STATUSCODE_BADNOTWRITABLE;

    /* This Method cannot be called if the containing TrustList Object is open
     * (Part 12, 7.8.2.7) */
    UA_FileInfo *fileInfo =
        UA_GDSPush_getFileInfo(ctx, certGroup->certificateGroupId);
    if(!fileInfo)
        return UA_STATUSCODE_BADINTERNALERROR;
    if(hasWriteHandle(ctx, fileInfo, NULL))
        return UA_STATUSCODE_BADINVALIDSTATE;
    if(fileInfo->openCount > 0)
        return UA_STATUSCODE_BADNOTWRITABLE;

    /* When a certificate is removed, a transaction is created which is then
     * executed directly. No apply changes is required */
    UA_StatusCode retval = UA_GDSTransaction_init(transaction, server, *sessionId);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    UA_CertificateGroup *transactionCG =
        UA_GDSTransaction_getCertificateGroup(transaction, certGroup);
    if(!transactionCG) {
        UA_GDSTransaction_clear(transaction);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_Boolean *validBefore = NULL;

    UA_TrustListDataType trustList;
    UA_TrustListDataType_init(&trustList);
    trustList.specifiedLists = UA_TRUSTLISTMASKS_ALL;

    UA_ByteString *certificates;
    size_t certificatesSize = 0;
    retval = certGroup->getTrustList(certGroup, &trustList);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_TrustListDataType_clear(&trustList);
        UA_GDSTransaction_clear(transaction);
        return retval;
    }

    if(*isTrustedCertificate) {
        certificates = trustList.trustedCertificates;
        certificatesSize = trustList.trustedCertificatesSize;
    } else {
        certificates = trustList.issuerCertificates;
        certificatesSize = trustList.issuerCertificatesSize;
    }

    UA_TrustListDataType list;
    UA_TrustListDataType_init(&list);

    UA_ByteString *crls = NULL;
    size_t crlsSize = 0;
    UA_ByteString certificate = UA_BYTESTRING_NULL;

    UA_Byte buf[UA_SHA1_LENGTH * 2];
    UA_String thumbpr = {UA_SHA1_LENGTH * 2, buf};
    for(size_t i = 0; i < certificatesSize; i++) {
        /* Compare thumbprint */
        certificate = certificates[i];
        retval = UA_CertificateUtils_getThumbprint(&certificate, &thumbpr);
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup;
        if(!String_equal_ignorecase(thumbprint, &thumbpr))
            continue;

        retval = certGroup->getCertificateCrls(certGroup, &certificate,
                                               isTrustedCertificate,
                                               &crls, &crlsSize);

        /* Tolerate "Bad_NoMatch" to support removing CA certificates that do
         * not have an associated CRL. */
        if(retval != UA_STATUSCODE_GOOD && retval != UA_STATUSCODE_BADNOMATCH)
            goto cleanup;

        if(*isTrustedCertificate) {
            list.specifiedLists =
                UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES | UA_TRUSTLISTMASKS_TRUSTEDCRLS;
            list.trustedCertificates = &certificate;
            list.trustedCertificatesSize = 1;
            list.trustedCrls = crls;
            list.trustedCrlsSize = crlsSize;
        } else {
            list.specifiedLists =
                UA_TRUSTLISTMASKS_ISSUERCERTIFICATES | UA_TRUSTLISTMASKS_ISSUERCRLS;
            list.issuerCertificates = &certificate;
            list.issuerCertificatesSize = 1;
            list.issuerCrls = crls;
            list.issuerCrlsSize = crlsSize;
        }
        break;
    }

    /* Thumbprint not found */
    if(list.specifiedLists == UA_TRUSTLISTMASKS_NONE) {
        UA_LOG_INFO(sc->logging, UA_LOGCATEGORY_SERVER,
                    "The certificate to remove was not found");
        retval = UA_STATUSCODE_BADINVALIDARGUMENT;
        goto cleanup;
    }

    /* A CA Certificate may be needed to validate other Certificates of the
     * TrustList (Part 12, 7.8.2.7). Note which Certificates are valid now. */
    UA_Boolean removesCA =
        (UA_CertificateUtils_checkCA(&certificate) == UA_STATUSCODE_GOOD);
    if(removesCA && trustList.trustedCertificatesSize > 0) {
        validBefore = (UA_Boolean*)
            UA_calloc(trustList.trustedCertificatesSize, sizeof(UA_Boolean));
        if(!validBefore) {
            retval = UA_STATUSCODE_BADOUTOFMEMORY;
            goto cleanup;
        }
        for(size_t i = 0; i < trustList.trustedCertificatesSize; i++) {
            UA_ByteString *cert = &trustList.trustedCertificates[i];
            validBefore[i] = UA_CertificateUtils_checkCA(cert) != UA_STATUSCODE_GOOD &&
                verifyCertificate(ctx, transactionCG, cert) == UA_STATUSCODE_GOOD;
        }
    }

    /* Add to the transaction */
    retval = transactionCG->removeFromTrustList(transactionCG, &list);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;

    for(size_t i = 0; validBefore && i < trustList.trustedCertificatesSize; i++) {
        UA_ByteString *cert = &trustList.trustedCertificates[i];
        if(!validBefore[i] || UA_ByteString_equal(cert, &certificate))
            continue;
        if(verifyCertificate(ctx, transactionCG, cert) != UA_STATUSCODE_GOOD) {
            retval = UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE;
            goto cleanup;
        }
    }

    /* Apply */
    retval = UA_GDSPush_applyChanges(ctx);

cleanup:
    UA_free(validBefore);
    UA_TrustListDataType_clear(&trustList);
    UA_Array_delete(crls, crlsSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(retval != UA_STATUSCODE_GOOD)
        UA_GDSTransaction_clear(transaction);
    return retval;
}

UA_StatusCode
UA_GDSPush_getRejectedList(UA_GDSPushContext *ctx, size_t outputSize,
                              UA_Variant *output) {
    if(outputSize < 1)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    if(outputSize > 1)
        return UA_STATUSCODE_BADTOOMANYARGUMENTS;

    UA_Server *server = ctx->drv.server;
    UA_ServerConfig *sc = UA_Server_getConfig(server);

    size_t rejectedListSize = 0;

    /* DefaultApplicationGroup */
    UA_CertificateGroup *certGroup = &sc->secureChannelPKI;
    UA_ByteString *rejectedListSecureChannel = NULL;
    size_t rejectedListSecureChannelSize = 0;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(certGroup->getRejectedList)
        res = certGroup->getRejectedList(certGroup, &rejectedListSecureChannel,
                                         &rejectedListSecureChannelSize);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Array_delete(rejectedListSecureChannel,
                        rejectedListSecureChannelSize,
                        &UA_TYPES[UA_TYPES_BYTESTRING]);
        return res;
    }
    rejectedListSize += rejectedListSecureChannelSize;

    /* DefaultUserTokenGroup */
    certGroup = &sc->sessionPKI;
    UA_ByteString *rejectedListSession = NULL;
    size_t rejectedListSessionSize = 0;
    if(certGroup->getRejectedList)
        res = certGroup->getRejectedList(certGroup, &rejectedListSession,
                                         &rejectedListSessionSize);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Array_delete(rejectedListSecureChannel,
                        rejectedListSecureChannelSize,
                        &UA_TYPES[UA_TYPES_BYTESTRING]);
        UA_Array_delete(rejectedListSession, rejectedListSessionSize,
                        &UA_TYPES[UA_TYPES_BYTESTRING]);
        return res;
    }
    rejectedListSize += rejectedListSessionSize;

    if(rejectedListSize == 0) {
        UA_Variant_setArray(&output[0], NULL, 0, &UA_TYPES[UA_TYPES_BYTESTRING]);
        UA_Array_delete(rejectedListSecureChannel,
                        rejectedListSecureChannelSize,
                        &UA_TYPES[UA_TYPES_BYTESTRING]);
        UA_Array_delete(rejectedListSession, rejectedListSessionSize,
                        &UA_TYPES[UA_TYPES_BYTESTRING]);
        return UA_STATUSCODE_GOOD;
    }

    /* Create a temp array (shallow) */
    UA_ByteString *rejectedList = (UA_ByteString*)
        UA_Array_new(rejectedListSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(!rejectedList) {
        UA_Array_delete(rejectedListSecureChannel,
                        rejectedListSecureChannelSize,
                        &UA_TYPES[UA_TYPES_BYTESTRING]);
        UA_Array_delete(rejectedListSession,
                        rejectedListSessionSize,
                        &UA_TYPES[UA_TYPES_BYTESTRING]);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    memcpy(rejectedList, rejectedListSecureChannel,
           rejectedListSecureChannelSize * sizeof(UA_ByteString));
    memcpy(rejectedList + rejectedListSecureChannelSize,
           rejectedListSession, rejectedListSessionSize * sizeof(UA_ByteString));

    /* Set the array in the output */
    res = UA_Variant_setArrayCopy(&output[0], rejectedList, rejectedListSize,
                                  &UA_TYPES[UA_TYPES_BYTESTRING]);

    /* Clean up */
    UA_Array_delete(rejectedListSecureChannel, rejectedListSecureChannelSize,
                    &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Array_delete(rejectedListSession, rejectedListSessionSize,
                    &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_free(rejectedList);
    return res;
}

static UA_StatusCode
createFileHandleId(UA_FileInfo *fileInfo, UA_UInt32 *fileHandle) {
    if(!fileInfo || !fileHandle)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_UInt32 id;
    UA_Boolean isFree = true;
    for(id = 1; id < UA_UINT32_MAX; id++) {
        UA_FileContext *fileContext = NULL;
        LIST_FOREACH(fileContext, &fileInfo->fileContext, listEntry) {
            if(fileContext->fileHandle == id){
                isFree = false;
                break;
            }
        }
        if(isFree) {
            *fileHandle = id;
            return UA_STATUSCODE_GOOD;
        }
        isFree = true;
    }
    return UA_STATUSCODE_BADINTERNALERROR;
}

UA_StatusCode
UA_GDSPush_openTrustListWithMask(UA_GDSPushContext *ctx, UA_CertificateGroup *certGroup,
                                    const UA_NodeId *sessionId, UA_UInt32 mask,
                                    UA_Variant *output) {
    UA_assert(certGroup != NULL);
    UA_Server *server = ctx->drv.server;

    if(!certGroup->getTrustList)
        return UA_STATUSCODE_BADNOTSUPPORTED;

    /* Reading is possible during a transaction, but not while the TrustList is
     * open for writing (Part 12, 7.8.2.5 and Part 20) */
    UA_FileInfo *fileInfo =
        UA_GDSPush_getFileInfo(ctx, certGroup->certificateGroupId);
    if(!fileInfo)
        return UA_STATUSCODE_BADINTERNALERROR;
    if(hasWriteHandle(ctx, fileInfo, NULL))
        return UA_STATUSCODE_BADNOTREADABLE;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(ctx->checkSessionCallbackId == 0) {
        retval = UA_Server_addRepeatedCallback(server, checkSessionActive, ctx,
                                               CHECKACTIVESESSIONINTERVAL,
                                               &ctx->checkSessionCallbackId);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
    }

    UA_TrustListDataType trustList;
    UA_TrustListDataType_init(&trustList);
    trustList.specifiedLists = mask;
    retval = certGroup->getTrustList(certGroup, &trustList);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_TrustListDataType_clear(&trustList);
        return retval;
    }

    /* The plugins return all lists */
    filterTrustList(&trustList, mask);

    UA_ByteString encTrustList = UA_BYTESTRING_NULL;
    retval = UA_encodeBinary(&trustList, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE],
                             &encTrustList, NULL);
    UA_TrustListDataType_clear(&trustList);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(&encTrustList);
        return retval;
    }

    UA_FileContext *fileContext = (UA_FileContext*)
        UA_calloc(1, sizeof(UA_FileContext));
    if(!fileContext) {
        UA_ByteString_clear(&encTrustList);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
        
    fileContext->file = encTrustList;
    fileContext->sessionId = *sessionId;
    fileContext->openFileMode = UA_OPENFILEMODE_READ;
    fileContext->currentPos = 0;
    fileContext->dataToWrite = UA_BYTESTRING_NULL;
    retval = createFileHandleId(fileInfo, &fileContext->fileHandle);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(&fileContext->file);
        UA_free(fileContext);
        return retval;
    }

    retval = UA_Variant_setScalarCopy(output, &fileContext->fileHandle,
                                      &UA_TYPES[UA_TYPES_UINT32]);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(&fileContext->file);
        UA_free(fileContext);
        return retval;
    }
    fileInfo->openCount += 1;

    /* Updating OpenCount Variable in the information model */
    UA_GDSPush_writeOpenCount(ctx, certGroup);

    LIST_INSERT_HEAD(&fileInfo->fileContext, fileContext, listEntry);

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_GDSPush_openTrustList(UA_GDSPushContext *ctx, UA_CertificateGroup *certGroup,
                            const UA_NodeId *sessionId, UA_Byte fileOpenMode,
                            UA_Variant *output) {
    UA_assert(certGroup != NULL);
    UA_Server *server = ctx->drv.server;
    UA_GDSTransaction *transaction = &ctx->transaction;

    /* Only Read and Write + EraseExisting (Part 12, 7.8.2.2) */
    const UA_Byte writeMode = UA_OPENFILEMODE_WRITE | UA_OPENFILEMODE_ERASEEXISTING;
    if(fileOpenMode != UA_OPENFILEMODE_READ && fileOpenMode != writeMode)
        return UA_STATUSCODE_BADNOTSUPPORTED;
    if(!certGroup->getTrustList)
        return UA_STATUSCODE_BADNOTSUPPORTED;

    UA_FileInfo *fileInfo =
        UA_GDSPush_getFileInfo(ctx, certGroup->certificateGroupId);
    if(!fileInfo)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_Boolean created = false;
    if(fileOpenMode == UA_OPENFILEMODE_READ) {
        /* Readers get the active TrustList, also during a transaction (Part 12,
         * 7.8.2.5). Not while the TrustList is open for writing. */
        if(hasWriteHandle(ctx, fileInfo, NULL))
            return UA_STATUSCODE_BADNOTREADABLE;
    } else {
        /* Continue the transaction of the Session or create a new one
         * (Part 12, 7.8.2.2) */
        retval = UA_GDSPush_checkTransaction(ctx, sessionId);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
        if(fileInfo->openCount != 0)
            return UA_STATUSCODE_BADNOTWRITABLE;
        if(transaction->state == UA_GDSTRANSACTIONSTATE_FRESH) {
            retval = UA_GDSTransaction_init(transaction, server, *sessionId);
            if(retval != UA_STATUSCODE_GOOD)
                return retval;
            created = true;
        }
    }

    UA_ByteString encTrustList = UA_BYTESTRING_NULL;
    UA_FileContext *fileContext = NULL;
    if(ctx->checkSessionCallbackId == 0) {
        retval = UA_Server_addRepeatedCallback(server, checkSessionActive, ctx,
                                               CHECKACTIVESESSIONINTERVAL,
                                               &ctx->checkSessionCallbackId);
        if(retval != UA_STATUSCODE_GOOD)
            goto errout;
    }

    UA_TrustListDataType trustList;
    UA_TrustListDataType_init(&trustList);
    trustList.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    retval = certGroup->getTrustList(certGroup, &trustList);
    filterTrustList(&trustList, UA_TRUSTLISTMASKS_ALL);
    if(retval == UA_STATUSCODE_GOOD)
        retval = UA_encodeBinary(&trustList, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE],
                                 &encTrustList, NULL);
    UA_TrustListDataType_clear(&trustList);
    if(retval != UA_STATUSCODE_GOOD)
        goto errout;

    fileContext = (UA_FileContext*)UA_calloc(1, sizeof(UA_FileContext));
    if(!fileContext) {
        retval = UA_STATUSCODE_BADOUTOFMEMORY;
        goto errout;
    }
    fileContext->file = encTrustList;
    encTrustList = UA_BYTESTRING_NULL;
    fileContext->sessionId = *sessionId;
    fileContext->openFileMode = fileOpenMode;
    fileContext->currentPos = 0;
    fileContext->dataToWrite = UA_BYTESTRING_NULL;
    retval = createFileHandleId(fileInfo, &fileContext->fileHandle);
    if(retval == UA_STATUSCODE_GOOD)
        retval = UA_Variant_setScalarCopy(output, &fileContext->fileHandle,
                                          &UA_TYPES[UA_TYPES_UINT32]);
    if(retval != UA_STATUSCODE_GOOD)
        goto errout;

    fileInfo->openCount += 1;
    LIST_INSERT_HEAD(&fileInfo->fileContext, fileContext, listEntry);

    /* Updating OpenCount Variable in the information model */
    UA_GDSPush_writeOpenCount(ctx, certGroup);
    return UA_STATUSCODE_GOOD;

 errout:
    /* A failed call does not change the transaction state (Part 12, 7.10.2) */
    if(fileContext) {
        UA_ByteString_clear(&fileContext->file);
        UA_free(fileContext);
    }
    UA_ByteString_clear(&encTrustList);
    if(created)
        UA_GDSTransaction_clear(transaction);
    return retval;
}

static void
secureChannel_delayedClose(void *application, void *context) {
    UA_GDSPushContext *ctx = (UA_GDSPushContext*)context;
    UA_GDSTransactionChanges *changes = (UA_GDSTransactionChanges*)application;

    /* Close the SecureChannels that use an updated certificate type */
    UA_GDSTransaction *transaction = &ctx->transaction;
    if(*changes == UA_GDSTRANSACTIONCHANGES_CERTIFICATE ||
       *changes == UA_GDSTRANSACTIONCHANGES_BOTH) {
        for(size_t i = 0; i < transaction->certificateInfosSize; i++)
            UA_GDSCore_closeChannels(&ctx->core, 1,
                                     &transaction->certificateInfos[i].certificateType);
    }

    /* Close the SecureChannels whose remote certificate is no longer valid
     * with the new TrustList */
    if(*changes == UA_GDSTRANSACTIONCHANGES_TRUSTLIST ||
       *changes == UA_GDSTRANSACTIONCHANGES_BOTH)
        UA_GDSCore_verifyChannels(&ctx->core);

    UA_free(changes);
    transaction->applyChangesQueued = false;
    UA_GDSTransaction_clear(transaction);
    UA_GDSCore_delayedCallbackDone(&ctx->core);
}

static UA_StatusCode
updateCertificateLocked(UA_GDSPushDriver *driver,
                        const UA_NodeId certificateGroupId,
                        const UA_NodeId certificateTypeId,
                        const UA_ByteString certificate,
                        const UA_ByteString *privateKey) {
    UA_GDSPushContext *ctx = (UA_GDSPushContext*)driver;
    if(ctx->drv.state != UA_LIFECYCLESTATE_STARTED)
        return UA_STATUSCODE_BADINVALIDSTATE;

    static UA_NodeId defaultApplicationGroup =
        STATIC_NS0ID(SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_NodeId certGroupId = certificateGroupId;
    if(UA_NodeId_isNull(&certGroupId))
        certGroupId = defaultApplicationGroup;
    if(!UA_NodeId_equal(&certGroupId, &defaultApplicationGroup))
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* Bad_TransactionPending while a transaction is pending */
    return UA_GDSCore_updateCertificate(&ctx->core, UA_GDSREQUESTOWNER_PUSH,
                                        &certificateTypeId, certificate,
                                        privateKey ? *privateKey : UA_BYTESTRING_NULL);
}

UA_StatusCode
UA_GDSPushDriver_updateCertificate(UA_GDSPushDriver *driver,
                                 const UA_NodeId certificateGroupId,
                                 const UA_NodeId certificateTypeId,
                                 const UA_ByteString certificate,
                                 const UA_ByteString *privateKey) {
    if(!driver || certificate.length == 0)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(!driver->drv.server)
        return UA_STATUSCODE_BADINVALIDSTATE;

    UA_ServerConfig *sc = UA_Server_getConfig(driver->drv.server);
    sc->eventLoop->lock(sc->eventLoop);
    UA_StatusCode res = updateCertificateLocked(driver, certificateGroupId,
                                                certificateTypeId, certificate,
                                                privateKey);
    sc->eventLoop->unlock(sc->eventLoop);
    return res;
}

static UA_StatusCode
createSigningRequestLocked(UA_GDSPushDriver *driver,
                           const UA_NodeId certificateGroupId,
                           const UA_NodeId certificateTypeId,
                           const UA_String *subjectName,
                           const UA_Boolean *regenerateKey,
                           const UA_ByteString *nonce,
                           UA_ByteString *csr) {
    UA_GDSPushContext *ctx = (UA_GDSPushContext*)driver;
    if(ctx->drv.state != UA_LIFECYCLESTATE_STARTED)
        return UA_STATUSCODE_BADINVALIDSTATE;

    static UA_NodeId defaultApplicationGroup =
        STATIC_NS0ID(SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_NodeId certGroupId = certificateGroupId;
    if(UA_NodeId_isNull(&certGroupId))
        certGroupId = defaultApplicationGroup;
    if(!UA_NodeId_equal(&certGroupId, &defaultApplicationGroup))
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    return UA_GDSCore_createSigningRequest(&ctx->core, UA_GDSREQUESTOWNER_PUSH,
                                           &certificateTypeId, subjectName, nonce,
                                           regenerateKey && *regenerateKey, csr);
}

UA_StatusCode
UA_GDSPushDriver_createSigningRequest(UA_GDSPushDriver *driver,
                                    const UA_NodeId certificateGroupId,
                                    const UA_NodeId certificateTypeId,
                                    const UA_String *subjectName,
                                    const UA_Boolean *regenerateKey,
                                    const UA_ByteString *nonce,
                                    UA_ByteString *csr) {
    if(!driver || !csr)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(!driver->drv.server)
        return UA_STATUSCODE_BADINVALIDSTATE;

    UA_ServerConfig *sc = UA_Server_getConfig(driver->drv.server);
    sc->eventLoop->lock(sc->eventLoop);
    UA_StatusCode res = createSigningRequestLocked(
        driver, certificateGroupId, certificateTypeId, subjectName,
        regenerateKey, nonce, csr);
    sc->eventLoop->unlock(sc->eventLoop);
    return res;
}

static UA_StatusCode
UA_GDSPush_applyChanges(UA_GDSPushContext *ctx) {
    UA_Server *server = ctx->drv.server;
    UA_ServerConfig *sc = UA_Server_getConfig(server);
    UA_GDSTransaction *transaction = &ctx->transaction;
    if(transaction->applyChangesQueued)
        return UA_STATUSCODE_BADINVALIDSTATE;

    /* No changes are applied while a TrustList is open for writing (Part 12,
     * 7.10.9) */
    if(hasWriteHandle(ctx, NULL, NULL))
        return UA_STATUSCODE_BADINVALIDSTATE;

    /* Verify that the changes are consistent before anything is applied. The
     * Certificates are validated with the final TrustLists (Part 12, 7.10.2). */
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < transaction->certificateInfosSize; i++) {
        UA_GDSCertificateInfo *certInfo = &transaction->certificateInfos[i];
        UA_CertificateGroup *liveGroup =
            UA_GDSPush_getCertGroup(server, &certInfo->certificateGroup);
        if(!liveGroup) {
            UA_GDSTransaction_clear(transaction);
            return UA_STATUSCODE_BADINTERNALERROR;
        }
        retval = UA_GDSPush_validateCertificate(ctx, &transaction->sessionId,
                                                    liveGroup, &certInfo->certificate);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING(sc->logging, UA_LOGCATEGORY_SERVER,
                           "ApplyChanges: A staged Certificate is not valid with "
                           "the new TrustList (%s). The changes are discarded.",
                           UA_StatusCode_name(retval));
            UA_GDSTransaction_clear(transaction);
            return retval;
        }
    }

    UA_GDSTransactionChanges *changes = (UA_GDSTransactionChanges*)
        UA_calloc(1, sizeof(UA_GDSTransactionChanges));
    if(!changes)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    size_t groupsSize = transaction->certGroupSize;
    size_t appliedGroups = 0;
    UA_CertificateGroup **groups = NULL;
    UA_TrustListDataType *newTrustLists = NULL;
    UA_TrustListDataType *oldTrustLists = NULL;

    /* Prepare the certificate updates of the ServerConfiguration before
     * anything is changed. Then a failure of one certificate type does not
     * leave the others applied. */
    UA_GDSCertificateUpdate *updates = NULL;
    if(transaction->certificateInfosSize > 0) {
        updates = (UA_GDSCertificateUpdate*)
            UA_calloc(transaction->certificateInfosSize,
                      sizeof(UA_GDSCertificateUpdate));
        if(!updates) {
            retval = UA_STATUSCODE_BADOUTOFMEMORY;
            goto cleanup;
        }
        for(size_t i = 0; i < transaction->certificateInfosSize; i++) {
            UA_GDSCertificateInfo *certInfo = &transaction->certificateInfos[i];
            retval = UA_GDSCertificateUpdate_prepare(&updates[i], sc,
                                                     &certInfo->certificateType,
                                                     &certInfo->certificate);
            if(retval != UA_STATUSCODE_GOOD)
                goto cleanup;
        }
    }

    if(groupsSize > 0) {
        groups = (UA_CertificateGroup**)UA_calloc(groupsSize, sizeof(void*));
        newTrustLists = (UA_TrustListDataType*)
            UA_calloc(groupsSize, sizeof(UA_TrustListDataType));
        oldTrustLists = (UA_TrustListDataType*)
            UA_calloc(groupsSize, sizeof(UA_TrustListDataType));
        if(!groups || !newTrustLists || !oldTrustLists) {
            retval = UA_STATUSCODE_BADOUTOFMEMORY;
            goto cleanup;
        }
    }

    /* Resolve every live group and snapshot both the staged and current trust
     * lists before mutating configuration. The snapshots permit rolling back
     * all trust-list changes if any subsequent operation fails. */
    for(size_t i = 0; i < groupsSize; i++) {
        UA_CertificateGroup *stagedGroup = &transaction->certGroups[i];
        groups[i] = UA_GDSPush_getCertGroup(server, &stagedGroup->certificateGroupId);
        if(!groups[i]) {
            retval = UA_STATUSCODE_BADINTERNALERROR;
            goto cleanup;
        }
        newTrustLists[i].specifiedLists = UA_TRUSTLISTMASKS_ALL;
        oldTrustLists[i].specifiedLists = UA_TRUSTLISTMASKS_ALL;
        retval = stagedGroup->getTrustList(stagedGroup, &newTrustLists[i]);
        if(retval == UA_STATUSCODE_GOOD)
            retval = groups[i]->getTrustList(groups[i], &oldTrustLists[i]);
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup;
    }

    for(size_t i = 0; i < groupsSize; i++) {
        /* Include the current group in rollback even if its plugin reports an
         * error after partially changing its internal state. */
        appliedGroups = i + 1;
        retval = groups[i]->setTrustList(groups[i], &newTrustLists[i]);
        if(retval != UA_STATUSCODE_GOOD)
            goto rollback;
    }

    /* Apply the prepared certificate changes of the ServerConfiguration */
    for(size_t i = 0; i < transaction->certificateInfosSize; i++) {
        UA_GDSCertificateInfo *certInfo = &transaction->certificateInfos[i];
        retval = UA_GDSCertificateUpdate_commit(&updates[i], sc,
                                                certInfo->certificate,
                                                certInfo->privateKey);
        if(retval != UA_STATUSCODE_GOOD) {
            if(i > 0)
                UA_LOG_ERROR(sc->logging, UA_LOGCATEGORY_SERVER,
                             "ApplyChanges: %u of %u certificates were updated "
                             "and cannot be rolled back", (unsigned)i,
                             (unsigned)transaction->certificateInfosSize);
            goto rollback;
        }

        /* The pending signing request of the type is completed */
        UA_GDSCore_certificateInstalled(&ctx->core, UA_GDSREQUESTOWNER_PUSH,
                                        &certInfo->certificateType,
                                        &certInfo->certificate);
    }

    if(groupsSize > 0 && transaction->certificateInfosSize > 0)
        *changes = UA_GDSTRANSACTIONCHANGES_BOTH;
    else if(groupsSize > 0)
        *changes = UA_GDSTRANSACTIONCHANGES_TRUSTLIST;
    else if(transaction->certificateInfosSize > 0)
        *changes = UA_GDSTRANSACTIONCHANGES_CERTIFICATE;

    /* Publish metadata only after the complete transaction has succeeded. */
    for(size_t i = 0; i < groupsSize; i++) {
        UA_FileInfo *fileInfo =
            UA_GDSPush_getFileInfo(ctx, groups[i]->certificateGroupId);
        UA_assert(fileInfo != NULL);
        fileInfo->lastUpdateTime = UA_DateTime_now();
        UA_GDSPush_writeLastUpdateTime(ctx, groups[i]);
    }

    /* Add to the delayed callback list. Will be cleaned up in the next
     * eventloop iteration. This is required so that the apply function can
     * return a statuscode before the SecureChannel is closed. */
    UA_DelayedCallback *dc = &transaction->dc;
    dc->callback = secureChannel_delayedClose;
    dc->application = changes;
    dc->context = ctx;

    transaction->applyChangesQueued = true;
    UA_GDSCore_addDelayedCallback(&ctx->core, dc);
    for(size_t i = 0; i < groupsSize; i++) {
        UA_TrustListDataType_clear(&newTrustLists[i]);
        UA_TrustListDataType_clear(&oldTrustLists[i]);
    }
    UA_free(groups);
    UA_free(newTrustLists);
    UA_free(oldTrustLists);
    UA_free(updates); /* All updates were committed and cleared */
    return UA_STATUSCODE_GOOD;

rollback:
    while(appliedGroups > 0) {
        appliedGroups--;
        UA_StatusCode rollbackRes = groups[appliedGroups]->setTrustList(
            groups[appliedGroups], &oldTrustLists[appliedGroups]);
        if(rollbackRes != UA_STATUSCODE_GOOD)
            UA_LOG_ERROR(sc->logging, UA_LOGCATEGORY_SERVER,
                         "Could not roll back a GDS Push trust-list update");
    }

cleanup:
    if(newTrustLists) {
        for(size_t i = 0; i < groupsSize; i++)
            UA_TrustListDataType_clear(&newTrustLists[i]);
    }
    if(oldTrustLists) {
        for(size_t i = 0; i < groupsSize; i++)
            UA_TrustListDataType_clear(&oldTrustLists[i]);
    }
    UA_free(groups);
    UA_free(newTrustLists);
    UA_free(oldTrustLists);
    if(updates) {
        for(size_t i = 0; i < transaction->certificateInfosSize; i++)
            UA_GDSCertificateUpdate_clear(&updates[i]);
        UA_free(updates);
    }
    UA_GDSTransaction_clear(transaction);
    UA_free(changes);
    return retval;
}

static void
secureChannelNotificationCallback(UA_Driver *drv,
                                  UA_ApplicationNotificationType type,
                                  const UA_KeyValueMap payload) {
    UA_GDSPushContext *ctx = (UA_GDSPushContext*)drv;
    UA_GDSCore_handleNotification(&ctx->core, type, payload);
}

static UA_StatusCode
UA_GDSPush_start(UA_Driver *drv) {
    UA_GDSPushContext *ctx = (UA_GDSPushContext*)drv;

    /* The certificate types of the endpoints can change while the driver is
     * stopped */
    UA_StatusCode slotRes = UA_GDSCore_updateSlots(&ctx->core);
    if(slotRes != UA_STATUSCODE_GOOD)
        return slotRes;

    /* Initialize ns0 entries only once */
    if(!ctx->initialized) {
        UA_StatusCode res = UA_GDSPush_initNS0(ctx);
        if(res != UA_STATUSCODE_GOOD)
            return res;
#ifdef UA_ENABLE_RBAC
        /* Restrict the GDS methods to the SecurityAdmin role. Runs after the
         * ns0 GDS nodes have been created so the permissions can be applied.
         * The AccessControl plugin can restrict the methods as well. So a
         * failure is only logged. */
        res = UA_GDSPush_initRolePermissions(drv->server);
        if(res != UA_STATUSCODE_GOOD) {
            UA_ServerConfig *sc = UA_Server_getConfig(drv->server);
            UA_LOG_WARNING(sc->logging, UA_LOGCATEGORY_SERVER,
                           "Could not restrict the PushManagement methods to "
                           "the SecurityAdmin role (%s). Only the AccessControl "
                           "restricts them.", UA_StatusCode_name(res));
        }
#endif
        ctx->initialized = true;
    } else {
        UA_StatusCode res = UA_GDSPush_writeCertificateTypes(ctx);
        if(res != UA_STATUSCODE_GOOD)
            return res;
    }

    drv->state = UA_LIFECYCLESTATE_STARTED;

    return UA_STATUSCODE_GOOD;
}

static void
UA_GDSPush_stop(UA_Driver *drv) {
    UA_GDSPushContext *ctx = (UA_GDSPushContext*)drv;
    if(ctx->initialized) {
        UA_GDSPush_clearNS0(ctx);
        ctx->initialized = false;
    }
    if(ctx->checkSessionCallbackId != 0) {
        UA_Server_removeCallback(drv->server, ctx->checkSessionCallbackId);
        ctx->checkSessionCallbackId = 0;
    }

    /* The Sessions end with the server. Discard their transaction and the
     * handles of open TrustLists. */
    if(!ctx->transaction.applyChangesQueued)
        UA_GDSTransaction_clear(&ctx->transaction);
    for(UA_FileInfo *fi = ctx->fileInfos; fi; fi = fi->next) {
        UA_FileContext *fileContext, *fileContextTmp;
        LIST_FOREACH_SAFE(fileContext, &fi->fileContext, listEntry, fileContextTmp)
            UA_FileContext_delete(fi, fileContext);
        fi->openCount = 0;
    }

    if(ctx->core.pendingDelayedCallbacks > 0)
        drv->state = UA_LIFECYCLESTATE_STOPPING;
    else
        drv->state = UA_LIFECYCLESTATE_STOPPED;
}

static UA_StatusCode
UA_GDSPush_free(UA_Driver *drv) {
    if(drv->state != UA_LIFECYCLESTATE_STOPPED) {
        if(drv->server) {
            UA_ServerConfig *sc = UA_Server_getConfig(drv->server);
            UA_LOG_ERROR(sc->logging, UA_LOGCATEGORY_SERVER,
                         "Cannot delete the GDS Push driver because "
                         "it is not stopped");
        }
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_GDSPushContext *ctx = (UA_GDSPushContext*)drv;
    ctx->checkSessionCallbackId = 0;
    UA_GDSTransaction_clear(&ctx->transaction);
    UA_GDSCore_clear(&ctx->core);
    UA_FileInfo *fi = (UA_FileInfo*)ctx->fileInfos;

    /* free all fileInfoContexts */
    while(fi) {
        UA_FileInfo *next = fi->next;
        UA_FileContext *fileContext = NULL;
        UA_FileContext *fileContextTmp = NULL;

        /* free all fileContexts in this fileInfo */
        LIST_FOREACH_SAFE(fileContext, &fi->fileContext, listEntry, fileContextTmp) {
            UA_ByteString_clear(&fileContext->file);
            UA_ByteString_clear(&fileContext->dataToWrite);
            LIST_REMOVE(fileContext, listEntry);
            UA_free(fileContext);
        }

        UA_free(fi);
        fi = next;
    }

    UA_KeyValueMap_clear(&drv->params);
    UA_free(drv);
    return UA_STATUSCODE_GOOD;
}

/* The changes of a transaction are pending until its delayed callback ran */
static UA_Boolean
coreChangesPending(UA_GDSCore *core) {
    return UA_GDSPush_transactionPending((UA_GDSPushContext*)core->drv);
}

/* A TrustList was changed outside of a transaction (by the GDS Pull driver) */
static void
coreTrustListChanged(UA_GDSCore *core, UA_CertificateGroup *group) {
    UA_GDSPushContext *ctx = (UA_GDSPushContext*)core->drv;
    UA_FileInfo *fileInfo = UA_GDSPush_getFileInfo(ctx, group->certificateGroupId);
    if(!fileInfo)
        return;
    fileInfo->lastUpdateTime = UA_DateTime_now();
    UA_GDSPush_writeLastUpdateTime(ctx, group);
}

UA_GDSPushDriver *
UA_GDSPushDriver_new(const UA_KeyValueMap params) {
    UA_GDSPushContext *ctx = (UA_GDSPushContext*)UA_calloc(1, sizeof(UA_GDSPushContext));
    if(!ctx)
        return NULL;
    if(UA_KeyValueMap_copy(&params, &ctx->drv.params) != UA_STATUSCODE_GOOD) {
        UA_free(ctx);
        return NULL;
    }

    ctx->drv.driverType = UA_DRIVERTYPE_GDS_PUSH;
    ctx->drv.name = UA_STRING("gds-push");
    ctx->drv.start = UA_GDSPush_start;
    ctx->drv.stop = UA_GDSPush_stop;
    ctx->drv.free = UA_GDSPush_free;

    ctx->drv.notificationCallback = secureChannelNotificationCallback;
    ctx->drv.notificationFilter = UA_APPLICATIONNOTIFICATIONTYPE_SECURECHANNEL;

    UA_GDSCore_init(&ctx->core, &ctx->drv);
    ctx->core.changesPending = coreChangesPending;
    ctx->core.trustListChanged = coreTrustListChanged;

    return (UA_GDSPushDriver*)ctx;
}

#endif
