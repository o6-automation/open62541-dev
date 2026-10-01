/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2024 (c) Fraunhofer IOSB (Author: Noel Graf)
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Julius Pfrommer)
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#include <open62541/plugin/certificategroup_default.h>
#include "gds_receiver_internal.h"

#ifdef UA_ENABLE_DRIVER_GDS_RECEIVER

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

typedef struct ChannelMetadata {
    LIST_ENTRY(ChannelMetadata) pointers;
    UA_UInt32 channelId;
    UA_NodeId certificateTypeId;
    UA_ByteString certificate;
} ChannelMetadata;

struct UA_GDSReceiverContext {
    UA_Driver drv;
    UA_Boolean initialized;
    UA_GDSTransaction transaction;
    UA_FileInfo *fileInfos;
    LIST_HEAD(, ChannelMetadata) secureChannels;
    UA_UInt64 checkSessionCallbackId;
    size_t pendingDelayedCallbacks;
    /* The CertificateType slots of the DefaultApplicationGroup. They are
     * updated when the receiver starts. */
    size_t serverSlotsSize;
    UA_GDSCertificateSlot *serverSlots;
};

typedef enum UA_GDSTransactionChanges {
    UA_GDSTRANSACTIONCHANGES_NOTHING = 0,
    UA_GDSTRANSACTIONCHANGES_TRUSTLIST,
    UA_GDSTRANSACTIONCHANGES_CERTIFICATE,
    UA_GDSTRANSACTIONCHANGES_BOTH,
} UA_GDSTransactionChanges;

/************************/
/* CertificateType Slots */
/************************/

void
UA_GDSCertificateSlot_clearPending(UA_GDSCertificateSlot *slot) {
    UA_ByteString_clear(&slot->pendingCsr);
}

UA_GDSCertificateSlot *
UA_GDSCertificateSlots_find(UA_GDSCertificateSlot *slots, size_t slotsSize,
                            const UA_NodeId *certificateTypeId) {
    for(size_t i = 0; i < slotsSize; i++) {
        if(UA_NodeId_equal(&slots[i].certificateTypeId, certificateTypeId))
            return &slots[i];
    }
    return NULL;
}

void
UA_GDSCertificateSlots_delete(UA_GDSCertificateSlot *slots, size_t slotsSize) {
    for(size_t i = 0; i < slotsSize; i++) {
        UA_GDSCertificateSlot_clearPending(&slots[i]);
        UA_NodeId_clear(&slots[i].certificateTypeId);
    }
    UA_free(slots);
}

UA_GDSCertificateSlot *
UA_GDSReceiver_serverSlots(UA_GDSReceiverContext *ctx, size_t *slotsSize) {
    *slotsSize = ctx->serverSlotsSize;
    return ctx->serverSlots;
}

static UA_StatusCode
UA_GDSReceiver_applyChanges(UA_GDSReceiverContext *ctx);

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
UA_GDSReceiver_getFileInfo(UA_GDSReceiverContext *ctx,
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
hasWriteHandle(UA_GDSReceiverContext *ctx, const UA_FileInfo *fileInfo,
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
closeSessionWriteHandles(UA_GDSReceiverContext *ctx, const UA_NodeId *sessionId) {
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
        UA_CertificateGroup *certGroup = getCertGroup(ctx->drv.server,
                                                      &fi->certificateGroupId);
        if(closed && certGroup)
            writeOpenCountVariable(ctx, certGroup);
    }
}

/* Close a write handle and discard its data (Part 12, 7.8.2.5). A transaction
 * without staged changes and without other write handles is closed. */
static void
closeWriteHandle(UA_GDSReceiverContext *ctx, UA_CertificateGroup *certGroup,
                 UA_FileInfo *fileInfo, UA_FileContext *fileContext) {
    UA_NodeId sessionId;
    UA_StatusCode res = UA_NodeId_copy(&fileContext->sessionId, &sessionId);
    UA_FileContext_delete(fileInfo, fileContext);
    writeOpenCountVariable(ctx, certGroup);
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
UA_GDSReceiver_checkTransaction(UA_GDSReceiverContext *ctx,
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
verifyCertificate(UA_GDSReceiverContext *ctx, UA_CertificateGroup *group,
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
UA_GDSReceiver_validateCertificate(UA_GDSReceiverContext *ctx,
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
verifyTrustList(UA_GDSReceiverContext *ctx, UA_CertificateGroup *group) {
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
UA_GDSReceiver_initFileInfos(UA_GDSReceiverContext *ctx, UA_UtcTime lastUpdateTime) {
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
UA_GDSReceiver_getFileInfoMetadata(UA_GDSReceiverContext *ctx,
                                  const UA_NodeId certificateGroupId,
                                  UA_UInt16 *openCount,
                                  UA_UtcTime *lastUpdateTime) {
    UA_FileInfo *fi = UA_GDSReceiver_getFileInfo(ctx, certificateGroupId);
    if(!fi)
        return UA_STATUSCODE_BADNOTFOUND;
    *openCount = fi->openCount;
    *lastUpdateTime = fi->lastUpdateTime;
    return UA_STATUSCODE_GOOD;
}

UA_Boolean
UA_GDSReceiver_transactionPending(UA_GDSReceiverContext *ctx) {
    return ctx->transaction.state != UA_GDSTRANSACTIONSTATE_FRESH;
}

UA_StatusCode
UA_GDSReceiver_applyChangesForSession(UA_GDSReceiverContext *ctx,
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
    return UA_GDSReceiver_applyChanges(ctx);
}

UA_StatusCode
UA_GDSReceiver_cancelChangesForSession(UA_GDSReceiverContext *ctx,
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

    UA_GDSReceiverContext *ctx = (UA_GDSReceiverContext*)data;
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
            getCertGroup(server, &fi->certificateGroupId);
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
            writeOpenCountVariable(ctx, certGroup);
        }
    }

    if(removingCallback) {
        UA_Server_removeCallback(server, ctx->checkSessionCallbackId);
        ctx->checkSessionCallbackId = 0;
    }

    el->unlock(el);
}

UA_StatusCode
UA_GDSReceiver_getPositionTrustList(UA_GDSReceiverContext *ctx, UA_CertificateGroup *certGroup,
                                   const UA_NodeId *sessionId, UA_UInt32 fileHandle,
                                   UA_Variant *output) {
    UA_assert(certGroup != NULL);
    UA_FileInfo *fileInfo =
        UA_GDSReceiver_getFileInfo(ctx, certGroup->certificateGroupId);
    if(!fileInfo)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_FileContext *fileContext = getFileContext(fileInfo, sessionId, fileHandle);
    if(!fileContext)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    return UA_Variant_setScalarCopy(output, &fileContext->currentPos,
                                    &UA_TYPES[UA_TYPES_UINT64]);
}

UA_StatusCode
UA_GDSReceiver_setPositionTrustList(UA_GDSReceiverContext *ctx, UA_CertificateGroup *certGroup,
                                   const UA_NodeId *sessionId, UA_UInt32 fileHandle,
                                   UA_UInt64 position) {
    UA_assert(certGroup != NULL);
    UA_FileInfo *fileInfo =
        UA_GDSReceiver_getFileInfo(ctx, certGroup->certificateGroupId);
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
UA_GDSReceiver_writeTrustList(UA_GDSReceiverContext *ctx, UA_CertificateGroup *certGroup,
                             const UA_NodeId *sessionId, UA_UInt32 fileHandle,
                             const UA_ByteString data) {
    UA_assert(certGroup != NULL);
    UA_Server *server = ctx->drv.server;
    UA_ServerConfig *sc = UA_Server_getConfig(server);

    UA_FileInfo *fileInfo =
        UA_GDSReceiver_getFileInfo(ctx, certGroup->certificateGroupId);
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
UA_GDSReceiver_closeAndUpdateTrustList(UA_GDSReceiverContext *ctx,
                                      UA_CertificateGroup *certGroup,
                                      const UA_NodeId *sessionId,
                                      UA_UInt32 fileHandle,
                                      UA_Variant *output) {
    UA_assert(certGroup != NULL);
    UA_ServerConfig *sc = UA_Server_getConfig(ctx->drv.server);

    UA_GDSTransaction *transaction = &ctx->transaction;
    UA_FileInfo *fileInfo =
        UA_GDSReceiver_getFileInfo(ctx, certGroup->certificateGroupId);
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
    writeOpenCountVariable(ctx, certGroup);

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
UA_GDSReceiver_closeTrustList(UA_GDSReceiverContext *ctx,
                             UA_CertificateGroup *certGroup,
                             const UA_NodeId *sessionId,
                             UA_UInt32 fileHandle) {
    UA_assert(certGroup != NULL);

    UA_FileInfo *fileInfo =
        UA_GDSReceiver_getFileInfo(ctx, certGroup->certificateGroupId);
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
    writeOpenCountVariable(ctx, certGroup);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_GDSReceiver_readTrustList(UA_GDSReceiverContext *ctx, UA_CertificateGroup *certGroup,
                            const UA_NodeId *sessionId, UA_UInt32 fileHandle,
                            UA_Int32 length, UA_Variant *output) {
    UA_assert(certGroup != NULL);

    UA_FileInfo *fileInfo =
        UA_GDSReceiver_getFileInfo(ctx, certGroup->certificateGroupId);
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
UA_GDSReceiver_addCertificate(UA_GDSReceiverContext *ctx,
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
        UA_GDSReceiver_getFileInfo(ctx, certGroup->certificateGroupId);
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
    writeLastUpdateVariable(ctx, certGroup);
    return UA_STATUSCODE_GOOD;
}

/* Does the Certificate belong to the current key of a SecurityPolicy with the
 * CertificateType? */
static UA_Boolean
matchesCurrentKey(UA_ServerConfig *sc, const UA_NodeId *certificateTypeId,
                  const UA_ByteString *certificate) {
    for(size_t i = 0; i < sc->securityPoliciesSize; i++) {
        UA_SecurityPolicy *sp = &sc->securityPolicies[i];
        if(sp->policyType == UA_SECURITYPOLICYTYPE_NONE ||
           !UA_NodeId_equal(&sp->certificateTypeId, certificateTypeId) ||
           sp->localCertificate.length == 0)
            continue;
        if(UA_CertificateUtils_comparePublicKeys(certificate, &sp->localCertificate) ==
           UA_STATUSCODE_GOOD)
            return true;
    }
    return false;
}

UA_StatusCode
UA_GDSReceiver_stageCertificateUpdate(UA_GDSReceiverContext *ctx,
                                const UA_NodeId *sessionId,
                                const UA_NodeId *certificateGroupId,
                                const UA_NodeId *certificateTypeId,
                                const UA_ByteString *certificate,
                                const UA_String *privateKeyFormat,
                                const UA_ByteString *privateKey) {
    UA_Server *server = ctx->drv.server;
    UA_ServerConfig *sc = UA_Server_getConfig(server);

    /* Another Session has a transaction (Part 12, 7.10.5) */
    UA_StatusCode retval = UA_GDSReceiver_checkTransaction(ctx, sessionId);
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

    /* The certificate type must be one of the CertificateTypes of the group */
    UA_GDSCertificateSlot *slot =
        UA_GDSCertificateSlots_find(ctx->serverSlots, ctx->serverSlotsSize,
                                    certificateTypeId);
    if(!slot)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    if(!certificate || certificate->length == 0)
        return UA_STATUSCODE_BADCERTIFICATEINVALID;

    if(privateKey && privateKey->length > 0) {
        /* Verify that the privateKey is in a supported format and that it
         * matches the specified certificate */
        const UA_String pemFormat = UA_STRING("PEM");
        const UA_String derFormat = UA_STRING("DER");
        if(!privateKeyFormat || (!UA_String_equal(&pemFormat, privateKeyFormat) &&
                                 !UA_String_equal(&derFormat, privateKeyFormat)))
            return UA_STATUSCODE_BADNOTSUPPORTED;
        if(UA_CertificateUtils_checkKeyPair(certificate, privateKey) !=
           UA_STATUSCODE_GOOD)
            return UA_STATUSCODE_BADNOTSUPPORTED;
    } else {
        /* Validate the certificate before staging a keyless update. */
        size_t keySize = 0;
        if(UA_CertificateUtils_getKeySize((UA_ByteString*)(uintptr_t)certificate,
                                          &keySize) != UA_STATUSCODE_GOOD)
            return UA_STATUSCODE_BADCERTIFICATEINVALID;

        /* Without a PrivateKey, the Certificate has to belong to the current
         * key or to the key of the last CreateSigningRequest */
        if(!matchesCurrentKey(sc, certificateTypeId, certificate) &&
           (slot->pendingCsr.length == 0 ||
            UA_CertificateUtils_comparePublicKeys(certificate,
                                                  &slot->pendingCsr) !=
            UA_STATUSCODE_GOOD))
            return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
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
    UA_CertificateGroup *certGroup = getCertGroup(server, certificateGroupId);
    if(!certGroup)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    retval = UA_GDSReceiver_validateCertificate(ctx, sessionId, certGroup,
                                                certificate);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* A queued ApplyChanges is refused by UA_GDSReceiver_checkTransaction
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
UA_GDSReceiver_removeCertificate(UA_GDSReceiverContext *ctx,
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
        UA_GDSReceiver_getFileInfo(ctx, certGroup->certificateGroupId);
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
    retval = UA_GDSReceiver_applyChanges(ctx);

cleanup:
    UA_free(validBefore);
    UA_TrustListDataType_clear(&trustList);
    UA_Array_delete(crls, crlsSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(retval != UA_STATUSCODE_GOOD)
        UA_GDSTransaction_clear(transaction);
    return retval;
}

UA_StatusCode
UA_GDSReceiver_getRejectedList(UA_GDSReceiverContext *ctx, size_t outputSize,
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
UA_GDSReceiver_openTrustListWithMask(UA_GDSReceiverContext *ctx, UA_CertificateGroup *certGroup,
                                    const UA_NodeId *sessionId, UA_UInt32 mask,
                                    UA_Variant *output) {
    UA_assert(certGroup != NULL);
    UA_Server *server = ctx->drv.server;

    if(!certGroup->getTrustList)
        return UA_STATUSCODE_BADNOTSUPPORTED;

    /* Reading is possible during a transaction, but not while the TrustList is
     * open for writing (Part 12, 7.8.2.5 and Part 20) */
    UA_FileInfo *fileInfo =
        UA_GDSReceiver_getFileInfo(ctx, certGroup->certificateGroupId);
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
    writeOpenCountVariable(ctx, certGroup);

    LIST_INSERT_HEAD(&fileInfo->fileContext, fileContext, listEntry);

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_GDSReceiver_openTrustList(UA_GDSReceiverContext *ctx, UA_CertificateGroup *certGroup,
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
        UA_GDSReceiver_getFileInfo(ctx, certGroup->certificateGroupId);
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
        retval = UA_GDSReceiver_checkTransaction(ctx, sessionId);
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
    writeOpenCountVariable(ctx, certGroup);
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
    UA_GDSReceiverContext *ctx = (UA_GDSReceiverContext*)context;
    UA_Server *server = ctx->drv.server;
    UA_ServerConfig *sc = UA_Server_getConfig(server);
    UA_GDSTransactionChanges *changes = (UA_GDSTransactionChanges*)application;

    ChannelMetadata *cm;
    UA_CertificateGroup *certGroup = &sc->secureChannelPKI;
    switch(*changes) {
    case UA_GDSTRANSACTIONCHANGES_NOTHING:
        break;

    case UA_GDSTRANSACTIONCHANGES_BOTH:
    case UA_GDSTRANSACTIONCHANGES_CERTIFICATE:
        /* Shutdown SecureChannels that use an updated certificate type. */
        LIST_FOREACH(cm, &ctx->secureChannels, pointers) {
            UA_Boolean certificateTypeUpdated = false;
            for(size_t i = 0; i < ctx->transaction.certificateInfosSize; i++) {
                UA_GDSCertificateInfo *certInfo =
                    &ctx->transaction.certificateInfos[i];
                if(UA_NodeId_equal(&cm->certificateTypeId,
                                   &certInfo->certificateType)) {
                    certificateTypeUpdated = true;
                    break;
                }
            }
            if(!certificateTypeUpdated)
                continue;
            UA_Server_closeSecureChannel(server, cm->channelId,
                                         UA_SHUTDOWNREASON_CLOSE);
        }
        break;

    default:
        /* Re-verify remote certificates. Close the SecureChannel on failure. */
        LIST_FOREACH(cm, &ctx->secureChannels, pointers) {
            UA_StatusCode res =
                certGroup->verifyCertificate(certGroup, &cm->certificate);
            if(res != UA_STATUSCODE_GOOD)
                UA_Server_closeSecureChannel(server, cm->channelId,
                                             UA_SHUTDOWNREASON_CLOSE);
        }
        break;
    }

    UA_free(changes);
    ctx->transaction.applyChangesQueued = false;
    UA_GDSTransaction_clear(&ctx->transaction);
    UA_assert(ctx->pendingDelayedCallbacks > 0);
    ctx->pendingDelayedCallbacks--;
    if(ctx->pendingDelayedCallbacks == 0 &&
       ctx->drv.state == UA_LIFECYCLESTATE_STOPPING)
        ctx->drv.state = UA_LIFECYCLESTATE_STOPPED;
}

static UA_SecurityPolicy *
getSecPolicyByUri(UA_ServerConfig *sc, const UA_String *securityPolicyUri) {
    for(size_t i = 0; i < sc->securityPoliciesSize; i++) {
        UA_SecurityPolicy *sp = &sc->securityPolicies[i];
        if(UA_String_equal(securityPolicyUri, &sp->policyUri))
            return sp;
    }
    return NULL;
}

/* The ApplicationCertificateTypes the receiver can update, in the order of
 * the CertificateTypes Property (Part 12, 7.8.4) */
static const UA_UInt32 knownCertificateTypes[] = {
    UA_NS0ID_RSAMINAPPLICATIONCERTIFICATETYPE,
    UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE
};

/* Does an endpoint use a SecurityPolicy of the DefaultApplicationGroup with
 * the certificate type? Otherwise an update would have no effect. */
static UA_Boolean
endpointUsesCertificateType(UA_ServerConfig *sc,
                            const UA_NodeId *certificateTypeId) {
    static UA_NodeId defaultApplicationGroup =
        STATIC_NS0ID(SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    for(size_t i = 0; i < sc->endpointsSize; i++) {
        UA_SecurityPolicy *sp =
            getSecPolicyByUri(sc, &sc->endpoints[i].securityPolicyUri);
        if(sp && UA_NodeId_equal(&sp->certificateTypeId, certificateTypeId) &&
           UA_NodeId_equal(&sp->certificateGroupId, &defaultApplicationGroup))
            return true;
    }
    return false;
}

/* Create the slots of the ServerConfiguration for the certificate types that
 * an endpoint uses. Pending signing requests of the remaining types are
 * kept. */
static UA_StatusCode
updateServerSlots(UA_GDSReceiverContext *ctx) {
    UA_ServerConfig *sc = UA_Server_getConfig(ctx->drv.server);
    const size_t knownSize =
        sizeof(knownCertificateTypes) / sizeof(knownCertificateTypes[0]);
    UA_GDSCertificateSlot *slots = (UA_GDSCertificateSlot*)
        UA_calloc(knownSize, sizeof(UA_GDSCertificateSlot));
    if(!slots)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    size_t slotsSize = 0;
    for(size_t i = 0; i < knownSize; i++) {
        UA_NodeId typeId = UA_NODEID_NUMERIC(0, knownCertificateTypes[i]);
        if(!endpointUsesCertificateType(sc, &typeId))
            continue;
        UA_GDSCertificateSlot *slot = &slots[slotsSize++];
        slot->certificateTypeId = typeId; /* Numeric, nothing to copy */
        UA_GDSCertificateSlot *old =
            UA_GDSCertificateSlots_find(ctx->serverSlots, ctx->serverSlotsSize,
                                        &typeId);
        if(old) {
            slot->pendingCsr = old->pendingCsr;
            UA_ByteString_init(&old->pendingCsr);
        }
    }
    UA_GDSCertificateSlots_delete(ctx->serverSlots, ctx->serverSlotsSize);
    ctx->serverSlots = slots;
    ctx->serverSlotsSize = slotsSize;
    return UA_STATUSCODE_GOOD;
}

/* The SecurityPolicies and endpoints changed by a certificate update */
typedef struct {
    size_t policiesSize;
    UA_SecurityPolicy **policies;
    size_t endpointsSize;
    UA_ByteString *endpointCertificates; /* Empty for unchanged endpoints */
} UA_GDSCertificateUpdate;

static void
UA_GDSCertificateUpdate_clear(UA_GDSCertificateUpdate *update) {
    for(size_t i = 0; i < update->endpointsSize; i++)
        UA_ByteString_clear(&update->endpointCertificates[i]);
    UA_free(update->endpointCertificates);
    UA_free(update->policies);
    memset(update, 0, sizeof(UA_GDSCertificateUpdate));
}

/* Resolve every SecurityPolicy and endpoint that uses the certificate type and
 * allocate the replacement endpoint certificates. Nothing is changed, so
 * configuration and allocation errors are reported before any live policy is
 * changed. A SecurityPolicy referenced by multiple endpoints is updated only
 * once. */
static UA_StatusCode
prepareCertificateUpdate(UA_ServerConfig *sc,
                         const UA_NodeId *certificateTypeId,
                         const UA_ByteString *certificate,
                         UA_GDSCertificateUpdate *update) {
    memset(update, 0, sizeof(UA_GDSCertificateUpdate));
    update->policies = (UA_SecurityPolicy**)
        UA_calloc(sc->endpointsSize + 1, sizeof(UA_SecurityPolicy*));
    update->endpointCertificates = (UA_ByteString*)
        UA_calloc(sc->endpointsSize + 1, sizeof(UA_ByteString));
    if(!update->policies || !update->endpointCertificates) {
        UA_GDSCertificateUpdate_clear(update);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    update->endpointsSize = sc->endpointsSize;

    UA_StatusCode res = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < sc->endpointsSize; i++) {
        UA_EndpointDescription *ed = &sc->endpoints[i];
        UA_SecurityPolicy *sp = getSecPolicyByUri(sc, &ed->securityPolicyUri);
        if(!sp) {
            res = UA_STATUSCODE_BADINTERNALERROR;
            goto errout;
        }
        if(!UA_NodeId_equal(&sp->certificateTypeId, certificateTypeId))
            continue;

        res = UA_ByteString_copy(certificate, &update->endpointCertificates[i]);
        if(res != UA_STATUSCODE_GOOD)
            goto errout;

        size_t j = 0;
        for(; j < update->policiesSize; j++) {
            if(update->policies[j] == sp)
                break;
        }
        if(j == update->policiesSize)
            update->policies[update->policiesSize++] = sp;
    }

    /* No endpoint uses the certificate type. The update would have no
     * effect. */
    if(update->policiesSize == 0) {
        res = UA_STATUSCODE_BADINVALIDARGUMENT;
        goto errout;
    }

    /* A SecurityPolicy#None endpoint presents the certificate of the None
     * SecurityPolicy, which is usually the replaced certificate. Update it as
     * well, so that all endpoints present the same certificate. */
    size_t typePolicies = update->policiesSize;
    for(size_t i = 0; i < sc->endpointsSize; i++) {
        if(update->endpointCertificates[i].length > 0)
            continue;
        UA_SecurityPolicy *sp =
            getSecPolicyByUri(sc, &sc->endpoints[i].securityPolicyUri);
        if(!sp || sp->policyType != UA_SECURITYPOLICYTYPE_NONE ||
           sp->localCertificate.length == 0)
            continue;

        UA_Boolean replaced = false;
        for(size_t j = 0; j < typePolicies; j++) {
            if(UA_ByteString_equal(&sp->localCertificate,
                                   &update->policies[j]->localCertificate))
                replaced = true;
        }
        size_t j = typePolicies;
        for(; j < update->policiesSize; j++) {
            if(update->policies[j] == sp)
                break;
        }
        if(j == update->policiesSize && !replaced)
            continue;

        res = UA_ByteString_copy(certificate, &update->endpointCertificates[i]);
        if(res != UA_STATUSCODE_GOOD)
            goto errout;
        if(j == update->policiesSize)
            update->policies[update->policiesSize++] = sp;
    }
    return UA_STATUSCODE_GOOD;

 errout:
    UA_GDSCertificateUpdate_clear(update);
    return res;
}

/* Update the SecurityPolicies and commit the prepared endpoint certificates.
 * SecurityPolicy implementations update their private state directly and do
 * not expose the previous private key for rollback. An unexpected failure from
 * a policy after an earlier policy succeeded is therefore logged explicitly.
 * The update is cleared. */
static UA_StatusCode
commitCertificateUpdate(UA_ServerConfig *sc, UA_GDSCertificateUpdate *update,
                        const UA_ByteString certificate,
                        const UA_ByteString privateKey) {
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < update->policiesSize; i++) {
        res = update->policies[i]->updateCertificate(update->policies[i],
                                                     certificate, privateKey);
        if(res != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR(sc->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                         "Updating the certificate failed after %u of %u "
                         "SecurityPolicies were updated",
                         (unsigned)i, (unsigned)update->policiesSize);
            UA_GDSCertificateUpdate_clear(update);
            return res;
        }
    }

    /* Commit the preallocated endpoint certificates without further errors */
    for(size_t i = 0; i < update->endpointsSize && i < sc->endpointsSize; i++) {
        if(update->endpointCertificates[i].length == 0)
            continue;
        UA_ByteString_clear(&sc->endpoints[i].serverCertificate);
        sc->endpoints[i].serverCertificate = update->endpointCertificates[i];
        UA_ByteString_init(&update->endpointCertificates[i]);
    }
    UA_GDSCertificateUpdate_clear(update);
    return UA_STATUSCODE_GOOD;
}

typedef struct {
    UA_DelayedCallback dc;
    UA_GDSReceiverContext *ctx;
    UA_NodeId certificateTypeId;
} CloseChannelsCallback;

static void
closeChannelsAfterCertificateUpdate(void *application, void *context) {
    CloseChannelsCallback *ccb = (CloseChannelsCallback*)context;
    UA_GDSReceiverContext *ctx = ccb->ctx;
    ChannelMetadata *cm, *cmTmp;
    LIST_FOREACH_SAFE(cm, &ctx->secureChannels, pointers, cmTmp) {
        if(!UA_NodeId_equal(&cm->certificateTypeId, &ccb->certificateTypeId))
            continue;
        UA_Server_closeSecureChannel(ctx->drv.server, cm->channelId,
                                     UA_SHUTDOWNREASON_CLOSE);
    }
    UA_assert(ctx->pendingDelayedCallbacks > 0);
    ctx->pendingDelayedCallbacks--;
    if(ctx->pendingDelayedCallbacks == 0 &&
       ctx->drv.state == UA_LIFECYCLESTATE_STOPPING)
        ctx->drv.state = UA_LIFECYCLESTATE_STOPPED;
    UA_NodeId_clear(&ccb->certificateTypeId);
    UA_free(ccb);
}

static UA_StatusCode
updateCertificateLocked(UA_GDSReceiver *receiver,
                        const UA_NodeId certificateGroupId,
                        const UA_NodeId certificateTypeId,
                        const UA_ByteString certificate,
                        const UA_ByteString *privateKey) {
    UA_GDSReceiverContext *ctx = (UA_GDSReceiverContext*)receiver;
    if(ctx->drv.state != UA_LIFECYCLESTATE_STARTED)
        return UA_STATUSCODE_BADINVALIDSTATE;
    if(ctx->transaction.state == UA_GDSTRANSACTIONSTATE_PENDING)
        return UA_STATUSCODE_BADTRANSACTIONPENDING;

    static UA_NodeId defaultApplicationGroup =
        STATIC_NS0ID(SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_NodeId certGroupId = certificateGroupId;
    if(UA_NodeId_isNull(&certGroupId))
        certGroupId = defaultApplicationGroup;
    if(!UA_NodeId_equal(&certGroupId, &defaultApplicationGroup))
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    static UA_NodeId certTypRsaSha256 =
        STATIC_NS0ID(RSASHA256APPLICATIONCERTIFICATETYPE);
    if(!UA_NodeId_equal(&certificateTypeId, &certTypRsaSha256))
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_ByteString newPrivateKey = UA_BYTESTRING_NULL;
    if(privateKey) {
        if(UA_CertificateUtils_checkKeyPair(&certificate, privateKey) !=
           UA_STATUSCODE_GOOD)
            return UA_STATUSCODE_BADNOTSUPPORTED;
        newPrivateKey = *privateKey;
    } else {
        size_t keySize = 0;
        if(UA_CertificateUtils_getKeySize((UA_ByteString*)(uintptr_t)&certificate,
                                          &keySize) != UA_STATUSCODE_GOOD)
            return UA_STATUSCODE_BADCERTIFICATEINVALID;
    }

    UA_Server *server = receiver->drv.server;
    UA_ServerConfig *sc = UA_Server_getConfig(server);
    CloseChannelsCallback *ccb =
        (CloseChannelsCallback*)UA_calloc(1, sizeof(CloseChannelsCallback));
    if(!ccb)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    ccb->ctx = ctx;
    UA_StatusCode res =
        UA_NodeId_copy(&certificateTypeId, &ccb->certificateTypeId);
    if(res != UA_STATUSCODE_GOOD) {
        UA_free(ccb);
        return res;
    }

    UA_GDSCertificateUpdate update;
    res = prepareCertificateUpdate(sc, &certificateTypeId, &certificate, &update);
    if(res == UA_STATUSCODE_GOOD)
        res = commitCertificateUpdate(sc, &update, certificate, newPrivateKey);
    if(res != UA_STATUSCODE_GOOD) {
        UA_NodeId_clear(&ccb->certificateTypeId);
        UA_free(ccb);
        return res;
    }

    ccb->dc.callback = closeChannelsAfterCertificateUpdate;
    ccb->dc.context = ccb;
    ctx->pendingDelayedCallbacks++;
    sc->eventLoop->addDelayedCallback(sc->eventLoop, &ccb->dc);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_GDSReceiver_updateCertificate(UA_GDSReceiver *receiver,
                                 const UA_NodeId certificateGroupId,
                                 const UA_NodeId certificateTypeId,
                                 const UA_ByteString certificate,
                                 const UA_ByteString *privateKey) {
    if(!receiver || certificate.length == 0)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(!receiver->drv.server)
        return UA_STATUSCODE_BADINVALIDSTATE;

    UA_ServerConfig *sc = UA_Server_getConfig(receiver->drv.server);
    sc->eventLoop->lock(sc->eventLoop);
    UA_StatusCode res = updateCertificateLocked(receiver, certificateGroupId,
                                                certificateTypeId, certificate,
                                                privateKey);
    sc->eventLoop->unlock(sc->eventLoop);
    return res;
}

static UA_StatusCode
createSigningRequestLocked(UA_GDSReceiver *receiver,
                           const UA_NodeId certificateGroupId,
                           const UA_NodeId certificateTypeId,
                           const UA_String *subjectName,
                           const UA_Boolean *regenerateKey,
                           const UA_ByteString *nonce,
                           UA_ByteString *csr) {
    UA_GDSReceiverContext *ctx = (UA_GDSReceiverContext*)receiver;
    if(ctx->drv.state != UA_LIFECYCLESTATE_STARTED)
        return UA_STATUSCODE_BADINVALIDSTATE;

    static UA_NodeId defaultApplicationGroup =
        STATIC_NS0ID(SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_NodeId certGroupId = certificateGroupId;
    if(UA_NodeId_isNull(&certGroupId))
        certGroupId = defaultApplicationGroup;
    if(!UA_NodeId_equal(&certGroupId, &defaultApplicationGroup))
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* Without a SecurityPolicy for the certificate type, no CSR would be
     * created */
    UA_ServerConfig *sc = UA_Server_getConfig(receiver->drv.server);
    UA_GDSCertificateSlot *slot =
        UA_GDSCertificateSlots_find(ctx->serverSlots, ctx->serverSlotsSize,
                                    &certificateTypeId);
    if(!slot)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    if(!UA_NodeId_equal(&sc->secureChannelPKI.certificateGroupId,
                        &defaultApplicationGroup))
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_ByteString *newPrivateKey = NULL;
    if(regenerateKey && *regenerateKey) {
        newPrivateKey = UA_ByteString_new();
        if(!newPrivateKey)
            return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    /* The first SecurityPolicy creates the request (and the new key). The
     * others take over the new key. Several endpoints can share a policy,
     * which is called only once. */
    UA_SecurityPolicy **called = (UA_SecurityPolicy**)
        UA_calloc(sc->endpointsSize + 1, sizeof(UA_SecurityPolicy*));
    size_t calledSize = 0;
    if(!called) {
        retval = UA_STATUSCODE_BADOUTOFMEMORY;
        goto cleanup;
    }
    for(size_t i = 0; i < sc->endpointsSize; i++) {
        UA_SecurityPolicy *sp =
            getSecPolicyByUri(sc, &sc->endpoints[i].securityPolicyUri);
        if(!sp) {
            retval = UA_STATUSCODE_BADINTERNALERROR;
            goto cleanup;
        }
        if(sp->policyType == UA_SECURITYPOLICYTYPE_NONE)
            continue;
        if(!UA_NodeId_equal(&certificateTypeId, &sp->certificateTypeId) ||
           !UA_NodeId_equal(&certGroupId, &sp->certificateGroupId))
            continue;
        size_t j = 0;
        for(; j < calledSize; j++) {
            if(called[j] == sp)
                break;
        }
        if(j < calledSize)
            continue;
        called[calledSize++] = sp;

        retval = sp->createSigningRequest(sp, subjectName, nonce,
                                          &UA_KEYVALUEMAP_NULL, csr,
                                          newPrivateKey);
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup;
    }

    /* Remember the request for the certificate update without a private key */
    UA_ByteString pendingCsr = UA_BYTESTRING_NULL;
    retval = UA_ByteString_copy(csr, &pendingCsr);
    if(retval == UA_STATUSCODE_GOOD) {
        UA_GDSCertificateSlot_clearPending(slot);
        slot->pendingCsr = pendingCsr;
    }

cleanup:
    UA_free(called);
    if(newPrivateKey) {
        UA_ByteString_memZero(newPrivateKey);
        UA_ByteString_delete(newPrivateKey);
    }
    return retval;
}

UA_StatusCode
UA_GDSReceiver_createSigningRequest(UA_GDSReceiver *receiver,
                                    const UA_NodeId certificateGroupId,
                                    const UA_NodeId certificateTypeId,
                                    const UA_String *subjectName,
                                    const UA_Boolean *regenerateKey,
                                    const UA_ByteString *nonce,
                                    UA_ByteString *csr) {
    if(!receiver || !csr)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(!receiver->drv.server)
        return UA_STATUSCODE_BADINVALIDSTATE;

    UA_ServerConfig *sc = UA_Server_getConfig(receiver->drv.server);
    sc->eventLoop->lock(sc->eventLoop);
    UA_StatusCode res = createSigningRequestLocked(
        receiver, certificateGroupId, certificateTypeId, subjectName,
        regenerateKey, nonce, csr);
    sc->eventLoop->unlock(sc->eventLoop);
    return res;
}

static UA_StatusCode
UA_GDSReceiver_applyChanges(UA_GDSReceiverContext *ctx) {
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
            getCertGroup(server, &certInfo->certificateGroup);
        if(!liveGroup) {
            UA_GDSTransaction_clear(transaction);
            return UA_STATUSCODE_BADINTERNALERROR;
        }
        retval = UA_GDSReceiver_validateCertificate(ctx, &transaction->sessionId,
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
            retval = prepareCertificateUpdate(sc, &certInfo->certificateType,
                                              &certInfo->certificate, &updates[i]);
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
        groups[i] = getCertGroup(server, &stagedGroup->certificateGroupId);
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
        retval = commitCertificateUpdate(sc, &updates[i], certInfo->certificate,
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
        UA_GDSCertificateSlot *slot =
            UA_GDSCertificateSlots_find(ctx->serverSlots, ctx->serverSlotsSize,
                                        &certInfo->certificateType);
        if(slot)
            UA_GDSCertificateSlot_clearPending(slot);
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
            UA_GDSReceiver_getFileInfo(ctx, groups[i]->certificateGroupId);
        UA_assert(fileInfo != NULL);
        fileInfo->lastUpdateTime = UA_DateTime_now();
        writeLastUpdateVariable(ctx, groups[i]);
    }

    /* Add to the delayed callback list. Will be cleaned up in the next
     * eventloop iteration. This is required so that the apply function can
     * return a statuscode before the SecureChannel is closed. */
    UA_DelayedCallback *dc = &transaction->dc;
    dc->callback = secureChannel_delayedClose;
    dc->application = changes;
    dc->context = ctx;

    UA_EventLoop *el = sc->eventLoop;
    transaction->applyChangesQueued = true;
    ctx->pendingDelayedCallbacks++;
    el->addDelayedCallback(el, dc);
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
                         "Could not roll back a GDS Receiver trust-list update");
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
    UA_GDSReceiverContext *ctx = (UA_GDSReceiverContext*)drv;
    if(type == UA_APPLICATIONNOTIFICATIONTYPE_SECURECHANNEL_OPENED) {
        UA_UInt32 channelId = *(const UA_UInt32*)
            UA_KeyValueMap_getScalar(&payload,
                                     UA_QUALIFIEDNAME(0, "securechannel-id"),
                                     &UA_TYPES[UA_TYPES_UINT32]);
        UA_ByteString certificate = *(const UA_ByteString*)
            UA_KeyValueMap_getScalar(&payload,
                                     UA_QUALIFIEDNAME(0, "remote-certificate"),
                                     &UA_TYPES[UA_TYPES_BYTESTRING]);
        const UA_NodeId *certificateTypeId = (const UA_NodeId*)
            UA_KeyValueMap_getScalar(&payload,
                                     UA_QUALIFIEDNAME(0, "certificate-type-id"),
                                     &UA_TYPES[UA_TYPES_NODEID]);
        if(!certificateTypeId)
            return;

        ChannelMetadata *cm = (ChannelMetadata*)UA_calloc(1, sizeof(ChannelMetadata));
        if(!cm) {
            UA_ServerConfig *sc = UA_Server_getConfig(drv->server);
            UA_LOG_WARNING(sc->logging, UA_LOGCATEGORY_SERVER,
                           "Could not register SecureChannel (oom)");
            return;
        }
        cm->channelId = channelId;
        UA_StatusCode res = UA_NodeId_copy(certificateTypeId,
                                           &cm->certificateTypeId);
        res |= UA_ByteString_copy(&certificate, &cm->certificate);
        if(res != UA_STATUSCODE_GOOD) {
            UA_NodeId_clear(&cm->certificateTypeId);
            UA_ByteString_clear(&cm->certificate);
            UA_free(cm);
            return;
        }
        LIST_INSERT_HEAD(&ctx->secureChannels, cm, pointers);
    } else if(type == UA_APPLICATIONNOTIFICATIONTYPE_SECURECHANNEL_CLOSED) {
        UA_UInt32 channelId = *(const UA_UInt32*)
            UA_KeyValueMap_getScalar(&payload,
                                     UA_QUALIFIEDNAME(0, "securechannel-id"),
                                     &UA_TYPES[UA_TYPES_UINT32]);
        ChannelMetadata *cm;
        LIST_FOREACH(cm, &ctx->secureChannels, pointers) {
            if(cm->channelId != channelId)
                continue;
            LIST_REMOVE(cm, pointers);
            UA_NodeId_clear(&cm->certificateTypeId);
            UA_ByteString_clear(&cm->certificate);
            UA_free(cm);
            break;
        }
    }
}

static UA_StatusCode
UA_GDSReceiver_start(UA_Driver *drv) {
    UA_GDSReceiverContext *ctx = (UA_GDSReceiverContext*)drv;

    /* The certificate types of the endpoints can change while the receiver is
     * stopped */
    UA_StatusCode slotRes = updateServerSlots(ctx);
    if(slotRes != UA_STATUSCODE_GOOD)
        return slotRes;

    /* Initialize ns0 entries only once */
    if(!ctx->initialized) {
        UA_StatusCode res = initNS0PushManagement(ctx);
        if(res != UA_STATUSCODE_GOOD)
            return res;
#ifdef UA_ENABLE_RBAC
        /* Restrict the GDS methods to the SecurityAdmin role. Runs after the
         * ns0 GDS nodes have been created so the permissions can be applied.
         * The AccessControl plugin can restrict the methods as well. So a
         * failure is only logged. */
        res = initGDSRolePermissions(drv->server);
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
        UA_StatusCode res = writeServerCertificateTypes(ctx);
        if(res != UA_STATUSCODE_GOOD)
            return res;
    }

    drv->state = UA_LIFECYCLESTATE_STARTED;

    return UA_STATUSCODE_GOOD;
}

static void
UA_GDSReceiver_stop(UA_Driver *drv) {
    UA_GDSReceiverContext *ctx = (UA_GDSReceiverContext*)drv;
    if(ctx->initialized) {
        clearNS0PushManagement(ctx);
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

    if(ctx->pendingDelayedCallbacks > 0)
        drv->state = UA_LIFECYCLESTATE_STOPPING;
    else
        drv->state = UA_LIFECYCLESTATE_STOPPED;
}

static UA_StatusCode
UA_GDSReceiver_free(UA_Driver *drv) {
    if(drv->state != UA_LIFECYCLESTATE_STOPPED) {
        if(drv->server) {
            UA_ServerConfig *sc = UA_Server_getConfig(drv->server);
            UA_LOG_ERROR(sc->logging, UA_LOGCATEGORY_SERVER,
                         "Cannot delete the GDS Receiver driver because "
                         "it is not stopped");
        }
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_GDSReceiverContext *ctx = (UA_GDSReceiverContext*)drv;
    ctx->checkSessionCallbackId = 0;
    UA_GDSTransaction_clear(&ctx->transaction);
    UA_GDSCertificateSlots_delete(ctx->serverSlots, ctx->serverSlotsSize);
    ctx->serverSlots = NULL;
    ctx->serverSlotsSize = 0;
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

    /* Free SecureChannel Metadata */
    ChannelMetadata *cm, *cm_tmp;
    LIST_FOREACH_SAFE(cm, &ctx->secureChannels, pointers, cm_tmp) {
        LIST_REMOVE(cm, pointers);
        UA_NodeId_clear(&cm->certificateTypeId);
        UA_ByteString_clear(&cm->certificate);
        UA_free(cm);
    }

    UA_free(drv);
    return UA_STATUSCODE_GOOD;
}

UA_GDSReceiver *
UA_GDSReceiver_new(void) {
    UA_GDSReceiverContext *ctx = (UA_GDSReceiverContext*)UA_calloc(1, sizeof(UA_GDSReceiverContext));
    if(!ctx)
        return NULL;

    ctx->drv.driverType = UA_DRIVERTYPE_GDS_RECEIVER;
    ctx->drv.name = UA_STRING("gds-receiver");
    ctx->drv.start = UA_GDSReceiver_start;
    ctx->drv.stop = UA_GDSReceiver_stop;
    ctx->drv.free = UA_GDSReceiver_free;

    ctx->drv.notificationCallback = secureChannelNotificationCallback;
    ctx->drv.notificationFilter = UA_APPLICATIONNOTIFICATIONTYPE_SECURECHANNEL;

    return (UA_GDSReceiver*)ctx;
}

#endif
