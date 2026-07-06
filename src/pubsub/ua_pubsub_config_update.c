/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2025 Fraunhofer IOSB (Author: Andreas Ebner)
 */

#include <open62541/server_pubsub.h>

#if defined(UA_ENABLE_PUBSUB) && defined(UA_ENABLE_PUBSUB_FILE_CONFIG)

#include "ua_pubsub_internal.h"

/* Incremental update of the PubSub configuration with the semantics of the
 * Part 14 CloseAndUpdate method (9.1.3.7.6). The update file provides the
 * configuration elements, the references select the elements and the
 * operation (add/match/modify/remove).
 *
 * Limitations of this implementation (documented in the result codes):
 * - SecurityGroup and PushTarget references are not supported
 *   (Bad_ResourceUnavailable per element).
 * - Modify of PublishedDataSets and SubscribedDataSets is not supported
 *   (Bad_NotImplemented per element) -- changing the field list of a PDS
 *   requires recreating it (remove + add in one call).
 * - With requireCompleteUpdate the validation pass cannot cover every
 *   runtime condition. Errors in the apply phase are reported per element
 *   but already-applied operations are not rolled back (best effort).
 * - The automatic WriterGroupId/DataSetWriterId assignment does not consult
 *   the session ReserveIds reservations of the caller (no session context in
 *   the C API). The NS0 CloseAndUpdate front-end can pass reserved ids
 *   explicitly in the file elements. */

#define UA_REFMASK_OPBITS                                   \
    (UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |             \
     UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMATCH |           \
     UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMODIFY |          \
     UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTREMOVE)

#define UA_REFMASK_REFBITS                                  \
    (UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITER |        \
     UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADER |        \
     UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP |   \
     UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADERGROUP |   \
     UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION |    \
     UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEPUBDATASET |    \
     UA_PUBSUBCONFIGURATIONREFMASK_REFERENCESUBDATASET |    \
     UA_PUBSUBCONFIGURATIONREFMASK_REFERENCESECURITYGROUP | \
     UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEPUSHTARGET)

/* One reference resolved into the update file */
typedef struct {
    const UA_PubSubConfigurationRefDataType *ref;
    size_t inputIndex;
    UA_UInt32 op;     /* the operation bits */
    UA_UInt32 refbit; /* the single reference bit */
    UA_StatusCode status;

    /* Resolved file elements. The connection/group entries are also resolved
     * for child references (they provide the parent names). */
    const UA_PubSubConnectionDataType *fileConn;
    const UA_WriterGroupDataType *fileWg;
    const UA_ReaderGroupDataType *fileRg;
    const UA_DataSetWriterDataType *fileDsw;
    const UA_DataSetReaderDataType *fileDsr;
    const UA_PublishedDataSetDataType *filePds;
    const UA_StandaloneSubscribedDataSetDataType *fileSsds;
} UA_ConfigUpdateOp;

/*********************/
/* Lookups by name   */
/*********************/

static UA_PubSubConnection *
findConnectionByName(UA_PubSubManager *psm, const UA_String name) {
    UA_PubSubConnection *c;
    TAILQ_FOREACH(c, &psm->connections, listEntry) {
        if(UA_String_equal(&c->config.name, &name))
            return c;
    }
    return NULL;
}

static UA_WriterGroup *
findWriterGroupByName(UA_PubSubConnection *c, const UA_String name) {
    UA_WriterGroup *wg;
    LIST_FOREACH(wg, &c->writerGroups, listEntry) {
        if(UA_String_equal(&wg->config.name, &name))
            return wg;
    }
    return NULL;
}

static UA_ReaderGroup *
findReaderGroupByName(UA_PubSubConnection *c, const UA_String name) {
    UA_ReaderGroup *rg;
    LIST_FOREACH(rg, &c->readerGroups, listEntry) {
        if(UA_String_equal(&rg->config.name, &name))
            return rg;
    }
    return NULL;
}

static UA_DataSetWriter *
findDataSetWriterByName(UA_WriterGroup *wg, const UA_String name) {
    UA_DataSetWriter *dsw;
    LIST_FOREACH(dsw, &wg->writers, listEntry) {
        if(UA_String_equal(&dsw->config.name, &name))
            return dsw;
    }
    return NULL;
}

static UA_DataSetReader *
findDataSetReaderByName(UA_ReaderGroup *rg, const UA_String name) {
    UA_DataSetReader *dsr;
    LIST_FOREACH(dsr, &rg->readers, listEntry) {
        if(UA_String_equal(&dsr->config.name, &name))
            return dsr;
    }
    return NULL;
}

/*******************************/
/* Shadow state for validation */
/*******************************/

/* For the requireCompleteUpdate validation pass the effects of earlier
 * operations are tracked without mutating the live model. An element is
 * identified by the reference type and the names along its path. */
typedef struct {
    UA_UInt32 refbit;
    UA_String connName;  /* empty when not applicable */
    UA_String groupName; /* empty when not applicable */
    UA_String name;
} UA_ShadowEntry;

typedef struct {
    UA_ShadowEntry *added;
    size_t addedSize;
    UA_ShadowEntry *removed;
    size_t removedSize;
} UA_ShadowState;

static UA_Boolean
shadowContains(const UA_ShadowEntry *entries, size_t entriesSize,
               UA_UInt32 refbit, const UA_String connName,
               const UA_String groupName, const UA_String name) {
    for(size_t i = 0; i < entriesSize; i++) {
        if(entries[i].refbit == refbit &&
           UA_String_equal(&entries[i].connName, &connName) &&
           UA_String_equal(&entries[i].groupName, &groupName) &&
           UA_String_equal(&entries[i].name, &name))
            return true;
    }
    return false;
}

static void
shadowAdd(UA_ShadowEntry *entries, size_t *entriesSize, UA_UInt32 refbit,
          const UA_String connName, const UA_String groupName,
          const UA_String name) {
    entries[*entriesSize].refbit = refbit;
    entries[*entriesSize].connName = connName;
    entries[*entriesSize].groupName = groupName;
    entries[*entriesSize].name = name;
    (*entriesSize)++;
}

/* Extract the identifying names of an operation */
static void
opNames(const UA_ConfigUpdateOp *op, UA_String *connName,
        UA_String *groupName, UA_String *name) {
    *connName = UA_STRING_NULL;
    *groupName = UA_STRING_NULL;
    *name = UA_STRING_NULL;
    switch(op->refbit) {
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION:
        *name = op->fileConn->name; break;
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP:
        *connName = op->fileConn->name; *name = op->fileWg->name; break;
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADERGROUP:
        *connName = op->fileConn->name; *name = op->fileRg->name; break;
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITER:
        *connName = op->fileConn->name; *groupName = op->fileWg->name;
        *name = op->fileDsw->name; break;
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADER:
        *connName = op->fileConn->name; *groupName = op->fileRg->name;
        *name = op->fileDsr->name; break;
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEPUBDATASET:
        *name = op->filePds->name; break;
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCESUBDATASET:
        *name = op->fileSsds->name; break;
    default: break;
    }
}

/**********************/
/* Reference resolving */
/**********************/

static UA_StatusCode
resolveOp(const UA_PubSubConfiguration2DataType *cfg,
          const UA_PubSubConfigurationRefDataType *ref,
          UA_ConfigUpdateOp *op) {
    op->ref = ref;
    op->op = ref->configurationMask & UA_REFMASK_OPBITS;
    op->refbit = ref->configurationMask & UA_REFMASK_REFBITS;

    /* Unknown bits set */
    if(ref->configurationMask & ~(UA_REFMASK_OPBITS | UA_REFMASK_REFBITS))
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* Validate the operation bits. Allowed: Add, Match, Add|Match, Modify,
     * Remove. */
    if(op->op != UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD &&
       op->op != UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMATCH &&
       op->op != (UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                  UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMATCH) &&
       op->op != UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMODIFY &&
       op->op != UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTREMOVE)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* Exactly one reference bit */
    UA_UInt32 rb = op->refbit;
    if(rb == 0 || (rb & (rb - 1)) != 0)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* Match only for Connection, WriterGroup and ReaderGroup */
    if((op->op & UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMATCH) &&
       rb != UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION &&
       rb != UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP &&
       rb != UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADERGROUP)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* SecurityGroups and PushTargets are not supported */
    if(rb == UA_PUBSUBCONFIGURATIONREFMASK_REFERENCESECURITYGROUP ||
       rb == UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEPUSHTARGET)
        return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;

    /* Resolve the indices into the file configuration */
    switch(rb) {
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION:
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP:
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADERGROUP:
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITER:
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADER:
        if(ref->connectionIndex >= cfg->connectionsSize)
            return UA_STATUSCODE_BADINVALIDARGUMENT;
        op->fileConn = &cfg->connections[ref->connectionIndex];
        break;
    default:
        break;
    }

    switch(rb) {
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP:
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITER:
        if(ref->groupIndex >= op->fileConn->writerGroupsSize)
            return UA_STATUSCODE_BADINVALIDARGUMENT;
        op->fileWg = &op->fileConn->writerGroups[ref->groupIndex];
        if(rb == UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITER) {
            if(ref->elementIndex >= op->fileWg->dataSetWritersSize)
                return UA_STATUSCODE_BADINVALIDARGUMENT;
            op->fileDsw = &op->fileWg->dataSetWriters[ref->elementIndex];
        }
        break;
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADERGROUP:
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADER:
        if(ref->groupIndex >= op->fileConn->readerGroupsSize)
            return UA_STATUSCODE_BADINVALIDARGUMENT;
        op->fileRg = &op->fileConn->readerGroups[ref->groupIndex];
        if(rb == UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADER) {
            if(ref->elementIndex >= op->fileRg->dataSetReadersSize)
                return UA_STATUSCODE_BADINVALIDARGUMENT;
            op->fileDsr = &op->fileRg->dataSetReaders[ref->elementIndex];
        }
        break;
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEPUBDATASET:
        if(ref->elementIndex >= cfg->publishedDataSetsSize)
            return UA_STATUSCODE_BADINVALIDARGUMENT;
        op->filePds = &cfg->publishedDataSets[ref->elementIndex];
        break;
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCESUBDATASET:
        if(ref->elementIndex >= cfg->subscribedDataSetsSize)
            return UA_STATUSCODE_BADINVALIDARGUMENT;
        op->fileSsds = &cfg->subscribedDataSets[ref->elementIndex];
        break;
    default:
        break;
    }

    return UA_STATUSCODE_GOOD;
}

/*******************/
/* Match operation */
/*******************/

/* Compare only the provided KeyValuePairs against the live map */
static UA_Boolean
matchProperties(const UA_KeyValueMap *live, const UA_KeyValuePair *provided,
                size_t providedSize) {
    for(size_t i = 0; i < providedSize; i++) {
        const UA_Variant *value = UA_KeyValueMap_get(live, provided[i].key);
        if(!value)
            return false;
        if(UA_order(value, &provided[i].value,
                    &UA_TYPES[UA_TYPES_VARIANT]) != UA_ORDER_EQ)
            return false;
    }
    return true;
}

static UA_Boolean
orderEqual(const void *a, const void *b, const UA_DataType *type) {
    return (UA_order(a, b, type) == UA_ORDER_EQ);
}

static UA_Boolean
matchEndpointArrays(const UA_EndpointDescription *a, size_t aSize,
                    const UA_EndpointDescription *b, size_t bSize) {
    if(aSize != bSize)
        return false;
    for(size_t i = 0; i < aSize; i++) {
        if(!orderEqual(&a[i], &b[i], &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]))
            return false;
    }
    return true;
}

/* Field sets per Part 14 Table 239 */
static UA_Boolean
matchConnection(UA_PubSubConnection *c, const UA_PubSubConnectionDataType *p) {
    UA_PubSubConnectionDataType live;
    if(UA_PubSubConnectionConfig_toDataType(&c->config, &live) != UA_STATUSCODE_GOOD)
        return false;
    UA_Boolean res =
        UA_String_equal(&live.transportProfileUri, &p->transportProfileUri) &&
        orderEqual(&live.address, &p->address, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]) &&
        orderEqual(&live.transportSettings, &p->transportSettings,
                   &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]) &&
        matchProperties(&c->config.connectionProperties,
                        p->connectionProperties, p->connectionPropertiesSize);
    UA_PubSubConnectionDataType_clear(&live);
    return res;
}

static UA_Boolean
matchWriterGroup(UA_WriterGroup *wg, const UA_WriterGroupDataType *p) {
    UA_WriterGroupDataType live;
    if(UA_WriterGroupConfig_toDataType(&wg->config, &live) != UA_STATUSCODE_GOOD)
        return false;
    UA_Boolean res =
        live.securityMode == p->securityMode &&
        UA_String_equal(&live.securityGroupId, &p->securityGroupId) &&
        matchEndpointArrays(live.securityKeyServices, live.securityKeyServicesSize,
                            p->securityKeyServices, p->securityKeyServicesSize) &&
        live.maxNetworkMessageSize == p->maxNetworkMessageSize &&
        live.publishingInterval == p->publishingInterval &&
        live.keepAliveTime == p->keepAliveTime &&
        live.priority == p->priority &&
        UA_String_equal(&live.headerLayoutUri, &p->headerLayoutUri) &&
        orderEqual(&live.transportSettings, &p->transportSettings,
                   &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]) &&
        orderEqual(&live.messageSettings, &p->messageSettings,
                   &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]) &&
        matchProperties(&wg->config.groupProperties,
                        p->groupProperties, p->groupPropertiesSize);
    UA_WriterGroupDataType_clear(&live);
    return res;
}

static UA_Boolean
matchReaderGroup(UA_ReaderGroup *rg, const UA_ReaderGroupDataType *p) {
    UA_ReaderGroupDataType live;
    if(UA_ReaderGroupConfig_toDataType(&rg->config, &live) != UA_STATUSCODE_GOOD)
        return false;
    UA_Boolean res =
        live.securityMode == p->securityMode &&
        UA_String_equal(&live.securityGroupId, &p->securityGroupId) &&
        matchEndpointArrays(live.securityKeyServices, live.securityKeyServicesSize,
                            p->securityKeyServices, p->securityKeyServicesSize) &&
        live.maxNetworkMessageSize == p->maxNetworkMessageSize &&
        orderEqual(&live.transportSettings, &p->transportSettings,
                   &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]) &&
        orderEqual(&live.messageSettings, &p->messageSettings,
                   &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]) &&
        matchProperties(&rg->config.groupProperties,
                        p->groupProperties, p->groupPropertiesSize);
    UA_ReaderGroupDataType_clear(&live);
    return res;
}

/* An enabled WriterGroup with the GroupHeader flag in the
 * NetworkMessageContentMask cannot be matched (Bad_InvalidState) */
static UA_Boolean
writerGroupHeaderActive(UA_WriterGroup *wg) {
    if(!UA_PubSubState_isEnabled(wg->head.state))
        return false;
    const UA_ExtensionObject *ms = &wg->config.messageSettings;
    if(ms->encoding != UA_EXTENSIONOBJECT_DECODED ||
       ms->content.decoded.type != &UA_TYPES[UA_TYPES_UADPWRITERGROUPMESSAGEDATATYPE])
        return false;
    UA_UadpWriterGroupMessageDataType *m =
        (UA_UadpWriterGroupMessageDataType*)ms->content.decoded.data;
    return (m->networkMessageContentMask &
            UA_UADPNETWORKMESSAGECONTENTMASK_GROUPHEADER) != 0;
}

/*******************/
/* Name generation */
/*******************/

typedef UA_Boolean (*nameExistsCallback)(UA_PubSubManager *psm, void *context,
                                         const UA_String name);

static UA_String
generateUniqueName(UA_PubSubManager *psm, const char *prefix,
                   nameExistsCallback exists, void *context) {
    for(UA_UInt32 i = 1; i < 0xFFFF; i++) {
        UA_String candidate = UA_STRING_NULL;
        if(UA_String_format(&candidate, "%s %u", prefix,
                            (unsigned)i) != UA_STATUSCODE_GOOD)
            return UA_STRING_NULL;
        if(!exists(psm, context, candidate))
            return candidate; /* Allocated, the caller clears */
        UA_String_clear(&candidate);
    }
    return UA_STRING_NULL;
}

static UA_Boolean
connectionNameExists(UA_PubSubManager *psm, void *context, const UA_String name) {
    (void)context;
    return (findConnectionByName(psm, name) != NULL);
}

static UA_Boolean
writerGroupNameExists(UA_PubSubManager *psm, void *context, const UA_String name) {
    (void)psm;
    return (findWriterGroupByName((UA_PubSubConnection*)context, name) != NULL);
}

static UA_Boolean
readerGroupNameExists(UA_PubSubManager *psm, void *context, const UA_String name) {
    (void)psm;
    return (findReaderGroupByName((UA_PubSubConnection*)context, name) != NULL);
}

static UA_Boolean
dataSetWriterNameExists(UA_PubSubManager *psm, void *context, const UA_String name) {
    (void)psm;
    return (findDataSetWriterByName((UA_WriterGroup*)context, name) != NULL);
}

static UA_Boolean
dataSetReaderNameExists(UA_PubSubManager *psm, void *context, const UA_String name) {
    (void)psm;
    return (findDataSetReaderByName((UA_ReaderGroup*)context, name) != NULL);
}

static UA_Boolean
pdsNameExists(UA_PubSubManager *psm, void *context, const UA_String name) {
    (void)context;
    return (UA_PublishedDataSet_findByName(psm, name) != NULL);
}

static UA_Boolean
ssdsNameExists(UA_PubSubManager *psm, void *context, const UA_String name) {
    (void)context;
    return (UA_SubscribedDataSet_findByName(psm, name) != NULL);
}

/* Assign a free id from the internal range 0x8000-0xFFFF. Returns 0 when the
 * range is exhausted. */
static UA_UInt16
assignFreeId(UA_PubSubManager *psm, UA_String transportProfileUri,
             UA_ReserveIdType type) {
    for(UA_UInt32 id = 0x8000; id <= 0xFFFF; id++) {
        if(UA_ReserveId_isFree(psm, (UA_UInt16)id, transportProfileUri, type))
            return (UA_UInt16)id;
    }
    return 0;
}

/**********************/
/* Result bookkeeping */
/**********************/

static void
addConfigValue(UA_PubSubConfigUpdateResult *result,
               const UA_PubSubConfigurationRefDataType *ref,
               const UA_String name, const UA_Variant *identifier) {
    UA_PubSubConfigurationValueDataType *v =
        &result->configurationValues[result->configurationValuesSize];
    UA_PubSubConfigurationValueDataType_init(v);
    UA_StatusCode res =
        UA_PubSubConfigurationRefDataType_copy(ref, &v->configurationElement);
    res |= UA_String_copy(&name, &v->name);
    if(identifier)
        res |= UA_Variant_copy(identifier, &v->identifier);
    if(res != UA_STATUSCODE_GOOD) {
        UA_PubSubConfigurationValueDataType_clear(v);
        return;
    }
    result->configurationValuesSize++;
}

/*********************/
/* Remove operations */
/*********************/

/* Run an operation on a writer/reader with the parent group temporarily
 * disabled (the component model requires a disabled group for
 * add/remove/update of writers and readers) */
static UA_StatusCode
applyRemove(UA_PubSubManager *psm, UA_ConfigUpdateOp *op, UA_NodeId *objId) {
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    switch(op->refbit) {
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION: {
        UA_PubSubConnection *c = findConnectionByName(psm, op->fileConn->name);
        if(!c)
            return UA_STATUSCODE_BADNOMATCH;
        *objId = c->head.identifier;
        return UA_PubSubConnection_delete(psm, c);
    }
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP: {
        UA_PubSubConnection *c = findConnectionByName(psm, op->fileConn->name);
        UA_WriterGroup *wg = (c) ?
            findWriterGroupByName(c, op->fileWg->name) : NULL;
        if(!wg)
            return UA_STATUSCODE_BADNOMATCH;
        *objId = wg->head.identifier;
        return UA_WriterGroup_remove(psm, wg);
    }
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADERGROUP: {
        UA_PubSubConnection *c = findConnectionByName(psm, op->fileConn->name);
        UA_ReaderGroup *rg = (c) ?
            findReaderGroupByName(c, op->fileRg->name) : NULL;
        if(!rg)
            return UA_STATUSCODE_BADNOMATCH;
        *objId = rg->head.identifier;
        return UA_ReaderGroup_remove(psm, rg);
    }
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITER: {
        UA_PubSubConnection *c = findConnectionByName(psm, op->fileConn->name);
        UA_WriterGroup *wg = (c) ?
            findWriterGroupByName(c, op->fileWg->name) : NULL;
        UA_DataSetWriter *dsw = (wg) ?
            findDataSetWriterByName(wg, op->fileDsw->name) : NULL;
        if(!dsw)
            return UA_STATUSCODE_BADNOMATCH;
        *objId = dsw->head.identifier;
        UA_Boolean wasEnabled = UA_PubSubState_isEnabled(wg->head.state);
        if(wasEnabled)
            UA_WriterGroup_setPubSubState(psm, wg, UA_PUBSUBSTATE_DISABLED);
        res = UA_DataSetWriter_remove(psm, dsw);
        if(wasEnabled)
            UA_WriterGroup_setPubSubState(psm, wg, UA_PUBSUBSTATE_OPERATIONAL);
        return res;
    }
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADER: {
        UA_PubSubConnection *c = findConnectionByName(psm, op->fileConn->name);
        UA_ReaderGroup *rg = (c) ?
            findReaderGroupByName(c, op->fileRg->name) : NULL;
        UA_DataSetReader *dsr = (rg) ?
            findDataSetReaderByName(rg, op->fileDsr->name) : NULL;
        if(!dsr)
            return UA_STATUSCODE_BADNOMATCH;
        *objId = dsr->head.identifier;
        UA_Boolean wasEnabled = UA_PubSubState_isEnabled(rg->head.state);
        if(wasEnabled)
            UA_ReaderGroup_setPubSubState(psm, rg, UA_PUBSUBSTATE_DISABLED);
        res = UA_DataSetReader_remove(psm, dsr);
        if(wasEnabled)
            UA_ReaderGroup_setPubSubState(psm, rg, UA_PUBSUBSTATE_OPERATIONAL);
        return res;
    }
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEPUBDATASET: {
        UA_PublishedDataSet *pds =
            UA_PublishedDataSet_findByName(psm, op->filePds->name);
        if(!pds)
            return UA_STATUSCODE_BADNOMATCH;
        *objId = pds->head.identifier;
        return UA_PublishedDataSet_remove(psm, pds);
    }
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCESUBDATASET: {
        UA_SubscribedDataSet *sds =
            UA_SubscribedDataSet_findByName(psm, op->fileSsds->name);
        if(!sds)
            return UA_STATUSCODE_BADNOMATCH;
        *objId = sds->head.identifier;
        UA_SubscribedDataSet_remove(psm, sds);
        return UA_STATUSCODE_GOOD;
    }
    default:
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
}

/******************/
/* Add operations */
/******************/

static UA_StatusCode
applyAddConnection(UA_PubSubManager *psm, UA_ConfigUpdateOp *op,
                   UA_PubSubConfigUpdateResult *result, UA_NodeId *objId) {
    const UA_PubSubConnectionDataType *p = op->fileConn;
    if(!UA_String_isEmpty(&p->name) && findConnectionByName(psm, p->name))
        return UA_STATUSCODE_BADBROWSENAMEDUPLICATED;

    UA_PubSubConnectionConfig config;
    UA_StatusCode res = UA_PubSubConnectionConfig_fromDataType(p, &config);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* Assign a name and the default PublisherId if not provided */
    UA_String assignedName = UA_STRING_NULL;
    UA_Boolean idAssigned = false;
    if(UA_String_isEmpty(&config.name)) {
        assignedName = generateUniqueName(psm, "Connection",
                                          connectionNameExists, NULL);
        if(UA_String_isEmpty(&assignedName)) {
            UA_PubSubConnectionConfig_clearView(&config);
            return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
        }
        config.name = assignedName;
    }
    if(UA_Variant_isEmpty(&p->publisherId)) {
        config.publisherId.idType = UA_PUBLISHERIDTYPE_UINT64;
        config.publisherId.id.uint64 = psm->defaultPublisherId;
        idAssigned = true;
    }

    UA_NodeId newId;
    res = UA_PubSubConnection_create(psm, &config, &newId);
    if(res == UA_STATUSCODE_GOOD) {
        *objId = newId;
        if(!UA_String_isEmpty(&assignedName) || idAssigned) {
            UA_Variant identifier;
            UA_PublisherId_toVariant(&config.publisherId, &identifier);
            addConfigValue(result, op->ref, config.name, &identifier);
        }
    }
    UA_String finalName = assignedName; /* keep for clear below */
    UA_PubSubConnectionConfig_clearView(&config);
    UA_String_clear(&finalName);
    return res;
}

static UA_StatusCode
applyAddWriterGroup(UA_PubSubManager *psm, UA_ConfigUpdateOp *op,
                    UA_PubSubConfigUpdateResult *result, UA_NodeId *objId) {
    UA_PubSubConnection *c = findConnectionByName(psm, op->fileConn->name);
    if(!c)
        return UA_STATUSCODE_BADNOTFOUND;
    const UA_WriterGroupDataType *p = op->fileWg;
    if(!UA_String_isEmpty(&p->name) && findWriterGroupByName(c, p->name))
        return UA_STATUSCODE_BADBROWSENAMEDUPLICATED;

    UA_WriterGroupConfig config;
    UA_StatusCode res = UA_WriterGroupConfig_fromDataType(p, &config);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_String assignedName = UA_STRING_NULL;
    UA_Boolean idAssigned = false;
    if(UA_String_isEmpty(&config.name)) {
        assignedName = generateUniqueName(psm, "WriterGroup",
                                          writerGroupNameExists, c);
        if(UA_String_isEmpty(&assignedName))
            return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
        config.name = assignedName;
    }
    if(config.writerGroupId == 0) {
        config.writerGroupId =
            assignFreeId(psm, c->config.transportProfileUri, UA_WRITER_GROUP);
        if(config.writerGroupId == 0) {
            UA_String_clear(&assignedName);
            return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
        }
        idAssigned = true;
    }

    UA_NodeId newId;
    res = UA_WriterGroup_create(psm, c->head.identifier, &config, &newId);
    if(res == UA_STATUSCODE_GOOD) {
        *objId = newId;
        if(!UA_String_isEmpty(&assignedName) || idAssigned) {
            UA_Variant identifier;
            UA_Variant_setScalar(&identifier, &config.writerGroupId,
                                 &UA_TYPES[UA_TYPES_UINT16]);
            addConfigValue(result, op->ref, config.name, &identifier);
        }
    }
    UA_String_clear(&assignedName);
    return res;
}

static UA_StatusCode
applyAddReaderGroup(UA_PubSubManager *psm, UA_ConfigUpdateOp *op,
                    UA_PubSubConfigUpdateResult *result, UA_NodeId *objId) {
    UA_PubSubConnection *c = findConnectionByName(psm, op->fileConn->name);
    if(!c)
        return UA_STATUSCODE_BADNOTFOUND;
    const UA_ReaderGroupDataType *p = op->fileRg;
    if(!UA_String_isEmpty(&p->name) && findReaderGroupByName(c, p->name))
        return UA_STATUSCODE_BADBROWSENAMEDUPLICATED;

    UA_ReaderGroupConfig config;
    UA_StatusCode res = UA_ReaderGroupConfig_fromDataType(p, &config);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_String assignedName = UA_STRING_NULL;
    if(UA_String_isEmpty(&config.name)) {
        assignedName = generateUniqueName(psm, "ReaderGroup",
                                          readerGroupNameExists, c);
        if(UA_String_isEmpty(&assignedName))
            return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
        config.name = assignedName;
    }

    UA_NodeId newId;
    res = UA_ReaderGroup_create(psm, c->head.identifier, &config, &newId);
    if(res == UA_STATUSCODE_GOOD) {
        *objId = newId;
        if(!UA_String_isEmpty(&assignedName))
            addConfigValue(result, op->ref, config.name, NULL);
    }
    UA_String_clear(&assignedName);
    return res;
}

static UA_StatusCode
applyAddDataSetWriter(UA_PubSubManager *psm, UA_ConfigUpdateOp *op,
                      UA_PubSubConfigUpdateResult *result, UA_NodeId *objId) {
    UA_PubSubConnection *c = findConnectionByName(psm, op->fileConn->name);
    UA_WriterGroup *wg = (c) ? findWriterGroupByName(c, op->fileWg->name) : NULL;
    if(!wg)
        return UA_STATUSCODE_BADNOTFOUND;
    const UA_DataSetWriterDataType *p = op->fileDsw;
    if(!UA_String_isEmpty(&p->name) && findDataSetWriterByName(wg, p->name))
        return UA_STATUSCODE_BADBROWSENAMEDUPLICATED;

    /* An empty DataSetName indicates a heartbeat writer */
    UA_NodeId pdsId = UA_NODEID_NULL;
    if(!UA_String_isEmpty(&p->dataSetName)) {
        UA_PublishedDataSet *pds =
            UA_PublishedDataSet_findByName(psm, p->dataSetName);
        if(!pds)
            return UA_STATUSCODE_BADNOTFOUND;
        pdsId = pds->head.identifier;
    }

    UA_DataSetWriterConfig config;
    UA_StatusCode res = UA_DataSetWriterConfig_fromDataType(p, &config);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_String assignedName = UA_STRING_NULL;
    UA_Boolean idAssigned = false;
    if(UA_String_isEmpty(&config.name)) {
        assignedName = generateUniqueName(psm, "DataSetWriter",
                                          dataSetWriterNameExists, wg);
        if(UA_String_isEmpty(&assignedName))
            return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
        config.name = assignedName;
    }
    UA_PubSubConnection *pc = wg->linkedConnection;
    if(config.dataSetWriterId == 0) {
        config.dataSetWriterId =
            assignFreeId(psm, pc->config.transportProfileUri, UA_DATA_SET_WRITER);
        if(config.dataSetWriterId == 0) {
            UA_String_clear(&assignedName);
            return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
        }
        idAssigned = true;
    }

    /* The writer can only be added to a disabled group */
    UA_Boolean wasEnabled = UA_PubSubState_isEnabled(wg->head.state);
    if(wasEnabled)
        UA_WriterGroup_setPubSubState(psm, wg, UA_PUBSUBSTATE_DISABLED);

    UA_NodeId newId;
    res = UA_DataSetWriter_create(psm, wg->head.identifier, pdsId,
                                  &config, &newId);

    if(wasEnabled)
        UA_WriterGroup_setPubSubState(psm, wg, UA_PUBSUBSTATE_OPERATIONAL);

    if(res == UA_STATUSCODE_GOOD) {
        *objId = newId;
        if(!UA_String_isEmpty(&assignedName) || idAssigned) {
            UA_Variant identifier;
            UA_Variant_setScalar(&identifier, &config.dataSetWriterId,
                                 &UA_TYPES[UA_TYPES_UINT16]);
            addConfigValue(result, op->ref, config.name, &identifier);
        }
    }
    UA_String_clear(&assignedName);
    return res;
}

static UA_StatusCode
applyAddDataSetReader(UA_PubSubManager *psm, UA_ConfigUpdateOp *op,
                      UA_PubSubConfigUpdateResult *result, UA_NodeId *objId) {
    UA_PubSubConnection *c = findConnectionByName(psm, op->fileConn->name);
    UA_ReaderGroup *rg = (c) ? findReaderGroupByName(c, op->fileRg->name) : NULL;
    if(!rg)
        return UA_STATUSCODE_BADNOTFOUND;
    const UA_DataSetReaderDataType *p = op->fileDsr;
    if(!UA_String_isEmpty(&p->name) && findDataSetReaderByName(rg, p->name))
        return UA_STATUSCODE_BADBROWSENAMEDUPLICATED;

    UA_DataSetReaderConfig config;
    UA_StatusCode res = UA_DataSetReaderConfig_fromDataType(p, &config);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_String assignedName = UA_STRING_NULL;
    if(UA_String_isEmpty(&config.name)) {
        assignedName = generateUniqueName(psm, "DataSetReader",
                                          dataSetReaderNameExists, rg);
        if(UA_String_isEmpty(&assignedName)) {
            UA_DataSetReaderConfig_clearView(&config);
            return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
        }
        config.name = assignedName;
    }

    /* The reader can only be added to a disabled group */
    UA_Boolean wasEnabled = UA_PubSubState_isEnabled(rg->head.state);
    if(wasEnabled)
        UA_ReaderGroup_setPubSubState(psm, rg, UA_PUBSUBSTATE_DISABLED);

    UA_NodeId newId;
    res = UA_DataSetReader_create(psm, rg->head.identifier, &config, &newId);

    if(wasEnabled)
        UA_ReaderGroup_setPubSubState(psm, rg, UA_PUBSUBSTATE_OPERATIONAL);

    if(res == UA_STATUSCODE_GOOD) {
        *objId = newId;
        if(!UA_String_isEmpty(&assignedName))
            addConfigValue(result, op->ref, config.name, NULL);
    }
    UA_DataSetReaderConfig_clearView(&config);
    UA_String_clear(&assignedName);
    return res;
}

static UA_StatusCode
applyAddPublishedDataSet(UA_PubSubManager *psm, UA_ConfigUpdateOp *op,
                         UA_PubSubConfigUpdateResult *result, UA_NodeId *objId) {
    const UA_PublishedDataSetDataType *p = op->filePds;
    if(!UA_String_isEmpty(&p->name) && UA_PublishedDataSet_findByName(psm, p->name))
        return UA_STATUSCODE_BADBROWSENAMEDUPLICATED;

    UA_PublishedDataSetConfig config;
    UA_StatusCode res = UA_PublishedDataSetConfig_fromDataType(p, &config);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_String assignedName = UA_STRING_NULL;
    if(UA_String_isEmpty(&config.name)) {
        assignedName = generateUniqueName(psm, "PublishedDataSet",
                                          pdsNameExists, NULL);
        if(UA_String_isEmpty(&assignedName))
            return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
        config.name = assignedName;
    }

    UA_NodeId newId;
    res = UA_PublishedDataSet_create(psm, &config, &newId).addResult;
    if(res != UA_STATUSCODE_GOOD) {
        UA_String_clear(&assignedName);
        return res;
    }

    /* Add the DataSetFields */
    for(size_t i = 0; i < p->dataSetMetaData.fieldsSize; i++) {
        UA_DataSetFieldConfig fc;
        res = UA_DataSetFieldConfig_fromDataType(p, i, &fc);
        if(res == UA_STATUSCODE_GOOD)
            res = UA_DataSetField_create(psm, newId, &fc, NULL).result;
        if(res != UA_STATUSCODE_GOOD) {
            /* Remove the partially created PDS */
            UA_PublishedDataSet *pds = UA_PublishedDataSet_find(psm, newId);
            if(pds)
                UA_PublishedDataSet_remove(psm, pds);
            UA_String_clear(&assignedName);
            return res;
        }
    }

    *objId = newId;
    if(!UA_String_isEmpty(&assignedName))
        addConfigValue(result, op->ref, config.name, NULL);
    UA_String_clear(&assignedName);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
applyAddSubscribedDataSet(UA_PubSubManager *psm, UA_ConfigUpdateOp *op,
                          UA_PubSubConfigUpdateResult *result, UA_NodeId *objId) {
    const UA_StandaloneSubscribedDataSetDataType *p = op->fileSsds;
    if(!UA_String_isEmpty(&p->name) && UA_SubscribedDataSet_findByName(psm, p->name))
        return UA_STATUSCODE_BADBROWSENAMEDUPLICATED;

    UA_SubscribedDataSetConfig config;
    UA_StatusCode res = UA_SubscribedDataSetConfig_fromDataType(p, &config);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_String assignedName = UA_STRING_NULL;
    if(UA_String_isEmpty(&config.name)) {
        assignedName = generateUniqueName(psm, "SubscribedDataSet",
                                          ssdsNameExists, NULL);
        if(UA_String_isEmpty(&assignedName))
            return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
        config.name = assignedName;
    }

    UA_NodeId newId;
    res = UA_SubscribedDataSet_create(psm, &config, &newId);
    if(res == UA_STATUSCODE_GOOD) {
        *objId = newId;
        if(!UA_String_isEmpty(&assignedName))
            addConfigValue(result, op->ref, config.name, NULL);
    }
    UA_String_clear(&assignedName);
    return res;
}

/********************/
/* Match operations */
/********************/

/* Returns GOOD and the matched component, BADNOMATCH when nothing matches,
 * BADINVALIDSTATE for a WriterGroup with active GroupHeader */
static UA_StatusCode
applyMatch(UA_PubSubManager *psm, UA_ConfigUpdateOp *op,
           UA_PubSubConfigUpdateResult *result, UA_NodeId *objId) {
    switch(op->refbit) {
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION: {
        UA_PubSubConnection *c;
        TAILQ_FOREACH(c, &psm->connections, listEntry) {
            if(!matchConnection(c, op->fileConn))
                continue;
            *objId = c->head.identifier;
            UA_Variant identifier;
            UA_PublisherId_toVariant(&c->config.publisherId, &identifier);
            addConfigValue(result, op->ref, c->config.name, &identifier);
            return UA_STATUSCODE_GOOD;
        }
        return UA_STATUSCODE_BADNOMATCH;
    }
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP: {
        UA_PubSubConnection *c = findConnectionByName(psm, op->fileConn->name);
        if(!c)
            return UA_STATUSCODE_BADNOMATCH;
        UA_WriterGroup *wg;
        LIST_FOREACH(wg, &c->writerGroups, listEntry) {
            if(!matchWriterGroup(wg, op->fileWg))
                continue;
            if(writerGroupHeaderActive(wg))
                return UA_STATUSCODE_BADINVALIDSTATE;
            *objId = wg->head.identifier;
            UA_Variant identifier;
            UA_Variant_setScalar(&identifier, &wg->config.writerGroupId,
                                 &UA_TYPES[UA_TYPES_UINT16]);
            addConfigValue(result, op->ref, wg->config.name, &identifier);
            return UA_STATUSCODE_GOOD;
        }
        return UA_STATUSCODE_BADNOMATCH;
    }
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADERGROUP: {
        UA_PubSubConnection *c = findConnectionByName(psm, op->fileConn->name);
        if(!c)
            return UA_STATUSCODE_BADNOMATCH;
        UA_ReaderGroup *rg;
        LIST_FOREACH(rg, &c->readerGroups, listEntry) {
            if(!matchReaderGroup(rg, op->fileRg))
                continue;
            *objId = rg->head.identifier;
            addConfigValue(result, op->ref, rg->config.name, NULL);
            return UA_STATUSCODE_GOOD;
        }
        return UA_STATUSCODE_BADNOMATCH;
    }
    default:
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
}

/*********************/
/* Modify operations */
/*********************/

static UA_StatusCode
applyModify(UA_PubSubManager *psm, UA_ConfigUpdateOp *op, UA_NodeId *objId) {
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    switch(op->refbit) {
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION: {
        UA_PubSubConnection *c = findConnectionByName(psm, op->fileConn->name);
        if(!c)
            return UA_STATUSCODE_BADNOMATCH;
        *objId = c->head.identifier;
        UA_PubSubConnectionConfig config;
        res = UA_PubSubConnectionConfig_fromDataType(op->fileConn, &config);
        if(res != UA_STATUSCODE_GOOD)
            return res;
        config.enabled = false;
        UA_Boolean wasEnabled = UA_PubSubState_isEnabled(c->head.state);
        if(wasEnabled)
            UA_PubSubConnection_setPubSubState(psm, c, UA_PUBSUBSTATE_DISABLED);
        res = UA_PubSubConnection_updateConfig(psm, c, &config);
        if(wasEnabled)
            UA_PubSubConnection_setPubSubState(psm, c, UA_PUBSUBSTATE_OPERATIONAL);
        UA_PubSubConnectionConfig_clearView(&config);
        return res;
    }
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP: {
        UA_PubSubConnection *c = findConnectionByName(psm, op->fileConn->name);
        UA_WriterGroup *wg = (c) ?
            findWriterGroupByName(c, op->fileWg->name) : NULL;
        if(!wg)
            return UA_STATUSCODE_BADNOMATCH;
        *objId = wg->head.identifier;
        UA_WriterGroupConfig config;
        res = UA_WriterGroupConfig_fromDataType(op->fileWg, &config);
        if(res != UA_STATUSCODE_GOOD)
            return res;
        config.enabled = false;
        UA_Boolean wasEnabled = UA_PubSubState_isEnabled(wg->head.state);
        if(wasEnabled)
            UA_WriterGroup_setPubSubState(psm, wg, UA_PUBSUBSTATE_DISABLED);
        res = UA_WriterGroup_updateConfig(psm, wg, &config);
        if(wasEnabled)
            UA_WriterGroup_setPubSubState(psm, wg, UA_PUBSUBSTATE_OPERATIONAL);
        return res;
    }
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADERGROUP: {
        UA_PubSubConnection *c = findConnectionByName(psm, op->fileConn->name);
        UA_ReaderGroup *rg = (c) ?
            findReaderGroupByName(c, op->fileRg->name) : NULL;
        if(!rg)
            return UA_STATUSCODE_BADNOMATCH;
        *objId = rg->head.identifier;
        UA_ReaderGroupConfig config;
        res = UA_ReaderGroupConfig_fromDataType(op->fileRg, &config);
        if(res != UA_STATUSCODE_GOOD)
            return res;
        config.enabled = false;
        UA_Boolean wasEnabled = UA_PubSubState_isEnabled(rg->head.state);
        if(wasEnabled)
            UA_ReaderGroup_setPubSubState(psm, rg, UA_PUBSUBSTATE_DISABLED);
        res = UA_ReaderGroup_updateConfig(psm, rg, &config);
        if(wasEnabled)
            UA_ReaderGroup_setPubSubState(psm, rg, UA_PUBSUBSTATE_OPERATIONAL);
        return res;
    }
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITER: {
        UA_PubSubConnection *c = findConnectionByName(psm, op->fileConn->name);
        UA_WriterGroup *wg = (c) ?
            findWriterGroupByName(c, op->fileWg->name) : NULL;
        UA_DataSetWriter *dsw = (wg) ?
            findDataSetWriterByName(wg, op->fileDsw->name) : NULL;
        if(!dsw)
            return UA_STATUSCODE_BADNOMATCH;
        *objId = dsw->head.identifier;
        UA_DataSetWriterConfig config;
        res = UA_DataSetWriterConfig_fromDataType(op->fileDsw, &config);
        if(res != UA_STATUSCODE_GOOD)
            return res;
        config.enabled = false;
        UA_Boolean wasEnabled = UA_PubSubState_isEnabled(dsw->head.state);
        if(wasEnabled)
            UA_DataSetWriter_setPubSubState(psm, dsw, UA_PUBSUBSTATE_DISABLED);
        res = UA_DataSetWriter_updateConfig(psm, dsw, &config);
        if(wasEnabled)
            UA_DataSetWriter_setPubSubState(psm, dsw, UA_PUBSUBSTATE_OPERATIONAL);
        return res;
    }
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADER: {
        UA_PubSubConnection *c = findConnectionByName(psm, op->fileConn->name);
        UA_ReaderGroup *rg = (c) ?
            findReaderGroupByName(c, op->fileRg->name) : NULL;
        UA_DataSetReader *dsr = (rg) ?
            findDataSetReaderByName(rg, op->fileDsr->name) : NULL;
        if(!dsr)
            return UA_STATUSCODE_BADNOMATCH;
        *objId = dsr->head.identifier;
        UA_DataSetReaderConfig config;
        res = UA_DataSetReaderConfig_fromDataType(op->fileDsr, &config);
        if(res != UA_STATUSCODE_GOOD) {
            UA_DataSetReaderConfig_clearView(&config);
            return res;
        }
        config.enabled = false;
        UA_Boolean wasEnabled = UA_PubSubState_isEnabled(dsr->head.state);
        if(wasEnabled)
            UA_DataSetReader_setPubSubState(psm, dsr, UA_PUBSUBSTATE_DISABLED,
                                            UA_STATUSCODE_GOOD);
        res = UA_DataSetReader_updateConfig(psm, dsr, &config);
        if(wasEnabled)
            UA_DataSetReader_setPubSubState(psm, dsr, UA_PUBSUBSTATE_OPERATIONAL,
                                            UA_STATUSCODE_GOOD);
        UA_DataSetReaderConfig_clearView(&config);
        return res;
    }
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEPUBDATASET:
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCESUBDATASET:
        /* Changing the field list of a dataset requires recreating the
         * component. Use remove + add with the same name in one call. */
        return UA_STATUSCODE_BADNOTIMPLEMENTED;
    default:
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
}

/**************/
/* Validation */
/**************/

/* Does the element exist in the live model (ignoring the shadow state)? */
static UA_Boolean
elementExists(UA_PubSubManager *psm, const UA_ConfigUpdateOp *op) {
    UA_PubSubConnection *c;
    switch(op->refbit) {
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION:
        return (findConnectionByName(psm, op->fileConn->name) != NULL);
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP:
        c = findConnectionByName(psm, op->fileConn->name);
        return (c && findWriterGroupByName(c, op->fileWg->name));
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADERGROUP:
        c = findConnectionByName(psm, op->fileConn->name);
        return (c && findReaderGroupByName(c, op->fileRg->name));
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITER: {
        c = findConnectionByName(psm, op->fileConn->name);
        UA_WriterGroup *wg = (c) ?
            findWriterGroupByName(c, op->fileWg->name) : NULL;
        return (wg && findDataSetWriterByName(wg, op->fileDsw->name));
    }
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADER: {
        c = findConnectionByName(psm, op->fileConn->name);
        UA_ReaderGroup *rg = (c) ?
            findReaderGroupByName(c, op->fileRg->name) : NULL;
        return (rg && findDataSetReaderByName(rg, op->fileDsr->name));
    }
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEPUBDATASET:
        return (UA_PublishedDataSet_findByName(psm, op->filePds->name) != NULL);
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCESUBDATASET:
        return (UA_SubscribedDataSet_findByName(psm, op->fileSsds->name) != NULL);
    default:
        return false;
    }
}

/* Does the parent of the element exist, considering the shadow state? */
static UA_Boolean
parentAvailable(UA_PubSubManager *psm, const UA_ConfigUpdateOp *op,
                const UA_ShadowState *shadow) {
    UA_String connName = UA_STRING_NULL;
    UA_String parentName = UA_STRING_NULL;
    UA_UInt32 parentRefbit = 0;
    switch(op->refbit) {
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP:
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADERGROUP:
        parentRefbit = UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION;
        parentName = op->fileConn->name;
        break;
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITER:
        parentRefbit = UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP;
        connName = op->fileConn->name;
        parentName = op->fileWg->name;
        break;
    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADER:
        parentRefbit = UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADERGROUP;
        connName = op->fileConn->name;
        parentName = op->fileRg->name;
        break;
    default:
        return true; /* Top-level elements have no parent */
    }

    /* Removed earlier in the same call? */
    if(shadowContains(shadow->removed, shadow->removedSize, parentRefbit,
                      UA_STRING_NULL, UA_STRING_NULL, parentName) ||
       shadowContains(shadow->removed, shadow->removedSize, parentRefbit,
                      connName, UA_STRING_NULL, parentName))
        return false;

    /* Added earlier in the same call? */
    if(shadowContains(shadow->added, shadow->addedSize, parentRefbit,
                      connName, UA_STRING_NULL, parentName))
        return true;

    /* Exists in the live model? */
    UA_PubSubConnection *c;
    if(parentRefbit == UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION)
        return (findConnectionByName(psm, parentName) != NULL);
    c = findConnectionByName(psm, connName);
    if(!c)
        return false;
    if(parentRefbit == UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP)
        return (findWriterGroupByName(c, parentName) != NULL);
    return (findReaderGroupByName(c, parentName) != NULL);
}

/* Validate an operation without mutating the live model. Updates the shadow
 * state on success. */
static UA_StatusCode
validateOp(UA_PubSubManager *psm, const UA_ConfigUpdateOp *op,
           UA_ShadowState *shadow) {
    UA_String connName, groupName, name;
    opNames(op, &connName, &groupName, &name);

    UA_Boolean liveExists = elementExists(psm, op);
    UA_Boolean shadowRemoved =
        shadowContains(shadow->removed, shadow->removedSize, op->refbit,
                       connName, groupName, name);
    UA_Boolean shadowAdded =
        shadowContains(shadow->added, shadow->addedSize, op->refbit,
                       connName, groupName, name);
    UA_Boolean exists = (liveExists && !shadowRemoved) || shadowAdded;

    if(op->op == UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTREMOVE) {
        if(!exists)
            return UA_STATUSCODE_BADNOMATCH;
        shadowAdd(shadow->removed, &shadow->removedSize, op->refbit,
                  connName, groupName, name);
        return UA_STATUSCODE_GOOD;
    }

    if(op->op == UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMODIFY) {
        if(!exists)
            return UA_STATUSCODE_BADNOMATCH;
        return UA_STATUSCODE_GOOD;
    }

    if(op->op == UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMATCH) {
        /* A pure match must find a matching element. The match itself does
         * not mutate, so run it against the live model. The shadow state
         * cannot help here. */
        UA_PubSubConfigUpdateResult dummy;
        memset(&dummy, 0, sizeof(dummy));
        UA_PubSubConfigurationValueDataType values[1];
        memset(values, 0, sizeof(values));
        dummy.configurationValues = values;
        UA_NodeId objId = UA_NODEID_NULL;
        UA_StatusCode res = applyMatch(psm, (UA_ConfigUpdateOp*)(uintptr_t)op,
                                       &dummy, &objId);
        for(size_t i = 0; i < dummy.configurationValuesSize; i++)
            UA_PubSubConfigurationValueDataType_clear(&values[i]);
        return res;
    }

    /* Add or Add|Match */
    if(op->op & UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD) {
        if(!parentAvailable(psm, op, shadow))
            return UA_STATUSCODE_BADNOTFOUND;
        /* With a provided name the element must not exist yet (unless
         * Add|Match, where an existing match is used) */
        if(!UA_String_isEmpty(&name) && exists &&
           !(op->op & UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMATCH))
            return UA_STATUSCODE_BADBROWSENAMEDUPLICATED;
        shadowAdd(shadow->added, &shadow->addedSize, op->refbit,
                  connName, groupName, name);
        return UA_STATUSCODE_GOOD;
    }

    return UA_STATUSCODE_BADINVALIDARGUMENT;
}

/*************/
/* Top level */
/*************/

static UA_Boolean
applyTopLevelFields(UA_PubSubManager *psm,
                    const UA_PubSubConfiguration2DataType *cfg) {
    UA_Boolean changed = false;

    /* Replace the DefaultSecurityKeyServices if non-empty */
    if(cfg->defaultSecurityKeyServicesSize > 0) {
        UA_EndpointDescription *copy = NULL;
        UA_StatusCode res =
            UA_Array_copy(cfg->defaultSecurityKeyServices,
                          cfg->defaultSecurityKeyServicesSize, (void**)&copy,
                          &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
        if(res == UA_STATUSCODE_GOOD) {
            UA_Array_delete(psm->defaultSecurityKeyServices,
                            psm->defaultSecurityKeyServicesSize,
                            &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
            psm->defaultSecurityKeyServices = copy;
            psm->defaultSecurityKeyServicesSize =
                cfg->defaultSecurityKeyServicesSize;
            changed = true;
        }
    }

    /* Merge the ConfigurationProperties. A null value deletes the key. */
    for(size_t i = 0; i < cfg->configurationPropertiesSize; i++) {
        const UA_KeyValuePair *kvp = &cfg->configurationProperties[i];
        if(UA_Variant_isEmpty(&kvp->value)) {
            if(UA_KeyValueMap_remove(&psm->configurationProperties,
                                     kvp->key) == UA_STATUSCODE_GOOD)
                changed = true;
        } else {
            if(UA_KeyValueMap_set(&psm->configurationProperties, kvp->key,
                                  &kvp->value) == UA_STATUSCODE_GOOD)
                changed = true;
        }
    }

    return changed;
}

/***************/
/* Entry point */
/***************/

static UA_StatusCode
updatePubSubConfig2(UA_PubSubManager *psm,
                    const UA_PubSubConfiguration2DataType *cfg,
                    size_t refsSize, const UA_PubSubConfigurationRefDataType *refs,
                    UA_Boolean requireCompleteUpdate,
                    UA_PubSubConfigUpdateResult *result) {
    UA_LOCK_ASSERT(&psm->sc.server->serviceMutex);

    /* Allocate the result arrays. The configurationValues array is
     * over-allocated to the number of references and only partially used. */
    result->referencesResults = (UA_StatusCode*)
        UA_Array_new(refsSize, &UA_TYPES[UA_TYPES_STATUSCODE]);
    result->configurationObjects = (UA_NodeId*)
        UA_Array_new(refsSize, &UA_TYPES[UA_TYPES_NODEID]);
    result->configurationValues = (UA_PubSubConfigurationValueDataType*)
        UA_Array_new(refsSize, &UA_TYPES[UA_TYPES_PUBSUBCONFIGURATIONVALUEDATATYPE]);
    UA_ConfigUpdateOp *ops = (UA_ConfigUpdateOp*)
        UA_calloc(refsSize, sizeof(UA_ConfigUpdateOp));
    UA_ShadowState shadow;
    memset(&shadow, 0, sizeof(shadow));
    shadow.added = (UA_ShadowEntry*)
        UA_calloc(refsSize, sizeof(UA_ShadowEntry));
    shadow.removed = (UA_ShadowEntry*)
        UA_calloc(refsSize, sizeof(UA_ShadowEntry));

    if(!result->referencesResults || !result->configurationObjects ||
       !result->configurationValues || !ops || !shadow.added || !shadow.removed) {
        UA_free(ops);
        UA_free(shadow.added);
        UA_free(shadow.removed);
        UA_PubSubConfigUpdateResult_clear(result);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    result->referencesResultsSize = refsSize;
    result->configurationObjectsSize = refsSize;
    result->configurationValuesSize = 0; /* grows in addConfigValue */

    /* Resolve all references. The execution order processes the remove
     * operations first (allows remove + add with the same name). */
    size_t opsSize = 0;
    for(size_t i = 0; i < refsSize; i++) {
        if((refs[i].configurationMask & UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTREMOVE) == 0)
            continue;
        ops[opsSize].inputIndex = i;
        ops[opsSize].status = resolveOp(cfg, &refs[i], &ops[opsSize]);
        opsSize++;
    }
    for(size_t i = 0; i < refsSize; i++) {
        if(refs[i].configurationMask & UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTREMOVE)
            continue;
        ops[opsSize].inputIndex = i;
        ops[opsSize].status = resolveOp(cfg, &refs[i], &ops[opsSize]);
        opsSize++;
    }

    /* Validation pass for a complete update */
    UA_Boolean validationFailed = false;
    if(requireCompleteUpdate) {
        for(size_t i = 0; i < opsSize; i++) {
            if(ops[i].status == UA_STATUSCODE_GOOD)
                ops[i].status = validateOp(psm, &ops[i], &shadow);
            if(ops[i].status != UA_STATUSCODE_GOOD)
                validationFailed = true;
        }
    }

    /* Apply the operations */
    UA_Boolean anyApplied = false;
    if(!validationFailed) {
        for(size_t i = 0; i < opsSize; i++) {
            UA_ConfigUpdateOp *op = &ops[i];
            if(op->status != UA_STATUSCODE_GOOD)
                continue;
            UA_NodeId objId = UA_NODEID_NULL;
            if(op->op == UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTREMOVE) {
                op->status = applyRemove(psm, op, &objId);
            } else if(op->op == UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMODIFY) {
                op->status = applyModify(psm, op, &objId);
            } else if(op->op == UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMATCH) {
                op->status = applyMatch(psm, op, result, &objId);
                if(op->status == UA_STATUSCODE_GOOD) {
                    /* A pure match does not modify the configuration */
                    UA_NodeId_copy(&objId, &result->configurationObjects[op->inputIndex]);
                    continue;
                }
            } else { /* Add or Add|Match */
                op->status = UA_STATUSCODE_BADNOMATCH;
                if(op->op & UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMATCH)
                    op->status = applyMatch(psm, op, result, &objId);
                if(op->status == UA_STATUSCODE_BADNOMATCH) {
                    switch(op->refbit) {
                    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION:
                        op->status = applyAddConnection(psm, op, result, &objId);
                        break;
                    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP:
                        op->status = applyAddWriterGroup(psm, op, result, &objId);
                        break;
                    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADERGROUP:
                        op->status = applyAddReaderGroup(psm, op, result, &objId);
                        break;
                    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITER:
                        op->status = applyAddDataSetWriter(psm, op, result, &objId);
                        break;
                    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADER:
                        op->status = applyAddDataSetReader(psm, op, result, &objId);
                        break;
                    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEPUBDATASET:
                        op->status = applyAddPublishedDataSet(psm, op, result, &objId);
                        break;
                    case UA_PUBSUBCONFIGURATIONREFMASK_REFERENCESUBDATASET:
                        op->status = applyAddSubscribedDataSet(psm, op, result, &objId);
                        break;
                    default:
                        op->status = UA_STATUSCODE_BADINVALIDARGUMENT;
                        break;
                    }
                } else if(op->status == UA_STATUSCODE_GOOD) {
                    /* Add|Match used the existing element */
                    UA_NodeId_copy(&objId, &result->configurationObjects[op->inputIndex]);
                    continue;
                }
            }
            if(op->status == UA_STATUSCODE_GOOD) {
                anyApplied = true;
                UA_NodeId_copy(&objId, &result->configurationObjects[op->inputIndex]);
            }
        }

        /* Top-level fields are applied when the operations were processed */
        if(applyTopLevelFields(psm, cfg))
            anyApplied = true;
    }

    /* Copy the per-reference status codes into the result */
    for(size_t i = 0; i < opsSize; i++)
        result->referencesResults[ops[i].inputIndex] = ops[i].status;

    result->changesApplied = anyApplied;
    if(anyApplied)
        psm->configurationVersion =
            UA_PubSubConfigurationVersionTimeDifference(UA_DateTime_now());

    UA_free(ops);
    UA_free(shadow.added);
    UA_free(shadow.removed);
    return UA_STATUSCODE_GOOD;
}

void
UA_PubSubConfigUpdateResult_clear(UA_PubSubConfigUpdateResult *result) {
    UA_Array_delete(result->referencesResults, result->referencesResultsSize,
                    &UA_TYPES[UA_TYPES_STATUSCODE]);
    UA_Array_delete(result->configurationObjects, result->configurationObjectsSize,
                    &UA_TYPES[UA_TYPES_NODEID]);
    /* The values array is over-allocated to the number of references. The
     * entries beyond configurationValuesSize are zero-initialized, so the
     * array-delete with the full allocation size is not possible. Clear the
     * used entries and free the memory. */
    for(size_t i = 0; i < result->configurationValuesSize; i++)
        UA_PubSubConfigurationValueDataType_clear(&result->configurationValues[i]);
    UA_free(result->configurationValues);
    memset(result, 0, sizeof(UA_PubSubConfigUpdateResult));
}

UA_StatusCode
UA_Server_updatePubSubConfig2(UA_Server *server,
                              const UA_PubSubConfiguration2DataType *config,
                              size_t refsSize,
                              const UA_PubSubConfigurationRefDataType *refs,
                              UA_Boolean requireCompleteUpdate,
                              UA_PubSubConfigUpdateResult *result) {
    if(!server || !config || !result)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    memset(result, 0, sizeof(UA_PubSubConfigUpdateResult));
    if(refsSize == 0 || !refs)
        return UA_STATUSCODE_BADNOTHINGTODO;

    lockServer(server);
    UA_PubSubManager *psm = getPSM(server);
    if(!psm) {
        unlockServer(server);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_StatusCode res = updatePubSubConfig2(psm, config, refsSize, refs,
                                            requireCompleteUpdate, result);
    unlockServer(server);
    return res;
}

#endif /* UA_ENABLE_PUBSUB && UA_ENABLE_PUBSUB_FILE_CONFIG */
