/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2022 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#include "ua_server_internal.h"
#include "ua_session.h"
#include "ua_subscription.h"
#include "itoa.h"

#ifdef UA_ENABLE_RBAC
#include "ua_server_rbac.h"
#endif

#ifdef UA_ENABLE_DIAGNOSTICS

static UA_Boolean
equalBrowseName(UA_String *bn, char *n) {
    UA_String name = UA_STRING(n);
    return UA_String_equal(bn, &name);
}

#ifdef UA_ENABLE_RBAC
static UA_Boolean
hasSecurityAdminRole(const UA_Session *session) {
    const UA_NodeId securityAdmin =
        UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN);
    for(size_t i = 0; i < session->rolesSize; i++) {
        if(UA_NodeId_equal(&session->roles[i], &securityAdmin))
            return true;
    }
    return false;
}

/* The per-Session diagnostics Nodes live in namespace one, where the strict
 * template lets Anonymous only browse. They get built-in RolePermissions so
 * that every Session can read them (enforced while the namespace has a model).
 * The value callbacks restrict the security-related values to the owning
 * Session, the local admin and SecurityAdmin (Part 5 §6.3.5). */
static void
protectSessionDiagnosticsNode(UA_Server *server, const UA_NodeId *nodeId) {
    const UA_RolePermission entries[2] = {
        {UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS),
         UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ},
        {UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN),
         UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ |
         UA_PERMISSIONTYPE_READROLEPERMISSIONS}
    };
    UA_StatusCode res = protectNodeRolePermissions(server, nodeId, 2, entries);
    if(res != UA_STATUSCODE_GOOD)
        UA_LOG_WARNING(server->config.logging, UA_LOGCATEGORY_SERVER,
                       "Could not set the RolePermissions of the diagnostics "
                       "Node %N (%s)", *nodeId, UA_StatusCode_name(res));
}
#endif

/* The Session that owns a Node of a per-Session diagnostics object. The
 * object has the NodeId of the Session. Its Variables hang below it through
 * HasComponent and HasProperty References. The values are those of the owning
 * Session, not of the reading Session. */
static void *
copyFirstTarget(void *context, UA_ReferenceTarget *t) {
    UA_NodeId id = UA_NodePointer_toNodeId(t->targetId);
    if(UA_NodeId_copy(&id, (UA_NodeId*)context) != UA_STATUSCODE_GOOD)
        return NULL;
    return context;
}

static UA_Session *
getDiagnosticsOwnerSession(UA_Server *server, const UA_NodeId *nodeId) {
    UA_LOCK_ASSERT(&server->serviceMutex);
    UA_NodeId current;
    if(UA_NodeId_copy(nodeId, &current) != UA_STATUSCODE_GOOD)
        return NULL;
    UA_Session *owner = NULL;
    for(size_t depth = 0; depth < 4; depth++) {
        owner = getSessionById(server, &current);
        if(owner)
            break;

        /* Walk up to the parent */
        const UA_Node *node = UA_NODESTORE_GET(server, &current);
        if(!node)
            break;
        UA_NodeId parent = UA_NODEID_NULL;
        void *found = NULL;
        for(size_t i = 0; i < node->head.referencesSize && !found; i++) {
            UA_NodeReferenceKind *rk = &node->head.references[i];
            if(!rk->isInverse ||
               (rk->referenceTypeIndex != UA_REFERENCETYPEINDEX_HASCOMPONENT &&
                rk->referenceTypeIndex != UA_REFERENCETYPEINDEX_HASPROPERTY))
                continue;
            found = UA_NodeReferenceKind_iterate(rk, copyFirstTarget, &parent);
        }
        UA_NODESTORE_RELEASE(server, node);
        if(!found)
            break;
        UA_NodeId_clear(&current);
        current = parent;
    }
    UA_NodeId_clear(&current);

    /* The admin Session has no diagnostics object */
    if(owner == &server->adminSession)
        owner = NULL;
    return owner;
}

#ifdef UA_ENABLE_SUBSCRIPTIONS

static const UA_NodeId subDiagArray = {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SUBSCRIPTIONDIAGNOSTICSARRAY}};

/****************************/
/* Subscription Diagnostics */
/****************************/

static void *
countDisabledMonitoredItemsVisitor(void *context, UA_MonitoredItem *mon) {
    UA_SubscriptionDiagnosticsDataType *diag =
        (UA_SubscriptionDiagnosticsDataType*)context;

    if(mon->monitoringMode == UA_MONITORINGMODE_DISABLED)
        diag->disabledMonitoredItemCount++;

    return NULL;
}

static void
fillSubscriptionDiagnostics(UA_Subscription *sub,
                            UA_SubscriptionDiagnosticsDataType *diag) {
    UA_NodeId_copy(&sub->session->sessionId, &diag->sessionId); /* ignore status */
    diag->subscriptionId = sub->subscriptionId;
    diag->priority = sub->priority;
    diag->publishingInterval = sub->publishingInterval;
    diag->maxKeepAliveCount = sub->maxKeepAliveCount;
    diag->maxLifetimeCount = sub->lifeTimeCount;
    diag->maxNotificationsPerPublish = sub->notificationsPerPublish;
    diag->publishingEnabled = (sub->state > UA_SUBSCRIPTIONSTATE_ENABLED_NOPUBLISH);
    diag->modifyCount = sub->modifyCount;
    diag->enableCount = sub->enableCount;
    diag->disableCount = sub->disableCount;
    diag->republishRequestCount = sub->republishRequestCount;
    diag->republishMessageRequestCount =
        sub->republishRequestCount; /* Always equal to the previous republishRequestCount */
    diag->republishMessageCount = sub->republishMessageCount;
    diag->transferRequestCount = sub->transferRequestCount;
    diag->transferredToAltClientCount = sub->transferredToAltClientCount;
    diag->transferredToSameClientCount = sub->transferredToSameClientCount;
    diag->publishRequestCount = sub->publishRequestCount;
    diag->dataChangeNotificationsCount = sub->dataChangeNotificationsCount;
    diag->eventNotificationsCount = sub->eventNotificationsCount;
    diag->notificationsCount = sub->notificationsCount;
    diag->latePublishRequestCount = sub->latePublishRequestCount;
    diag->currentKeepAliveCount = sub->currentKeepAliveCount;
    diag->currentLifetimeCount = sub->currentLifetimeCount;
    diag->unacknowledgedMessageCount = (UA_UInt32)sub->retransmissionQueueSize;
    diag->discardedMessageCount = sub->discardedMessageCount;
    diag->monitoredItemCount = sub->monitoredItemsSize;
    diag->monitoringQueueOverflowCount = sub->monitoringQueueOverflowCount;
    diag->nextSequenceNumber = sub->nextSequenceNumber;
    diag->eventQueueOverflowCount = sub->eventQueueOverflowCount;

    /* Count the disabled MonitoredItems */
    ZIP_ITER(UA_MonitoredItemIdTree, &sub->monitoredItemsById,
             countDisabledMonitoredItemsVisitor, diag);
}

/* The node context points to the subscription */
static UA_StatusCode
readSubscriptionDiagnostics(UA_Server *server,
                            const UA_NodeId *sessionId, void *sessionContext,
                            const UA_NodeId *nodeId, void *nodeContext,
                            UA_Boolean sourceTimestamp,
                            const UA_NumericRange *range, UA_DataValue *value) {
    /* Check the Subscription pointer */
    UA_Subscription *sub = (UA_Subscription*)nodeContext;
    if(!sub)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Read the BrowseName */
    UA_QualifiedName bn;
    UA_StatusCode res = UA_Server_readBrowseName(server, *nodeId, &bn);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* Set the value */
    UA_SubscriptionDiagnosticsDataType sddt;
    UA_SubscriptionDiagnosticsDataType_init(&sddt);
    fillSubscriptionDiagnostics(sub, &sddt);

    char memberName[128];
    if(bn.name.length >= sizeof(memberName)) {
        UA_SubscriptionDiagnosticsDataType_clear(&sddt);
        UA_QualifiedName_clear(&bn);
        return UA_STATUSCODE_BADNOTIMPLEMENTED;
    }
    memcpy(memberName, bn.name.data, bn.name.length);
    memberName[bn.name.length] = 0;

    size_t memberOffset;
    const UA_DataType *memberType;
    UA_Boolean isArray;
    UA_Boolean found =
        UA_DataType_getStructMember(&UA_TYPES[UA_TYPES_SUBSCRIPTIONDIAGNOSTICSDATATYPE],
                                    memberName, &memberOffset, &memberType, &isArray);
    if(!found) {
        /* Not the member, but the main subscription diagnostics variable... */
        memberOffset = 0;
        memberType = &UA_TYPES[UA_TYPES_SUBSCRIPTIONDIAGNOSTICSDATATYPE];
    }

    void *content = (void*)(((uintptr_t)&sddt) + memberOffset);
    res = UA_Variant_setScalarCopy(&value->value, content, memberType);
    if(UA_LIKELY(res == UA_STATUSCODE_GOOD))
        value->hasValue = true;

    UA_SubscriptionDiagnosticsDataType_clear(&sddt);
    UA_QualifiedName_clear(&bn);
    return res;
}

/* Return all subscriptions in the server. */
UA_StatusCode
readSubscriptionDiagnosticsArray(UA_Server *server,
                                 const UA_NodeId *sessionId, void *sessionContext,
                                 const UA_NodeId *nodeId, void *nodeContext,
                                 UA_Boolean sourceTimestamp,
                                 const UA_NumericRange *range, UA_DataValue *value) {
    lockServer(server);

    /* Get the current session */
    size_t sdSize = 0;
    session_list_entry *sentry;
    LIST_FOREACH(sentry, &server->sessions, pointers) {
        sdSize += sentry->session.subscriptionsSize;
    }

    /* Allocate the output array */
    UA_SubscriptionDiagnosticsDataType *sd = (UA_SubscriptionDiagnosticsDataType*)
        UA_Array_new(sdSize, &UA_TYPES[UA_TYPES_SUBSCRIPTIONDIAGNOSTICSDATATYPE]);
    if(!sd) {
        unlockServer(server);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    /* Collect the statistics */
    size_t i = 0;
    UA_Subscription *sub;
    LIST_FOREACH(sentry, &server->sessions, pointers) {
        TAILQ_FOREACH(sub, &sentry->session.subscriptions, sessionListEntry) {
            fillSubscriptionDiagnostics(sub, &sd[i]);
            i++;
        }
    }

    /* Set the output */
    value->hasValue = true;
    UA_Variant_setArray(&value->value, sd, sdSize,
                        &UA_TYPES[UA_TYPES_SUBSCRIPTIONDIAGNOSTICSDATATYPE]);

    unlockServer(server);
    return UA_STATUSCODE_GOOD;
}

void
createSubscriptionObject(UA_Server *server, UA_Session *session,
                         UA_Subscription *sub) {
    UA_ExpandedNodeId *children = NULL;
    size_t childrenSize = 0;
    UA_ReferenceTypeSet refTypes;
    UA_NodeId hasComponent = UA_NS0ID(HASCOMPONENT);

    char subIdStr[32];
    itoaUnsigned(sub->subscriptionId, subIdStr, 10);

    /* Find the NodeId of the SubscriptionDiagnosticsArray */
    UA_BrowsePath bp;
    UA_BrowsePath_init(&bp);
    bp.startingNode = sub->session->sessionId;
    UA_RelativePathElement rpe[1];
    memset(rpe, 0, sizeof(UA_RelativePathElement) * 1);
    rpe[0].targetName = UA_QUALIFIEDNAME(0, "SubscriptionDiagnosticsArray");
    bp.relativePath.elements = rpe;
    bp.relativePath.elementsSize = 1;
    UA_BrowsePathResult bpr = translateBrowsePathToNodeIds(server, &bp);
    if(bpr.targetsSize < 1)
        return;

    /* Create an object for the subscription. Instantiates all the mandatory
     * children. */
    UA_VariableAttributes var_attr = UA_VariableAttributes_default;
    var_attr.valueRank = -1;
    var_attr.displayName.text = UA_STRING(subIdStr);
    var_attr.dataType = UA_TYPES[UA_TYPES_SUBSCRIPTIONDIAGNOSTICSDATATYPE].typeId;
    UA_NodeId refId = UA_NS0ID(HASCOMPONENT);
    UA_QualifiedName browseName = UA_QUALIFIEDNAME(0, subIdStr);
    UA_NodeId typeId = UA_NS0ID(SUBSCRIPTIONDIAGNOSTICSTYPE);
    UA_CallbackValueSource subDiagSource = {readSubscriptionDiagnostics, NULL};

    /* Assign a random free NodeId */
    UA_StatusCode res = addNode(server, UA_NODECLASS_VARIABLE, UA_NODEID_NUMERIC(1, 0),
                                bpr.targets[0].targetId.nodeId,
                                refId, browseName, typeId, &var_attr,
                                &UA_TYPES[UA_TYPES_VARIABLEATTRIBUTES], NULL,
                                &sub->ns0Id);
    UA_CHECK_STATUS(res, goto cleanup);

    /* Add a second reference from the overall SubscriptionDiagnosticsArray
     * variable. The diagnostics belong to the server. The Session that creates
     * the Subscription need not be allowed to add References in Namespace
     * Zero. */
    res = addRef(server, subDiagArray, refId, sub->ns0Id, true);
    if(res != UA_STATUSCODE_GOOD)
        goto cleanup;

    /* Get all children (including the variable itself) and set the contenxt + callback */
    res = referenceTypeIndices(server, &hasComponent, &refTypes, false);
    if(UA_LIKELY(res == UA_STATUSCODE_GOOD)) {
        res = browseRecursive(server, 1, &sub->ns0Id,
                              UA_BROWSEDIRECTION_FORWARD, &refTypes,
                              UA_NODECLASS_VARIABLE, true, &childrenSize, &children);
    }
    if(res != UA_STATUSCODE_GOOD)
        goto cleanup;

    /* Add the callback to all variables  */
    for(size_t i = 0; i < childrenSize; i++) {
        setVariableNode_callbackValueSource(server, children[i].nodeId, subDiagSource);
        setNodeContext(server, children[i].nodeId, sub);
#ifdef UA_ENABLE_RBAC
        protectSessionDiagnosticsNode(server, &children[i].nodeId);
#endif
    }

    UA_Array_delete(children, childrenSize, &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);

 cleanup:
    UA_BrowsePathResult_clear(&bpr);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING_SESSION(server->config.logging, session,
                               "Creating the subscription diagnostics object failed "
                               "with StatusCode %s", UA_StatusCode_name(res));
    }
}

/***********************/
/* Session Diagnostics */
/***********************/

static UA_StatusCode
setSessionSubscriptionDiagnostics(UA_Server *server, UA_Session *session,
                                  UA_DataValue *value) {
    UA_LOCK_ASSERT(&server->serviceMutex);

    /* Get the current session */
    size_t sdSize = session->subscriptionsSize;

    /* Allocate the output array */
    UA_SubscriptionDiagnosticsDataType *sd = (UA_SubscriptionDiagnosticsDataType*)
        UA_Array_new(sdSize, &UA_TYPES[UA_TYPES_SUBSCRIPTIONDIAGNOSTICSDATATYPE]);
    if(!sd)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    /* Collect the statistics */
    size_t i = 0;
    UA_Subscription *sub;
    TAILQ_FOREACH(sub, &session->subscriptions, sessionListEntry) {
        fillSubscriptionDiagnostics(sub, &sd[i]);
        i++;
    }

    /* Set the output */
    value->hasValue = true;
    UA_Variant_setArray(&value->value, sd, sdSize,
                        &UA_TYPES[UA_TYPES_SUBSCRIPTIONDIAGNOSTICSDATATYPE]);
    return UA_STATUSCODE_GOOD;
}

#endif /* UA_ENABLE_SUBSCRIPTIONS */

static void
setSessionDiagnostics(UA_Session *session, UA_SessionDiagnosticsDataType *sd) {
    UA_SessionDiagnosticsDataType_copy(&session->diagnostics, sd);
    UA_NodeId_copy(&session->sessionId, &sd->sessionId);
    UA_String_copy(&session->sessionName, &sd->sessionName);
    UA_ApplicationDescription_copy(&session->clientDescription,
                                   &sd->clientDescription);
    sd->maxResponseMessageSize = session->maxResponseMessageSize;
#ifdef UA_ENABLE_SUBSCRIPTIONS
    sd->currentPublishRequestsInQueue = (UA_UInt32)session->responseQueueSize;
#endif
    sd->actualSessionTimeout = session->timeout;

    /* Set LocaleIds */
    UA_StatusCode res =
        UA_Array_copy(session->localeIds, session->localeIdsSize,
                      (void **)&sd->localeIds, &UA_TYPES[UA_TYPES_STRING]);
    if(UA_LIKELY(res == UA_STATUSCODE_GOOD))
        sd->localeIdsSize = session->localeIdsSize;

        /* Set Subscription diagnostics */
#ifdef UA_ENABLE_SUBSCRIPTIONS
    sd->currentSubscriptionsCount = (UA_UInt32)session->subscriptionsSize;

    UA_Subscription *sub;
    TAILQ_FOREACH(sub, &session->subscriptions, sessionListEntry) {
        sd->currentMonitoredItemsCount += (UA_UInt32)sub->monitoredItemsSize;
    }
#endif
}

UA_StatusCode
readSessionDiagnosticsArray(UA_Server *server,
                            const UA_NodeId *sessionId, void *sessionContext,
                            const UA_NodeId *nodeId, void *nodeContext,
                            UA_Boolean sourceTimestamp,
                            const UA_NumericRange *range, UA_DataValue *value) {
    /* Allocate the output array */
    UA_SessionDiagnosticsDataType *sd = (UA_SessionDiagnosticsDataType*)
        UA_Array_new(server->sessionCount,
                     &UA_TYPES[UA_TYPES_SESSIONDIAGNOSTICSDATATYPE]);
    if(!sd)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    lockServer(server);

    /* Collect the statistics */
    size_t i = 0;
    session_list_entry *session;
    LIST_FOREACH(session, &server->sessions, pointers) {
        setSessionDiagnostics(&session->session, &sd[i]);
        i++;
    }

    /* Set the output */
    value->hasValue = true;
    UA_Variant_setArray(&value->value, sd, server->sessionCount,
                        &UA_TYPES[UA_TYPES_SESSIONDIAGNOSTICSDATATYPE]);

    unlockServer(server);
    return UA_STATUSCODE_GOOD;
}

static void
setSessionSecurityDiagnostics(UA_Session *session,
                              UA_SessionSecurityDiagnosticsDataType *sd) {
    UA_SessionSecurityDiagnosticsDataType_copy(&session->securityDiagnostics, sd);
    UA_NodeId_copy(&session->sessionId, &sd->sessionId);
    UA_String_copy(&session->clientUserIdOfSession, &sd->clientUserIdOfSession);
    UA_SecureChannel *channel = session->channel;
    if(channel) {
        UA_ByteString_copy(&channel->remoteCertificate, &sd->clientCertificate);
        UA_String_copy(&channel->securityPolicy->policyUri, &sd->securityPolicyUri);
        sd->securityMode = channel->securityMode;
        sd->encoding = UA_STRING_ALLOC("UA Binary"); /* The only one atm */
        sd->transportProtocol = UA_STRING_ALLOC("opc.tcp"); /* The only one atm */
    }
}

/* The security diagnostics of a Session "should not be made accessible to all
 * users, but only to authorised users" (Part 5 §6.3.4, §6.3.5). While Namespace
 * Zero has a RolePermission model, a Session sees the entries of other
 * Sessions only as the local admin or with the SecurityAdmin Role. Without RBAC
 * or in legacy mode all entries are visible. */
static UA_Boolean
showSessionSecurityDiagnostics(UA_Server *server, const UA_Session *reader,
                               const UA_Session *session) {
#ifdef UA_ENABLE_RBAC
    if(reader == session || reader == &server->adminSession)
        return true;
    size_t entriesSize = 0;
    const UA_RolePermission *entries = NULL;
    if(!getNamespaceRolePermissionModel(server, 0, &entriesSize, &entries))
        return true;
    return (reader && hasSecurityAdminRole(reader));
#else
    return true;
#endif
}

static UA_StatusCode
readSessionDiagnostics(UA_Server *server,
                       const UA_NodeId *sessionId, void *sessionContext,
                       const UA_NodeId *nodeId, void *nodeContext,
                       UA_Boolean sourceTimestamp,
                       const UA_NumericRange *range, UA_DataValue *value) {
    lockServer(server);

    /* Get the Session that owns the diagnostics object */
    UA_Session *session = getDiagnosticsOwnerSession(server, nodeId);
    if(!session) {
        unlockServer(server);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    const UA_Session *reader = getSessionById(server, sessionId);

    /* Read the BrowseName */
    UA_QualifiedName bn;
    UA_StatusCode res = readWithReadValue(server, nodeId, UA_ATTRIBUTEID_BROWSENAME, &bn);
    if(res != UA_STATUSCODE_GOOD) {
        unlockServer(server);
        return res;
    }

    union {
        UA_SessionDiagnosticsDataType sddt;
        UA_SessionSecurityDiagnosticsDataType ssddt;
    } data;
    void *content;
    UA_Boolean isArray = false;
    const UA_DataType *type = NULL;
    UA_Boolean securityDiagnostics = false;

    char memberName[128];
    size_t memberOffset;
    UA_Boolean found;

#ifdef UA_ENABLE_SUBSCRIPTIONS
    if(equalBrowseName(&bn.name, "SubscriptionDiagnosticsArray")) {
        res = setSessionSubscriptionDiagnostics(server, session, value);
        goto cleanup;
    }
#endif

    if(equalBrowseName(&bn.name, "SessionDiagnostics")) {
        setSessionDiagnostics(session, &data.sddt);
        content = &data.sddt;
        type = &UA_TYPES[UA_TYPES_SESSIONDIAGNOSTICSDATATYPE];
    } else if(equalBrowseName(&bn.name, "SessionSecurityDiagnostics")) {
        setSessionSecurityDiagnostics(session, &data.ssddt);
        securityDiagnostics = true;
        content = &data.ssddt;
        type = &UA_TYPES[UA_TYPES_SESSIONSECURITYDIAGNOSTICSDATATYPE];
    } else {
        /* Try to find the member in SessionDiagnosticsDataType and
         * SessionSecurityDiagnosticsDataType */
        if(bn.name.length >= sizeof(memberName)) {
            res = UA_STATUSCODE_BADNOTIMPLEMENTED;
            goto cleanup;
        }
        memcpy(memberName, bn.name.data, bn.name.length);
        memberName[bn.name.length] = 0;
        found = UA_DataType_getStructMember(&UA_TYPES[UA_TYPES_SESSIONDIAGNOSTICSDATATYPE],
                                            memberName, &memberOffset, &type, &isArray);
        if(found) {
            setSessionDiagnostics(session, &data.sddt);
            content = (void*)(((uintptr_t)&data.sddt) + memberOffset);
        } else {
            const UA_DataType *dt = &UA_TYPES[UA_TYPES_SESSIONSECURITYDIAGNOSTICSDATATYPE];
            found = UA_DataType_getStructMember(dt, memberName, &memberOffset,
                                                &type, &isArray);
            if(!found) {
                res = UA_STATUSCODE_BADNOTIMPLEMENTED;
                goto cleanup;
            }
            setSessionSecurityDiagnostics(session, &data.ssddt);
            securityDiagnostics = true;
            content = (void*)(((uintptr_t)&data.ssddt) + memberOffset);
        }
    }

    /* Only authorised users see the security diagnostics of other Sessions */
    if(securityDiagnostics &&
       !showSessionSecurityDiagnostics(server, reader, session)) {
        res = UA_STATUSCODE_BADUSERACCESSDENIED;
        UA_SessionSecurityDiagnosticsDataType_clear(&data.ssddt);
        goto cleanup;
    }

    if(!isArray) {
        res = UA_Variant_setScalarCopy(&value->value, content, type);
    } else {
        size_t len = *(size_t*)content;
        content = *(void**)((uintptr_t)content + sizeof(size_t));
        res = UA_Variant_setArrayCopy(&value->value, content, len, type);
    }
    if(UA_LIKELY(res == UA_STATUSCODE_GOOD))
        value->hasValue = true;

    if(securityDiagnostics)
        UA_SessionSecurityDiagnosticsDataType_clear(&data.ssddt);
    else
        UA_SessionDiagnosticsDataType_clear(&data.sddt);

 cleanup:
    UA_QualifiedName_clear(&bn);
    unlockServer(server);
    return res;
}

UA_StatusCode
readSessionSecurityDiagnostics(UA_Server *server,
                               const UA_NodeId *sessionId, void *sessionContext,
                               const UA_NodeId *nodeId, void *nodeContext,
                               UA_Boolean sourceTimestamp,
                               const UA_NumericRange *range, UA_DataValue *value) {
    lockServer(server);

    /* Count the visible Sessions */
    const UA_Session *reader = getSessionById(server, sessionId);
    size_t visible = 0;
    session_list_entry *session;
    LIST_FOREACH(session, &server->sessions, pointers) {
        if(showSessionSecurityDiagnostics(server, reader, &session->session))
            visible++;
    }

    /* Allocate the output array */
    UA_SessionSecurityDiagnosticsDataType *sd = (UA_SessionSecurityDiagnosticsDataType*)
        UA_Array_new(visible, &UA_TYPES[UA_TYPES_SESSIONSECURITYDIAGNOSTICSDATATYPE]);
    if(!sd) {
        unlockServer(server);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    /* Collect the statistics */
    size_t i = 0;
    LIST_FOREACH(session, &server->sessions, pointers) {
        if(!showSessionSecurityDiagnostics(server, reader, &session->session))
            continue;
        setSessionSecurityDiagnostics(&session->session, &sd[i]);
        i++;
    }

    /* Set the output */
    value->hasValue = true;
    UA_Variant_setArray(&value->value, sd, visible,
                        &UA_TYPES[UA_TYPES_SESSIONSECURITYDIAGNOSTICSDATATYPE]);

    unlockServer(server);
    return UA_STATUSCODE_GOOD;
}

#ifdef UA_ENABLE_RBAC
/* CurrentRoleIds lists the Roles granted to the Session. Since this is
 * security-related, other Sessions than the owning Session see it only as the
 * local admin or with the SecurityAdmin Role (Part 5 §6.3.5). */
static UA_StatusCode
readSessionCurrentRoleIds(UA_Server *server,
                          const UA_NodeId *sessionId, void *sessionContext,
                          const UA_NodeId *nodeId, void *nodeContext,
                          UA_Boolean sourceTimestamp,
                          const UA_NumericRange *range, UA_DataValue *value) {
    lockServer(server);
    UA_Session *owner = getDiagnosticsOwnerSession(server, nodeId);
    if(!owner) {
        unlockServer(server);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    const UA_Session *reader = getSessionById(server, sessionId);
    if(reader != owner && reader != &server->adminSession &&
       (!reader || !hasSecurityAdminRole(reader))) {
        unlockServer(server);
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    }
    UA_StatusCode res =
        UA_Variant_setArrayCopy(&value->value, owner->roles, owner->rolesSize,
                                &UA_TYPES[UA_TYPES_NODEID]);
    if(res == UA_STATUSCODE_GOOD)
        value->hasValue = true;
    unlockServer(server);
    return res;
}

/* Add the optional CurrentRoleIds Property to the diagnostics object */
static UA_StatusCode
addSessionCurrentRoleIds(UA_Server *server, UA_Session *session) {
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    attr.displayName = UA_LOCALIZEDTEXT("", "CurrentRoleIds");
    attr.dataType = UA_TYPES[UA_TYPES_NODEID].typeId;
    attr.valueRank = UA_VALUERANK_ONE_DIMENSION;
    UA_UInt32 arrayDimensions = 0;
    attr.arrayDimensions = &arrayDimensions;
    attr.arrayDimensionsSize = 1;
    attr.accessLevel = UA_ACCESSLEVELMASK_READ;
    UA_NodeId propertyId;
    UA_StatusCode res =
        addNode(server, UA_NODECLASS_VARIABLE, UA_NODEID_NUMERIC(1, 0),
                session->sessionId, UA_NS0ID(HASPROPERTY),
                UA_QUALIFIEDNAME(0, "CurrentRoleIds"), UA_NS0ID(PROPERTYTYPE),
                &attr, &UA_TYPES[UA_TYPES_VARIABLEATTRIBUTES], NULL, &propertyId);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    UA_CallbackValueSource src = {readSessionCurrentRoleIds, NULL};
    res = setVariableNode_callbackValueSource(server, propertyId, src);
    if(res == UA_STATUSCODE_GOOD)
        protectSessionDiagnosticsNode(server, &propertyId);
    UA_NodeId_clear(&propertyId);
    return res;
}
#endif

void
createSessionObject(UA_Server *server, UA_Session *session) {
    UA_ExpandedNodeId *children = NULL;
    size_t childrenSize = 0;
    UA_ReferenceTypeSet refTypes;
    UA_NodeId hasComponent = UA_NS0ID(HASCOMPONENT);
    UA_CallbackValueSource sessionDiagSource = {readSessionDiagnostics, NULL};

    /* Create an object for the session. Instantiates all the mandatory children. */
    UA_ObjectAttributes object_attr = UA_ObjectAttributes_default;
    object_attr.displayName.text = session->sessionName;
    UA_NodeId parentId = UA_NS0ID(SERVER_SERVERDIAGNOSTICS_SESSIONSDIAGNOSTICSSUMMARY);
    UA_NodeId refId = UA_NS0ID(HASCOMPONENT);
    UA_QualifiedName browseName = UA_QUALIFIEDNAME(0, "");
    browseName.name = session->sessionName; /* shallow copy */
    UA_NodeId typeId = UA_NS0ID(SESSIONDIAGNOSTICSOBJECTTYPE);
    UA_StatusCode res = addNode(server, UA_NODECLASS_OBJECT, session->sessionId,
                                parentId, refId, browseName, typeId, &object_attr,
                                &UA_TYPES[UA_TYPES_OBJECTATTRIBUTES], NULL, NULL);
    if(res != UA_STATUSCODE_GOOD)
        goto cleanup;

    /* Recursively browse all children */
    res = referenceTypeIndices(server, &hasComponent, &refTypes, false);
    if(res != UA_STATUSCODE_GOOD)
        goto cleanup;

    res = browseRecursive(server, 1, &session->sessionId,
                          UA_BROWSEDIRECTION_FORWARD, &refTypes,
                          UA_NODECLASS_VARIABLE, false, &childrenSize, &children);
    if(res != UA_STATUSCODE_GOOD)
        goto cleanup;

    /* Add the callback to all variables  */
    for(size_t i = 0; i < childrenSize; i++) {
        setVariableNode_callbackValueSource(server, children[i].nodeId, sessionDiagSource);
    }

#ifdef UA_ENABLE_RBAC
    /* Every Session can read the diagnostics object. The value callbacks
     * restrict the security-related values. */
    protectSessionDiagnosticsNode(server, &session->sessionId);
    for(size_t i = 0; i < childrenSize; i++)
        protectSessionDiagnosticsNode(server, &children[i].nodeId);
    res = addSessionCurrentRoleIds(server, session);
#endif

 cleanup:
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING_SESSION(server->config.logging, session,
                               "Creating the session diagnostics object failed "
                               "with StatusCode %s", UA_StatusCode_name(res));
    }
    UA_Array_delete(children, childrenSize, &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
}

/***************************/
/* Server-Wide Diagnostics */
/***************************/

UA_StatusCode
readDiagnostics(UA_Server *server, const UA_NodeId *sessionId, void *sessionContext,
                const UA_NodeId *nodeId, void *nodeContext, UA_Boolean sourceTimestamp,
                const UA_NumericRange *range, UA_DataValue *value) {
    if(range) {
        value->hasStatus = true;
        value->status = UA_STATUSCODE_BADINDEXRANGEINVALID;
        return UA_STATUSCODE_GOOD;
    }

    if(sourceTimestamp) {
        UA_EventLoop *el = server->config.eventLoop;
        value->hasSourceTimestamp = true;
        value->sourceTimestamp = el->dateTime_now(el);
    }

    UA_assert(nodeId->identifierType == UA_NODEIDTYPE_NUMERIC);

    void *data = NULL;
    const UA_DataType *type = &UA_TYPES[UA_TYPES_UINT32]; /* Default */

    lockServer(server);

    switch(nodeId->identifier.numeric) {
    case UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY:
        server->serverDiagnosticsSummary.currentSessionCount =
            server->activeSessionCount;
        data = &server->serverDiagnosticsSummary;
        type = &UA_TYPES[UA_TYPES_SERVERDIAGNOSTICSSUMMARYDATATYPE];
        break;
    case UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_SERVERVIEWCOUNT:
        data = &server->serverDiagnosticsSummary.serverViewCount;
        break;
    case UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_CURRENTSESSIONCOUNT:
        data = &server->activeSessionCount;
        break;
    case UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_CUMULATEDSESSIONCOUNT:
        data = &server->serverDiagnosticsSummary.cumulatedSessionCount;
        break;
    case UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_SECURITYREJECTEDSESSIONCOUNT:
        data = &server->serverDiagnosticsSummary.securityRejectedSessionCount;
        break;
    case UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_REJECTEDSESSIONCOUNT:
        data = &server->serverDiagnosticsSummary.rejectedSessionCount;
        break;
    case UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_SESSIONTIMEOUTCOUNT:
        data = &server->serverDiagnosticsSummary.sessionTimeoutCount;
        break;
    case UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_SESSIONABORTCOUNT:
        data = &server->serverDiagnosticsSummary.sessionAbortCount;
        break;
    case UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_CURRENTSUBSCRIPTIONCOUNT:
        data = &server->serverDiagnosticsSummary.currentSubscriptionCount;
        break;
    case UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_CUMULATEDSUBSCRIPTIONCOUNT:
        data = &server->serverDiagnosticsSummary.cumulatedSubscriptionCount;
        break;
    case UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_PUBLISHINGINTERVALCOUNT:
        data = &server->serverDiagnosticsSummary.publishingIntervalCount;
        break;
    case UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_SECURITYREJECTEDREQUESTSCOUNT:
        data = &server->serverDiagnosticsSummary.securityRejectedRequestsCount;
        break;
    case UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_REJECTEDREQUESTSCOUNT:
        data = &server->serverDiagnosticsSummary.rejectedRequestsCount;
        break;
    default:
        unlockServer(server);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_StatusCode res = UA_Variant_setScalarCopy(&value->value, data, type);
    if(res == UA_STATUSCODE_GOOD)
        value->hasValue = true;

    unlockServer(server);
    return res;
}

#endif /* UA_ENABLE_DIAGNOSTICS */
