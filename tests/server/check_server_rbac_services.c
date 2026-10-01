/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

/* RBAC enforcement in the services, called with in-process Sessions. The
 * Sessions have no SecureChannel and the server has no TCP listener. */

#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/nodeids.h>

#include "server/ua_server_internal.h"
#include "server/ua_services.h"

#include "test_helpers.h"

#include <check.h>
#include <stdlib.h>
#include <string.h>

static UA_Server *server = NULL;

static void setup(void) {
    server = UA_Server_newForUnitTest();
    ck_assert(server != NULL);
    UA_Server_getConfig(server)->tcpEnabled = false;
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
}

/* Strict mode with the namespace templates */
static void setupStrict(void) {
    server = UA_Server_newForUnitTest();
    ck_assert(server != NULL);
    UA_ServerConfig *config = UA_Server_getConfig(server);
    config->tcpEnabled = false;
    config->allPermissionsForAnonymous = false;
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
}

static void teardown(void) {
    UA_Server_run_shutdown(server);
    UA_Server_delete(server);
    server = NULL;
}

/* Create an in-process Session that holds exactly one Role */
static UA_Session *
createSessionWithRole(UA_UInt32 roleId) {
    UA_CreateSessionRequest request;
    UA_CreateSessionRequest_init(&request);
    request.requestedSessionTimeout = UA_UINT32_MAX;
    UA_Session *session = NULL;
    lockServer(server);
    UA_StatusCode res = UA_Session_create(server, NULL, &request, &session);
    unlockServer(server);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_ptr_ne(session, NULL);

    UA_NodeId role = UA_NODEID_NUMERIC(0, roleId);
    UA_Variant v;
    UA_Variant_setArray(&v, &role, 1, &UA_TYPES[UA_TYPES_NODEID]);
    ck_assert_uint_eq(UA_Server_setSessionAttribute(server, &session->sessionId,
                                                    UA_QUALIFIEDNAME(0, "roles"), &v),
                      UA_STATUSCODE_GOOD);
    return session;
}

/* Anonymous may browse. ConfigureAdmin gets the given permissions. */
static void
setPermissions(const UA_NodeId nodeId, UA_PermissionType configureAdminPermissions) {
    UA_RolePermission rp[2];
    rp[0].roleId = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS);
    rp[0].permissions = UA_PERMISSIONTYPE_BROWSE;
    rp[1].roleId = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_CONFIGUREADMIN);
    rp[1].permissions = configureAdminPermissions;
    ck_assert_uint_eq(UA_Server_setNodeRolePermissions(server, nodeId, 2, rp,
                                                       false, NULL),
                      UA_STATUSCODE_GOOD);
}

static UA_NodeId
addObject(const char *name, const UA_NodeId parentId,
          const UA_NodeId referenceTypeId, UA_Byte eventNotifier) {
    UA_ObjectAttributes attr = UA_ObjectAttributes_default;
    attr.displayName = UA_LOCALIZEDTEXT("en-US", (char*)(uintptr_t)name);
    attr.eventNotifier = eventNotifier;
    UA_NodeId nodeId = UA_NODEID_STRING(1, (char*)(uintptr_t)name);
    ck_assert_uint_eq(UA_Server_addObjectNode(server, nodeId, parentId,
                                              referenceTypeId,
                                              UA_QUALIFIEDNAME(1, (char*)(uintptr_t)name),
                                              UA_NS0ID(BASEOBJECTTYPE),
                                              attr, NULL, NULL),
                      UA_STATUSCODE_GOOD);
    return nodeId;
}

static UA_Boolean
nodeExists(const UA_NodeId nodeId) {
    UA_NodeClass nodeClass;
    return (UA_Server_readNodeClass(server, nodeId, &nodeClass) == UA_STATUSCODE_GOOD);
}

static void *
matchReferenceTarget(void *context, UA_ReferenceTarget *t) {
    const UA_NodeId *target = (const UA_NodeId*)context;
    if(!UA_NodePointer_isLocal(t->targetId))
        return NULL;
    UA_NodeId id = UA_NodePointer_toNodeId(t->targetId);
    return UA_NodeId_equal(&id, target) ? (void*)0x01 : NULL;
}

/* Inspect the references stored in the source node. Browse would hide
 * references to deleted nodes. */
static UA_Boolean
hasReferenceTo(const UA_NodeId source, const UA_NodeId target) {
    UA_Boolean found = false;
    lockServer(server);
    const UA_Node *node = UA_NODESTORE_GET(server, &source);
    ck_assert_ptr_ne(node, NULL);
    for(size_t i = 0; i < node->head.referencesSize && !found; i++) {
        found = (UA_NodeReferenceKind_iterate(&node->head.references[i],
                                              matchReferenceTarget,
                                              (void*)(uintptr_t)&target) != NULL);
    }
    UA_NODESTORE_RELEASE(server, node);
    unlockServer(server);
    return found;
}

static UA_StatusCode
deleteNodeAs(UA_Session *session, const UA_NodeId nodeId) {
    UA_DeleteNodesItem item;
    UA_DeleteNodesItem_init(&item);
    item.nodeId = nodeId;
    item.deleteTargetReferences = true;
    UA_DeleteNodesRequest request;
    UA_DeleteNodesRequest_init(&request);
    request.nodesToDeleteSize = 1;
    request.nodesToDelete = &item;

    UA_DeleteNodesResponse response;
    UA_DeleteNodesResponse_init(&response);
    lockServer(server);
    Service_DeleteNodes(server, session, &request, &response);
    unlockServer(server);
    ck_assert_uint_eq(response.responseHeader.serviceResult, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(response.resultsSize, 1);
    UA_StatusCode res = response.results[0];
    UA_DeleteNodesResponse_clear(&response);
    return res;
}

/****************/
/* Delete Nodes */
/****************/

/* The child is deleted together with its parent. Without DeleteNode on the
 * child, the whole delete is refused and nothing is deleted. */
START_TEST(deleteNodes_recursive_refusedWithoutChildPermission) {
    UA_NodeId parent = addObject("Parent", UA_NS0ID(OBJECTSFOLDER),
                                 UA_NS0ID(ORGANIZES), 0);
    UA_NodeId child = addObject("Child", parent, UA_NS0ID(HASCOMPONENT), 0);
    setPermissions(parent, UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_DELETENODE);
    setPermissions(child, UA_PERMISSIONTYPE_BROWSE);
    UA_Session *session = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_CONFIGUREADMIN);

    ck_assert_uint_eq(deleteNodeAs(session, parent), UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert(nodeExists(parent));
    ck_assert(nodeExists(child));
    ck_assert(hasReferenceTo(UA_NS0ID(OBJECTSFOLDER), parent));
    ck_assert(hasReferenceTo(parent, child));

    /* The local admin is not restricted */
    ck_assert_uint_eq(UA_Server_deleteNode(server, parent, true), UA_STATUSCODE_GOOD);
    ck_assert(!nodeExists(parent));
    ck_assert(!nodeExists(child));
} END_TEST

START_TEST(deleteNodes_recursive_grantedWithChildPermission) {
    UA_NodeId parent = addObject("Parent", UA_NS0ID(OBJECTSFOLDER),
                                 UA_NS0ID(ORGANIZES), 0);
    UA_NodeId child = addObject("Child", parent, UA_NS0ID(HASCOMPONENT), 0);
    setPermissions(parent, UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_DELETENODE);
    setPermissions(child, UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_DELETENODE);
    UA_Session *session = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_CONFIGUREADMIN);

    ck_assert_uint_eq(deleteNodeAs(session, parent), UA_STATUSCODE_GOOD);
    ck_assert(!nodeExists(parent));
    ck_assert(!nodeExists(child));
    ck_assert(!hasReferenceTo(UA_NS0ID(OBJECTSFOLDER), parent));
} END_TEST

/* The AccessRestrictions of the child apply as well. The in-process Session
 * has no SecureChannel and cannot satisfy EncryptionRequired. */
START_TEST(deleteNodes_recursive_childEncryptionRequired) {
    UA_NodeId parent = addObject("Parent", UA_NS0ID(OBJECTSFOLDER),
                                 UA_NS0ID(ORGANIZES), 0);
    UA_NodeId child = addObject("Child", parent, UA_NS0ID(HASCOMPONENT), 0);
    setPermissions(parent, UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_DELETENODE);
    setPermissions(child, UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_DELETENODE);
    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, child,
                          UA_ACCESSRESTRICTIONTYPE_ENCRYPTIONREQUIRED),
                      UA_STATUSCODE_GOOD);
    UA_Session *session = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_CONFIGUREADMIN);

    ck_assert_uint_eq(deleteNodeAs(session, parent),
                      UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT);
    ck_assert(nodeExists(parent));
    ck_assert(nodeExists(child));
    ck_assert(hasReferenceTo(parent, child));
} END_TEST

/* Deleting a node removes the references that point to it. This must not
 * depend on the RemoveReference permission on the referencing nodes. Otherwise
 * the references would dangle. */
START_TEST(deleteNodes_removesIncomingReferences) {
    UA_NodeId referrer = addObject("Referrer", UA_NS0ID(OBJECTSFOLDER),
                                   UA_NS0ID(ORGANIZES), 0);
    UA_NodeId target = addObject("Target", UA_NS0ID(OBJECTSFOLDER),
                                 UA_NS0ID(ORGANIZES), 0);
    ck_assert_uint_eq(UA_Server_addReference(server, referrer,
                                             UA_NS0ID(HASNOTIFIER),
                                             UA_EXPANDEDNODEID_NODEID(target), true),
                      UA_STATUSCODE_GOOD);
    setPermissions(referrer, UA_PERMISSIONTYPE_BROWSE);
    setPermissions(target, UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_DELETENODE);
    UA_Session *session = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_CONFIGUREADMIN);
    ck_assert(hasReferenceTo(referrer, target));

    ck_assert_uint_eq(deleteNodeAs(session, target), UA_STATUSCODE_GOOD);
    ck_assert(!nodeExists(target));
    ck_assert(nodeExists(referrer));
    ck_assert(!hasReferenceTo(referrer, target));
    ck_assert(!hasReferenceTo(UA_NS0ID(OBJECTSFOLDER), target));
} END_TEST

/* A child with another parent is not deleted along. So its permissions do
 * not matter for the delete. */
START_TEST(deleteNodes_childWithOtherParentNotCollected) {
    UA_NodeId parent = addObject("Parent", UA_NS0ID(OBJECTSFOLDER),
                                 UA_NS0ID(ORGANIZES), 0);
    UA_NodeId otherParent = addObject("OtherParent", UA_NS0ID(OBJECTSFOLDER),
                                      UA_NS0ID(ORGANIZES), 0);
    UA_NodeId child = addObject("Child", parent, UA_NS0ID(HASCOMPONENT), 0);
    ck_assert_uint_eq(UA_Server_addReference(server, otherParent,
                                             UA_NS0ID(ORGANIZES),
                                             UA_EXPANDEDNODEID_NODEID(child), true),
                      UA_STATUSCODE_GOOD);
    setPermissions(parent, UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_DELETENODE);
    setPermissions(child, UA_PERMISSIONTYPE_BROWSE);
    UA_Session *session = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_CONFIGUREADMIN);

    ck_assert_uint_eq(deleteNodeAs(session, parent), UA_STATUSCODE_GOOD);
    ck_assert(!nodeExists(parent));
    ck_assert(nodeExists(child));
    ck_assert(hasReferenceTo(otherParent, child));
    ck_assert(!hasReferenceTo(child, parent));
} END_TEST

/*************/
/* Add Nodes */
/*************/

static UA_StatusCode
addObjectAs(UA_Session *session, const char *name, const UA_NodeId parentId,
            const UA_NodeId typeId, UA_NodeId *outNodeId) {
    UA_ObjectAttributes attr = UA_ObjectAttributes_default;
    attr.displayName = UA_LOCALIZEDTEXT("en-US", (char*)(uintptr_t)name);
    UA_AddNodesItem item;
    UA_AddNodesItem_init(&item);
    item.parentNodeId.nodeId = parentId;
    item.referenceTypeId = UA_NS0ID(HASCOMPONENT);
    item.requestedNewNodeId.nodeId = UA_NODEID_STRING(1, (char*)(uintptr_t)name);
    item.browseName = UA_QUALIFIEDNAME(1, (char*)(uintptr_t)name);
    item.nodeClass = UA_NODECLASS_OBJECT;
    item.typeDefinition.nodeId = typeId;
    UA_ExtensionObject_setValueNoDelete(&item.nodeAttributes, &attr,
                                        &UA_TYPES[UA_TYPES_OBJECTATTRIBUTES]);
    UA_AddNodesRequest request;
    UA_AddNodesRequest_init(&request);
    request.nodesToAddSize = 1;
    request.nodesToAdd = &item;

    UA_AddNodesResponse response;
    UA_AddNodesResponse_init(&response);
    lockServer(server);
    Service_AddNodes(server, session, &request, &response);
    unlockServer(server);
    ck_assert_uint_eq(response.responseHeader.serviceResult, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(response.resultsSize, 1);
    UA_StatusCode res = response.results[0].statusCode;
    if(outNodeId)
        UA_NodeId_copy(&response.results[0].addedNodeId, outNodeId);
    UA_AddNodesResponse_clear(&response);
    return res;
}

/* The parent gets a Reference to the new Node. Without AddReference on the
 * parent the Node is not added. */
START_TEST(addNodes_refusedWithoutParentAddReference) {
    UA_NodeId parent = addObject("Parent", UA_NS0ID(OBJECTSFOLDER),
                                 UA_NS0ID(ORGANIZES), 0);
    setPermissions(parent, UA_PERMISSIONTYPE_BROWSE);
    UA_Session *session = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_CONFIGUREADMIN);

    UA_NodeId child = UA_NODEID_STRING(1, "Child");
    ck_assert_uint_eq(addObjectAs(session, "Child", parent,
                                  UA_NS0ID(BASEOBJECTTYPE), NULL),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert(!nodeExists(child));
    ck_assert(!hasReferenceTo(parent, child));
} END_TEST

START_TEST(addNodes_grantedWithParentAddReference) {
    UA_NodeId parent = addObject("Parent", UA_NS0ID(OBJECTSFOLDER),
                                 UA_NS0ID(ORGANIZES), 0);
    setPermissions(parent, UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_ADDREFERENCE);
    UA_Session *session = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_CONFIGUREADMIN);

    UA_NodeId child = UA_NODEID_STRING(1, "Child");
    ck_assert_uint_eq(addObjectAs(session, "Child", parent,
                                  UA_NS0ID(BASEOBJECTTYPE), NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert(nodeExists(child));
    ck_assert(hasReferenceTo(parent, child));
} END_TEST

/* Adding the Reference from the parent also needs a SecureChannel that
 * satisfies the AccessRestrictions of the parent, as for AddReferences. The
 * parent Reference is added with the Session, which enforces them, and the
 * Node is removed again. */
START_TEST(addNodes_refusedByParentAccessRestrictions) {
    UA_NodeId parent = addObject("Parent", UA_NS0ID(OBJECTSFOLDER),
                                 UA_NS0ID(ORGANIZES), 0);
    setPermissions(parent, UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_ADDREFERENCE);
    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, parent,
                          UA_ACCESSRESTRICTIONTYPE_ENCRYPTIONREQUIRED),
                      UA_STATUSCODE_GOOD);
    UA_Session *session = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_CONFIGUREADMIN);

    UA_NodeId child = UA_NODEID_STRING(1, "Child");
    ck_assert_uint_eq(addObjectAs(session, "Child", parent,
                                  UA_NS0ID(BASEOBJECTTYPE), NULL),
                      UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT);
    ck_assert(!nodeExists(child));
    ck_assert(!hasReferenceTo(parent, child));
} END_TEST

/* The children of an instantiated type are referenced from the new instance,
 * not from the parent. AddReference on the parent is sufficient. The type and
 * its InstanceDeclarations only allow Browse. */
START_TEST(addNodes_instantiationNeedsOnlyParentAddReference) {
    UA_ObjectTypeAttributes typeAttr = UA_ObjectTypeAttributes_default;
    typeAttr.displayName = UA_LOCALIZEDTEXT("en-US", "DeviceType");
    UA_NodeId typeId = UA_NODEID_STRING(1, "DeviceType");
    ck_assert_uint_eq(UA_Server_addObjectTypeNode(server, typeId,
                          UA_NS0ID(BASEOBJECTTYPE), UA_NS0ID(HASSUBTYPE),
                          UA_QUALIFIEDNAME(1, "DeviceType"), typeAttr,
                          NULL, NULL), UA_STATUSCODE_GOOD);

    UA_VariableAttributes varAttr = UA_VariableAttributes_default;
    varAttr.displayName = UA_LOCALIZEDTEXT("en-US", "Status");
    UA_NodeId statusDecl = UA_NODEID_STRING(1, "DeviceType.Status");
    ck_assert_uint_eq(UA_Server_addVariableNode(server, statusDecl, typeId,
                          UA_NS0ID(HASCOMPONENT), UA_QUALIFIEDNAME(1, "Status"),
                          UA_NS0ID(BASEDATAVARIABLETYPE), varAttr, NULL, NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_addReference(server, statusDecl,
                          UA_NS0ID(HASMODELLINGRULE),
                          UA_EXPANDEDNODEID_NUMERIC(0, UA_NS0ID_MODELLINGRULE_MANDATORY),
                          true), UA_STATUSCODE_GOOD);

    UA_MethodAttributes methodAttr = UA_MethodAttributes_default;
    methodAttr.displayName = UA_LOCALIZEDTEXT("en-US", "Reset");
    methodAttr.executable = true;
    UA_NodeId resetDecl = UA_NODEID_STRING(1, "DeviceType.Reset");
    ck_assert_uint_eq(UA_Server_addMethodNode(server, resetDecl, typeId,
                          UA_NS0ID(HASCOMPONENT), UA_QUALIFIEDNAME(1, "Reset"),
                          methodAttr, NULL, 0, NULL, 0, NULL, NULL, NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_addReference(server, resetDecl,
                          UA_NS0ID(HASMODELLINGRULE),
                          UA_EXPANDEDNODEID_NUMERIC(0, UA_NS0ID_MODELLINGRULE_MANDATORY),
                          true), UA_STATUSCODE_GOOD);

    setPermissions(typeId, UA_PERMISSIONTYPE_BROWSE);
    setPermissions(statusDecl, UA_PERMISSIONTYPE_BROWSE);
    setPermissions(resetDecl, UA_PERMISSIONTYPE_BROWSE);

    UA_NodeId parent = addObject("Parent", UA_NS0ID(OBJECTSFOLDER),
                                 UA_NS0ID(ORGANIZES), 0);
    setPermissions(parent, UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_ADDREFERENCE);
    UA_Session *session = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_CONFIGUREADMIN);

    UA_NodeId device = UA_NODEID_NULL;
    ck_assert_uint_eq(addObjectAs(session, "Device", parent, typeId, &device),
                      UA_STATUSCODE_GOOD);
    ck_assert(nodeExists(device));
    ck_assert(hasReferenceTo(parent, device));
    ck_assert(hasReferenceTo(device, resetDecl));

    /* The mandatory Variable was instantiated */
    UA_QualifiedName statusName = UA_QUALIFIEDNAME(1, "Status");
    UA_BrowsePathResult bpr =
        UA_Server_browseSimplifiedBrowsePath(server, device, 1, &statusName);
    ck_assert_uint_eq(bpr.statusCode, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(bpr.targetsSize, 1);
    ck_assert(!UA_NodeId_equal(&bpr.targets[0].targetId.nodeId, &statusDecl));
    UA_BrowsePathResult_clear(&bpr);
    UA_NodeId_clear(&device);
} END_TEST

/**************************/
/* Event MonitoredItems   */
/**************************/

#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
static UA_StatusCode
createEventItemAsEx(UA_Session *session, const UA_NodeId nodeId,
                    UA_MonitoredItem **outMon) {
    UA_CreateSubscriptionRequest subRequest;
    UA_CreateSubscriptionRequest_init(&subRequest);
    subRequest.publishingEnabled = true;
    UA_CreateSubscriptionResponse subResponse;
    UA_CreateSubscriptionResponse_init(&subResponse);
    lockServer(server);
    Service_CreateSubscription(server, session, &subRequest, &subResponse);
    unlockServer(server);
    ck_assert_uint_eq(subResponse.responseHeader.serviceResult, UA_STATUSCODE_GOOD);

    UA_QualifiedName message = UA_QUALIFIEDNAME(0, "Message");
    UA_SimpleAttributeOperand select;
    UA_SimpleAttributeOperand_init(&select);
    select.typeDefinitionId = UA_NS0ID(BASEEVENTTYPE);
    select.browsePathSize = 1;
    select.browsePath = &message;
    select.attributeId = UA_ATTRIBUTEID_VALUE;
    UA_EventFilter filter;
    UA_EventFilter_init(&filter);
    filter.selectClausesSize = 1;
    filter.selectClauses = &select;

    UA_MonitoredItemCreateRequest item;
    UA_MonitoredItemCreateRequest_init(&item);
    item.itemToMonitor.nodeId = nodeId;
    item.itemToMonitor.attributeId = UA_ATTRIBUTEID_EVENTNOTIFIER;
    item.monitoringMode = UA_MONITORINGMODE_REPORTING;
    UA_ExtensionObject_setValue(&item.requestedParameters.filter, &filter,
                                &UA_TYPES[UA_TYPES_EVENTFILTER]);
    UA_CreateMonitoredItemsRequest request;
    UA_CreateMonitoredItemsRequest_init(&request);
    request.subscriptionId = subResponse.subscriptionId;
    request.timestampsToReturn = UA_TIMESTAMPSTORETURN_BOTH;
    request.itemsToCreateSize = 1;
    request.itemsToCreate = &item;

    UA_CreateMonitoredItemsResponse response;
    UA_CreateMonitoredItemsResponse_init(&response);
    lockServer(server);
    Service_CreateMonitoredItems(server, session, &request, &response);
    unlockServer(server);
    ck_assert_uint_eq(response.responseHeader.serviceResult, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(response.resultsSize, 1);
    UA_StatusCode res = response.results[0].statusCode;
    if(outMon && res == UA_STATUSCODE_GOOD) {
        lockServer(server);
        UA_Subscription *sub =
            UA_Session_getSubscriptionById(session, subResponse.subscriptionId);
        ck_assert_ptr_ne(sub, NULL);
        *outMon = UA_Subscription_getMonitoredItem(sub,
                                                   response.results[0].monitoredItemId);
        unlockServer(server);
        ck_assert_ptr_ne(*outMon, NULL);
    }
    UA_CreateMonitoredItemsResponse_clear(&response);
    UA_CreateSubscriptionResponse_clear(&subResponse);
    return res;
}

static UA_StatusCode
createEventItemAs(UA_Session *session, const UA_NodeId nodeId) {
    return createEventItemAsEx(session, nodeId, NULL);
}

/* The EventNotifier of a node the Session may not browse cannot be read. The
 * reason for that is returned. */
START_TEST(eventItem_unbrowsableNode) {
    UA_NodeId nodeId = addObject("Notifier", UA_NS0ID(OBJECTSFOLDER),
                                 UA_NS0ID(ORGANIZES),
                                 UA_EVENTNOTIFIER_SUBSCRIBE_TO_EVENT);
    setPermissions(nodeId, UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_RECEIVEEVENTS);
    UA_Session *session =
        createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_AUTHENTICATEDUSER);
    ck_assert_uint_eq(createEventItemAs(session, nodeId),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
} END_TEST

START_TEST(eventItem_encryptionRequired) {
    UA_NodeId nodeId = addObject("Notifier", UA_NS0ID(OBJECTSFOLDER),
                                 UA_NS0ID(ORGANIZES),
                                 UA_EVENTNOTIFIER_SUBSCRIBE_TO_EVENT);
    setPermissions(nodeId, UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_RECEIVEEVENTS);
    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, nodeId,
                          UA_ACCESSRESTRICTIONTYPE_ENCRYPTIONREQUIRED),
                      UA_STATUSCODE_GOOD);
    UA_Session *session = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_CONFIGUREADMIN);
    ck_assert_uint_eq(createEventItemAs(session, nodeId),
                      UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT);
} END_TEST

/* Control: with Browse and without restrictions the item is created */
START_TEST(eventItem_browsableNode) {
    UA_NodeId nodeId = addObject("Notifier", UA_NS0ID(OBJECTSFOLDER),
                                 UA_NS0ID(ORGANIZES),
                                 UA_EVENTNOTIFIER_SUBSCRIBE_TO_EVENT);
    setPermissions(nodeId, UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_RECEIVEEVENTS);
    UA_Session *session = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_CONFIGUREADMIN);
    ck_assert_uint_eq(createEventItemAs(session, nodeId), UA_STATUSCODE_GOOD);
} END_TEST

/* Emit a BaseEventType Event with the SourceNode. It is emitted at the Server
 * Object in any case. Returns the number of Events the item received. */
static size_t
emitEventFrom(UA_MonitoredItem *mon, const UA_NodeId sourceNode,
              const UA_NodeId eventType) {
    size_t before = mon->queueSize;
    UA_EventDescription ed;
    memset(&ed, 0, sizeof(ed));
    ed.sourceNode = sourceNode;
    ed.eventType = eventType;
    ed.severity = 100;
    ed.message = UA_LOCALIZEDTEXT("en-US", "Event");
    UA_Server_createEventEx(server, &ed, NULL);
    return mon->queueSize - before;
}

/* Legacy mode: an Event whose SourceNode is not in the AddressSpace is
 * delivered unless the namespace of the SourceNode has a default without
 * ReceiveEvents. An unknown EventType is never delivered. */
START_TEST(eventItem_unknownSourceLegacy) {
    UA_Session *session = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_ANONYMOUS);
    UA_MonitoredItem *mon = NULL;
    ck_assert_uint_eq(createEventItemAsEx(session, UA_NS0ID(SERVER), &mon),
                      UA_STATUSCODE_GOOD);
    const UA_NodeId baseEventType = UA_NS0ID(BASEEVENTTYPE);
    const UA_NodeId unknown = UA_NODEID_STRING(1, "UnknownSource");
    ck_assert_uint_eq(emitEventFrom(mon, unknown, baseEventType), 1);
    ck_assert_uint_eq(emitEventFrom(mon, UA_NODEID_NULL, baseEventType), 1);
    ck_assert_uint_eq(emitEventFrom(mon, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER),
                                    UA_NODEID_STRING(1, "UnknownEventType")), 0);

    /* The namespace default applies to the unknown SourceNode */
    UA_RolePermission browseOnly = {
        UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS),
        UA_PERMISSIONTYPE_BROWSE};
    ck_assert_uint_eq(UA_Server_setNamespaceDefaultRolePermissions(server, 1, 1,
                                                                   &browseOnly),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(emitEventFrom(mon, unknown, baseEventType), 0);
    ck_assert_uint_eq(emitEventFrom(mon, UA_NODEID_NULL, baseEventType), 1);
} END_TEST

/* Strict mode: the template of the namespace of the unknown SourceNode
 * applies. Anonymous may only browse in namespace 1, Observer receives Events
 * there. The null SourceNode is evaluated in Namespace Zero. */
START_TEST(eventItem_unknownSourceStrict) {
    const UA_NodeId baseEventType = UA_NS0ID(BASEEVENTTYPE);
    const UA_NodeId unknown = UA_NODEID_STRING(1, "UnknownSource");

    UA_Session *anonymous = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_ANONYMOUS);
    UA_MonitoredItem *anonymousMon = NULL;
    ck_assert_uint_eq(createEventItemAsEx(anonymous, UA_NS0ID(SERVER), &anonymousMon),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(emitEventFrom(anonymousMon, unknown, baseEventType), 0);
    ck_assert_uint_eq(emitEventFrom(anonymousMon, UA_NODEID_NULL, baseEventType), 1);

    UA_Session *observer = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_OBSERVER);
    UA_MonitoredItem *observerMon = NULL;
    ck_assert_uint_eq(createEventItemAsEx(observer, UA_NS0ID(SERVER), &observerMon),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(emitEventFrom(observerMon, unknown, baseEventType), 1);

    /* The default AccessRestrictions of the namespace apply as well. The
     * in-process Session has no SecureChannel. */
    ck_assert_uint_eq(UA_Server_setNamespaceDefaultAccessRestrictions(server, 1,
                          UA_ACCESSRESTRICTIONTYPE_ENCRYPTIONREQUIRED),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(emitEventFrom(observerMon, unknown, baseEventType), 0);
    ck_assert_uint_eq(emitEventFrom(observerMon, UA_NODEID_NULL, baseEventType), 1);
} END_TEST
#endif /* UA_ENABLE_SUBSCRIPTIONS_EVENTS */

/*********************************************/
/* RolePermissions, UserRolePermissions and  */
/* AccessRestrictions (Part 3 §5.2.9-5.2.11) */
/*********************************************/

/* Read with Operation_Read. A NULL Session reads like a detached
 * Subscription. */
static UA_DataValue
readAs(UA_Session *session, const UA_NodeId nodeId, UA_UInt32 attributeId) {
    UA_ReadValueId rvi;
    UA_ReadValueId_init(&rvi);
    rvi.nodeId = nodeId;
    rvi.attributeId = attributeId;
    UA_DataValue dv;
    UA_DataValue_init(&dv);
    lockServer(server);
    Operation_Read(server, session, UA_TIMESTAMPSTORETURN_NEITHER, &rvi, &dv);
    unlockServer(server);
    return dv;
}

static UA_StatusCode
readStatusAs(UA_Session *session, const UA_NodeId nodeId, UA_UInt32 attributeId) {
    UA_DataValue dv = readAs(session, nodeId, attributeId);
    UA_StatusCode res = (dv.hasStatus) ? dv.status : UA_STATUSCODE_GOOD;
    if(res == UA_STATUSCODE_GOOD)
        ck_assert(dv.hasValue);
    UA_DataValue_clear(&dv);
    return res;
}

/* The attribute is a RolePermissionType array with the expected entries */
static void
expectRolePermissions(UA_Session *session, const UA_NodeId nodeId,
                      UA_UInt32 attributeId, size_t expectedSize,
                      const UA_RolePermission *expected) {
    UA_DataValue dv = readAs(session, nodeId, attributeId);
    ck_assert_msg(!dv.hasStatus || dv.status == UA_STATUSCODE_GOOD,
                  "Attribute %u returned %s", (unsigned)attributeId,
                  UA_StatusCode_name(dv.status));
    ck_assert(dv.hasValue);
    ck_assert(UA_Variant_hasArrayType(&dv.value,
                                      &UA_TYPES[UA_TYPES_ROLEPERMISSIONTYPE]));
    ck_assert_uint_eq(dv.value.arrayLength, expectedSize);
    const UA_RolePermissionType *rp = (const UA_RolePermissionType*)dv.value.data;
    for(size_t i = 0; i < expectedSize; i++) {
        ck_assert(UA_NodeId_equal(&rp[i].roleId, &expected[i].roleId));
        ck_assert_uint_eq(rp[i].permissions, expected[i].permissions);
    }
    UA_DataValue_clear(&dv);
}

static void
expectAccessRestrictions(UA_Session *session, const UA_NodeId nodeId,
                         UA_AccessRestrictionType expected) {
    UA_DataValue dv = readAs(session, nodeId, UA_ATTRIBUTEID_ACCESSRESTRICTIONS);
    ck_assert(!dv.hasStatus || dv.status == UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasScalarType(&dv.value,
                                       &UA_TYPES[UA_TYPES_ACCESSRESTRICTIONTYPE]));
    ck_assert_uint_eq(*(UA_AccessRestrictionType*)dv.value.data, expected);
    UA_DataValue_clear(&dv);
}


#define ROLE(id) UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_##id)

/* The Node has its own override: RolePermissions reports it,
 * UserRolePermissions filters it, AccessRestrictions reports the Node's own
 * value. This holds although namespace 1 has no RolePermission model. */
START_TEST(rbacAttributes_nodeOverride) {
    UA_NodeId nodeId = addObject("Override", UA_NS0ID(OBJECTSFOLDER),
                                 UA_NS0ID(ORGANIZES), 0);
    UA_RolePermission override[2] = {
        {ROLE(CONFIGUREADMIN),
         UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READROLEPERMISSIONS},
        {ROLE(OBSERVER), UA_PERMISSIONTYPE_BROWSE}};
    ck_assert_uint_eq(UA_Server_setNodeRolePermissions(server, nodeId, 2, override,
                                                       false, NULL),
                      UA_STATUSCODE_GOOD);
    UA_AccessRestrictionType ar = UA_ACCESSRESTRICTIONTYPE_SESSIONREQUIRED |
        UA_ACCESSRESTRICTIONTYPE_APPLYRESTRICTIONSTOBROWSE;
    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, nodeId, ar),
                      UA_STATUSCODE_GOOD);

    UA_Session *admin = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_CONFIGUREADMIN);
    UA_Session *observer = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_OBSERVER);

    expectRolePermissions(admin, nodeId, UA_ATTRIBUTEID_ROLEPERMISSIONS, 2, override);
    expectRolePermissions(admin, nodeId, UA_ATTRIBUTEID_USERROLEPERMISSIONS,
                          1, &override[0]);
    expectAccessRestrictions(admin, nodeId, ar);

    /* RolePermissions requires ReadRolePermissions, the others Browse */
    ck_assert_uint_eq(readStatusAs(observer, nodeId, UA_ATTRIBUTEID_ROLEPERMISSIONS),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    expectRolePermissions(observer, nodeId, UA_ATTRIBUTEID_USERROLEPERMISSIONS,
                          1, &override[1]);
    expectAccessRestrictions(observer, nodeId, ar);

    /* The local admin Session holds no Role */
    expectRolePermissions(&server->adminSession, nodeId,
                          UA_ATTRIBUTEID_ROLEPERMISSIONS, 2, override);
    expectRolePermissions(&server->adminSession, nodeId,
                          UA_ATTRIBUTEID_USERROLEPERMISSIONS, 0, NULL);
    UA_AccessRestrictionType reported = 0;
    ck_assert_uint_eq(UA_Server_readAccessRestrictions(server, nodeId, &reported),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(reported, ar);
} END_TEST

/* Legacy mode (allPermissionsForAnonymous) and no namespace default: the
 * Server publishes no information about how it manages Permissions (Part 3
 * §5.2.9). AccessRestrictions exists and reports that the Node has none of its
 * own. */
START_TEST(rbacAttributes_legacyWithoutModel) {
    ck_assert(UA_Server_getConfig(server)->allPermissionsForAnonymous);
    UA_NodeId nodeId = addObject("Unconfigured", UA_NS0ID(OBJECTSFOLDER),
                                 UA_NS0ID(ORGANIZES), 0);
    ck_assert_uint_eq(UA_Server_setNamespaceDefaultAccessRestrictions(server, 1,
                          UA_ACCESSRESTRICTIONTYPE_SESSIONREQUIRED),
                      UA_STATUSCODE_GOOD);
    UA_Session *session = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_CONFIGUREADMIN);
    UA_Session *sessions[2] = {session, &server->adminSession};
    for(size_t i = 0; i < 2; i++) {
        ck_assert_uint_eq(readStatusAs(sessions[i], nodeId,
                                       UA_ATTRIBUTEID_ROLEPERMISSIONS),
                          UA_STATUSCODE_BADATTRIBUTEIDINVALID);
        ck_assert_uint_eq(readStatusAs(sessions[i], nodeId,
                                       UA_ATTRIBUTEID_USERROLEPERMISSIONS),
                          UA_STATUSCODE_BADATTRIBUTEIDINVALID);
        expectAccessRestrictions(sessions[i], nodeId, UA_ACCESSRESTRICTIONTYPE_NONE);
    }

    /* The enforced value is the namespace default */
    UA_AccessRestrictionType effective = 0;
    ck_assert_uint_eq(UA_Server_getNodeAccessRestrictions(server, nodeId, &effective),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(effective, UA_ACCESSRESTRICTIONTYPE_SESSIONREQUIRED);
} END_TEST

/* No override, the namespace has a default: RolePermissions is an empty array
 * (no override), UserRolePermissions is the namespace default filtered to the
 * Session's Roles */
START_TEST(rbacAttributes_namespaceDefault) {
    UA_NodeId nodeId = addObject("Inheriting", UA_NS0ID(OBJECTSFOLDER),
                                 UA_NS0ID(ORGANIZES), 0);
    UA_RolePermission nsDefault[2] = {
        {ROLE(CONFIGUREADMIN),
         UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READROLEPERMISSIONS},
        {ROLE(OBSERVER), UA_PERMISSIONTYPE_BROWSE}};
    ck_assert_uint_eq(UA_Server_setNamespaceDefaultRolePermissions(server, 1, 2,
                                                                   nsDefault),
                      UA_STATUSCODE_GOOD);

    UA_Session *admin = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_CONFIGUREADMIN);
    UA_Session *observer = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_OBSERVER);
    UA_Session *user = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_AUTHENTICATEDUSER);

    expectRolePermissions(admin, nodeId, UA_ATTRIBUTEID_ROLEPERMISSIONS,
                          0, NULL);
    expectRolePermissions(admin, nodeId, UA_ATTRIBUTEID_USERROLEPERMISSIONS,
                          1, &nsDefault[0]);
    expectAccessRestrictions(admin, nodeId, UA_ACCESSRESTRICTIONTYPE_NONE);

    ck_assert_uint_eq(readStatusAs(observer, nodeId, UA_ATTRIBUTEID_ROLEPERMISSIONS),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    expectRolePermissions(observer, nodeId, UA_ATTRIBUTEID_USERROLEPERMISSIONS,
                          1, &nsDefault[1]);

    /* Without Browse the Session reads none of them */
    ck_assert_uint_eq(readStatusAs(user, nodeId, UA_ATTRIBUTEID_ROLEPERMISSIONS),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert_uint_eq(readStatusAs(user, nodeId, UA_ATTRIBUTEID_USERROLEPERMISSIONS),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert_uint_eq(readStatusAs(user, nodeId, UA_ATTRIBUTEID_ACCESSRESTRICTIONS),
                      UA_STATUSCODE_BADUSERACCESSDENIED);

    /* The local admin Session needs no Role */
    expectRolePermissions(&server->adminSession, nodeId,
                          UA_ATTRIBUTEID_ROLEPERMISSIONS, 0, NULL);
    expectRolePermissions(&server->adminSession, nodeId,
                          UA_ATTRIBUTEID_USERROLEPERMISSIONS, 0, NULL);
    expectAccessRestrictions(&server->adminSession, nodeId,
                             UA_ACCESSRESTRICTIONTYPE_NONE);
} END_TEST

/* Strict mode: every namespace has a model, even without an explicit default:
 * the template of the configuration. An empty template grants nothing to
 * Nodes without an override. */
START_TEST(rbacAttributes_strictWithoutDefault) {
    UA_Server_getConfig(server)->allPermissionsForAnonymous = false;
    UA_NodeId inheriting = addObject("Inheriting", UA_NS0ID(OBJECTSFOLDER),
                                     UA_NS0ID(ORGANIZES), 0);
    UA_NodeId overridden = addObject("Overridden", UA_NS0ID(OBJECTSFOLDER),
                                     UA_NS0ID(ORGANIZES), 0);
    UA_RolePermission override[1] = {
        {ROLE(CONFIGUREADMIN),
         UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READROLEPERMISSIONS}};
    ck_assert_uint_eq(UA_Server_setNodeRolePermissions(server, overridden, 1,
                                                       override, false, NULL),
                      UA_STATUSCODE_GOOD);

    expectRolePermissions(&server->adminSession, inheriting,
                          UA_ATTRIBUTEID_ROLEPERMISSIONS, 0, NULL);
    expectRolePermissions(&server->adminSession, inheriting,
                          UA_ATTRIBUTEID_USERROLEPERMISSIONS, 0, NULL);
    expectAccessRestrictions(&server->adminSession, inheriting,
                             UA_ACCESSRESTRICTIONTYPE_NONE);

    /* The ns1 template lets ConfigureAdmin browse, but not read the
     * RolePermissions. UserRolePermissions is the template entry of the
     * Session's Role. */
    UA_Session *session = createSessionWithRole(UA_NS0ID_WELLKNOWNROLE_CONFIGUREADMIN);
    ck_assert_uint_eq(readStatusAs(session, inheriting, UA_ATTRIBUTEID_ROLEPERMISSIONS),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    const UA_RolePermissionSet *tmpl =
        &UA_Server_getConfig(server)->namespaceDefaultRolePermissions;
    UA_RolePermission tmplEntry = {ROLE(CONFIGUREADMIN), 0};
    for(size_t i = 0; i < tmpl->rolePermissionsSize; i++) {
        if(UA_NodeId_equal(&tmpl->rolePermissions[i].roleId, &tmplEntry.roleId))
            tmplEntry.permissions = tmpl->rolePermissions[i].permissions;
    }
    ck_assert(tmplEntry.permissions & UA_PERMISSIONTYPE_BROWSE);
    ck_assert(!(tmplEntry.permissions & UA_PERMISSIONTYPE_READROLEPERMISSIONS));
    expectRolePermissions(session, inheriting, UA_ATTRIBUTEID_USERROLEPERMISSIONS,
                          1, &tmplEntry);
    expectRolePermissions(session, overridden, UA_ATTRIBUTEID_ROLEPERMISSIONS,
                          1, override);
    expectRolePermissions(session, overridden, UA_ATTRIBUTEID_USERROLEPERMISSIONS,
                          1, override);

    /* An empty template grants nothing */
    UA_RolePermissionSet_clear(
        &UA_Server_getConfig(server)->namespaceDefaultRolePermissions);
    ck_assert_uint_eq(readStatusAs(session, inheriting,
                                   UA_ATTRIBUTEID_USERROLEPERMISSIONS),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    expectRolePermissions(&server->adminSession, inheriting,
                          UA_ATTRIBUTEID_ROLEPERMISSIONS, 0, NULL);
} END_TEST

/* A detached Subscription samples without a Session and is denied */
START_TEST(rbacAttributes_withoutSession) {
    UA_NodeId nodeId = addObject("NoSession", UA_NS0ID(OBJECTSFOLDER),
                                 UA_NS0ID(ORGANIZES), 0);
    setPermissions(nodeId, UA_PERMISSIONTYPE_BROWSE |
                   UA_PERMISSIONTYPE_READROLEPERMISSIONS);
    ck_assert_uint_eq(readStatusAs(NULL, nodeId, UA_ATTRIBUTEID_ROLEPERMISSIONS),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert_uint_eq(readStatusAs(NULL, nodeId, UA_ATTRIBUTEID_USERROLEPERMISSIONS),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert_uint_eq(readStatusAs(NULL, nodeId, UA_ATTRIBUTEID_ACCESSRESTRICTIONS),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
} END_TEST

/* A Node override emptied by removing a Role reports the deny entry */
START_TEST(rbacAttributes_purgedOverride) {
    UA_Role role;
    UA_Role_init(&role);
    role.roleName = UA_QUALIFIEDNAME(1, "PurgedRole");
    UA_NodeId roleId;
    ck_assert_uint_eq(UA_Server_addRole(server, &role, &roleId), UA_STATUSCODE_GOOD);
    UA_NodeId nodeId = addObject("Purged", UA_NS0ID(OBJECTSFOLDER),
                                 UA_NS0ID(ORGANIZES), 0);
    UA_RolePermission override = {roleId, UA_PERMISSIONTYPE_BROWSE};
    ck_assert_uint_eq(UA_Server_setNodeRolePermissions(server, nodeId, 1, &override,
                                                       false, NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_removeRole(server, role.roleName), UA_STATUSCODE_GOOD);

    UA_RolePermission deny = {ROLE(ANONYMOUS), 0};
    expectRolePermissions(&server->adminSession, nodeId,
                          UA_ATTRIBUTEID_ROLEPERMISSIONS, 1, &deny);
    UA_NodeId_clear(&roleId);
} END_TEST

/* The three attributes are read-only */
START_TEST(rbacAttributes_notWritable) {
    UA_NodeId nodeId = addObject("ReadOnly", UA_NS0ID(OBJECTSFOLDER),
                                 UA_NS0ID(ORGANIZES), 0);
    UA_RolePermissionType rp;
    UA_RolePermissionType_init(&rp);
    rp.roleId = ROLE(ANONYMOUS);
    UA_AccessRestrictionType ar = UA_ACCESSRESTRICTIONTYPE_NONE;
    UA_WriteValue wv;
    UA_WriteValue_init(&wv);
    wv.nodeId = nodeId;
    wv.value.hasValue = true;
    UA_Variant_setArray(&wv.value.value, &rp, 1,
                        &UA_TYPES[UA_TYPES_ROLEPERMISSIONTYPE]);
    wv.attributeId = UA_ATTRIBUTEID_ROLEPERMISSIONS;
    ck_assert_uint_eq(UA_Server_write(server, &wv), UA_STATUSCODE_BADNOTWRITABLE);
    wv.attributeId = UA_ATTRIBUTEID_USERROLEPERMISSIONS;
    ck_assert_uint_eq(UA_Server_write(server, &wv), UA_STATUSCODE_BADNOTWRITABLE);
    UA_Variant_setScalar(&wv.value.value, &ar,
                         &UA_TYPES[UA_TYPES_ACCESSRESTRICTIONTYPE]);
    wv.attributeId = UA_ATTRIBUTEID_ACCESSRESTRICTIONS;
    ck_assert_uint_eq(UA_Server_write(server, &wv), UA_STATUSCODE_BADNOTWRITABLE);
} END_TEST

static Suite *testSuite_rbacServices(void) {
    Suite *s = suite_create("RBAC Services");

    TCase *tc_delete = tcase_create("DeleteNodes");
    tcase_add_checked_fixture(tc_delete, setup, teardown);
    tcase_add_test(tc_delete, deleteNodes_recursive_refusedWithoutChildPermission);
    tcase_add_test(tc_delete, deleteNodes_recursive_grantedWithChildPermission);
    tcase_add_test(tc_delete, deleteNodes_recursive_childEncryptionRequired);
    tcase_add_test(tc_delete, deleteNodes_removesIncomingReferences);
    tcase_add_test(tc_delete, deleteNodes_childWithOtherParentNotCollected);
    suite_add_tcase(s, tc_delete);

    TCase *tc_attr = tcase_create("RBAC attributes");
    tcase_add_checked_fixture(tc_attr, setup, teardown);
    tcase_add_test(tc_attr, rbacAttributes_nodeOverride);
    tcase_add_test(tc_attr, rbacAttributes_legacyWithoutModel);
    tcase_add_test(tc_attr, rbacAttributes_namespaceDefault);
    tcase_add_test(tc_attr, rbacAttributes_strictWithoutDefault);
    tcase_add_test(tc_attr, rbacAttributes_withoutSession);
    tcase_add_test(tc_attr, rbacAttributes_purgedOverride);
    tcase_add_test(tc_attr, rbacAttributes_notWritable);
    suite_add_tcase(s, tc_attr);

    TCase *tc_add = tcase_create("AddNodes");
    tcase_add_checked_fixture(tc_add, setup, teardown);
    tcase_add_test(tc_add, addNodes_refusedWithoutParentAddReference);
    tcase_add_test(tc_add, addNodes_grantedWithParentAddReference);
    tcase_add_test(tc_add, addNodes_refusedByParentAccessRestrictions);
    tcase_add_test(tc_add, addNodes_instantiationNeedsOnlyParentAddReference);
    suite_add_tcase(s, tc_add);

#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    TCase *tc_events = tcase_create("Event MonitoredItems");
    tcase_add_checked_fixture(tc_events, setup, teardown);
    tcase_add_test(tc_events, eventItem_unbrowsableNode);
    tcase_add_test(tc_events, eventItem_encryptionRequired);
    tcase_add_test(tc_events, eventItem_browsableNode);
    tcase_add_test(tc_events, eventItem_unknownSourceLegacy);
    suite_add_tcase(s, tc_events);

    TCase *tc_eventsStrict = tcase_create("Event MonitoredItems (strict)");
    tcase_add_checked_fixture(tc_eventsStrict, setupStrict, teardown);
    tcase_add_test(tc_eventsStrict, eventItem_unknownSourceStrict);
    suite_add_tcase(s, tc_eventsStrict);
#endif

    return s;
}

int main(void) {
    Suite *s = testSuite_rbacServices();
    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
