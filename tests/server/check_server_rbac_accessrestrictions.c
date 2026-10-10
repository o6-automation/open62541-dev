/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

/* AccessRestrictions (Part 3 §5.2.11): their storage next to the
 * RolePermissions of a Node and their enforcement in the services for
 * in-process Sessions on SecureChannels of every SecurityMode. */

#include <open62541/server.h>
#include <open62541/server_config_default.h>
#ifdef UA_ENABLE_HISTORIZING
#include <open62541/plugin/historydata/history_data_backend_memory.h>
#include <open62541/plugin/historydata/history_data_gathering_default.h>
#include <open62541/plugin/historydata/history_database_default.h>
#endif
#include <open62541/plugin/log_stdout.h>

#include "test_helpers.h"
#include "test_helpers_rbac.h"
#include "server/ua_server_rbac.h"

#include <check.h>
#include <stdio.h>
#include <stdlib.h>

#define ENC UA_ACCESSRESTRICTIONTYPE_ENCRYPTIONREQUIRED
#define SIGN UA_ACCESSRESTRICTIONTYPE_SIGNINGREQUIRED

static UA_Server *server;
static UA_SecureChannel channels[3]; /* None, Sign, SignAndEncrypt */
#ifdef UA_ENABLE_HISTORIZING
static UA_HistoryDataGathering gathering;
#endif

static void setup(void) {
    server = UA_Server_newForUnitTest();
    ck_assert_ptr_nonnull(server);
    UA_ServerConfig *config = UA_Server_getConfig(server);
    config->tcpEnabled = false;
#ifdef UA_ENABLE_HISTORIZING
    gathering = UA_HistoryDataGathering_Default(16);
    config->historyDatabase = UA_HistoryDatabase_default(gathering);
#endif
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
    for(int i = 0; i < 3; i++)
        rbacChannelInit(server, &channels[i],
                        (UA_MessageSecurityMode)(UA_MESSAGESECURITYMODE_NONE + i));
}

static void teardown(void) {
    UA_Server_run_shutdown(server);
    UA_Server_delete(server);
    for(int i = 0; i < 3; i++)
        UA_SecureChannel_clear(&channels[i]);
}

static UA_AccessRestrictionType
nodeAr(const UA_NodeId nodeId) {
    UA_AccessRestrictionType ar = 0xFFFF;
    ck_assert_uint_eq(UA_Server_getNodeAccessRestrictions(server, nodeId, &ar),
                      UA_STATUSCODE_GOOD);
    return ar;
}

/* The own RolePermissions of the node. If there is one entry, it is checked. */
static size_t
ownRolePermissions(const UA_NodeId nodeId, const UA_NodeId *role,
                   UA_PermissionType permissions) {
    size_t size = 0;
    UA_RolePermission *rp = NULL;
    ck_assert_uint_eq(UA_Server_getNodeRolePermissions(server, nodeId, &size, &rp),
                      UA_STATUSCODE_GOOD);
    if(size == 1) {
        ck_assert(UA_NodeId_equal(&rp[0].roleId, role));
        ck_assert_uint_eq(rp[0].permissions, permissions);
    }
    for(size_t i = 0; i < size; i++)
        UA_NodeId_clear(&rp[i].roleId);
    UA_free(rp);
    return size;
}

static UA_StatusCode
readValueAs(UA_Session *session, const UA_NodeId nodeId) {
    UA_ReadValueId rvi;
    UA_ReadValueId_init(&rvi);
    rvi.nodeId = nodeId;
    rvi.attributeId = UA_ATTRIBUTEID_VALUE;
    UA_DataValue dv;
    UA_DataValue_init(&dv);
    lockServer(server);
    Operation_Read(server, session, UA_TIMESTAMPSTORETURN_NEITHER, &rvi, &dv);
    unlockServer(server);
    UA_StatusCode res = dv.hasStatus ? dv.status : UA_STATUSCODE_GOOD;
    UA_DataValue_clear(&dv);
    return res;
}

static void
browseAs(UA_Session *session, const UA_NodeId nodeId, UA_BrowseResult *br) {
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = nodeId;
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.resultMask = UA_BROWSERESULTMASK_ALL;
    UA_UInt32 maxReferences = 0;
    UA_BrowseResult_init(br);
    lockServer(server);
    Operation_Browse(server, session, &maxReferences, &bd, br);
    unlockServer(server);
}

/****************************/
/* Storage and API          */
/****************************/

/* Get, set, the attribute and the fallback to the namespace default */
START_TEST(api_setGetRead) {
    UA_NodeId x = rbacAddNode(server, "X", UA_NODECLASS_VARIABLE);
    UA_NodeId y = rbacAddNode(server, "Y", UA_NODECLASS_VARIABLE);
    ck_assert_uint_eq(nodeAr(x), UA_ACCESSRESTRICTIONTYPE_NONE);
    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, x, ENC),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(nodeAr(x), ENC);

    UA_ReadValueId rvi;
    UA_ReadValueId_init(&rvi);
    rvi.nodeId = x;
    rvi.attributeId = UA_ATTRIBUTEID_ACCESSRESTRICTIONS;
    UA_DataValue dv = UA_Server_read(server, &rvi, UA_TIMESTAMPSTORETURN_NEITHER);
    ck_assert_uint_eq(dv.status, UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasScalarType(&dv.value,
                                       &UA_TYPES[UA_TYPES_ACCESSRESTRICTIONTYPE]));
    ck_assert_uint_eq(*(UA_AccessRestrictionType*)dv.value.data, ENC);
    UA_DataValue_clear(&dv);

    ck_assert_uint_eq(UA_Server_setNamespaceDefaultAccessRestrictions(server, 1, SIGN),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(nodeAr(y), SIGN);
    ck_assert_uint_eq(nodeAr(x), ENC);
} END_TEST

/* RolePermissions and AccessRestrictions are set independently in any order. A
 * node with only AccessRestrictions uses the namespace default. */
START_TEST(storage_independentOfRolePermissions) {
    UA_NodeId role = rbacAddRole(server, "ArRole", RBAC_NO_RULE, NULL);
    UA_RolePermission rp = {role, UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ};
    ck_assert_uint_eq(UA_Server_setNamespaceDefaultRolePermissions(server, 1, 1, &rp),
                      UA_STATUSCODE_GOOD);

    UA_NodeId x = rbacAddNode(server, "X", UA_NODECLASS_VARIABLE);
    UA_NodeId y = rbacAddNode(server, "Y", UA_NODECLASS_VARIABLE);
    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, x, SIGN),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(ownRolePermissions(x, &role, 0), 0);
    UA_Session *session = rbacSession(server, &channels[1], role);
    ck_assert_uint_eq(readValueAs(session, x), UA_STATUSCODE_GOOD);

    /* The RolePermissions after or before the AccessRestrictions */
    ck_assert_uint_eq(UA_Server_setNodeRolePermissions(server, x, 1, &rp, false, NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_setNodeRolePermissions(server, y, 1, &rp, false, NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, y, SIGN),
                      UA_STATUSCODE_GOOD);
    for(size_t i = 0; i < 2; i++) {
        UA_NodeId n = (i == 0) ? x : y;
        ck_assert_uint_eq(ownRolePermissions(n, &role, rp.permissions), 1);
        ck_assert_uint_eq(nodeAr(n), SIGN);
    }

    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, y, ENC),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(ownRolePermissions(y, &role, rp.permissions), 1);
    ck_assert_uint_eq(nodeAr(x), SIGN);

    ck_assert_uint_eq(UA_Server_addRolePermissions(server, x, role,
                          UA_PERMISSIONTYPE_WRITE, false, false), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_removeRolePermissions(server, x, role,
                          UA_PERMISSIONTYPE_ALL, false), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(ownRolePermissions(x, &role, 0), 0);
    ck_assert_uint_eq(nodeAr(x), SIGN);
    ck_assert_uint_eq(UA_Server_removeNodeRolePermissions(server, y, false),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(ownRolePermissions(y, &role, 0), 0);
    ck_assert_uint_eq(nodeAr(y), ENC);
    UA_NodeId_clear(&role);
} END_TEST

/* Recursive changes of the RolePermissions keep the AccessRestrictions of
 * every Node in the hierarchy */
START_TEST(storage_recursiveKeepsChildAr) {
    UA_NodeId role = rbacAddRole(server, "ArRole", RBAC_NO_RULE, NULL);
    UA_PermissionType perms = UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ;
    UA_RolePermission rp = {role, perms};
    const UA_AccessRestrictionType ar[3] = {UA_ACCESSRESTRICTIONTYPE_NONE, ENC, SIGN};
    UA_NodeId tree[3];
    tree[0] = rbacAddNode(server, "Root", UA_NODECLASS_OBJECT);
    for(size_t i = 1; i < 3; i++) {
        tree[i] = UA_NODEID_NUMERIC(1, (UA_UInt32)(70000 + i));
        ck_assert_uint_eq(UA_Server_addObjectNode(server, tree[i], tree[i-1],
                              UA_NS0ID(ORGANIZES), UA_QUALIFIEDNAME(1, "Child"),
                              UA_NS0ID(BASEOBJECTTYPE), UA_ObjectAttributes_default,
                              NULL, NULL), UA_STATUSCODE_GOOD);
        ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, tree[i], ar[i]),
                          UA_STATUSCODE_GOOD);
    }

    ck_assert_uint_eq(UA_Server_setNodeRolePermissions(server, tree[0], 1, &rp,
                                                       true, NULL), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_addRolePermissions(server, tree[0], role,
                          UA_PERMISSIONTYPE_WRITE, false, true), UA_STATUSCODE_GOOD);
    for(size_t i = 0; i < 3; i++) {
        ck_assert_uint_eq(ownRolePermissions(tree[i], &role,
                                             perms | UA_PERMISSIONTYPE_WRITE), 1);
        ck_assert_uint_eq(nodeAr(tree[i]), ar[i]);
    }
    ck_assert_uint_eq(UA_Server_removeRolePermissions(server, tree[0], role,
                          UA_PERMISSIONTYPE_WRITE, true), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_removeNodeRolePermissions(server, tree[1], true),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(ownRolePermissions(tree[0], &role, perms), 1);
    for(size_t i = 0; i < 3; i++)
        ck_assert_uint_eq(nodeAr(tree[i]), ar[i]);
    ck_assert_uint_eq(ownRolePermissions(tree[2], &role, 0), 0);
    UA_NodeId_clear(&role);
} END_TEST

/* An instance child gets the AccessRestrictions of its InstanceDeclaration,
 * but not its RolePermissions */
START_TEST(storage_inheritedByInstanceChild) {
    UA_NodeId role = rbacAddRole(server, "ArRole", RBAC_NO_RULE, NULL);
    UA_RolePermission rp = {role, UA_PERMISSIONTYPE_BROWSE};
    UA_NodeId typeId = UA_NODEID_STRING(1, "ArType");
    ck_assert_uint_eq(UA_Server_addObjectTypeNode(server, typeId,
                          UA_NS0ID(BASEOBJECTTYPE), UA_NS0ID(HASSUBTYPE),
                          UA_QUALIFIEDNAME(1, "ArType"),
                          UA_ObjectTypeAttributes_default, NULL, NULL),
                      UA_STATUSCODE_GOOD);
    UA_NodeId decl = UA_NODEID_STRING(1, "ArType.Restricted");
    ck_assert_uint_eq(UA_Server_addVariableNode(server, decl, typeId,
                          UA_NS0ID(HASCOMPONENT), UA_QUALIFIEDNAME(1, "Restricted"),
                          UA_NS0ID(BASEDATAVARIABLETYPE),
                          UA_VariableAttributes_default, NULL, NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_addReference(server, decl, UA_NS0ID(HASMODELLINGRULE),
                          UA_EXPANDEDNODEID_NUMERIC(0, UA_NS0ID_MODELLINGRULE_MANDATORY),
                          true), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_setNodeRolePermissions(server, decl, 1, &rp,
                                                       false, NULL), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, decl, ENC),
                      UA_STATUSCODE_GOOD);

    UA_NodeId inst = UA_NODEID_STRING(1, "ArInstance");
    ck_assert_uint_eq(UA_Server_addObjectNode(server, inst, UA_NS0ID(OBJECTSFOLDER),
                          UA_NS0ID(ORGANIZES), UA_QUALIFIEDNAME(1, "ArInstance"),
                          typeId, UA_ObjectAttributes_default, NULL, NULL),
                      UA_STATUSCODE_GOOD);
    UA_QualifiedName name = UA_QUALIFIEDNAME(1, "Restricted");
    UA_BrowsePathResult bpr = UA_Server_browseSimplifiedBrowsePath(server, inst, 1, &name);
    ck_assert_uint_eq(bpr.statusCode, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(bpr.targetsSize, 1);
    UA_NodeId child = bpr.targets[0].targetId.nodeId;
    ck_assert_uint_eq(nodeAr(child), ENC);
    ck_assert_uint_eq(ownRolePermissions(child, &role, 0), 0);
    UA_BrowsePathResult_clear(&bpr);
    ck_assert_uint_eq(ownRolePermissions(decl, &role, rp.permissions), 1);
    UA_NodeId_clear(&role);
} END_TEST

/* Removing a Role purges it from the RolePermissions and keeps the
 * AccessRestrictions */
START_TEST(storage_survivesPurgeOfRemovedRole) {
    UA_NodeId role = rbacAddRole(server, "PurgedRole", RBAC_NO_RULE, NULL);
    UA_RolePermission rp = {role, UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ};
    UA_NodeId x = rbacAddNode(server, "X", UA_NODECLASS_VARIABLE);
    ck_assert_uint_eq(UA_Server_setNodeRolePermissions(server, x, 1, &rp, false, NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, x, SIGN),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_removeRole(server, UA_QUALIFIEDNAME(1, "PurgedRole")),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(nodeAr(x), SIGN);
    UA_NodeId_clear(&role);
} END_TEST

/* A server with a RolePermission preset (index 0) */
static void setupWithPreset(void) {
    UA_ServerConfig sc;
    memset(&sc, 0, sizeof(UA_ServerConfig));
    sc.logging = UA_Log_Stdout_new(UA_LOGLEVEL_WARNING);
    ck_assert_uint_eq(UA_ServerConfig_setMinimal(&sc, 0, NULL), UA_STATUSCODE_GOOD);
    sc.tcpEnabled = false;
    sc.rolePermissionPresets = (UA_RolePermissionSet*)
        UA_calloc(1, sizeof(UA_RolePermissionSet));
    sc.rolePermissionPresetsSize = 1;
    sc.rolePermissionPresets[0].rolePermissions = (UA_RolePermission*)
        UA_calloc(1, sizeof(UA_RolePermission));
    sc.rolePermissionPresets[0].rolePermissionsSize = 1;
    sc.rolePermissionPresets[0].rolePermissions[0].roleId =
        UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_OBSERVER);
    sc.rolePermissionPresets[0].rolePermissions[0].permissions =
        UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ;
    server = UA_Server_newWithConfig(&sc);
    ck_assert_ptr_nonnull(server);
}

static void teardownWithPreset(void) {
    UA_Server_delete(server);
}

/* Updating a preset reaches the Nodes that use it, also those with own
 * AccessRestrictions set before or after the preset was assigned */
START_TEST(storage_presetUpdateReachesNodesWithAr) {
    const UA_NodeId observer = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_OBSERVER);
    UA_NodeId n[3] = {rbacAddNode(server, "X", UA_NODECLASS_VARIABLE),
                      rbacAddNode(server, "Y", UA_NODECLASS_VARIABLE),
                      rbacAddNode(server, "Z", UA_NODECLASS_VARIABLE)};
    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, n[1], ENC),
                      UA_STATUSCODE_GOOD);
    for(size_t i = 0; i < 3; i++)
        ck_assert_uint_eq(UA_Server_setNodePermissionIndex(server, n[i], 0, false),
                          UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, n[2], SIGN),
                      UA_STATUSCODE_GOOD);

    UA_RolePermission update = {observer, UA_PERMISSIONTYPE_BROWSE};
    ck_assert_uint_eq(UA_Server_updateRolePermissionConfig(server, 0, 1, &update),
                      UA_STATUSCODE_GOOD);
    const UA_AccessRestrictionType ar[3] = {UA_ACCESSRESTRICTIONTYPE_NONE, ENC, SIGN};
    for(size_t i = 0; i < 3; i++) {
        ck_assert_uint_eq(ownRolePermissions(n[i], &observer, UA_PERMISSIONTYPE_BROWSE), 1);
        ck_assert_uint_eq(nodeAr(n[i]), ar[i]);
    }
} END_TEST

/****************************/
/* Enforcement              */
/****************************/

/* The Nodes of one case. The AccessRestrictions are set on "restricted". */
typedef struct {
    UA_NodeId obj;    /* Object with an EventNotifier */
    UA_NodeId var;    /* Historized Variable below obj */
    UA_NodeId method; /* Method of obj */
    UA_NodeId child;  /* Object below obj */
} Nodes;

static UA_StatusCode
methodCallback(UA_Server *s, const UA_NodeId *sessionId, void *sessionContext,
               const UA_NodeId *methodId, void *methodContext,
               const UA_NodeId *objectId, void *objectContext,
               size_t inputSize, const UA_Variant *input,
               size_t outputSize, UA_Variant *output) {
    return UA_STATUSCODE_GOOD;
}

static void
addNodes(size_t caseIndex, Nodes *n) {
    char name[32];
    snprintf(name, sizeof(name), "Obj%u", (unsigned)caseIndex);
    UA_ObjectAttributes oAttr = UA_ObjectAttributes_default;
    oAttr.eventNotifier = UA_EVENTNOTIFIER_SUBSCRIBE_TO_EVENT;
    n->obj = UA_NODEID_NUMERIC(1, (UA_UInt32)(1000 + 10 * caseIndex));
    ck_assert_uint_eq(UA_Server_addObjectNode(server, n->obj, UA_NS0ID(OBJECTSFOLDER),
                          UA_NS0ID(ORGANIZES), UA_QUALIFIEDNAME(1, name),
                          UA_NS0ID(BASEOBJECTTYPE), oAttr, NULL, NULL),
                      UA_STATUSCODE_GOOD);
    UA_VariableAttributes vAttr = UA_VariableAttributes_default;
    UA_Int32 value = 1;
    UA_Variant_setScalar(&vAttr.value, &value, &UA_TYPES[UA_TYPES_INT32]);
    vAttr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE |
        UA_ACCESSLEVELMASK_HISTORYREAD | UA_ACCESSLEVELMASK_HISTORYWRITE;
    vAttr.historizing = true;
    n->var = UA_NODEID_NUMERIC(1, (UA_UInt32)(1001 + 10 * caseIndex));
    ck_assert_uint_eq(UA_Server_addVariableNode(server, n->var, n->obj,
                          UA_NS0ID(HASCOMPONENT), UA_QUALIFIEDNAME(1, "Var"),
                          UA_NS0ID(BASEDATAVARIABLETYPE), vAttr, NULL, NULL),
                      UA_STATUSCODE_GOOD);
    UA_MethodAttributes mAttr = UA_MethodAttributes_default;
    mAttr.executable = true;
    n->method = UA_NODEID_NUMERIC(1, (UA_UInt32)(1002 + 10 * caseIndex));
    ck_assert_uint_eq(UA_Server_addMethodNode(server, n->method, n->obj,
                          UA_NS0ID(HASCOMPONENT), UA_QUALIFIEDNAME(1, "Method"),
                          mAttr, methodCallback, 0, NULL, 0, NULL, NULL, NULL),
                      UA_STATUSCODE_GOOD);
    n->child = UA_NODEID_NUMERIC(1, (UA_UInt32)(1003 + 10 * caseIndex));
    ck_assert_uint_eq(UA_Server_addObjectNode(server, n->child, n->obj,
                          UA_NS0ID(HASCOMPONENT), UA_QUALIFIEDNAME(1, "Child"),
                          UA_NS0ID(BASEOBJECTTYPE), UA_ObjectAttributes_default,
                          NULL, NULL), UA_STATUSCODE_GOOD);
#ifdef UA_ENABLE_HISTORIZING
    UA_HistorizingNodeIdSettings setting;
    memset(&setting, 0, sizeof(setting));
    setting.historizingBackend = UA_HistoryDataBackend_Memory(1, 10);
    setting.maxHistoryDataResponseSize = 10;
    setting.historizingUpdateStrategy = UA_HISTORIZINGUPDATESTRATEGY_USER;
    ck_assert_uint_eq(gathering.registerNodeId(server, gathering.context, &n->var,
                                               setting), UA_STATUSCODE_GOOD);
#endif
}

static UA_StatusCode
opRead(UA_Session *s, const Nodes *n) {
    return readValueAs(s, n->var);
}

static UA_StatusCode
opWrite(UA_Session *s, const Nodes *n) {
    UA_Int32 value = 2;
    UA_WriteValue wv;
    UA_WriteValue_init(&wv);
    wv.nodeId = n->var;
    wv.attributeId = UA_ATTRIBUTEID_VALUE;
    wv.value.hasValue = true;
    UA_Variant_setScalar(&wv.value.value, &value, &UA_TYPES[UA_TYPES_INT32]);
    UA_StatusCode res = UA_STATUSCODE_BADINTERNALERROR;
    lockServer(server);
    Operation_Write(server, s, &wv, &res);
    unlockServer(server);
    return res;
}

static UA_StatusCode
opCall(UA_Session *s, const Nodes *n) {
    return rbacCall(server, s, n->obj, n->method, 0, NULL);
}

static UA_StatusCode
opBrowse(UA_Session *s, const Nodes *n) {
    UA_BrowseResult br;
    browseAs(s, n->obj, &br);
    UA_StatusCode res = br.statusCode;
    UA_BrowseResult_clear(&br);
    return res;
}

static UA_StatusCode
opTranslate(UA_Session *s, const Nodes *n) {
    UA_RelativePathElement rpe;
    UA_RelativePathElement_init(&rpe);
    rpe.referenceTypeId = UA_NS0ID(HASCOMPONENT);
    rpe.targetName = UA_QUALIFIEDNAME(1, "Var");
    UA_BrowsePath bp;
    UA_BrowsePath_init(&bp);
    bp.startingNode = n->obj;
    bp.relativePath.elements = &rpe;
    bp.relativePath.elementsSize = 1;
    UA_TranslateBrowsePathsToNodeIdsRequest request;
    UA_TranslateBrowsePathsToNodeIdsRequest_init(&request);
    request.browsePaths = &bp;
    request.browsePathsSize = 1;
    UA_TranslateBrowsePathsToNodeIdsResponse response;
    UA_TranslateBrowsePathsToNodeIdsResponse_init(&response);
    rbacService(server, s, Service_TranslateBrowsePathsToNodeIds, &request, &response);
    ck_assert_uint_eq(response.resultsSize, 1);
    UA_StatusCode res = response.results[0].statusCode;
    UA_TranslateBrowsePathsToNodeIdsResponse_clear(&response);
    return res;
}

static UA_StatusCode
opAddNode(UA_Session *s, const Nodes *n) {
    UA_ObjectAttributes attr = UA_ObjectAttributes_default;
    UA_AddNodesItem item;
    UA_AddNodesItem_init(&item);
    item.parentNodeId.nodeId = n->obj;
    item.referenceTypeId = UA_NS0ID(HASCOMPONENT);
    item.requestedNewNodeId.nodeId = UA_NODEID_NUMERIC(1, 0);
    item.browseName = UA_QUALIFIEDNAME(1, "Added");
    item.nodeClass = UA_NODECLASS_OBJECT;
    item.typeDefinition.nodeId = UA_NS0ID(BASEOBJECTTYPE);
    UA_ExtensionObject_setValueNoDelete(&item.nodeAttributes, &attr,
                                        &UA_TYPES[UA_TYPES_OBJECTATTRIBUTES]);
    UA_AddNodesRequest request;
    UA_AddNodesRequest_init(&request);
    request.nodesToAdd = &item;
    request.nodesToAddSize = 1;
    UA_AddNodesResponse response;
    UA_AddNodesResponse_init(&response);
    rbacService(server, s, Service_AddNodes, &request, &response);
    ck_assert_uint_eq(response.resultsSize, 1);
    UA_StatusCode res = response.results[0].statusCode;
    UA_AddNodesResponse_clear(&response);
    return res;
}

static UA_StatusCode
opAddReference(UA_Session *s, const Nodes *n) {
    UA_AddReferencesItem item;
    UA_AddReferencesItem_init(&item);
    item.sourceNodeId = n->obj;
    item.referenceTypeId = UA_NS0ID(ORGANIZES);
    item.isForward = true;
    item.targetNodeId.nodeId = UA_NS0ID(SERVER);
    item.targetNodeClass = UA_NODECLASS_OBJECT;
    UA_AddReferencesRequest request;
    UA_AddReferencesRequest_init(&request);
    request.referencesToAdd = &item;
    request.referencesToAddSize = 1;
    UA_AddReferencesResponse response;
    UA_AddReferencesResponse_init(&response);
    rbacService(server, s, Service_AddReferences, &request, &response);
    ck_assert_uint_eq(response.resultsSize, 1);
    UA_StatusCode res = response.results[0];
    UA_AddReferencesResponse_clear(&response);
    return res;
}

static UA_StatusCode
opDeleteReference(UA_Session *s, const Nodes *n) {
    UA_DeleteReferencesItem item;
    UA_DeleteReferencesItem_init(&item);
    item.sourceNodeId = n->obj;
    item.referenceTypeId = UA_NS0ID(HASCOMPONENT);
    item.isForward = true;
    item.targetNodeId.nodeId = n->child;
    item.deleteBidirectional = true;
    UA_DeleteReferencesRequest request;
    UA_DeleteReferencesRequest_init(&request);
    request.referencesToDelete = &item;
    request.referencesToDeleteSize = 1;
    UA_DeleteReferencesResponse response;
    UA_DeleteReferencesResponse_init(&response);
    rbacService(server, s, Service_DeleteReferences, &request, &response);
    ck_assert_uint_eq(response.resultsSize, 1);
    UA_StatusCode res = response.results[0];
    UA_DeleteReferencesResponse_clear(&response);
    return res;
}

/* Deletes obj with its children. The restricted Node is the child. */
static UA_StatusCode
opDeleteNode(UA_Session *s, const Nodes *n) {
    UA_DeleteNodesItem item;
    UA_DeleteNodesItem_init(&item);
    item.nodeId = n->obj;
    item.deleteTargetReferences = true;
    UA_DeleteNodesRequest request;
    UA_DeleteNodesRequest_init(&request);
    request.nodesToDelete = &item;
    request.nodesToDeleteSize = 1;
    UA_DeleteNodesResponse response;
    UA_DeleteNodesResponse_init(&response);
    rbacService(server, s, Service_DeleteNodes, &request, &response);
    ck_assert_uint_eq(response.resultsSize, 1);
    UA_StatusCode res = response.results[0];
    UA_DeleteNodesResponse_clear(&response);
    UA_NodeClass nc;
    ck_assert_uint_eq(UA_Server_readNodeClass(server, n->child, &nc),
                      res == UA_STATUSCODE_GOOD ?
                      UA_STATUSCODE_BADNODEIDUNKNOWN : UA_STATUSCODE_GOOD);
    return res;
}

#ifdef UA_ENABLE_HISTORIZING
/* Reads the restricted Variable and the CurrentTime (without the HistoryRead
 * AccessLevel). The results keep the order of the request. */
static UA_StatusCode
opHistoryRead(UA_Session *s, const Nodes *n) {
    UA_ReadRawModifiedDetails details;
    UA_ReadRawModifiedDetails_init(&details);
    details.endTime = UA_DateTime_now();
    details.numValuesPerNode = 1;
    UA_HistoryReadValueId ids[2];
    UA_HistoryReadValueId_init(&ids[0]);
    UA_HistoryReadValueId_init(&ids[1]);
    ids[0].nodeId = n->var;
    ids[1].nodeId = UA_NS0ID(SERVER_SERVERSTATUS_CURRENTTIME);
    UA_HistoryReadRequest request;
    UA_HistoryReadRequest_init(&request);
    request.historyReadDetails.encoding = UA_EXTENSIONOBJECT_DECODED;
    request.historyReadDetails.content.decoded.type =
        &UA_TYPES[UA_TYPES_READRAWMODIFIEDDETAILS];
    request.historyReadDetails.content.decoded.data = &details;
    request.timestampsToReturn = UA_TIMESTAMPSTORETURN_BOTH;
    request.nodesToRead = ids;
    request.nodesToReadSize = 2;
    UA_HistoryReadResponse response;
    UA_HistoryReadResponse_init(&response);
    rbacService(server, s, Service_HistoryRead, &request, &response);
    ck_assert_uint_eq(response.resultsSize, 2);
    ck_assert_uint_eq(response.results[1].statusCode,
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    UA_StatusCode res = response.results[0].statusCode;
    UA_HistoryReadResponse_clear(&response);
    return res;
}

static UA_StatusCode
opHistoryUpdate(UA_Session *s, const Nodes *n) {
    UA_DataValue dv;
    UA_DataValue_init(&dv);
    UA_Int32 value = 4;
    UA_Variant_setScalar(&dv.value, &value, &UA_TYPES[UA_TYPES_INT32]);
    dv.hasValue = true;
    dv.sourceTimestamp = UA_DateTime_now();
    dv.hasSourceTimestamp = true;
    UA_UpdateDataDetails details;
    UA_UpdateDataDetails_init(&details);
    details.nodeId = n->var;
    details.performInsertReplace = UA_PERFORMUPDATETYPE_INSERT;
    details.updateValues = &dv;
    details.updateValuesSize = 1;
    UA_ExtensionObject eo;
    eo.encoding = UA_EXTENSIONOBJECT_DECODED;
    eo.content.decoded.type = &UA_TYPES[UA_TYPES_UPDATEDATADETAILS];
    eo.content.decoded.data = &details;
    UA_HistoryUpdateRequest request;
    UA_HistoryUpdateRequest_init(&request);
    request.historyUpdateDetails = &eo;
    request.historyUpdateDetailsSize = 1;
    UA_HistoryUpdateResponse response;
    UA_HistoryUpdateResponse_init(&response);
    rbacService(server, s, Service_HistoryUpdate, &request, &response);
    ck_assert_uint_eq(response.resultsSize, 1);
    UA_StatusCode res = response.results[0].statusCode;
    UA_HistoryUpdateResponse_clear(&response);
    return res;
}
#endif

#ifdef UA_ENABLE_SUBSCRIPTIONS
/* The status of the samples. A write of the local admin samples the item with
 * the rights of the subscriber. */
static UA_StatusCode
opDataChange(UA_Session *s, const Nodes *n) {
    UA_StatusCode res;
    UA_MonitoredItem *mon = rbacMonitor(server, s, n->var, UA_ATTRIBUTEID_VALUE, NULL, &res);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    UA_Int32 value = 3;
    UA_Variant v;
    UA_Variant_setScalar(&v, &value, &UA_TYPES[UA_TYPES_INT32]);
    ck_assert_uint_eq(UA_Server_writeValue(server, n->var, v), UA_STATUSCODE_GOOD);
    lockServer(server);
    ck_assert_uint_gt(mon->queueSize, 0);
    UA_Notification *notification;
    res = UA_STATUSCODE_GOOD;
    TAILQ_FOREACH(notification, &mon->queue, monEntry) {
        UA_DataValue *dv = &notification->data.dataChange.value;
        if(dv->hasStatus && dv->status != UA_STATUSCODE_GOOD) {
            ck_assert(!dv->hasValue);
            res = dv->status;
        }
    }
    unlockServer(server);
    return res;
}

#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
static UA_StatusCode
opEventItem(UA_Session *s, const Nodes *n) {
    UA_StatusCode res;
    rbacMonitor(server, s, n->obj, UA_ATTRIBUTEID_EVENTNOTIFIER, "Message", &res);
    return res;
}

/* An Event whose SourceNode is restricted is not delivered: Bad_NotFound */
static UA_StatusCode
opEventDelivery(UA_Session *s, const Nodes *n) {
    UA_StatusCode res;
    UA_MonitoredItem *mon = rbacMonitor(server, s, UA_NS0ID(SERVER),
                                        UA_ATTRIBUTEID_EVENTNOTIFIER, "Message", &res);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_createEvent(server, n->obj, UA_NS0ID(BASEEVENTTYPE),
                                            100, UA_LOCALIZEDTEXT("", "event"),
                                            NULL, NULL, NULL), UA_STATUSCODE_GOOD);
    lockServer(server);
    size_t delivered = mon->queueSize;
    unlockServer(server);
    ck_assert_uint_le(delivered, 1);
    return delivered ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADNOTFOUND;
}
#endif
#endif

typedef enum {ON_OBJ, ON_VAR, ON_METHOD, ON_CHILD} Restricted;

static const struct {
    const char *name;
    UA_StatusCode (*op)(UA_Session *s, const Nodes *n);
    Restricted restricted;
    UA_Boolean browse; /* Restricted only with ApplyRestrictionsToBrowse */
    UA_StatusCode denied;
} ops[] = {
    {"Read", opRead, ON_VAR, false, UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT},
    {"Write", opWrite, ON_VAR, false, UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT},
    {"Call", opCall, ON_METHOD, false, UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT},
    {"Browse", opBrowse, ON_OBJ, true, UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT},
    {"TranslateBrowsePaths", opTranslate, ON_VAR, true, UA_STATUSCODE_BADNOMATCH},
    {"AddNodes", opAddNode, ON_OBJ, false, UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT},
    {"AddReferences", opAddReference, ON_OBJ, false,
     UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT},
    {"DeleteReferences", opDeleteReference, ON_CHILD, false,
     UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT},
    {"DeleteNodes", opDeleteNode, ON_CHILD, false,
     UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT},
#ifdef UA_ENABLE_HISTORIZING
    {"HistoryRead", opHistoryRead, ON_VAR, false,
     UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT},
    {"HistoryUpdate", opHistoryUpdate, ON_VAR, false,
     UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT},
#endif
#ifdef UA_ENABLE_SUBSCRIPTIONS
    {"DataChange", opDataChange, ON_VAR, false,
     UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT},
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    {"EventItem", opEventItem, ON_OBJ, false,
     UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT},
    {"EventDelivery", opEventDelivery, ON_OBJ, false, UA_STATUSCODE_BADNOTFOUND},
#endif
#endif
};

/* Each service with every AccessRestriction on a channel of every mode.
 * SessionRequired is always satisfied by the in-process Session. */
START_TEST(enforcement_perServiceAndChannelMode) {
    const UA_AccessRestrictionType restrictions[] = {
        UA_ACCESSRESTRICTIONTYPE_NONE, SIGN, ENC,
        UA_ACCESSRESTRICTIONTYPE_SESSIONREQUIRED,
        ENC | UA_ACCESSRESTRICTIONTYPE_APPLYRESTRICTIONSTOBROWSE};
    size_t c = 0;
    for(size_t r = 0; r < sizeof(restrictions) / sizeof(restrictions[0]); r++) {
        UA_AccessRestrictionType ar = restrictions[r];
        for(int mode = UA_MESSAGESECURITYMODE_NONE;
            mode <= UA_MESSAGESECURITYMODE_SIGNANDENCRYPT; mode++, c++) {
            Nodes n;
            addNodes(c, &n);
            const UA_NodeId *restricted[] = {&n.obj, &n.var, &n.method, &n.child};
            ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(
                                  server, *restricted[ops[_i].restricted], ar),
                              UA_STATUSCODE_GOOD);
            UA_Boolean applies = !ops[_i].browse ||
                (ar & UA_ACCESSRESTRICTIONTYPE_APPLYRESTRICTIONSTOBROWSE);
            UA_Boolean denied = applies &&
                (((ar & ENC) && mode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT) ||
                 ((ar & SIGN) && mode == UA_MESSAGESECURITYMODE_NONE));
            UA_Session *session = rbacSession(server, &channels[mode - 1],
                UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS));
            UA_StatusCode res = ops[_i].op(session, &n);
            ck_assert_msg(res == (denied ? ops[_i].denied : UA_STATUSCODE_GOOD),
                          "%s with AccessRestrictions %u on mode %d: %s",
                          ops[_i].name, (unsigned)ar, mode, UA_StatusCode_name(res));
        }
    }
} END_TEST

/* The namespace default of the new Node applies to AddNodes */
START_TEST(enforcement_addNodeInRestrictedNamespace) {
    ck_assert_uint_eq(UA_Server_setNamespaceDefaultAccessRestrictions(server, 1, ENC),
                      UA_STATUSCODE_GOOD);
    for(int mode = UA_MESSAGESECURITYMODE_SIGN;
        mode <= UA_MESSAGESECURITYMODE_SIGNANDENCRYPT; mode++) {
        UA_Session *session = rbacSession(server, &channels[mode - 1],
            UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS));
        Nodes n;
        n.obj = UA_NS0ID(OBJECTSFOLDER);
        ck_assert_uint_eq(opAddNode(session, &n),
                          mode == UA_MESSAGESECURITYMODE_SIGN ?
                          UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT :
                          UA_STATUSCODE_GOOD);
    }
} END_TEST

/* Browse leaves out the Targets the Session may not browse and the Targets
 * hidden by ApplyRestrictionsToBrowse */
START_TEST(browse_hidesTargets) {
    Nodes n;
    addNodes(0, &n);
    UA_RolePermission browse = {UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_OBSERVER),
                                UA_PERMISSIONTYPE_BROWSE};
    ck_assert_uint_eq(UA_Server_setNodeRolePermissions(server, n.child, 1, &browse,
                                                       false, NULL), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, n.var,
                          ENC | UA_ACCESSRESTRICTIONTYPE_APPLYRESTRICTIONSTOBROWSE),
                      UA_STATUSCODE_GOOD);
    UA_Session *session = rbacSession(server, &channels[1],
        UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS));

    UA_BrowseResult br;
    browseAs(session, n.obj, &br);
    ck_assert_uint_eq(br.statusCode, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(br.referencesSize, 2); /* TypeDefinition, Method */
    for(size_t i = 0; i < br.referencesSize; i++) {
        ck_assert(!UA_NodeId_equal(&br.references[i].nodeId.nodeId, &n.child));
        ck_assert(!UA_NodeId_equal(&br.references[i].nodeId.nodeId, &n.var));
    }
    UA_BrowseResult_clear(&br);
} END_TEST

static Suite *testSuite_rbacAccessRestrictions(void) {
    Suite *s = suite_create("RBAC AccessRestrictions");
    TCase *tc = tcase_create("Storage");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, api_setGetRead);
    tcase_add_test(tc, storage_independentOfRolePermissions);
    tcase_add_test(tc, storage_recursiveKeepsChildAr);
    tcase_add_test(tc, storage_inheritedByInstanceChild);
    tcase_add_test(tc, storage_survivesPurgeOfRemovedRole);
    suite_add_tcase(s, tc);

    TCase *tc_preset = tcase_create("Presets");
    tcase_add_checked_fixture(tc_preset, setupWithPreset, teardownWithPreset);
    tcase_add_test(tc_preset, storage_presetUpdateReachesNodesWithAr);
    suite_add_tcase(s, tc_preset);

    TCase *tc_enforce = tcase_create("Enforcement");
    tcase_add_checked_fixture(tc_enforce, setup, teardown);
    tcase_add_loop_test(tc_enforce, enforcement_perServiceAndChannelMode, 0,
                        sizeof(ops) / sizeof(ops[0]));
    tcase_add_test(tc_enforce, enforcement_addNodeInRestrictedNamespace);
    tcase_add_test(tc_enforce, browse_hidesTargets);
    suite_add_tcase(s, tc_enforce);
    return s;
}

int main(void) {
    SRunner *sr = srunner_create(testSuite_rbacAccessRestrictions());
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
