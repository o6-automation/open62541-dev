/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

/* AccessRestrictions (Part 3 §5.2.11): their storage next to the
 * RolePermissions of a Node, the API and the attribute */

#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/log_stdout.h>

#include "test_helpers.h"
#include "test_helpers_rbac.h"
#include "server/ua_server_rbac.h"

#include <check.h>
#include <stdlib.h>

#define ENC UA_ACCESSRESTRICTIONTYPE_ENCRYPTIONREQUIRED
#define SIGN UA_ACCESSRESTRICTIONTYPE_SIGNINGREQUIRED

static UA_Server *server;
static UA_SecureChannel channels[3]; /* None, Sign, SignAndEncrypt */

static void setup(void) {
    server = UA_Server_newForUnitTest();
    ck_assert_ptr_nonnull(server);
    UA_ServerConfig *config = UA_Server_getConfig(server);
    config->tcpEnabled = false;
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
    UA_StatusCode res = dv.hasStatus ? dv.status : UA_STATUSCODE_GOOD;
    UA_DataValue_clear(&dv);
    return res;
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
    ck_assert_uint_eq(readAs(session, x, UA_ATTRIBUTEID_VALUE), UA_STATUSCODE_GOOD);

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

/* An own value, also NONE, overrides the namespace default until it is
 * removed. The RolePermissions are kept. */
START_TEST(api_removeAndNamespaceDefault) {
    UA_NodeId role = rbacAddRole(server, "ArRole", RBAC_NO_RULE, NULL);
    UA_RolePermission rp = {role, UA_PERMISSIONTYPE_BROWSE};
    UA_NodeId x = rbacAddNode(server, "X", UA_NODECLASS_VARIABLE);
    UA_AccessRestrictionType def = 0xFFFF;
    ck_assert_uint_eq(UA_Server_getNamespaceDefaultAccessRestrictions(server, 1, &def),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(def, UA_ACCESSRESTRICTIONTYPE_NONE);
    ck_assert_uint_eq(UA_Server_setNamespaceDefaultAccessRestrictions(server, 1, SIGN),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_getNamespaceDefaultAccessRestrictions(server, 1, &def),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(def, SIGN);

    ck_assert_uint_eq(UA_Server_setNodeRolePermissions(server, x, 1, &rp, false, NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, x,
                          UA_ACCESSRESTRICTIONTYPE_NONE), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(nodeAr(x), UA_ACCESSRESTRICTIONTYPE_NONE);
    for(size_t i = 0; i < 2; i++) { /* Also without an own value */
        ck_assert_uint_eq(UA_Server_removeNodeAccessRestrictions(server, x),
                          UA_STATUSCODE_GOOD);
        ck_assert_uint_eq(nodeAr(x), SIGN);
        ck_assert_uint_eq(ownRolePermissions(x, &role, rp.permissions), 1);
    }
    UA_NodeId_clear(&role);
} END_TEST

START_TEST(api_failurePaths) {
    const UA_NodeId unknown = UA_NODEID_STRING(1, "Unknown");
    const UA_UInt16 unknownNs = 99;
    UA_AccessRestrictionType ar;
    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, unknown, SIGN),
                      UA_STATUSCODE_BADNODEIDUNKNOWN);
    ck_assert_uint_eq(UA_Server_removeNodeAccessRestrictions(server, unknown),
                      UA_STATUSCODE_BADNODEIDUNKNOWN);
    ck_assert_uint_eq(UA_Server_getNodeAccessRestrictions(server, unknown, &ar),
                      UA_STATUSCODE_BADNODEIDUNKNOWN);
    ck_assert_uint_eq(UA_Server_setNamespaceDefaultAccessRestrictions(server, unknownNs,
                                                                      SIGN),
                      UA_STATUSCODE_BADINDEXRANGEINVALID);
    ck_assert_uint_eq(UA_Server_getNamespaceDefaultAccessRestrictions(server, unknownNs,
                                                                      &ar),
                      UA_STATUSCODE_BADINDEXRANGEINVALID);
    ck_assert_uint_eq(UA_Server_getNodeAccessRestrictions(server, UA_NS0ID(SERVER), NULL),
                      UA_STATUSCODE_BADINVALIDARGUMENT);
    ck_assert_uint_eq(UA_Server_getNamespaceDefaultAccessRestrictions(server, 0, NULL),
                      UA_STATUSCODE_BADINVALIDARGUMENT);
    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(NULL, UA_NS0ID(SERVER), SIGN),
                      UA_STATUSCODE_BADINVALIDARGUMENT);
} END_TEST

#ifdef UA_GENERATED_NAMESPACE_ZERO_FULL
/* The default of Namespace Zero is published in its NamespaceMetadata */
START_TEST(api_ns0MetadataFollowsDefault) {
    ck_assert_uint_eq(UA_Server_setNamespaceDefaultAccessRestrictions(server, 0, SIGN),
                      UA_STATUSCODE_GOOD);
    UA_Variant v;
    ck_assert_uint_eq(UA_Server_readValue(server,
                          UA_NS0ID(OPCUANAMESPACEMETADATA_DEFAULTACCESSRESTRICTIONS), &v),
                      UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_ACCESSRESTRICTIONTYPE]));
    ck_assert_uint_eq(*(UA_AccessRestrictionType*)v.data, SIGN);
    UA_Variant_clear(&v);
} END_TEST
#endif

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

static Suite *testSuite_rbacAccessRestrictions(void) {
    Suite *s = suite_create("RBAC AccessRestrictions");
    TCase *tc = tcase_create("Storage");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, api_setGetRead);
    tcase_add_test(tc, storage_independentOfRolePermissions);
    tcase_add_test(tc, storage_recursiveKeepsChildAr);
    tcase_add_test(tc, storage_inheritedByInstanceChild);
    tcase_add_test(tc, storage_survivesPurgeOfRemovedRole);
    tcase_add_test(tc, api_removeAndNamespaceDefault);
    tcase_add_test(tc, api_failurePaths);
#ifdef UA_GENERATED_NAMESPACE_ZERO_FULL
    tcase_add_test(tc, api_ns0MetadataFollowsDefault);
#endif
    suite_add_tcase(s, tc);

    TCase *tc_preset = tcase_create("Presets");
    tcase_add_checked_fixture(tc_preset, setupWithPreset, teardownWithPreset);
    tcase_add_test(tc_preset, storage_presetUpdateReachesNodesWithAr);
    suite_add_tcase(s, tc_preset);

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
