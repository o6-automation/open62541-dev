/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

/* The RoleType Objects of the RoleSet (Part 18 §4), the audit Events of Role
 * changes and the default rights of the RBAC Nodes and namespaces */

#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/log_stdout.h>

#include "test_helpers_rbac.h"

#include <check.h>
#include <stdlib.h>

#define SECURITYADMIN UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN)
#define ANONYMOUS UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS)

static UA_Server *server;
static UA_SecureChannel plain;  /* SecurityMode None */
static UA_SecureChannel secure; /* SecurityMode SignAndEncrypt */
static size_t roleAudits;

static void
auditCallback(UA_Server *s, UA_ApplicationNotificationType type,
              const UA_KeyValueMap payload) {
    if(type == UA_APPLICATIONNOTIFICATIONTYPE_AUDIT_UPDATE_METHOD_ROLEMAPPINGRULECHANGED)
        roleAudits++;
}

static void setup(void) {
    roleAudits = 0;
    UA_ServerConfig config;
    memset(&config, 0, sizeof(config));
    config.logging = UA_Log_Stdout_new(UA_LOGLEVEL_WARNING);
    ck_assert_uint_eq(UA_ServerConfig_setMinimal(&config, 0, NULL), UA_STATUSCODE_GOOD);
    config.tcpEnabled = false;
#ifdef UA_ENABLE_AUDITING
    config.auditingEnabled = true;
    config.auditNotificationCallback = auditCallback;
#endif
    rbacAddEndpointModes(&config);
    server = UA_Server_newWithConfig(&config);
    ck_assert_ptr_nonnull(server);
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
    rbacChannelInit(server, &plain, UA_MESSAGESECURITYMODE_NONE, NULL);
    rbacChannelInit(server, &secure, UA_MESSAGESECURITYMODE_SIGNANDENCRYPT, NULL);
}

static void teardown(void) {
    UA_Server_run_shutdown(server);
    UA_Server_delete(server);
    UA_SecureChannel_clear(&plain);
    UA_SecureChannel_clear(&secure);
}

/* The child of the Role Object with the BrowseName */
static UA_NodeId
roleChild(const UA_NodeId roleId, const char *name) {
    UA_QualifiedName qn = UA_QUALIFIEDNAME(0, (char*)(uintptr_t)name);
    UA_BrowsePathResult bpr = UA_Server_browseSimplifiedBrowsePath(server, roleId, 1, &qn);
    ck_assert_uint_eq(bpr.statusCode, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(bpr.targetsSize, 1);
    UA_NodeId id;
    UA_NodeId_copy(&bpr.targets[0].targetId.nodeId, &id);
    UA_BrowsePathResult_clear(&bpr);
    return id;
}

static UA_Boolean
readBoolean(const UA_NodeId nodeId) {
    UA_Variant v;
    ck_assert_uint_eq(UA_Server_readValue(server, nodeId, &v), UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_BOOLEAN]));
    UA_Boolean b = *(UA_Boolean*)v.data;
    UA_Variant_clear(&v);
    return b;
}

static UA_NodeId
anonymousSession(void) {
    UA_NodeId sessionId;
    ck_assert_uint_eq(rbacLogin(server, &plain, NULL, NULL, &sessionId),
                      UA_STATUSCODE_GOOD);
    return sessionId;
}

/********************/
/* RoleType Objects */
/********************/

/* The Properties reflect the Role. ApplicationsExclude and EndpointsExclude are
 * writable, and writing them re-evaluates the Sessions. */
START_TEST(roleObject_properties) {
    UA_IdentityMappingRuleType rule;
    UA_IdentityMappingRuleType_init(&rule);
    rule.criteriaType = UA_IDENTITYCRITERIATYPE_ANONYMOUS;
    UA_Role role;
    UA_Role_init(&role);
    role.roleName = UA_QUALIFIEDNAME(1, "PropertyRole");
    role.identityMappingRules = &rule;
    role.identityMappingRulesSize = 1;
    role.customConfiguration = true;
    UA_NodeId roleId;
    ck_assert_uint_eq(UA_Server_addRole(server, &role, &roleId), UA_STATUSCODE_GOOD);
    UA_NodeId sessionId = anonymousSession();
    ck_assert(rbacHasRole(server, &sessionId, roleId));

    UA_NodeId custom = roleChild(roleId, "CustomConfiguration");
    ck_assert(readBoolean(custom));
    const char *excludes[2] = {"ApplicationsExclude", "EndpointsExclude"};
    for(size_t i = 0; i < 2; i++) {
        UA_NodeId prop = roleChild(roleId, excludes[i]);
        ck_assert(readBoolean(prop));
        UA_Boolean include = false;
        UA_Variant v;
        UA_Variant_setScalar(&v, &include, &UA_TYPES[UA_TYPES_BOOLEAN]);
        ck_assert_uint_eq(UA_Server_writeValue(server, prop, v), UA_STATUSCODE_GOOD);
        ck_assert(!readBoolean(prop));
        UA_NodeId_clear(&prop);
        /* An empty include list grants nothing */
        ck_assert(!rbacHasRole(server, &sessionId, roleId));
    }
    UA_Role fetched;
    ck_assert_uint_eq(UA_Server_getRoleById(server, roleId, &fetched), UA_STATUSCODE_GOOD);
    ck_assert(!fetched.applicationsExclude);
    ck_assert(!fetched.endpointsExclude);
    UA_Role_clear(&fetched);
    UA_NodeId_clear(&custom);
    UA_NodeId_clear(&roleId);
} END_TEST

/* The RoleType Methods are called on the Role Object, also with the NodeId of
 * the declaration in the RoleType. They re-evaluate the Sessions. */
START_TEST(roleObject_addIdentityMethod) {
    UA_NodeId roleId = rbacAddRole(server, "MethodRole", RBAC_NO_RULE, NULL);
    UA_NodeId sessionId = anonymousSession();
    UA_IdentityMappingRuleType rule;
    UA_IdentityMappingRuleType_init(&rule);
    rule.criteriaType = UA_IDENTITYCRITERIATYPE_ANONYMOUS;
    UA_ExtensionObject eo;
    UA_ExtensionObject_setValueNoDelete(&eo, &rule,
                                        &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE]);
    UA_Variant in;
    UA_Variant_setScalar(&in, &eo, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = roleId;
    req.methodId = UA_NODEID_NUMERIC(0, UA_NS0ID_ROLETYPE_ADDIDENTITY);
    req.inputArguments = &in;
    req.inputArgumentsSize = 1;
    UA_CallMethodResult res = UA_Server_call(server, &req);
    ck_assert_uint_eq(res.statusCode, UA_STATUSCODE_GOOD);
    UA_CallMethodResult_clear(&res);
    ck_assert(rbacHasRole(server, &sessionId, roleId));

    res = UA_Server_call(server, &req);
    ck_assert_uint_eq(res.statusCode, UA_STATUSCODE_BADALREADYEXISTS);
    UA_CallMethodResult_clear(&res);
    UA_Role fetched;
    ck_assert_uint_eq(UA_Server_getRoleById(server, roleId, &fetched), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(fetched.identityMappingRulesSize, 1);
    UA_Role_clear(&fetched);
    UA_NodeId_clear(&roleId);
} END_TEST

/* A Role Object of a nodeset is adopted, a foreign NodeId is refused, and a
 * Node that took over the NodeId of a Role survives its removal */
START_TEST(roleObject_nodeIdOwnership) {
    UA_NodeId adopted = UA_NODEID_NUMERIC(1, 60001);
    ck_assert_uint_eq(UA_Server_addObjectNode(server, adopted,
                          UA_NS0ID(SERVER_SERVERCAPABILITIES_ROLESET),
                          UA_NS0ID(HASCOMPONENT), UA_QUALIFIEDNAME(1, "Adopted"),
                          UA_NS0ID(ROLETYPE), UA_ObjectAttributes_default, NULL, NULL),
                      UA_STATUSCODE_GOOD);
    UA_Role role;
    UA_Role_init(&role);
    role.roleId = adopted;
    role.roleName = UA_QUALIFIEDNAME(1, "Adopted");
    UA_NodeId outId;
    ck_assert_uint_eq(UA_Server_addRole(server, &role, &outId), UA_STATUSCODE_GOOD);
    ck_assert(UA_NodeId_equal(&outId, &adopted));
    ck_assert_uint_eq(UA_Server_removeRole(server, role.roleName), UA_STATUSCODE_GOOD);
    UA_NodeClass nc;
    ck_assert_uint_eq(UA_Server_readNodeClass(server, adopted, &nc),
                      UA_STATUSCODE_BADNODEIDUNKNOWN);

    UA_NodeId var = rbacAddNode(server, "Foreign", UA_NODECLASS_VARIABLE);
    role.roleId = var;
    role.roleName = UA_QUALIFIEDNAME(1, "Foreign");
    ck_assert_uint_eq(UA_Server_addRole(server, &role, NULL),
                      UA_STATUSCODE_BADNODEIDEXISTS);
    ck_assert_uint_eq(UA_Server_getRole(server, role.roleName, &role),
                      UA_STATUSCODE_BADNOTFOUND);

    UA_NodeId shadowed = rbacAddRole(server, "Shadowed", RBAC_NO_RULE, NULL);
    ck_assert_uint_eq(UA_Server_deleteNode(server, shadowed, true), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_addVariableNode(server, shadowed, UA_NS0ID(OBJECTSFOLDER),
                          UA_NS0ID(ORGANIZES), UA_QUALIFIEDNAME(1, "Squatter"),
                          UA_NS0ID(BASEDATAVARIABLETYPE),
                          UA_VariableAttributes_default, NULL, NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_removeRole(server, UA_QUALIFIEDNAME(1, "Shadowed")),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_readNodeClass(server, shadowed, &nc), UA_STATUSCODE_GOOD);
    UA_NodeId_clear(&shadowed);
} END_TEST

/* A Role without identity mapping rules is never granted automatically, also
 * with CustomConfiguration */
START_TEST(roleWithoutRules_notGranted) {
    UA_Role role;
    UA_Role_init(&role);
    role.roleName = UA_QUALIFIEDNAME(1, "NoRules");
    UA_NodeId plainRole, customRole;
    ck_assert_uint_eq(UA_Server_addRole(server, &role, &plainRole), UA_STATUSCODE_GOOD);
    role.roleName = UA_QUALIFIEDNAME(1, "CustomNoRules");
    role.customConfiguration = true;
    ck_assert_uint_eq(UA_Server_addRole(server, &role, &customRole), UA_STATUSCODE_GOOD);
    UA_NodeId sessionId = anonymousSession();
    ck_assert(!rbacHasRole(server, &sessionId, plainRole));
    ck_assert(!rbacHasRole(server, &sessionId, customRole));
    UA_NodeId_clear(&plainRole);
    UA_NodeId_clear(&customRole);
} END_TEST

/************/
/* Auditing */
/************/

#if defined(UA_ENABLE_AUDITING) && defined(UA_ENABLE_SUBSCRIPTIONS_EVENTS)
/* Each Role change emits one RoleMappingRuleChangedAuditEvent from the Role
 * Object, which only SecurityAdmin Sessions receive */
START_TEST(audit_roleMappingRuleChanged) {
    UA_Session *admin = rbacSession(server, &secure, SECURITYADMIN);
    UA_Session *anonymous = rbacSession(server, &secure, ANONYMOUS);
    UA_StatusCode res;
    UA_MonitoredItem *adminItem = rbacMonitor(server, admin, UA_NS0ID(SERVER),
                                              UA_ATTRIBUTEID_EVENTNOTIFIER,
                                              "SourceNode", &res);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    UA_MonitoredItem *anonymousItem =
        rbacMonitor(server, anonymous, UA_NS0ID(SERVER),
                    UA_ATTRIBUTEID_EVENTNOTIFIER, "SourceNode", &res);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);

    UA_NodeId roleId = rbacAddRole(server, "AuditedRole", RBAC_NO_RULE, NULL);
    ck_assert_uint_eq(roleAudits, 1);
    UA_Role role;
    ck_assert_uint_eq(UA_Server_getRoleById(server, roleId, &role), UA_STATUSCODE_GOOD);
    role.applicationsExclude = false;
    ck_assert_uint_eq(UA_Server_updateRole(server, &role), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(roleAudits, 2);
    UA_String app = UA_STRING("urn:app");
    UA_Variant in;
    UA_Variant_setScalar(&in, &app, &UA_TYPES[UA_TYPES_STRING]);
    ck_assert_uint_eq(rbacCall(server, admin, roleId,
                               UA_NODEID_NUMERIC(0, UA_NS0ID_ROLETYPE_ADDAPPLICATION),
                               1, &in), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(roleAudits, 3);

    lockServer(server);
    ck_assert_uint_eq(adminItem->queueSize, 3);
    ck_assert_uint_eq(anonymousItem->queueSize, 0);
    UA_Notification *n;
    TAILQ_FOREACH(n, &adminItem->queue, monEntry) {
        ck_assert_uint_eq(n->data.event.eventFieldsSize, 1);
        UA_Variant *source = &n->data.event.eventFields[0];
        ck_assert(UA_Variant_hasScalarType(source, &UA_TYPES[UA_TYPES_NODEID]));
        ck_assert(UA_NodeId_equal((UA_NodeId*)source->data, &roleId));
    }
    unlockServer(server);

    ck_assert_uint_eq(UA_Server_removeRole(server, role.roleName), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(roleAudits, 4);
    UA_Role_clear(&role);
    UA_NodeId_clear(&roleId);
} END_TEST
#endif

/******************/
/* Default rights */
/******************/

#define BRCR (UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ | \
              UA_PERMISSIONTYPE_CALL | UA_PERMISSIONTYPE_READROLEPERMISSIONS)
#define ENCRYPTED (UA_ACCESSRESTRICTIONTYPE_ENCRYPTIONREQUIRED | \
                   UA_ACCESSRESTRICTIONTYPE_APPLYRESTRICTIONSTOBROWSE)

/* The RolePermissions and AccessRestrictions of the RBAC Nodes after startup.
 * Only SecurityAdmin has permissions. */
START_TEST(defaults_rbacNodes) {
    static const struct {
        UA_UInt32 id;
        UA_PermissionType securityAdmin;
        UA_AccessRestrictionType ar;
    } nodes[] = {
        {UA_NS0ID_SERVER_SERVERCAPABILITIES_ROLESET, BRCR, ENCRYPTED},
        {UA_NS0ID_SERVER_SERVERCAPABILITIES_ROLESET_ADDROLE, BRCR, ENCRYPTED},
        {UA_NS0ID_SERVER_SERVERCAPABILITIES_ROLESET_REMOVEROLE, BRCR, ENCRYPTED},
        {UA_NS0ID_ROLETYPE_ADDIDENTITY, BRCR, ENCRYPTED},
        {UA_NS0ID_WELLKNOWNROLE_OPERATOR, BRCR | UA_PERMISSIONTYPE_RECEIVEEVENTS,
         ENCRYPTED},
        {UA_NS0ID_WELLKNOWNROLE_OPERATOR_ADDIDENTITY,
         BRCR | UA_PERMISSIONTYPE_RECEIVEEVENTS,
         ENCRYPTED},
        {UA_NS0ID_WELLKNOWNROLE_OPERATOR_IDENTITIES,
         UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ,
         ENCRYPTED},
        {UA_NS0ID_WELLKNOWNROLE_OPERATOR_APPLICATIONSEXCLUDE,
         UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ | UA_PERMISSIONTYPE_WRITE,
         ENCRYPTED},
        {UA_NS0ID_ROLEMAPPINGRULECHANGEDAUDITEVENTTYPE,
         UA_PERMISSIONTYPE_RECEIVEEVENTS, UA_ACCESSRESTRICTIONTYPE_NONE}
    };
    const UA_NodeId securityAdmin = SECURITYADMIN;
    for(size_t i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
        UA_NodeId nodeId = UA_NODEID_NUMERIC(0, nodes[i].id);
        size_t size = 0;
        UA_RolePermission *rp = NULL;
        ck_assert_uint_eq(UA_Server_getNodeRolePermissions(server, nodeId, &size, &rp),
                          UA_STATUSCODE_GOOD);
        ck_assert_msg(size == 1, "node %u: %u entries", nodes[i].id, (unsigned)size);
        ck_assert(UA_NodeId_equal(&rp[0].roleId, &securityAdmin));
        ck_assert_msg(rp[0].permissions == nodes[i].securityAdmin,
                      "node %u: permissions 0x%x", nodes[i].id, rp[0].permissions);
        UA_NodeId_clear(&rp[0].roleId);
        UA_free(rp);
        UA_AccessRestrictionType ar = 0xFFFF;
        ck_assert_uint_eq(UA_Server_getNodeAccessRestrictions(server, nodeId, &ar),
                          UA_STATUSCODE_GOOD);
        ck_assert_uint_eq(ar, nodes[i].ar);
    }
} END_TEST

/* No namespace has a default. A Node without RolePermissions grants all
 * permissions to every Session (allPermissionsForAnonymous). */
START_TEST(defaults_namespacesAndUnconfiguredNodes) {
    ck_assert(UA_Server_getConfig(server)->allPermissionsForAnonymous);
    UA_Variant uris;
    ck_assert_uint_eq(UA_Server_readValue(server, UA_NS0ID(SERVER_NAMESPACEARRAY), &uris),
                      UA_STATUSCODE_GOOD);
    for(size_t ns = 0; ns < uris.arrayLength; ns++) {
        size_t size = 1;
        UA_RolePermission *rp = NULL;
        ck_assert_uint_eq(UA_Server_getNamespaceDefaultRolePermissions(server,
                              (UA_UInt16)ns, &size, &rp), UA_STATUSCODE_GOOD);
        ck_assert_uint_eq(size, 0);
    }
    UA_Variant_clear(&uris);

    UA_NodeId var = rbacAddNode(server, "Unconfigured", UA_NODECLASS_VARIABLE);
    UA_Session *session = rbacSession(server, &plain, ANONYMOUS);
    UA_WriteValue wv;
    UA_WriteValue_init(&wv);
    wv.nodeId = var;
    wv.attributeId = UA_ATTRIBUTEID_VALUE;
    wv.value.hasValue = true;
    UA_Int32 value = 5;
    UA_Variant_setScalar(&wv.value.value, &value, &UA_TYPES[UA_TYPES_INT32]);
    UA_StatusCode res = UA_STATUSCODE_BADINTERNALERROR;
    lockServer(server);
    Operation_Write(server, session, &wv, &res);
    unlockServer(server);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
} END_TEST

/* An explicit list is enforced also with allPermissionsForAnonymous: an empty
 * namespace default and a list emptied by removeRole deny everything */
START_TEST(defaults_emptyListsDeny) {
    UA_NodeId role = rbacAddRole(server, "Removed", RBAC_NO_RULE, NULL);
    UA_RolePermission rp = {role, UA_PERMISSIONTYPE_ALL};
    UA_NodeId listed = rbacAddNode(server, "Listed", UA_NODECLASS_VARIABLE);
    ck_assert_uint_eq(UA_Server_setNodeRolePermissions(server, listed, 1, &rp,
                                                       false, NULL), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_removeRole(server, UA_QUALIFIEDNAME(1, "Removed")),
                      UA_STATUSCODE_GOOD);
    UA_NodeId other = rbacAddNode(server, "Other", UA_NODECLASS_VARIABLE);

    UA_Session *session = rbacSession(server, &plain, ANONYMOUS);
    UA_ReadValueId rvi;
    UA_ReadValueId_init(&rvi);
    rvi.attributeId = UA_ATTRIBUTEID_VALUE;
    UA_DataValue dv;
    for(size_t i = 0; i < 3; i++) {
        if(i == 2)
            ck_assert_uint_eq(UA_Server_setNamespaceDefaultRolePermissions(server, 1, 0,
                                                                           NULL),
                              UA_STATUSCODE_GOOD);
        rvi.nodeId = (i == 0) ? listed : other;
        UA_DataValue_init(&dv);
        lockServer(server);
        Operation_Read(server, session, UA_TIMESTAMPSTORETURN_NEITHER, &rvi, &dv);
        unlockServer(server);
        ck_assert_uint_eq(dv.hasStatus ? dv.status : UA_STATUSCODE_GOOD,
                          i == 1 ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADUSERACCESSDENIED);
        UA_DataValue_clear(&dv);
    }
    UA_NodeId_clear(&role);
} END_TEST

/* The (User)RolePermissions Attributes and the NamespaceMetadata report the
 * namespace default */
START_TEST(defaults_namespaceDefaultReported) {
    UA_NodeId role = rbacAddRole(server, "Reader", RBAC_NO_RULE, NULL);
    UA_RolePermission rp = {role, UA_PERMISSIONTYPE_BROWSE |
                                  UA_PERMISSIONTYPE_READROLEPERMISSIONS};
    ck_assert_uint_eq(UA_Server_setNamespaceDefaultRolePermissions(server, 0, 1, &rp),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_setNamespaceDefaultRolePermissions(server, 1, 1, &rp),
                      UA_STATUSCODE_GOOD);
    UA_NodeId var = rbacAddNode(server, "Inherits", UA_NODECLASS_VARIABLE);
    UA_Session *session = rbacSession(server, &plain, role);

    const UA_NodeId nodes[3] = {var, var,
        UA_NS0ID(OPCUANAMESPACEMETADATA_DEFAULTROLEPERMISSIONS)};
    const UA_UInt32 attributes[3] = {UA_ATTRIBUTEID_ROLEPERMISSIONS,
        UA_ATTRIBUTEID_USERROLEPERMISSIONS, UA_ATTRIBUTEID_VALUE};
    for(size_t i = 0; i < 3; i++) {
        UA_ReadValueId rvi;
        UA_ReadValueId_init(&rvi);
        rvi.nodeId = nodes[i];
        rvi.attributeId = attributes[i];
        UA_DataValue dv;
        UA_DataValue_init(&dv);
        if(i < 2) {
            lockServer(server);
            Operation_Read(server, session, UA_TIMESTAMPSTORETURN_NEITHER, &rvi, &dv);
            unlockServer(server);
        } else {
            dv = UA_Server_read(server, &rvi, UA_TIMESTAMPSTORETURN_NEITHER);
        }
        ck_assert_msg(!dv.hasStatus, "read %u: %s", (unsigned)i,
                      UA_StatusCode_name(dv.status));
        ck_assert(UA_Variant_hasArrayType(&dv.value,
                                          &UA_TYPES[UA_TYPES_ROLEPERMISSIONTYPE]));
        ck_assert_uint_eq(dv.value.arrayLength, 1);
        UA_RolePermissionType *reported = (UA_RolePermissionType*)dv.value.data;
        ck_assert(UA_NodeId_equal(&reported->roleId, &role));
        ck_assert_uint_eq(reported->permissions, rp.permissions);
        UA_DataValue_clear(&dv);
    }
    UA_NodeId_clear(&role);
} END_TEST

/* The RoleSet Methods require SecurityAdmin over an encrypted SecureChannel,
 * checked by the Methods themselves */
START_TEST(defaults_roleSetMethodsNeedSecurityAdmin) {
    static const struct {
        UA_Boolean encrypted;
        UA_Boolean securityAdmin;
        UA_StatusCode expected;
    } cases[] = {
        {false, true, UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT},
        {true, false, UA_STATUSCODE_BADUSERACCESSDENIED},
        {true, true, UA_STATUSCODE_GOOD}
    };
    /* Without permissions on the RoleSet Nodes the Methods decide alone */
    const UA_NodeId nodes[2] = {UA_NS0ID(SERVER_SERVERCAPABILITIES_ROLESET),
                                UA_NS0ID(SERVER_SERVERCAPABILITIES_ROLESET_ADDROLE)};
    for(size_t i = 0; i < 2; i++) {
        ck_assert_uint_eq(UA_Server_removeNodeRolePermissions(server, nodes[i], false),
                          UA_STATUSCODE_GOOD);
        ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, nodes[i], 0),
                          UA_STATUSCODE_GOOD);
    }
    UA_String name = UA_STRING("CalledRole");
    UA_String nsUri = UA_STRING_NULL;
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &name, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &nsUri, &UA_TYPES[UA_TYPES_STRING]);
    for(size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        UA_Session *session = rbacSession(server, cases[c].encrypted ? &secure : &plain,
                                          cases[c].securityAdmin ? SECURITYADMIN : ANONYMOUS);
        ck_assert_uint_eq(rbacCall(server, session, nodes[0], nodes[1], 2, in),
                          cases[c].expected);
    }
} END_TEST

static Suite *testSuite_rbacRoles(void) {
    Suite *s = suite_create("RBAC Roles");
    TCase *tc = tcase_create("RoleType Objects");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, roleObject_properties);
    tcase_add_test(tc, roleObject_addIdentityMethod);
    tcase_add_test(tc, roleObject_nodeIdOwnership);
    tcase_add_test(tc, roleWithoutRules_notGranted);
#if defined(UA_ENABLE_AUDITING) && defined(UA_ENABLE_SUBSCRIPTIONS_EVENTS)
    tcase_add_test(tc, audit_roleMappingRuleChanged);
#endif
    suite_add_tcase(s, tc);

    TCase *tc_defaults = tcase_create("Default rights");
    tcase_add_checked_fixture(tc_defaults, setup, teardown);
    tcase_add_test(tc_defaults, defaults_rbacNodes);
    tcase_add_test(tc_defaults, defaults_namespacesAndUnconfiguredNodes);
    tcase_add_test(tc_defaults, defaults_emptyListsDeny);
    tcase_add_test(tc_defaults, defaults_namespaceDefaultReported);
    tcase_add_test(tc_defaults, defaults_roleSetMethodsNeedSecurityAdmin);
    suite_add_tcase(s, tc_defaults);
    return s;
}

int main(void) {
    SRunner *sr = srunner_create(testSuite_rbacRoles());
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
