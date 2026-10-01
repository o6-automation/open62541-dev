/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

/* The built-in protection of sensitive Namespace Zero Nodes under the strict
 * NS0 template: configuration and key Methods, Condition Methods, the audit
 * EventTypes, Namespace Zero writes (ConfigureAdmin, non-security
 * configuration only) and the SessionSecurityDiagnostics. Uses
 * in-process Sessions; the server has no TCP listener. */

#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/nodeids.h>
#include <open62541/driver/alarms_conditions.h>

#include "server/ua_server_internal.h"
#include "server/ua_server_rbac.h"
#include "server/ua_services.h"

#include "test_helpers.h"

#include <check.h>
#include <stdlib.h>

#if defined(UA_ENABLE_SUBSCRIPTIONS_EVENTS) && defined(UA_GENERATED_NAMESPACE_ZERO_FULL)
# define TEST_ALARMS_CONDITIONS
#endif

#define ROLE(id) UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_##id)

#define B   UA_PERMISSIONTYPE_BROWSE
#define R   UA_PERMISSIONTYPE_READ
#define W   UA_PERMISSIONTYPE_WRITE
#define WA  UA_PERMISSIONTYPE_WRITEATTRIBUTE
#define C   UA_PERMISSIONTYPE_CALL
#define RE  UA_PERMISSIONTYPE_RECEIVEEVENTS
#define RRP UA_PERMISSIONTYPE_READROLEPERMISSIONS

static UA_Server *server = NULL;
#ifdef TEST_ALARMS_CONDITIONS
static UA_AlarmConditionsDriver *acDriver = NULL;
#endif

/* A UserManagement provider, so that the UserManagement Methods are bound */
static UA_StatusCode
umGetUsers(UA_Server *s, UA_AccessControl *ac,
           UA_UserManagementDataType **users, size_t *usersSize) {
    *users = NULL;
    *usersSize = 0;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
umGetPasswordPolicy(UA_Server *s, UA_AccessControl *ac, UA_Range *length,
                    UA_PasswordOptionsMask *options, UA_LocalizedText *restrictions) {
    length->low = 8;
    length->high = 64;
    *options = 0;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
umGetUserConfiguration(UA_Server *s, UA_AccessControl *ac, const UA_String *userName,
                       UA_UserConfigurationMask *configuration) {
    return UA_STATUSCODE_BADNOTFOUND;
}

static UA_StatusCode
umAddUser(UA_Server *s, UA_AccessControl *ac, const UA_String *userName,
          const UA_String *password, UA_UserConfigurationMask configuration,
          const UA_String *description) {
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
umModifyUser(UA_Server *s, UA_AccessControl *ac, const UA_String *userName,
             UA_Boolean modifyPassword, const UA_String *password,
             UA_Boolean modifyConfiguration, UA_UserConfigurationMask configuration,
             UA_Boolean modifyDescription, const UA_String *description) {
    return UA_STATUSCODE_BADNOTFOUND;
}

static UA_StatusCode
umRemoveUser(UA_Server *s, UA_AccessControl *ac, const UA_String *userName) {
    return UA_STATUSCODE_BADNOTFOUND;
}

static UA_StatusCode
umChangePassword(UA_Server *s, UA_AccessControl *ac, const UA_String *userName,
                 const UA_String *oldPassword, const UA_String *newPassword) {
    return UA_STATUSCODE_BADUSERACCESSDENIED;
}

/* The provider must be part of the configuration handed to
 * UA_Server_newWithConfig: initNS0RBAC binds the UserManagement Object in
 * UA_Server_init. The flag is set before the Server is created as well. */
static UA_Server *
newServer(UA_Boolean strict) {
    UA_ServerConfig sc;
    memset(&sc, 0, sizeof(UA_ServerConfig));
    sc.logging = UA_Log_Stdout_new(UA_LOGLEVEL_ERROR);
    ck_assert_uint_eq(UA_ServerConfig_setMinimal(&sc, 5020, NULL),
                      UA_STATUSCODE_GOOD);
    sc.tcpEnabled = false;
    sc.allPermissionsForAnonymous = !strict;
    sc.accessControl.getUsers = umGetUsers;
    sc.accessControl.getPasswordPolicy = umGetPasswordPolicy;
    sc.accessControl.getUserConfiguration = umGetUserConfiguration;
    sc.accessControl.addUser = umAddUser;
    sc.accessControl.modifyUser = umModifyUser;
    sc.accessControl.removeUser = umRemoveUser;
    sc.accessControl.changePassword = umChangePassword;
    UA_Server *s = UA_Server_newWithConfig(&sc);
    ck_assert(s != NULL);
    ck_assert_uint_eq(UA_Server_run_startup(s), UA_STATUSCODE_GOOD);

#ifdef TEST_ALARMS_CONDITIONS
    /* A Condition binds the Condition Methods of the A&C driver */
    acDriver = UA_AlarmsConditionsDriver(UA_KEYVALUEMAP_NULL);
    ck_assert_ptr_nonnull(acDriver);
    ck_assert_uint_eq(UA_Server_addDriver(s, &acDriver->drv), UA_STATUSCODE_GOOD);
    UA_NodeId condition = UA_NODEID_NULL;
    ck_assert_uint_eq(acDriver->createCondition(
                          acDriver, UA_NODEID_NULL,
                          UA_NODEID_NUMERIC(0, UA_NS0ID_OFFNORMALALARMTYPE),
                          UA_QUALIFIEDNAME(0, "TestCondition"),
                          UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER),
                          UA_NODEID_NULL, &condition),
                      UA_STATUSCODE_GOOD);
    UA_NodeId_clear(&condition);
#endif
    return s;
}

static void setupStrict(void) {
    server = newServer(true);
}

static void setupLegacy(void) {
    server = newServer(false);
}

static void teardown(void) {
    UA_Server_run_shutdown(server);
    UA_Server_delete(server);
    server = NULL;
}

/* Create an in-process Session that holds exactly the given Roles */
static UA_Session *
createSessionWithRoles(size_t rolesSize, const UA_NodeId *roles) {
    UA_CreateSessionRequest request;
    UA_CreateSessionRequest_init(&request);
    request.requestedSessionTimeout = UA_UINT32_MAX;
    UA_Session *session = NULL;
    lockServer(server);
    UA_StatusCode res = UA_Session_create(server, NULL, &request, &session);
    unlockServer(server);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_ptr_ne(session, NULL);

    UA_Variant v;
    UA_Variant_setArray(&v, (void*)(uintptr_t)roles, rolesSize,
                        &UA_TYPES[UA_TYPES_NODEID]);
    ck_assert_uint_eq(UA_Server_setSessionAttribute(server, &session->sessionId,
                                                    UA_QUALIFIEDNAME(0, "roles"), &v),
                      UA_STATUSCODE_GOOD);
    return session;
}

/* A Session with a well-known Role holds the Anonymous Role as well */
static UA_Session *
createSessionWithRole(const UA_NodeId role) {
    const UA_NodeId roles[2] = {ROLE(ANONYMOUS), role};
    return createSessionWithRoles(2, roles);
}

/* The Roles of a Session without any granted Role */
static UA_Session *
createPublicSession(void) {
    const UA_NodeId roles[2] = {ROLE(ANONYMOUS), ROLE(AUTHENTICATEDUSER)};
    return createSessionWithRoles(2, roles);
}

static UA_PermissionType
effective(const UA_Session *session, const UA_NodeId nodeId) {
    UA_PermissionType permissions = 0;
    ck_assert_uint_eq(UA_Server_getEffectivePermissions(server, &session->sessionId,
                                                        &nodeId, &permissions),
                      UA_STATUSCODE_GOOD);
    return permissions;
}

static UA_PermissionIndex
permissionIndexOf(const UA_NodeId nodeId) {
    UA_PermissionIndex index = UA_PERMISSION_INDEX_INVALID;
    ck_assert_uint_eq(UA_Server_getNodePermissionIndex(server, nodeId, &index),
                      UA_STATUSCODE_GOOD);
    return index;
}

static size_t
refCountOf(UA_PermissionIndex index) {
    ck_assert_uint_lt(index, server->rolePermissionsSize);
    return server->rolePermissions[index].refCount;
}

/* A Variable in ns=1 with the given AccessRestrictions */
static UA_NodeId
addVariableWithAccessRestrictions(const char *name, UA_AccessRestrictionType ar) {
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    attr.displayName = UA_LOCALIZEDTEXT("", (char*)(uintptr_t)name);
    UA_NodeId nodeId;
    ck_assert_uint_eq(UA_Server_addVariableNode(server,
                          UA_NODEID_STRING(1, (char*)(uintptr_t)name),
                          UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                          UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                          UA_QUALIFIEDNAME(1, (char*)(uintptr_t)name),
                          UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                          attr, NULL, &nodeId),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, nodeId, ar),
                      UA_STATUSCODE_GOOD);
    return nodeId;
}

static UA_StatusCode
protect(const UA_NodeId nodeId, size_t entriesSize, const UA_RolePermission *entries) {
    lockServer(server);
    UA_StatusCode res = protectNodeRolePermissions(server, &nodeId, entriesSize, entries);
    unlockServer(server);
    return res;
}

static UA_StatusCode
callAs(UA_Session *session, const UA_NodeId objectId, const UA_NodeId methodId) {
    UA_CallMethodRequest request;
    UA_CallMethodRequest_init(&request);
    request.objectId = objectId;
    request.methodId = methodId;
    UA_CallMethodResult result;
    UA_CallMethodResult_init(&result);
    lockServer(server);
    Operation_CallMethod(server, session, &request, &result);
    unlockServer(server);
    UA_StatusCode res = result.statusCode;
    UA_CallMethodResult_clear(&result);
    return res;
}

static UA_StatusCode
writeAs(UA_Session *session, const UA_NodeId nodeId, const UA_Variant *value) {
    UA_WriteValue wv;
    UA_WriteValue_init(&wv);
    wv.nodeId = nodeId;
    wv.attributeId = UA_ATTRIBUTEID_VALUE;
    wv.value.hasValue = true;
    wv.value.value = *value;
    UA_StatusCode res = UA_STATUSCODE_BADINTERNALERROR;
    lockServer(server);
    Operation_Write(server, session, &wv, &res);
    unlockServer(server);
    return res;
}

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

/* The Methods of Namespace Zero that every Session may call */
static const UA_UInt32 publicMethods[] = {
    /* Operate on a Subscription of the calling Session only */
    UA_NS0ID_SERVER_GETMONITOREDITEMS,
    UA_NS0ID_SERVER_RESENDDATA,
    /* Resend the Condition states to a Subscription of the calling Session */
    UA_NS0ID_CONDITIONTYPE_CONDITIONREFRESH,
    UA_NS0ID_CONDITIONTYPE_CONDITIONREFRESH2,
    /* Changes the password of the calling user only; the callback requires an
     * encrypted channel, a UserName token and the old password */
    UA_NS0ID_USERMANAGEMENT_CHANGEPASSWORD
};

static UA_Boolean
isPublicMethod(const UA_NodeId *nodeId) {
    for(size_t i = 0; i < sizeof(publicMethods) / sizeof(publicMethods[0]); i++) {
        if(nodeId->namespaceIndex == 0 &&
           nodeId->identifierType == UA_NODEIDTYPE_NUMERIC &&
           nodeId->identifier.numeric == publicMethods[i])
            return true;
    }
    return false;
}

typedef struct {
    size_t size;
    UA_NodeId ids[256];
} NodeList;

static void
collectCallableMethods(void *visitorCtx, const UA_Node *node) {
    NodeList *list = (NodeList*)visitorCtx;
    if(node->head.nodeClass != UA_NODECLASS_METHOD ||
       node->head.nodeId.namespaceIndex != 0 || !node->methodNode.method)
        return;
    ck_assert_uint_lt(list->size, 256);
    UA_NodeId_copy(&node->head.nodeId, &list->ids[list->size++]);
}

static UA_Boolean
listContains(const NodeList *list, UA_UInt32 numericId) {
    UA_NodeId id = UA_NODEID_NUMERIC(0, numericId);
    for(size_t i = 0; i < list->size; i++) {
        if(UA_NodeId_equal(&list->ids[i], &id))
            return true;
    }
    return false;
}

/* Every Method of Namespace Zero with a callback is either public or denies
 * Call to a Session without granted Roles. A new Method binding must be added
 * to the allowlist above, with a reason, or be protected. */
START_TEST(ns0Methods_publicOrRestricted) {
    NodeList list;
    memset(&list, 0, sizeof(list));
    lockServer(server);
    server->config.nodestore->iterate(server->config.nodestore,
                                      collectCallableMethods, &list);
    unlockServer(server);

    /* The walk saw the bindings of the RoleSet, UserManagement, PubSub and
     * the Server Object */
    ck_assert(listContains(&list, UA_NS0ID_SERVER_GETMONITOREDITEMS));
    ck_assert(listContains(&list, UA_NS0ID_SERVER_SERVERCAPABILITIES_ROLESET_ADDROLE));
    ck_assert(listContains(&list, UA_NS0ID_USERMANAGEMENT_ADDUSER));
#ifdef UA_ENABLE_PUBSUB_INFORMATIONMODEL
    ck_assert(listContains(&list, UA_NS0ID_PUBLISHSUBSCRIBE_ADDCONNECTION));
#endif
#ifdef UA_ENABLE_PUBSUB_SKS
    ck_assert(listContains(&list, UA_NS0ID_PUBLISHSUBSCRIBE_GETSECURITYKEYS));
#endif
#ifdef TEST_ALARMS_CONDITIONS
    ck_assert(listContains(&list, UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE_ACKNOWLEDGE));
#endif

    UA_Session *session = createPublicSession();
    for(size_t i = 0; i < list.size; i++) {
        UA_PermissionType perms = effective(session, list.ids[i]);
        if(isPublicMethod(&list.ids[i]))
            ck_assert_msg((perms & C) != 0, "Public Method %u is not callable",
                          (unsigned)list.ids[i].identifier.numeric);
        else
            ck_assert_msg((perms & C) == 0,
                          "Method i=%u is callable without a granted Role",
                          (unsigned)list.ids[i].identifier.numeric);
        UA_NodeId_clear(&list.ids[i]);
    }
}
END_TEST

#ifdef UA_ENABLE_PUBSUB_INFORMATIONMODEL
/* Only ConfigureAdmin changes the PubSub configuration */
START_TEST(pubSubConfigurationMethods_configureAdminOnly) {
    const UA_UInt32 methods[] = {
        UA_NS0ID_PUBLISHSUBSCRIBE_ADDCONNECTION,
        UA_NS0ID_PUBLISHSUBSCRIBE_REMOVECONNECTION,
        UA_NS0ID_PUBSUBCONNECTIONTYPE_ADDWRITERGROUP,
        UA_NS0ID_WRITERGROUPTYPE_ADDDATASETWRITER,
        UA_NS0ID_DATASETFOLDERTYPE_ADDPUBLISHEDDATAITEMS,
        UA_NS0ID_PUBSUBSTATUSTYPE_ENABLE,
        UA_NS0ID_PUBSUBSTATUSTYPE_DISABLE
    };
    UA_Session *pub = createPublicSession();
    UA_Session *op = createSessionWithRole(ROLE(OPERATOR));
    UA_Session *eng = createSessionWithRole(ROLE(ENGINEER));
    UA_Session *cfg = createSessionWithRole(ROLE(CONFIGUREADMIN));
    UA_Session *sec = createSessionWithRole(ROLE(SECURITYADMIN));
    for(size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        UA_NodeId m = UA_NODEID_NUMERIC(0, methods[i]);
        ck_assert_uint_eq(effective(pub, m), B | R);
        ck_assert_uint_eq(effective(op, m), B | R);
        ck_assert_uint_eq(effective(eng, m), B | R);
        ck_assert_uint_eq(effective(cfg, m), B | R | C);
        ck_assert_uint_eq(effective(sec, m), B | R | RRP);
    }

    /* The Call service denies the Method, the configuration is unchanged */
    const UA_NodeId ps = UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE);
    const UA_NodeId addConnection =
        UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE_ADDCONNECTION);
    ck_assert_uint_eq(callAs(pub, ps, addConnection), UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert_uint_eq(callAs(op, ps, addConnection), UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert_uint_ne(callAs(cfg, ps, addConnection), UA_STATUSCODE_BADUSERACCESSDENIED);
}
END_TEST
#endif

/* Without PubSub the PublishSubscribe Object and its Methods are removed */
#if defined(UA_NS0ID_WELLKNOWNROLE_SECURITYKEYSERVERADMIN) && defined(UA_ENABLE_PUBSUB)
#define TEST_SKS_METHODS
#endif

#ifdef TEST_SKS_METHODS
/* The Security Key Service Methods follow the SKS Roles of Part 14 §8.8 */
START_TEST(securityKeyServiceMethods_sksRoles) {
    const UA_NodeId getKeys = UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE_GETSECURITYKEYS);
    const UA_NodeId getGroup = UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE_GETSECURITYGROUP);
    const UA_NodeId setKeys = UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE_SETSECURITYKEYS);
    const UA_NodeId invalidate = UA_NODEID_NUMERIC(0, UA_NS0ID_SECURITYGROUPTYPE_INVALIDATEKEYS);
    const UA_NodeId rotate = UA_NODEID_NUMERIC(0, UA_NS0ID_SECURITYGROUPTYPE_FORCEKEYROTATION);

    UA_Session *pub = createPublicSession();
    UA_Session *cfg = createSessionWithRole(ROLE(CONFIGUREADMIN));
    UA_Session *access = createSessionWithRole(ROLE(SECURITYKEYSERVERACCESS));
    UA_Session *push = createSessionWithRole(ROLE(SECURITYKEYSERVERPUSH));
    UA_Session *admin = createSessionWithRole(ROLE(SECURITYKEYSERVERADMIN));

    const UA_NodeId all[] = {getKeys, getGroup, setKeys, invalidate, rotate};
    for(size_t i = 0; i < 5; i++) {
        ck_assert_uint_eq(effective(pub, all[i]) & C, 0);
        ck_assert_uint_eq(effective(cfg, all[i]) & C, 0);
    }

    ck_assert_uint_ne(effective(access, getKeys) & C, 0);
    ck_assert_uint_ne(effective(access, getGroup) & C, 0);
    ck_assert_uint_eq(effective(access, setKeys) & C, 0);
    ck_assert_uint_eq(effective(access, invalidate) & C, 0);

    ck_assert_uint_ne(effective(push, setKeys) & C, 0);
    ck_assert_uint_eq(effective(push, getKeys) & C, 0);
    ck_assert_uint_eq(effective(push, rotate) & C, 0);

    ck_assert_uint_ne(effective(admin, getKeys) & C, 0);
    ck_assert_uint_ne(effective(admin, getGroup) & C, 0);
    ck_assert_uint_ne(effective(admin, invalidate) & C, 0);
    ck_assert_uint_ne(effective(admin, rotate) & C, 0);
    ck_assert_uint_eq(effective(admin, setKeys) & C, 0);
}
END_TEST
#endif

/* Acknowledging and disabling Alarms needs a Role that calls Methods */
START_TEST(conditionMethods_operatorRoles) {
    const UA_UInt32 methods[] = {
        UA_NS0ID_CONDITIONTYPE_ENABLE,
        UA_NS0ID_CONDITIONTYPE_DISABLE,
        UA_NS0ID_CONDITIONTYPE_ADDCOMMENT,
        UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE_ACKNOWLEDGE,
        UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE_CONFIRM
    };
    UA_Session *pub = createPublicSession();
    UA_Session *obs = createSessionWithRole(ROLE(OBSERVER));
    UA_Session *op = createSessionWithRole(ROLE(OPERATOR));
    UA_Session *eng = createSessionWithRole(ROLE(ENGINEER));
    UA_Session *sup = createSessionWithRole(ROLE(SUPERVISOR));
    for(size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        UA_NodeId m = UA_NODEID_NUMERIC(0, methods[i]);
        ck_assert_uint_eq(effective(pub, m), B | R);
        ck_assert_uint_eq(effective(obs, m), B | R);
        ck_assert_uint_eq(effective(op, m), B | R | C);
        ck_assert_uint_eq(effective(eng, m), B | R | C);
        ck_assert_uint_eq(effective(sup, m), B | R | C);
    }

    /* ConditionRefresh stays public */
    const UA_NodeId refresh =
        UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE_CONDITIONREFRESH);
    ck_assert_uint_ne(effective(pub, refresh) & C, 0);
}
END_TEST

#ifdef TEST_ALARMS_CONDITIONS
/* A Condition Method that is copied into the instance (copyMethodsOnInstances)
 * keeps the protection of its declaration */
START_TEST(conditionMethods_copiedKeepProtection) {
    UA_Server_getConfig(server)->copyMethodsOnInstances = true;
    UA_NodeId condition = UA_NODEID_NULL;
    ck_assert_uint_eq(acDriver->createCondition(
                          acDriver, UA_NODEID_NULL,
                          UA_NODEID_NUMERIC(0, UA_NS0ID_OFFNORMALALARMTYPE),
                          UA_QUALIFIEDNAME(0, "CopiedMethodsCondition"),
                          UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER),
                          UA_NODEID_NULL, &condition),
                      UA_STATUSCODE_GOOD);

    UA_QualifiedName ackName = UA_QUALIFIEDNAME(0, "Acknowledge");
    UA_BrowsePathResult bpr =
        UA_Server_browseSimplifiedBrowsePath(server, condition, 1, &ackName);
    ck_assert_uint_eq(bpr.statusCode, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(bpr.targetsSize, 1);
    UA_NodeId ack = bpr.targets[0].targetId.nodeId;
    const UA_NodeId declaration =
        UA_NODEID_NUMERIC(0, UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE_ACKNOWLEDGE);
    ck_assert(!UA_NodeId_equal(&ack, &declaration)); /* A copy */

    UA_Session *pub = createPublicSession();
    UA_Session *obs = createSessionWithRole(ROLE(OBSERVER));
    UA_Session *op = createSessionWithRole(ROLE(OPERATOR));
    ck_assert_uint_eq(effective(pub, ack), B | R);
    ck_assert_uint_eq(effective(obs, ack), B | R);
    ck_assert_uint_eq(effective(op, ack), B | R | C);
    ck_assert_uint_eq(callAs(pub, condition, ack), UA_STATUSCODE_BADUSERACCESSDENIED);

    /* Other copied children use the namespace default */
    UA_QualifiedName enabledName = UA_QUALIFIEDNAME(0, "EnabledState");
    UA_BrowsePathResult bpr2 =
        UA_Server_browseSimplifiedBrowsePath(server, condition, 1, &enabledName);
    ck_assert_uint_eq(bpr2.statusCode, UA_STATUSCODE_GOOD);
    size_t rpSize = 1;
    UA_RolePermission *rp = NULL;
    ck_assert_uint_eq(UA_Server_getNodeRolePermissions(
                          server, bpr2.targets[0].targetId.nodeId, &rpSize, &rp),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(rpSize, 0);

    UA_BrowsePathResult_clear(&bpr2);
    UA_BrowsePathResult_clear(&bpr);
    UA_NodeId_clear(&condition);
}
END_TEST

/* The copied Method keeps the protection and the AccessRestrictions of its
 * declaration. Both are held in one shared entry. */
START_TEST(conditionMethods_copiedKeepAccessRestrictions) {
    UA_Server_getConfig(server)->copyMethodsOnInstances = true;
    const UA_NodeId declaration =
        UA_NODEID_NUMERIC(0, UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE_ACKNOWLEDGE);
    const UA_AccessRestrictionType sign = UA_ACCESSRESTRICTIONTYPE_SIGNINGREQUIRED;
    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, declaration, sign),
                      UA_STATUSCODE_GOOD);

    UA_NodeId condition = UA_NODEID_NULL;
    ck_assert_uint_eq(acDriver->createCondition(
                          acDriver, UA_NODEID_NULL,
                          UA_NODEID_NUMERIC(0, UA_NS0ID_OFFNORMALALARMTYPE),
                          UA_QUALIFIEDNAME(0, "CopiedArMethodsCondition"),
                          UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER),
                          UA_NODEID_NULL, &condition),
                      UA_STATUSCODE_GOOD);
    UA_QualifiedName ackName = UA_QUALIFIEDNAME(0, "Acknowledge");
    UA_BrowsePathResult bpr =
        UA_Server_browseSimplifiedBrowsePath(server, condition, 1, &ackName);
    ck_assert_uint_eq(bpr.statusCode, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(bpr.targetsSize, 1);
    UA_NodeId ack = bpr.targets[0].targetId.nodeId;
    ck_assert(!UA_NodeId_equal(&ack, &declaration)); /* A copy */

    /* The protection is kept */
    UA_Session *pub = createPublicSession();
    UA_Session *op = createSessionWithRole(ROLE(OPERATOR));
    ck_assert_uint_eq(effective(pub, ack), B | R);
    ck_assert_uint_eq(effective(op, ack), B | R | C);

    /* The AccessRestrictions are kept */
    UA_AccessRestrictionType ar = 0;
    ck_assert_uint_eq(UA_Server_readAccessRestrictions(server, ack, &ar),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(ar, sign);

    /* Same content as the declaration: the same shared entry */
    UA_PermissionIndex declIndex = UA_PERMISSION_INDEX_INVALID;
    UA_PermissionIndex ackIndex = UA_PERMISSION_INDEX_INVALID;
    ck_assert_uint_eq(UA_Server_getNodePermissionIndex(server, declaration,
                                                       &declIndex),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_getNodePermissionIndex(server, ack, &ackIndex),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_ne(declIndex, UA_PERMISSION_INDEX_INVALID);
    ck_assert_uint_eq(ackIndex, declIndex);

    UA_BrowsePathResult_clear(&bpr);
    UA_NodeId_clear(&condition);
}
END_TEST

/* Every Method copy that combines the protection with the AccessRestrictions
 * of its declaration references the shared entry of the declaration: the
 * refCount grows by one per copy and is back after the instances are
 * deleted */
START_TEST(conditionMethods_copiedProtectionRefCount) {
    UA_Server_getConfig(server)->copyMethodsOnInstances = true;
    const UA_NodeId declaration =
        UA_NODEID_NUMERIC(0, UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE_ACKNOWLEDGE);
    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(
                          server, declaration, UA_ACCESSRESTRICTIONTYPE_SIGNINGREQUIRED),
                      UA_STATUSCODE_GOOD);
    UA_PermissionIndex declIndex = permissionIndexOf(declaration);
    ck_assert(server->rolePermissions[declIndex].modelOnly);
    ck_assert(server->rolePermissions[declIndex].hasAccessRestrictions);
    const size_t base = refCountOf(declIndex);
    ck_assert_uint_ge(base, 1); /* The declaration itself */

    const UA_NodeId source = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER);
    UA_NodeId conditions[2];
    const char *names[2] = {"RefCountCondition1", "RefCountCondition2"};
    for(size_t i = 0; i < 2; i++) {
        ck_assert_uint_eq(acDriver->createCondition(
                              acDriver, UA_NODEID_NULL,
                              UA_NODEID_NUMERIC(0, UA_NS0ID_OFFNORMALALARMTYPE),
                              UA_QUALIFIEDNAME(0, (char*)(uintptr_t)names[i]),
                              source, UA_NODEID_NULL, &conditions[i]),
                          UA_STATUSCODE_GOOD);
        UA_QualifiedName ackName = UA_QUALIFIEDNAME(0, "Acknowledge");
        UA_BrowsePathResult bpr =
            UA_Server_browseSimplifiedBrowsePath(server, conditions[i], 1, &ackName);
        ck_assert_uint_eq(bpr.statusCode, UA_STATUSCODE_GOOD);
        ck_assert_uint_eq(bpr.targetsSize, 1);
        ck_assert(!UA_NodeId_equal(&bpr.targets[0].targetId.nodeId, &declaration));
        ck_assert_uint_eq(permissionIndexOf(bpr.targets[0].targetId.nodeId), declIndex);
        UA_BrowsePathResult_clear(&bpr);
        ck_assert_uint_eq(refCountOf(declIndex), base + i + 1);
    }

    for(size_t i = 0; i < 2; i++) {
        ck_assert_uint_eq(acDriver->deleteCondition(acDriver, conditions[i], source),
                          UA_STATUSCODE_GOOD);
        ck_assert_uint_eq(refCountOf(declIndex), base + 1 - i);
        UA_NodeId_clear(&conditions[i]);
    }
    ck_assert_uint_eq(permissionIndexOf(declaration), declIndex);
}
END_TEST
#endif

/* The audit trail is delivered to SecurityAdmin only. The audit EventTypes
 * stay browsable for everybody. */
START_TEST(auditEventTypes_securityAdminOnly) {
    const UA_UInt32 types[] = {
        UA_NS0ID_AUDITEVENTTYPE,
        UA_NS0ID_AUDITSECURITYEVENTTYPE,
        UA_NS0ID_AUDITACTIVATESESSIONEVENTTYPE,
        UA_NS0ID_AUDITWRITEUPDATEEVENTTYPE,
        UA_NS0ID_AUDITUPDATEMETHODEVENTTYPE,
        UA_NS0ID_AUDITCONDITIONACKNOWLEDGEEVENTTYPE,
#ifdef UA_NS0ID_ROLEMAPPINGRULECHANGEDAUDITEVENTTYPE
        UA_NS0ID_ROLEMAPPINGRULECHANGEDAUDITEVENTTYPE
#endif
    };
    UA_Session *pub = createPublicSession();
    UA_Session *obs = createSessionWithRole(ROLE(OBSERVER));
    UA_Session *cfg = createSessionWithRole(ROLE(CONFIGUREADMIN));
    UA_Session *sec = createSessionWithRole(ROLE(SECURITYADMIN));
    for(size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        UA_NodeId t = UA_NODEID_NUMERIC(0, types[i]);
        ck_assert_uint_eq(effective(pub, t), B | R);
        ck_assert_uint_eq(effective(obs, t), B | R);
        ck_assert_uint_eq(effective(cfg, t), B | R);
        ck_assert_uint_eq(effective(sec, t), B | R | RE | RRP);
    }

    /* Other EventTypes keep the NS0 template */
    const UA_NodeId baseEventType = UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE);
    ck_assert_uint_ne(effective(pub, baseEventType) & RE, 0);
    const UA_NodeId alarmType = UA_NODEID_NUMERIC(0, UA_NS0ID_ALARMCONDITIONTYPE);
    ck_assert_uint_ne(effective(obs, alarmType) & RE, 0);
}
END_TEST

/* Browse the hierarchical forward References of a Node through the Browse
 * Service */
static UA_BrowseResult
browseAs(UA_Session *session, const UA_NodeId nodeId) {
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = nodeId;
    bd.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HIERARCHICALREFERENCES);
    bd.includeSubtypes = true;
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.resultMask = UA_BROWSERESULTMASK_BROWSENAME;
    UA_BrowseRequest request;
    UA_BrowseRequest_init(&request);
    request.nodesToBrowse = &bd;
    request.nodesToBrowseSize = 1;
    UA_BrowseResponse response;
    UA_BrowseResponse_init(&response);
    lockServer(server);
    Service_Browse(server, session, &request, &response);
    unlockServer(server);
    ck_assert_uint_eq(response.responseHeader.serviceResult, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(response.resultsSize, 1);
    UA_BrowseResult result = response.results[0];
    UA_BrowseResult_init(&response.results[0]);
    UA_BrowseResponse_clear(&response);
    return result;
}

static UA_Boolean
browseResultContains(const UA_BrowseResult *br, const UA_NodeId nodeId) {
    for(size_t i = 0; i < br->referencesSize; i++) {
        if(UA_NodeId_equal(&br->references[i].nodeId.nodeId, &nodeId))
            return true;
    }
    return false;
}

static UA_Boolean
browseResultContainsName(const UA_BrowseResult *br, const char *name) {
    UA_String n = UA_STRING((char*)(uintptr_t)name);
    for(size_t i = 0; i < br->referencesSize; i++) {
        if(UA_String_equal(&br->references[i].browseName.name, &n))
            return true;
    }
    return false;
}

static UA_AccessRestrictionType
accessRestrictions(const UA_NodeId nodeId) {
    UA_AccessRestrictionType ar = 0xFFFF;
    ck_assert_uint_eq(UA_Server_getNodeAccessRestrictions(server, nodeId, &ar),
                      UA_STATUSCODE_GOOD);
    return ar;
}

/* The RoleSet and the Role Objects are browsable by every Session over any
 * channel, like in the standard NodeSet. Only the Properties and Methods of
 * the RoleType are restricted to administrators over an encrypted channel
 * (Part 18 §4.4.1). */
START_TEST(roleSet_browsableWithoutEncryption) {
    const UA_NodeId roleSet =
        UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERCAPABILITIES_ROLESET);
    const UA_NodeId observer = ROLE(OBSERVER);

    UA_Role role;
    UA_Role_init(&role);
    role.roleName = UA_QUALIFIEDNAME(1, "BrowsableRole");
    UA_NodeId runtimeRole = UA_NODEID_NULL;
    ck_assert_uint_eq(UA_Server_addRole(server, &role, &runtimeRole),
                      UA_STATUSCODE_GOOD);

    ck_assert_uint_eq(accessRestrictions(roleSet), UA_ACCESSRESTRICTIONTYPE_NONE);
    ck_assert_uint_eq(accessRestrictions(observer), UA_ACCESSRESTRICTIONTYPE_NONE);
    ck_assert_uint_eq(accessRestrictions(runtimeRole), UA_ACCESSRESTRICTIONTYPE_NONE);
    ck_assert_uint_ne(accessRestrictions(UA_NODEID_NUMERIC(
                          0, UA_NS0ID_WELLKNOWNROLE_OBSERVER_IDENTITIES)) &
                      UA_ACCESSRESTRICTIONTYPE_ENCRYPTIONREQUIRED, 0);
    ck_assert_uint_ne(accessRestrictions(UA_NODEID_NUMERIC(
                          0, UA_NS0ID_SERVER_SERVERCAPABILITIES_ROLESET_ADDROLE)) &
                      UA_ACCESSRESTRICTIONTYPE_ENCRYPTIONREQUIRED, 0);

    /* An Anonymous Session without a SecureChannel */
    const UA_NodeId anonymousOnly[1] = {ROLE(ANONYMOUS)};
    UA_Session *anon = createSessionWithRoles(1, anonymousOnly);
    ck_assert_uint_eq(effective(anon, roleSet), B);
    ck_assert_uint_eq(effective(anon, observer), B);
    ck_assert_uint_eq(effective(anon, runtimeRole), B);

    UA_BrowseResult br = browseAs(anon, UA_NODEID_NUMERIC(
                                      0, UA_NS0ID_SERVER_SERVERCAPABILITIES));
    ck_assert(browseResultContains(&br, roleSet));
    UA_BrowseResult_clear(&br);

    /* The Role Objects are visible, the RoleSet Methods are not */
    br = browseAs(anon, roleSet);
    ck_assert(browseResultContains(&br, observer));
    ck_assert(browseResultContains(&br, runtimeRole));
    ck_assert(!browseResultContainsName(&br, "AddRole"));
    ck_assert(!browseResultContainsName(&br, "RemoveRole"));
    UA_BrowseResult_clear(&br);

    /* The Properties and Methods of a Role stay hidden */
    br = browseAs(anon, observer);
    ck_assert(!browseResultContainsName(&br, "Identities"));
    ck_assert(!browseResultContainsName(&br, "AddIdentity"));
    UA_BrowseResult_clear(&br);
    br = browseAs(anon, runtimeRole);
    ck_assert(!browseResultContainsName(&br, "Identities"));
    ck_assert(!browseResultContainsName(&br, "AddIdentity"));
    UA_BrowseResult_clear(&br);

    /* The non-Value Attributes of the Objects are readable */
    UA_DataValue dv = readAs(anon, observer, UA_ATTRIBUTEID_BROWSENAME);
    ck_assert(!dv.hasStatus || dv.status == UA_STATUSCODE_GOOD);
    ck_assert(dv.hasValue);
    UA_DataValue_clear(&dv);
    dv = readAs(anon, UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_OBSERVER_IDENTITIES),
                UA_ATTRIBUTEID_VALUE);
    ck_assert(dv.hasStatus && UA_StatusCode_isBad(dv.status));
    UA_DataValue_clear(&dv);

    /* SecurityAdmin calls the Methods and receives the audit events of the
     * Objects, but over an encrypted channel only */
    UA_Session *sec = createSessionWithRole(ROLE(SECURITYADMIN));
    ck_assert_uint_eq(effective(sec, roleSet), B | R | C | RE | RRP);
    ck_assert_uint_eq(effective(sec, observer), B | R | C | RE | RRP);
    br = browseAs(sec, observer);
    ck_assert(!browseResultContainsName(&br, "Identities"));
    UA_BrowseResult_clear(&br);

    ck_assert_uint_eq(UA_Server_removeRole(server, role.roleName),
                      UA_STATUSCODE_GOOD);
    UA_NodeId_clear(&runtimeRole);
}
END_TEST

/* The Methods of a Role Object */
static size_t
countRoleMethods(const UA_NodeId roleId) {
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = roleId;
    bd.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT);
    bd.includeSubtypes = true;
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.nodeClassMask = UA_NODECLASS_METHOD;
    UA_BrowseResult br = UA_Server_browse(server, 0, &bd);
    ck_assert_uint_eq(br.statusCode, UA_STATUSCODE_GOOD);
    size_t count = br.referencesSize;
    UA_BrowseResult_clear(&br);
    return count;
}

/* The mapping rules of Anonymous, AuthenticatedUser and TrustedApplication
 * cannot be changed (Part 18 §4.3), so the mapping Methods are not present
 * (§4.4.1), like in the standard NodeSet */
START_TEST(mandatoryRoles_haveNoMappingMethods) {
    ck_assert_uint_eq(countRoleMethods(ROLE(ANONYMOUS)), 0);
    ck_assert_uint_eq(countRoleMethods(ROLE(AUTHENTICATEDUSER)), 0);
    ck_assert_uint_eq(countRoleMethods(ROLE(TRUSTEDAPPLICATION)), 0);
    ck_assert_uint_eq(countRoleMethods(ROLE(OBSERVER)), 6);
    ck_assert_uint_eq(countRoleMethods(ROLE(SECURITYADMIN)), 6);

    /* The RoleType Method cannot be called on these Role Objects */
    UA_IdentityMappingRuleType rule;
    UA_IdentityMappingRuleType_init(&rule);
    rule.criteriaType = UA_IDENTITYCRITERIATYPE_USERNAME;
    rule.criteria = UA_STRING("mallory");
    UA_ExtensionObject ext;
    UA_ExtensionObject_setValue(&ext, &rule,
                                &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE]);
    UA_Variant input;
    UA_Variant_setScalar(&input, &ext, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = ROLE(ANONYMOUS);
    req.methodId = UA_NODEID_NUMERIC(0, UA_NS0ID_ROLETYPE_ADDIDENTITY);
    req.inputArguments = &input;
    req.inputArgumentsSize = 1;
    UA_CallMethodResult res = UA_Server_call(server, &req);
    ck_assert_uint_eq(res.statusCode, UA_STATUSCODE_BADMETHODINVALID);
    UA_CallMethodResult_clear(&res);

    /* Observer keeps its Methods */
    req.objectId = ROLE(OBSERVER);
    res = UA_Server_call(server, &req);
    ck_assert_uint_eq(res.statusCode, UA_STATUSCODE_GOOD);
    UA_CallMethodResult_clear(&res);
}
END_TEST

/* The Applications and Endpoints Properties of the NS0 Role Objects report the
 * configuration of the role registry */
START_TEST(ns0RoleProperties_backedByRegistry) {
    const UA_NodeId applicationsId =
        UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_OPERATOR_APPLICATIONS);
    const UA_NodeId endpointsId =
        UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_OPERATOR_ENDPOINTS);

    UA_Variant v;
    ck_assert_uint_eq(UA_Server_readValue(server, applicationsId, &v),
                      UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_STRING]));
    ck_assert_uint_eq(v.arrayLength, 0);
    UA_Variant_clear(&v);

    UA_Role role;
    ck_assert_uint_eq(UA_Server_getRoleById(server, ROLE(OPERATOR), &role),
                      UA_STATUSCODE_GOOD);
    UA_String app = UA_STRING("urn:test:operator-app");
    ck_assert_uint_eq(UA_Array_appendCopy((void**)&role.applications,
                                          &role.applicationsSize, &app,
                                          &UA_TYPES[UA_TYPES_STRING]),
                      UA_STATUSCODE_GOOD);
    UA_EndpointType ep;
    UA_EndpointType_init(&ep);
    ep.endpointUrl = UA_STRING("opc.tcp://localhost:4852");
    ep.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    ck_assert_uint_eq(UA_Array_appendCopy((void**)&role.endpoints,
                                          &role.endpointsSize, &ep,
                                          &UA_TYPES[UA_TYPES_ENDPOINTTYPE]),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_updateRole(server, &role), UA_STATUSCODE_GOOD);
    UA_Role_clear(&role);

    ck_assert_uint_eq(UA_Server_readValue(server, applicationsId, &v),
                      UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_STRING]));
    ck_assert_uint_eq(v.arrayLength, 1);
    ck_assert(UA_String_equal((UA_String*)v.data, &app));
    UA_Variant_clear(&v);

    ck_assert_uint_eq(UA_Server_readValue(server, endpointsId, &v),
                      UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_ENDPOINTTYPE]));
    ck_assert_uint_eq(v.arrayLength, 1);
    ck_assert(UA_EndpointType_equal((UA_EndpointType*)v.data, &ep));
    UA_Variant_clear(&v);
}
END_TEST

/* The RolePermissions Attribute reports the protection to SecurityAdmin */
START_TEST(protection_reportedAsOverride) {
    UA_Session *sec = createSessionWithRole(ROLE(SECURITYADMIN));
    UA_DataValue dv = readAs(sec, UA_NODEID_NUMERIC(0, UA_NS0ID_AUDITEVENTTYPE),
                             UA_ATTRIBUTEID_ROLEPERMISSIONS);
    ck_assert(!dv.hasStatus || dv.status == UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasArrayType(&dv.value, &UA_TYPES[UA_TYPES_ROLEPERMISSIONTYPE]));
    ck_assert_uint_eq(dv.value.arrayLength, 2);
    UA_DataValue_clear(&dv);

    size_t size = 0;
    UA_RolePermission *rp = NULL;
    ck_assert_uint_eq(UA_Server_getNodeRolePermissions(
                          server, UA_NODEID_NUMERIC(0, UA_NS0ID_AUDITEVENTTYPE),
                          &size, &rp), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(size, 2);
    for(size_t i = 0; i < size; i++)
        UA_NodeId_clear(&rp[i].roleId);
    UA_free(rp);
}
END_TEST

/* A Node that already has AccessRestrictions (its shared entry holds no
 * RolePermissions) gets the protection and keeps the AccessRestrictions */
START_TEST(protection_keepsAccessRestrictions) {
    const UA_AccessRestrictionType ar = UA_ACCESSRESTRICTIONTYPE_SESSIONREQUIRED;
    UA_NodeId nodeId = addVariableWithAccessRestrictions("ProtectedWithAr", ar);
    UA_PermissionIndex arIndex = permissionIndexOf(nodeId);
    ck_assert_uint_ne(arIndex, UA_PERMISSION_INDEX_INVALID);
    ck_assert(!server->rolePermissions[arIndex].hasRolePermissions);

    const UA_RolePermission protection[1] = {{ROLE(OPERATOR), B | R}};
    ck_assert_uint_eq(protect(nodeId, 1, protection), UA_STATUSCODE_GOOD);
    UA_PermissionIndex index = permissionIndexOf(nodeId);
    ck_assert_uint_ne(index, arIndex);
    const UA_RolePermissionEntry *e = &server->rolePermissions[index];
    ck_assert(e->hasRolePermissions);
    ck_assert(e->modelOnly);
    ck_assert_uint_eq(e->rolePermissionsSize, 1);
    ck_assert(e->hasAccessRestrictions);
    ck_assert_uint_eq(e->accessRestrictions, ar);

    /* Enforced, and the AccessRestrictions are still reported */
    UA_Session *pub = createPublicSession();
    UA_Session *op = createSessionWithRole(ROLE(OPERATOR));
    ck_assert_uint_eq(effective(pub, nodeId), 0);
    ck_assert_uint_eq(effective(op, nodeId), B | R);
    UA_AccessRestrictionType out = UA_ACCESSRESTRICTIONTYPE_NONE;
    ck_assert_uint_eq(UA_Server_readAccessRestrictions(server, nodeId, &out),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(out, ar);

    /* The protection is now configured and is not replaced */
    const UA_RolePermission other[1] = {{ROLE(OBSERVER), B}};
    ck_assert_uint_eq(protect(nodeId, 1, other), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(permissionIndexOf(nodeId), index);
    UA_NodeId_clear(&nodeId);
}
END_TEST

/* Removing the only Role of a protection of a Node with AccessRestrictions
 * purges the shared entry in place. Like every RolePermission override it
 * keeps the deny entry {Anonymous, 0}, which grants nothing. The entry stays a
 * protection and keeps the AccessRestrictions. */
START_TEST(protection_removeRoleKeepsAccessRestrictions) {
    UA_Role role;
    UA_Role_init(&role);
    role.roleId = UA_NODEID_NUMERIC(1, 9100);
    role.roleName = UA_QUALIFIEDNAME(1, "PurgedProtectionRole");
    UA_NodeId roleId = UA_NODEID_NULL;
    ck_assert_uint_eq(UA_Server_addRole(server, &role, &roleId), UA_STATUSCODE_GOOD);

    const UA_AccessRestrictionType ar = UA_ACCESSRESTRICTIONTYPE_SESSIONREQUIRED;
    UA_NodeId nodeId = addVariableWithAccessRestrictions("PurgedProtection", ar);
    const UA_RolePermission protection[1] = {{roleId, B | R | W}};
    ck_assert_uint_eq(protect(nodeId, 1, protection), UA_STATUSCODE_GOOD);
    UA_PermissionIndex index = permissionIndexOf(nodeId);
    ck_assert(server->rolePermissions[index].modelOnly);

    ck_assert_uint_eq(UA_Server_removeRole(server, role.roleName), UA_STATUSCODE_GOOD);

    /* Edited in place */
    ck_assert_uint_eq(permissionIndexOf(nodeId), index);
    const UA_RolePermissionEntry *e = &server->rolePermissions[index];
    ck_assert(e->hasRolePermissions);
    ck_assert(e->modelOnly);
    ck_assert_uint_eq(e->rolePermissionsSize, 1);
    const UA_NodeId anonymous = ROLE(ANONYMOUS);
    ck_assert(UA_NodeId_equal(&e->rolePermissions[0].roleId, &anonymous));
    ck_assert_uint_eq(e->rolePermissions[0].permissions, 0);
    ck_assert(e->hasAccessRestrictions);
    ck_assert_uint_eq(e->accessRestrictions, ar);

    /* The override grants nothing; the namespace default does not apply */
    UA_Session *pub = createPublicSession();
    UA_Session *op = createSessionWithRole(ROLE(OPERATOR));
    ck_assert_uint_eq(effective(pub, nodeId), 0);
    ck_assert_uint_eq(effective(op, nodeId), 0);
    size_t rpSize = 0;
    UA_RolePermission *rp = NULL;
    ck_assert_uint_eq(UA_Server_getNodeRolePermissions(server, nodeId, &rpSize, &rp),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(rpSize, 1);
    ck_assert(UA_NodeId_equal(&rp[0].roleId, &anonymous));
    ck_assert_uint_eq(rp[0].permissions, 0);
    UA_NodeId_clear(&rp[0].roleId);
    UA_free(rp);
    UA_AccessRestrictionType out = UA_ACCESSRESTRICTIONTYPE_NONE;
    ck_assert_uint_eq(UA_Server_readAccessRestrictions(server, nodeId, &out),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(out, ar);

    UA_NodeId_clear(&nodeId);
    UA_NodeId_clear(&roleId);
}
END_TEST

/* Only ConfigureAdmin writes the non-security configuration in Namespace
 * Zero through the NS0 template (Part 3 Table 2) */
START_TEST(ns0Variables_configureAdminWrites) {
    UA_Session *op = createSessionWithRole(ROLE(OPERATOR));
    UA_Session *cfg = createSessionWithRole(ROLE(CONFIGUREADMIN));
    UA_Session *sec = createSessionWithRole(ROLE(SECURITYADMIN));
    UA_Session *sessions[] = {op, cfg, sec};

    UA_Boolean enabled = true;
    UA_Variant flag;
    UA_Variant_setScalar(&flag, &enabled, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_String uri = UA_STRING("http://opcfoundation.org/UA/");
    UA_Variant namespaces;
    UA_Variant_setArray(&namespaces, &uri, 1, &UA_TYPES[UA_TYPES_STRING]);
    UA_DateTime now = UA_DateTime_now();
    UA_Variant time;
    UA_Variant_setScalar(&time, &now, &UA_TYPES[UA_TYPES_DATETIME]);

    /* The Server keeps the flag read-only, an application may open it */
    const UA_NodeId enabledFlag =
        UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERDIAGNOSTICS_ENABLEDFLAG);
    ck_assert_uint_eq(UA_Server_writeAccessLevel(server, enabledFlag,
                                                 UA_ACCESSLEVELMASK_READ |
                                                 UA_ACCESSLEVELMASK_WRITE),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(writeAs(op, enabledFlag, &flag),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert_uint_eq(writeAs(sec, enabledFlag, &flag),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert_uint_eq(writeAs(cfg, enabledFlag, &flag), UA_STATUSCODE_GOOD);

    /* Not writable for anybody */
    for(size_t i = 0; i < 3; i++) {
        ck_assert_uint_ne(writeAs(sessions[i],
            UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_NAMESPACEARRAY), &namespaces),
            UA_STATUSCODE_GOOD);
        ck_assert_uint_ne(writeAs(sessions[i],
            UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_ESTIMATEDRETURNTIME), &time),
            UA_STATUSCODE_GOOD);
    }

    /* The Role configuration is security configuration */
    ck_assert_uint_eq(writeAs(cfg,
        UA_NODEID_NUMERIC(0, UA_NS0ID_ROLETYPE_APPLICATIONSEXCLUDE), &flag),
        UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert_uint_eq(writeAs(cfg,
        UA_NODEID_NUMERIC(0, UA_NS0ID_ROLETYPE_ENDPOINTSEXCLUDE), &flag),
        UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert_uint_ne(writeAs(cfg,
        UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_OPERATOR_APPLICATIONSEXCLUDE),
        &flag), UA_STATUSCODE_GOOD);
}
END_TEST

/* The writable Nodes of Namespace Zero that are not security configuration */
static const UA_UInt32 nonSecurityConfiguration[] = {
    UA_NS0ID_SERVER_SERVERDIAGNOSTICS_ENABLEDFLAG,
    UA_NS0ID_SERVERTYPE_SERVERDIAGNOSTICS_ENABLEDFLAG,
    UA_NS0ID_SERVERDIAGNOSTICSTYPE_ENABLEDFLAG
};

static void
collectWritableNodes(void *visitorCtx, const UA_Node *node) {
    NodeList *list = (NodeList*)visitorCtx;
    if(node->head.nodeId.namespaceIndex != 0)
        return;
    if(node->head.writeMask == 0 &&
       (node->head.nodeClass != UA_NODECLASS_VARIABLE ||
        !(node->variableNode.accessLevel & UA_ACCESSLEVELMASK_WRITE)))
        return;
    ck_assert_uint_lt(list->size, 256);
    UA_NodeId_copy(&node->head.nodeId, &list->ids[list->size++]);
}

/* Every writable Node of Namespace Zero is either non-security configuration
 * or denies Write and WriteAttribute to ConfigureAdmin. A new writable Node
 * must be added to the list above or be protected. */
START_TEST(ns0WritableNodes_nonSecurityOnly) {
    NodeList list;
    memset(&list, 0, sizeof(list));
    lockServer(server);
    server->config.nodestore->iterate(server->config.nodestore,
                                      collectWritableNodes, &list);
    unlockServer(server);
    ck_assert(listContains(&list, UA_NS0ID_SERVERDIAGNOSTICSTYPE_ENABLEDFLAG));
    ck_assert(listContains(&list, UA_NS0ID_ROLETYPE_APPLICATIONSEXCLUDE));
    ck_assert(listContains(&list, UA_NS0ID_WELLKNOWNROLE_OPERATOR_APPLICATIONSEXCLUDE));

    UA_Session *cfg = createSessionWithRole(ROLE(CONFIGUREADMIN));
    for(size_t i = 0; i < list.size; i++) {
        UA_Boolean allowed = false;
        for(size_t j = 0; j < sizeof(nonSecurityConfiguration) /
                sizeof(nonSecurityConfiguration[0]); j++) {
            if(list.ids[i].identifierType == UA_NODEIDTYPE_NUMERIC &&
               list.ids[i].identifier.numeric == nonSecurityConfiguration[j])
                allowed = true;
        }
        UA_PermissionType p = effective(cfg, list.ids[i]);
        if(!allowed && (p & (W | WA)) != 0) {
            UA_String idStr = UA_STRING_NULL;
            UA_NodeId_print(&list.ids[i], &idStr);
            ck_abort_msg("ConfigureAdmin may write %.*s",
                         (int)idStr.length, (const char*)idStr.data);
        }
        UA_NodeId_clear(&list.ids[i]);
    }
}
END_TEST

#ifdef UA_ENABLE_DIAGNOSTICS
static size_t
readSecurityDiagnostics(UA_Session *reader, UA_Boolean *containsOwn) {
    UA_DataValue dv = readAs(reader,
        UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SESSIONSDIAGNOSTICSSUMMARY_SESSIONSECURITYDIAGNOSTICSARRAY),
        UA_ATTRIBUTEID_VALUE);
    ck_assert(!dv.hasStatus || dv.status == UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasArrayType(&dv.value,
                                      &UA_TYPES[UA_TYPES_SESSIONSECURITYDIAGNOSTICSDATATYPE]));
    UA_SessionSecurityDiagnosticsDataType *sd =
        (UA_SessionSecurityDiagnosticsDataType*)dv.value.data;
    size_t size = dv.value.arrayLength;
    *containsOwn = false;
    for(size_t i = 0; i < size; i++) {
        if(UA_NodeId_equal(&sd[i].sessionId, &reader->sessionId))
            *containsOwn = true;
    }
    UA_DataValue_clear(&dv);
    return size;
}

/* A Session sees its own security diagnostics; those of other Sessions only
 * with the SecurityAdmin Role (Part 5 §6.3.4) */
START_TEST(sessionSecurityDiagnostics_ownSessionOnly) {
    UA_Session *pub = createPublicSession();
    UA_Session *op = createSessionWithRole(ROLE(OPERATOR));
    UA_Session *sec = createSessionWithRole(ROLE(SECURITYADMIN));
    UA_Boolean own = false;
    ck_assert_uint_eq(readSecurityDiagnostics(pub, &own), 1);
    ck_assert(own);
    ck_assert_uint_eq(readSecurityDiagnostics(op, &own), 1);
    ck_assert(own);
    ck_assert_uint_eq(readSecurityDiagnostics(sec, &own), 3);
    ck_assert(own);
    UA_Variant v;
    ck_assert_uint_eq(UA_Server_readValue(server,
        UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SESSIONSDIAGNOSTICSSUMMARY_SESSIONSECURITYDIAGNOSTICSARRAY),
        &v), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(v.arrayLength, 3);
    UA_Variant_clear(&v);
}
END_TEST

#ifdef UA_ENABLE_SUBSCRIPTIONS
/* The Server builds the diagnostics Variable of a Subscription. The Session
 * that creates the Subscription needs no permission in Namespace Zero. */
START_TEST(subscriptionDiagnostics_builtForPublicSession) {
    UA_Session *pub = createPublicSession();
    lockServer(server);
    UA_String_clear(&pub->sessionName);
    pub->sessionName = UA_STRING_ALLOC("PublicSession");
    createSessionObject(server, pub);
    unlockServer(server);

    UA_CreateSubscriptionRequest request;
    UA_CreateSubscriptionRequest_init(&request);
    request.publishingEnabled = true;
    UA_CreateSubscriptionResponse response;
    UA_CreateSubscriptionResponse_init(&response);
    lockServer(server);
    Service_CreateSubscription(server, pub, &request, &response);
    unlockServer(server);
    ck_assert_uint_eq(response.responseHeader.serviceResult, UA_STATUSCODE_GOOD);
    UA_UInt32 subId = response.subscriptionId;
    UA_CreateSubscriptionResponse_clear(&response);

    /* Referenced from the SubscriptionDiagnosticsArray of the Server */
    char subIdStr[32];
    snprintf(subIdStr, sizeof(subIdStr), "%u", (unsigned)subId);
    UA_QualifiedName bn = UA_QUALIFIEDNAME(0, subIdStr);
    UA_BrowsePathResult bpr = UA_Server_browseSimplifiedBrowsePath(server,
        UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SUBSCRIPTIONDIAGNOSTICSARRAY),
        1, &bn);
    ck_assert_uint_eq(bpr.statusCode, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(bpr.targetsSize, 1);

    /* The Variable reports the live diagnostics of the Subscription */
    UA_Variant v;
    ck_assert_uint_eq(UA_Server_readValue(server, bpr.targets[0].targetId.nodeId, &v),
                      UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasScalarType(&v,
                  &UA_TYPES[UA_TYPES_SUBSCRIPTIONDIAGNOSTICSDATATYPE]));
    ck_assert_uint_eq(((UA_SubscriptionDiagnosticsDataType*)v.data)->subscriptionId,
                      subId);
    UA_Variant_clear(&v);
    UA_BrowsePathResult_clear(&bpr);
}
END_TEST
#endif

START_TEST(legacy_sessionSecurityDiagnosticsUnfiltered) {
    UA_Session *pub = createPublicSession();
    (void)createSessionWithRole(ROLE(OPERATOR));
    UA_Boolean own = false;
    ck_assert_uint_eq(readSecurityDiagnostics(pub, &own), 2);
    ck_assert(own);
}
END_TEST
#endif

/* Legacy mode: the protections are not enforced and not reported, like any
 * other Node without RolePermissions */
START_TEST(legacy_protectionsInactive) {
    UA_Session *pub = createPublicSession();
    const UA_NodeId audit = UA_NODEID_NUMERIC(0, UA_NS0ID_AUDITEVENTTYPE);
    const UA_NodeId ack =
        UA_NODEID_NUMERIC(0, UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE_ACKNOWLEDGE);
    ck_assert_uint_eq(effective(pub, audit), UA_PERMISSIONTYPE_ALL);
    ck_assert_uint_eq(effective(pub, ack), UA_PERMISSIONTYPE_ALL);

    UA_DataValue dv = readAs(pub, audit, UA_ATTRIBUTEID_ROLEPERMISSIONS);
    ck_assert(dv.hasStatus);
    ck_assert_uint_eq(dv.status, UA_STATUSCODE_BADATTRIBUTEIDINVALID);
    UA_DataValue_clear(&dv);

    size_t size = 1;
    UA_RolePermission *rp = NULL;
    ck_assert_uint_eq(UA_Server_getNodeRolePermissions(server, audit, &size, &rp),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(size, 0);
    ck_assert_ptr_eq(rp, NULL);

#ifdef UA_ENABLE_PUBSUB_INFORMATIONMODEL
    const UA_NodeId addConnection =
        UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE_ADDCONNECTION);
    ck_assert_uint_eq(effective(pub, addConnection), UA_PERMISSIONTYPE_ALL);
#endif

    /* An explicit default for Namespace Zero gives it a model, the
     * protections apply */
    const UA_RolePermission ns0Default = {ROLE(ANONYMOUS), B | R | C | RE};
    ck_assert_uint_eq(UA_Server_setNamespaceDefaultRolePermissions(server, 0, 1,
                                                                   &ns0Default),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(effective(pub, audit), B | R);
    ck_assert_uint_eq(effective(pub, ack), B | R);
    ck_assert_uint_eq(UA_Server_removeNamespaceDefaultRolePermissions(server, 0),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(effective(pub, ack), UA_PERMISSIONTYPE_ALL);
}
END_TEST

/* Extending a protection keeps it conditional. Setting the RolePermissions
 * replaces it with an ordinary override. */
START_TEST(legacy_extendedProtectionStaysConditional) {
    const UA_NodeId ack =
        UA_NODEID_NUMERIC(0, UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE_ACKNOWLEDGE);
    ck_assert_uint_eq(UA_Server_addRolePermissions(server, ack, ROLE(OBSERVER), C,
                                                   false, false),
                      UA_STATUSCODE_GOOD);
    UA_Session *pub = createPublicSession();
    UA_Session *obs = createSessionWithRole(ROLE(OBSERVER));
    ck_assert_uint_eq(effective(pub, ack), UA_PERMISSIONTYPE_ALL);

    /* Strict mode at runtime: the protection with the added grant */
    UA_Server_getConfig(server)->allPermissionsForAnonymous = false;
    ck_assert_uint_eq(effective(pub, ack), B | R);
    ck_assert_uint_eq(effective(obs, ack), B | R | C);

    /* An explicit override is enforced in legacy mode as well */
    UA_Server_getConfig(server)->allPermissionsForAnonymous = true;
    const UA_RolePermission entries[] = {{ROLE(ANONYMOUS), B}};
    ck_assert_uint_eq(UA_Server_setNodeRolePermissions(server, ack, 1, entries,
                                                       false, NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(effective(pub, ack), B);
}
END_TEST

static Suite *testSuite(void) {
    Suite *s = suite_create("RBAC Namespace Zero protection");

    TCase *tc_strict = tcase_create("Strict NS0 template");
    tcase_add_checked_fixture(tc_strict, setupStrict, teardown);
    tcase_add_test(tc_strict, ns0Methods_publicOrRestricted);
#ifdef UA_ENABLE_PUBSUB_INFORMATIONMODEL
    tcase_add_test(tc_strict, pubSubConfigurationMethods_configureAdminOnly);
#endif
#ifdef TEST_SKS_METHODS
    tcase_add_test(tc_strict, securityKeyServiceMethods_sksRoles);
#endif
    tcase_add_test(tc_strict, conditionMethods_operatorRoles);
#ifdef TEST_ALARMS_CONDITIONS
    tcase_add_test(tc_strict, conditionMethods_copiedKeepProtection);
    tcase_add_test(tc_strict, conditionMethods_copiedKeepAccessRestrictions);
    tcase_add_test(tc_strict, conditionMethods_copiedProtectionRefCount);
#endif
    tcase_add_test(tc_strict, auditEventTypes_securityAdminOnly);
    tcase_add_test(tc_strict, roleSet_browsableWithoutEncryption);
    tcase_add_test(tc_strict, mandatoryRoles_haveNoMappingMethods);
    tcase_add_test(tc_strict, ns0RoleProperties_backedByRegistry);
    tcase_add_test(tc_strict, protection_reportedAsOverride);
    tcase_add_test(tc_strict, protection_keepsAccessRestrictions);
    tcase_add_test(tc_strict, protection_removeRoleKeepsAccessRestrictions);
    tcase_add_test(tc_strict, ns0Variables_configureAdminWrites);
    tcase_add_test(tc_strict, ns0WritableNodes_nonSecurityOnly);
#ifdef UA_ENABLE_DIAGNOSTICS
    tcase_add_test(tc_strict, sessionSecurityDiagnostics_ownSessionOnly);
# ifdef UA_ENABLE_SUBSCRIPTIONS
    tcase_add_test(tc_strict, subscriptionDiagnostics_builtForPublicSession);
# endif
#endif
    suite_add_tcase(s, tc_strict);

    TCase *tc_legacy = tcase_create("Legacy mode");
    tcase_add_checked_fixture(tc_legacy, setupLegacy, teardown);
    tcase_add_test(tc_legacy, legacy_protectionsInactive);
    tcase_add_test(tc_legacy, legacy_extendedProtectionStaysConditional);
#ifdef UA_ENABLE_DIAGNOSTICS
    tcase_add_test(tc_legacy, legacy_sessionSecurityDiagnosticsUnfiltered);
#endif
    suite_add_tcase(s, tc_legacy);

    return s;
}

int main(void) {
    Suite *s = testSuite();
    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
