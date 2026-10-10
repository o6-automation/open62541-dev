/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

/* The UserManagement Object (Part 18 §5) with an in-memory provider. The
 * provider also checks the passwords at ActivateSession. */

#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/accesscontrol_default.h>
#include <open62541/plugin/log_stdout.h>

#include "test_helpers_rbac.h"

#include <check.h>
#include <stdlib.h>

#define SECURITYADMIN UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN)
#define ANONYMOUS UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS)
#define UM UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT)

typedef struct {
    UA_String name;
    UA_String password;
    UA_String description;
    UA_UserConfigurationMask configuration;
} User;

static User users[8];
static size_t usersSize;
static UA_PasswordOptionsMask options;
static UA_StatusCode forcedStatus;

static UA_Server *server;
static UA_SecureChannel plain;  /* SecurityMode None */
static UA_SecureChannel secure; /* SecurityMode SignAndEncrypt */

static User *
findUser(const UA_String *name) {
    for(size_t i = 0; i < usersSize; i++) {
        if(UA_String_equal(&users[i].name, name))
            return &users[i];
    }
    return NULL;
}

static UA_StatusCode
login(const UA_String *userName, const UA_ByteString *password, size_t size,
      const UA_UsernamePasswordLogin *logins, void **sessionContext,
      void *loginContext) {
    if(userName->length == 0)
        return UA_STATUSCODE_GOOD; /* Anonymous */
    User *u = findUser(userName);
    return (u && UA_String_equal(&u->password, password)) ?
        UA_STATUSCODE_GOOD : UA_STATUSCODE_BADUSERACCESSDENIED;
}

static UA_StatusCode
getUsers(UA_Server *s, UA_AccessControl *ac, UA_UserManagementDataType **out,
         size_t *outSize) {
    if(forcedStatus != UA_STATUSCODE_GOOD)
        return forcedStatus;
    *out = (UA_UserManagementDataType*)
        UA_Array_new(usersSize, &UA_TYPES[UA_TYPES_USERMANAGEMENTDATATYPE]);
    for(size_t i = 0; i < usersSize; i++) {
        UA_String_copy(&users[i].name, &(*out)[i].userName);
        (*out)[i].userConfiguration = users[i].configuration;
    }
    *outSize = usersSize;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
getPasswordPolicy(UA_Server *s, UA_AccessControl *ac, UA_Range *length,
                  UA_PasswordOptionsMask *outOptions, UA_LocalizedText *restrictions) {
    length->low = 8.0;
    length->high = 64.0;
    *outOptions = options;
    *restrictions = UA_LOCALIZEDTEXT_ALLOC("en-US", "at least eight characters");
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
getUserConfiguration(UA_Server *s, UA_AccessControl *ac, const UA_String *name,
                     UA_UserConfigurationMask *configuration) {
    User *u = findUser(name);
    if(!u)
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    *configuration = u->configuration;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
addUser(UA_Server *s, UA_AccessControl *ac, const UA_String *name,
        const UA_String *password, UA_UserConfigurationMask configuration,
        const UA_String *description) {
    if(findUser(name))
        return UA_STATUSCODE_BADALREADYEXISTS;
    User *u = &users[usersSize++];
    UA_String_copy(name, &u->name);
    UA_String_copy(password, &u->password);
    UA_String_copy(description, &u->description);
    u->configuration = configuration;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
modifyUser(UA_Server *s, UA_AccessControl *ac, const UA_String *name,
           UA_Boolean modifyPassword, const UA_String *password,
           UA_Boolean modifyConfiguration, UA_UserConfigurationMask configuration,
           UA_Boolean modifyDescription, const UA_String *description) {
    User *u = findUser(name);
    if(!u)
        return UA_STATUSCODE_BADNOTFOUND;
    if(modifyPassword) {
        UA_String_clear(&u->password);
        UA_String_copy(password, &u->password);
    }
    if(modifyConfiguration)
        u->configuration = configuration;
    if(modifyDescription) {
        UA_String_clear(&u->description);
        UA_String_copy(description, &u->description);
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
removeUser(UA_Server *s, UA_AccessControl *ac, const UA_String *name) {
    User *u = findUser(name);
    if(!u)
        return UA_STATUSCODE_BADNOTFOUND;
    UA_String_clear(&u->name);
    UA_String_clear(&u->password);
    UA_String_clear(&u->description);
    *u = users[--usersSize];
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
changePassword(UA_Server *s, UA_AccessControl *ac, const UA_String *name,
               const UA_String *oldPassword, const UA_String *newPassword) {
    User *u = findUser(name);
    if(!u || !UA_String_equal(&u->password, oldPassword))
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    UA_String_clear(&u->password);
    return UA_String_copy(newPassword, &u->password);
}

/* The provider has to be in the configuration of UA_Server_newWithConfig */
static void
setupServer(UA_Boolean withProvider) {
    static const struct {
        const char *name;
        UA_UserConfigurationMask configuration;
    } initial[] = {{"alice", UA_USERCONFIGURATIONMASK_NONE},
                   {"bob", UA_USERCONFIGURATIONMASK_DISABLED},
                   {"carol", UA_USERCONFIGURATIONMASK_MUSTCHANGEPASSWORD},
                   {"erin", UA_USERCONFIGURATIONMASK_NONE}};
    usersSize = 0;
    for(size_t i = 0; i < 4; i++) {
        UA_String name = UA_STRING((char*)(uintptr_t)initial[i].name);
        UA_String password = UA_STRING("password");
        addUser(NULL, NULL, &name, &password, initial[i].configuration, &UA_STRING_NULL);
    }
    options = UA_PASSWORDOPTIONSMASK_SUPPORTINITIALPASSWORDCHANGE |
        UA_PASSWORDOPTIONSMASK_SUPPORTDISABLEUSER |
        UA_PASSWORDOPTIONSMASK_SUPPORTDISABLEDELETEFORUSER |
        UA_PASSWORDOPTIONSMASK_SUPPORTNOCHANGEFORUSER;
    forcedStatus = UA_STATUSCODE_GOOD;

    UA_ServerConfig config;
    memset(&config, 0, sizeof(config));
    config.logging = UA_Log_Stdout_new(UA_LOGLEVEL_WARNING);
    ck_assert_uint_eq(UA_ServerConfig_setMinimal(&config, 0, NULL), UA_STATUSCODE_GOOD);
    config.tcpEnabled = false;
    config.allowNonePolicyPassword = true;
    /* The list only enables the UserName token, the callback checks the user */
    UA_UsernamePasswordLogin unused = {UA_STRING_STATIC("unused"), UA_STRING_STATIC("")};
    ck_assert_uint_eq(UA_AccessControl_defaultWithLoginCallback(&config, true, NULL,
                                                                1, &unused, login, NULL),
                      UA_STATUSCODE_GOOD);
    if(withProvider) {
        config.accessControl.getUsers = getUsers;
        config.accessControl.getPasswordPolicy = getPasswordPolicy;
        config.accessControl.getUserConfiguration = getUserConfiguration;
        config.accessControl.addUser = addUser;
        config.accessControl.modifyUser = modifyUser;
        config.accessControl.removeUser = removeUser;
        config.accessControl.changePassword = changePassword;
    }
    rbacAddEndpointModes(&config);
    server = UA_Server_newWithConfig(&config);
    ck_assert_ptr_nonnull(server);
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
    rbacChannelInit(server, &plain, UA_MESSAGESECURITYMODE_NONE, NULL);
    rbacChannelInit(server, &secure, UA_MESSAGESECURITYMODE_SIGNANDENCRYPT, NULL);
}

static void setup(void) {
    setupServer(true);
}

static void setupNoProvider(void) {
    setupServer(false);
}

static void teardown(void) {
    UA_Server_run_shutdown(server);
    UA_Server_delete(server);
    UA_SecureChannel_clear(&plain);
    UA_SecureChannel_clear(&secure);
    while(usersSize > 0)
        removeUser(NULL, NULL, &users[0].name);
}

static UA_StatusCode
loginUser(UA_SecureChannel *channel, const char *name, const char *password,
          UA_NodeId *sessionId) {
    UA_UserNameIdentityToken token;
    UA_UserNameIdentityToken_init(&token);
    token.userName = UA_STRING((char*)(uintptr_t)name);
    token.password = UA_STRING((char*)(uintptr_t)password);
    return rbacLogin(server, channel, &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN],
                     &token, sessionId);
}

/* A Method of the UserManagement Object, called by the local admin Session
 * for a NULL Session */
static UA_StatusCode
callMethod(UA_Session *session, UA_UInt32 methodId, size_t inSize, UA_Variant *in) {
    if(session)
        return rbacCall(server, session, UM, UA_NODEID_NUMERIC(0, methodId), inSize, in);
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = UM;
    req.methodId = UA_NODEID_NUMERIC(0, methodId);
    req.inputArguments = in;
    req.inputArgumentsSize = inSize;
    UA_CallMethodResult res = UA_Server_call(server, &req);
    UA_StatusCode status = res.statusCode;
    UA_CallMethodResult_clear(&res);
    return status;
}

/* AddUser, ModifyUser and RemoveUser called with the arguments in this order */
static UA_StatusCode
callUserMethod(UA_Session *session, UA_UInt32 methodId, const char *name,
               const char *password, UA_UserConfigurationMask *configuration,
               const char *description) {
    UA_String n = UA_STRING((char*)(uintptr_t)name);
    UA_String p = UA_STRING((char*)(uintptr_t)password);
    UA_String d = UA_STRING((char*)(uintptr_t)description);
    UA_Boolean modifyPassword = (password != NULL);
    UA_Boolean modifyConfiguration = (configuration != NULL);
    UA_Boolean modifyDescription = (description != NULL);
    UA_UserConfigurationMask none = UA_USERCONFIGURATIONMASK_NONE;
    if(!configuration)
        configuration = &none;
    UA_Variant in[7];
    size_t inSize = 1;
    UA_Variant_setScalar(&in[0], &n, &UA_TYPES[UA_TYPES_STRING]);
    if(methodId == UA_NS0ID_USERMANAGEMENT_ADDUSER ||
       methodId == UA_NS0ID_USERMANAGEMENTTYPE_ADDUSER) {
        UA_Variant_setScalar(&in[1], &p, &UA_TYPES[UA_TYPES_STRING]);
        UA_Variant_setScalar(&in[2], configuration,
                             &UA_TYPES[UA_TYPES_USERCONFIGURATIONMASK]);
        UA_Variant_setScalar(&in[3], &d, &UA_TYPES[UA_TYPES_STRING]);
        inSize = 4;
    } else if(methodId == UA_NS0ID_USERMANAGEMENT_MODIFYUSER) {
        UA_Variant_setScalar(&in[1], &modifyPassword, &UA_TYPES[UA_TYPES_BOOLEAN]);
        UA_Variant_setScalar(&in[2], &p, &UA_TYPES[UA_TYPES_STRING]);
        UA_Variant_setScalar(&in[3], &modifyConfiguration, &UA_TYPES[UA_TYPES_BOOLEAN]);
        UA_Variant_setScalar(&in[4], configuration,
                             &UA_TYPES[UA_TYPES_USERCONFIGURATIONMASK]);
        UA_Variant_setScalar(&in[5], &modifyDescription, &UA_TYPES[UA_TYPES_BOOLEAN]);
        UA_Variant_setScalar(&in[6], &d, &UA_TYPES[UA_TYPES_STRING]);
        inSize = 7;
    }
    return callMethod(session, methodId, inSize, in);
}

static UA_StatusCode
callChangePassword(UA_Session *session, const char *oldPassword,
                   const char *newPassword) {
    UA_String o = UA_STRING((char*)(uintptr_t)oldPassword);
    UA_String n = UA_STRING((char*)(uintptr_t)newPassword);
    UA_Variant in[2];
    UA_Variant_setScalar(&in[0], &o, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[1], &n, &UA_TYPES[UA_TYPES_STRING]);
    return callMethod(session, UA_NS0ID_USERMANAGEMENT_CHANGEPASSWORD, 2, in);
}

/* The Methods reach the provider with their arguments. The Properties are
 * read from the provider, which can also fail. */
START_TEST(methods_reachProvider) {
    UA_String dave = UA_STRING("dave");
    ck_assert_uint_eq(callUserMethod(NULL, UA_NS0ID_USERMANAGEMENT_ADDUSER, "dave",
                                     "s3cret-password", NULL, "operator"),
                      UA_STATUSCODE_GOOD);
    User *u = findUser(&dave);
    ck_assert_ptr_nonnull(u);
    UA_String expected = UA_STRING("s3cret-password");
    ck_assert(UA_String_equal(&u->password, &expected));
    ck_assert_uint_eq(callUserMethod(NULL, UA_NS0ID_USERMANAGEMENT_MODIFYUSER, "dave",
                                     NULL, NULL, "supervisor"), UA_STATUSCODE_GOOD);
    expected = UA_STRING("supervisor");
    ck_assert(UA_String_equal(&findUser(&dave)->description, &expected));
    expected = UA_STRING("s3cret-password");
    ck_assert(UA_String_equal(&findUser(&dave)->password, &expected));

    UA_Variant v;
    ck_assert_uint_eq(UA_Server_readValue(server, UA_NS0ID(USERMANAGEMENT_USERS), &v),
                      UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_USERMANAGEMENTDATATYPE]));
    ck_assert_uint_eq(v.arrayLength, 5);
    UA_Variant_clear(&v);
    ck_assert_uint_eq(UA_Server_readValue(server, UA_NS0ID(USERMANAGEMENT_PASSWORDLENGTH),
                                          &v), UA_STATUSCODE_GOOD);
    ck_assert(((UA_Range*)v.data)->low == 8.0);
    UA_Variant_clear(&v);
    ck_assert_uint_eq(UA_Server_readValue(server, UA_NS0ID(USERMANAGEMENT_PASSWORDOPTIONS),
                                          &v), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(*(UA_PasswordOptionsMask*)v.data, options);
    UA_Variant_clear(&v);
    forcedStatus = UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
    ck_assert_uint_eq(UA_Server_readValue(server, UA_NS0ID(USERMANAGEMENT_USERS), &v),
                      UA_STATUSCODE_BADRESOURCEUNAVAILABLE);

    ck_assert_uint_eq(callUserMethod(NULL, UA_NS0ID_USERMANAGEMENT_REMOVEUSER, "dave",
                                     NULL, NULL, NULL), UA_STATUSCODE_GOOD);
    ck_assert_ptr_null(findUser(&dave));
    ck_assert_uint_eq(callUserMethod(NULL, UA_NS0ID_USERMANAGEMENT_REMOVEUSER, "dave",
                                     NULL, NULL, NULL), UA_STATUSCODE_BADNOTFOUND);
} END_TEST

/* The arguments and the requested UserConfiguration are validated before the
 * provider is called */
START_TEST(methods_validateArguments) {
    UA_String name = UA_STRING("dave");
    UA_Variant one;
    UA_Variant_setScalar(&one, &name, &UA_TYPES[UA_TYPES_STRING]);
    UA_CallMethodRequest req;
    UA_CallMethodRequest_init(&req);
    req.objectId = UM;
    req.methodId = UA_NS0ID(USERMANAGEMENT_ADDUSER);
    req.inputArguments = &one;
    req.inputArgumentsSize = 1;
    UA_CallMethodResult res = UA_Server_call(server, &req);
    ck_assert_uint_eq(res.statusCode, UA_STATUSCODE_BADARGUMENTSMISSING);
    UA_CallMethodResult_clear(&res);

    UA_UserConfigurationMask contradicting = UA_USERCONFIGURATIONMASK_NOCHANGEBYUSER |
        UA_USERCONFIGURATIONMASK_MUSTCHANGEPASSWORD;
    ck_assert_uint_eq(callUserMethod(NULL, UA_NS0ID_USERMANAGEMENT_ADDUSER, "dave",
                                     "s3cret-password", &contradicting, ""),
                      UA_STATUSCODE_BADCONFIGURATIONERROR);
    options = UA_PASSWORDOPTIONSMASK_NONE;
    UA_UserConfigurationMask disabled = UA_USERCONFIGURATIONMASK_DISABLED;
    ck_assert_uint_eq(callUserMethod(NULL, UA_NS0ID_USERMANAGEMENT_ADDUSER, "dave",
                                     "s3cret-password", &disabled, ""),
                      UA_STATUSCODE_BADNOTSUPPORTED);
    ck_assert_uint_eq(callUserMethod(NULL, UA_NS0ID_USERMANAGEMENT_MODIFYUSER, "alice",
                                     NULL, &disabled, NULL),
                      UA_STATUSCODE_BADNOTSUPPORTED);
    ck_assert_ptr_null(findUser(&name));
    options = UA_PASSWORDOPTIONSMASK_SUPPORTDISABLEUSER;
    ck_assert_uint_eq(callUserMethod(NULL, UA_NS0ID_USERMANAGEMENT_ADDUSER, "dave",
                                     "s3cret-password", &disabled, ""),
                      UA_STATUSCODE_GOOD);
} END_TEST

/* The UserManagement Nodes allow SecurityAdmin over an encrypted channel. The
 * Anonymous Role may call ChangePassword. */
START_TEST(permissions_securityAdminEncrypted) {
    static const struct {
        UA_UInt32 id;
        UA_PermissionType securityAdmin;
        UA_PermissionType anonymous;
    } nodes[] = {
        {UA_NS0ID_USERMANAGEMENT, UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ |
         UA_PERMISSIONTYPE_CALL | UA_PERMISSIONTYPE_READROLEPERMISSIONS,
         UA_PERMISSIONTYPE_CALL},
        {UA_NS0ID_USERMANAGEMENT_USERS, UA_PERMISSIONTYPE_BROWSE |
         UA_PERMISSIONTYPE_READ | UA_PERMISSIONTYPE_CALL |
         UA_PERMISSIONTYPE_READROLEPERMISSIONS, 0},
        {UA_NS0ID_USERMANAGEMENT_ADDUSER, UA_PERMISSIONTYPE_BROWSE |
         UA_PERMISSIONTYPE_READ | UA_PERMISSIONTYPE_CALL |
         UA_PERMISSIONTYPE_READROLEPERMISSIONS, 0},
        {UA_NS0ID_USERMANAGEMENT_CHANGEPASSWORD, 0, UA_PERMISSIONTYPE_CALL}
    };
    const UA_NodeId securityAdmin = SECURITYADMIN, anonymous = ANONYMOUS;
    for(size_t i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
        UA_NodeId nodeId = UA_NODEID_NUMERIC(0, nodes[i].id);
        size_t size = 0;
        UA_RolePermission *rp = NULL;
        ck_assert_uint_eq(UA_Server_getNodeRolePermissions(server, nodeId, &size, &rp),
                          UA_STATUSCODE_GOOD);
        UA_PermissionType admin = 0, anon = 0;
        for(size_t j = 0; j < size; j++) {
            if(UA_NodeId_equal(&rp[j].roleId, &securityAdmin))
                admin = rp[j].permissions;
            else if(UA_NodeId_equal(&rp[j].roleId, &anonymous))
                anon = rp[j].permissions;
            else
                ck_abort_msg("node %u: unexpected Role", nodes[i].id);
            UA_NodeId_clear(&rp[j].roleId);
        }
        UA_free(rp);
        ck_assert_msg(admin == nodes[i].securityAdmin && anon == nodes[i].anonymous,
                      "node %u: 0x%x 0x%x", nodes[i].id, admin, anon);
        UA_AccessRestrictionType ar = 0;
        ck_assert_uint_eq(UA_Server_getNodeAccessRestrictions(server, nodeId, &ar),
                          UA_STATUSCODE_GOOD);
        ck_assert(ar & UA_ACCESSRESTRICTIONTYPE_ENCRYPTIONREQUIRED);
    }

    static const struct {
        UA_Boolean encrypted;
        UA_Boolean securityAdmin;
        UA_StatusCode expected;
    } calls[] = {
        {false, true, UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT},
        {true, false, UA_STATUSCODE_BADUSERACCESSDENIED},
        {true, true, UA_STATUSCODE_GOOD}
    };
    for(size_t c = 0; c < sizeof(calls) / sizeof(calls[0]); c++) {
        UA_Session *session = rbacSession(server, calls[c].encrypted ? &secure : &plain,
                                          calls[c].securityAdmin ? securityAdmin : anonymous);
        ck_assert_uint_eq(callUserMethod(session, UA_NS0ID_USERMANAGEMENT_ADDUSER,
                                         "dave", "s3cret-password", NULL, ""),
                          calls[c].expected);
    }
} END_TEST

/* ChangePassword changes the password of the user of the Session, only over
 * an encrypted channel */
START_TEST(changePassword_ownUserEncrypted) {
    UA_NodeId plainId, secureId, anonymousId;
    ck_assert_uint_eq(loginUser(&plain, "alice", "password", &plainId), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(loginUser(&secure, "alice", "password", &secureId), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(rbacLogin(server, &secure, NULL, NULL, &anonymousId),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(callChangePassword(rbacGetSession(server, &plainId),
                                         "password", "new-password"),
                      UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT);
    ck_assert_uint_eq(callChangePassword(rbacGetSession(server, &anonymousId),
                                         "password", "new-password"),
                      UA_STATUSCODE_BADINVALIDSTATE);
    ck_assert_uint_eq(callChangePassword(rbacGetSession(server, &secureId),
                                         "wrong", "new-password"),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert_uint_eq(callChangePassword(rbacGetSession(server, &secureId),
                                         "password", "new-password"),
                      UA_STATUSCODE_GOOD);
    UA_NodeId sessionId;
    ck_assert_uint_eq(loginUser(&plain, "alice", "password", &sessionId),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert_uint_eq(loginUser(&plain, "alice", "new-password", &sessionId),
                      UA_STATUSCODE_GOOD);

    /* The local admin Session has no user of its own */
    ck_assert_uint_eq(callChangePassword(NULL, "new-password", "other"),
                      UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT);
} END_TEST

/* Disabling or removing a user closes its Sessions. A Session cannot disable
 * or remove its own user. */
START_TEST(disableOrRemove_closesSessions) {
    UA_NodeId alice, erin;
    ck_assert_uint_eq(loginUser(&plain, "alice", "password", &alice), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(loginUser(&plain, "erin", "password", &erin), UA_STATUSCODE_GOOD);
    UA_Session *admin = rbacSession(server, &secure, SECURITYADMIN);
    UA_UserConfigurationMask disabled = UA_USERCONFIGURATIONMASK_DISABLED;
    ck_assert_uint_eq(callUserMethod(admin, UA_NS0ID_USERMANAGEMENT_MODIFYUSER, "alice",
                                     NULL, &disabled, NULL), UA_STATUSCODE_GOOD);
    ck_assert_ptr_null(rbacGetSession(server, &alice));
    ck_assert_ptr_nonnull(rbacGetSession(server, &erin));
    ck_assert_uint_eq(callUserMethod(admin, UA_NS0ID_USERMANAGEMENT_REMOVEUSER, "erin",
                                     NULL, NULL, NULL), UA_STATUSCODE_GOOD);
    ck_assert_ptr_null(rbacGetSession(server, &erin));

    UA_NodeId selfId;
    ck_assert_uint_eq(loginUser(&secure, "carol", "password", &selfId),
                      UA_STATUSCODE_GOODPASSWORDCHANGEREQUIRED);
    UA_Session *self = rbacGetSession(server, &selfId);
    rbacSetRoles(server, &selfId, 1, (UA_NodeId[]){SECURITYADMIN});
    ck_assert_uint_eq(callUserMethod(self, UA_NS0ID_USERMANAGEMENT_REMOVEUSER, "carol",
                                     NULL, NULL, NULL),
                      UA_STATUSCODE_BADINVALIDSELFREFERENCE);
    ck_assert_uint_eq(callUserMethod(self, UA_NS0ID_USERMANAGEMENT_MODIFYUSER, "carol",
                                     NULL, &disabled, NULL),
                      UA_STATUSCODE_BADINVALIDSELFREFERENCE);
} END_TEST

/* A disabled user is refused at ActivateSession like an unknown user */
START_TEST(disabledUser_refusedLikeUnknown) {
    UA_NodeId sessionId;
    ck_assert_uint_eq(loginUser(&plain, "bob", "password", &sessionId),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert_uint_eq(loginUser(&plain, "bob", "wrong", &sessionId),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert_uint_eq(loginUser(&plain, "nobody", "password", &sessionId),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
} END_TEST

/* With MustChangePassword the Session gets only the Anonymous Role, also after
 * a change of the RoleSet. That suffices for ChangePassword. */
START_TEST(mustChangePassword_onlyAnonymous) {
    UA_NodeId sessionId;
    ck_assert_uint_eq(loginUser(&secure, "carol", "password", &sessionId),
                      UA_STATUSCODE_GOODPASSWORDCHANGEREQUIRED);
    UA_NodeId carolRole =
        rbacAddRole(server, "CarolRole", UA_IDENTITYCRITERIATYPE_USERNAME, "carol");
    ck_assert(rbacHasRole(server, &sessionId, ANONYMOUS));
    ck_assert(!rbacHasRole(server, &sessionId,
                           UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_AUTHENTICATEDUSER)));
    ck_assert(!rbacHasRole(server, &sessionId, carolRole));
    ck_assert_uint_eq(callChangePassword(rbacGetSession(server, &sessionId),
                                         "password", "new-password"),
                      UA_STATUSCODE_GOOD);
    UA_NodeId_clear(&carolRole);
} END_TEST

/* Deleting the pinned Roles of such a Session restores exactly Anonymous */
START_TEST(mustChangePassword_unpinRestoresAnonymous) {
    UA_NodeId sessionId;
    ck_assert_uint_eq(loginUser(&secure, "carol", "password", &sessionId),
                      UA_STATUSCODE_GOODPASSWORDCHANGEREQUIRED);
    const UA_NodeId pinned = SECURITYADMIN;
    rbacSetRoles(server, &sessionId, 1, &pinned);
    ck_assert(!rbacHasRole(server, &sessionId, ANONYMOUS));
    ck_assert_uint_eq(UA_Server_deleteSessionAttribute(server, &sessionId,
                                                       UA_QUALIFIEDNAME(0, "roles")),
                      UA_STATUSCODE_GOOD);
    UA_Variant roles;
    ck_assert_uint_eq(UA_Server_getSessionAttributeCopy(server, &sessionId,
                                                        UA_QUALIFIEDNAME(0, "roles"),
                                                        &roles),
                      UA_STATUSCODE_GOOD);
    const UA_NodeId anonymous = ANONYMOUS;
    ck_assert_uint_eq(roles.arrayLength, 1);
    ck_assert(UA_NodeId_equal((const UA_NodeId*)roles.data, &anonymous));
    UA_Variant_clear(&roles);
} END_TEST

#ifdef UA_ENABLE_AUDITING
static UA_Variant auditInputs;

static void
auditCallback(UA_Server *s, UA_ApplicationNotificationType type,
              const UA_KeyValueMap payload) {
    if(type != UA_APPLICATIONNOTIFICATIONTYPE_AUDIT_UPDATE_METHOD)
        return;
    UA_Variant_clear(&auditInputs);
    UA_Variant_copy(UA_KeyValueMap_get(&payload, UA_QUALIFIEDNAME(0, "/InputArguments")),
                    &auditInputs);
}

static void
assertAuditRedacted(size_t size, UA_UInt32 secrets) {
    ck_assert(auditInputs.type == &UA_TYPES[UA_TYPES_VARIANT]);
    ck_assert_uint_eq(auditInputs.arrayLength, size);
    for(size_t i = 0; i < size; i++)
        ck_assert(UA_Variant_isEmpty(&((UA_Variant*)auditInputs.data)[i]) ==
                  ((secrets & (1u << i)) != 0));
    UA_Variant_clear(&auditInputs);
}

/* The AuditUpdateMethodEvent does not contain the passwords, also when the
 * Method refuses the call. Bit i of the mask stands for argument i. */
START_TEST(audit_omitsPasswords) {
    UA_ServerConfig *config = UA_Server_getConfig(server);
    config->auditingEnabled = true;
    config->auditMethodUpdateEnabled = true;
    config->auditNotificationCallback = auditCallback;
    UA_NodeId aliceId;
    ck_assert_uint_eq(loginUser(&secure, "alice", "password", &aliceId),
                      UA_STATUSCODE_GOOD);
    UA_Session *admin = rbacSession(server, &secure, SECURITYADMIN);
    ck_assert_uint_eq(callUserMethod(admin, UA_NS0ID_USERMANAGEMENT_ADDUSER, "dave",
                                     "s3cret-password", NULL, ""), UA_STATUSCODE_GOOD);
    assertAuditRedacted(4, 1u << 1);
    ck_assert_uint_eq(callUserMethod(admin, UA_NS0ID_USERMANAGEMENTTYPE_ADDUSER, "frank",
                                     "s3cret-password", NULL, ""), UA_STATUSCODE_GOOD);
    assertAuditRedacted(4, 1u << 1);
    ck_assert_uint_eq(callUserMethod(admin, UA_NS0ID_USERMANAGEMENT_MODIFYUSER, "dave",
                                     "n3w-password", NULL, NULL), UA_STATUSCODE_GOOD);
    assertAuditRedacted(7, 1u << 2);
    ck_assert_uint_eq(callChangePassword(rbacGetSession(server, &aliceId),
                                         "password", "new-password"), UA_STATUSCODE_GOOD);
    assertAuditRedacted(2, 3u);
    ck_assert_uint_eq(callChangePassword(NULL, "new-password", "other"),
                      UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT);
    assertAuditRedacted(2, 3u);
    ck_assert_uint_eq(callUserMethod(admin, UA_NS0ID_USERMANAGEMENT_REMOVEUSER, "dave",
                                     NULL, NULL, NULL), UA_STATUSCODE_GOOD);
    assertAuditRedacted(1, 0);
    config->auditNotificationCallback = NULL;
} END_TEST
#endif

/* Without a provider the Methods have no implementation */
START_TEST(noProvider_inert) {
    ck_assert_uint_eq(callUserMethod(NULL, UA_NS0ID_USERMANAGEMENT_ADDUSER, "dave",
                                     "s3cret-password", NULL, ""),
                      UA_STATUSCODE_BADMETHODINVALID);
    UA_String dave = UA_STRING("dave");
    ck_assert_ptr_null(findUser(&dave));
} END_TEST

static Suite *testSuite_rbacUserManagement(void) {
    Suite *s = suite_create("RBAC UserManagement");
    TCase *tc = tcase_create("Provider");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, methods_reachProvider);
    tcase_add_test(tc, methods_validateArguments);
    tcase_add_test(tc, permissions_securityAdminEncrypted);
    tcase_add_test(tc, changePassword_ownUserEncrypted);
    tcase_add_test(tc, disableOrRemove_closesSessions);
    tcase_add_test(tc, disabledUser_refusedLikeUnknown);
    tcase_add_test(tc, mustChangePassword_onlyAnonymous);
    tcase_add_test(tc, mustChangePassword_unpinRestoresAnonymous);
#ifdef UA_ENABLE_AUDITING
    tcase_add_test(tc, audit_omitsPasswords);
#endif
    suite_add_tcase(s, tc);

    TCase *tc_none = tcase_create("No provider");
    tcase_add_checked_fixture(tc_none, setupNoProvider, teardown);
    tcase_add_test(tc_none, noProvider_inert);
    suite_add_tcase(s, tc_none);
    return s;
}

int main(void) {
    SRunner *sr = srunner_create(testSuite_rbacUserManagement());
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
