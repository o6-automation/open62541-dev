/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

/* Assignment of Roles to Sessions (Part 18 §4.4): identity mapping rules,
 * Application filters and the re-evaluation when the RoleSet changes. The
 * Sessions are activated in-process, see test_helpers_rbac.h. */

#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/accesscontrol_default.h>
#include <open62541/plugin/log_stdout.h>

#include "test_helpers_rbac.h"
#include "server/ua_server_rbac.h"

#include <check.h>
#include <stdlib.h>

#define TOKEN_CLAIM "issuer.example/operator"

static UA_Server *server;
static UA_SecureChannel plain;  /* SecurityMode None */
static UA_SecureChannel secure; /* SecurityMode SignAndEncrypt */
static size_t tokenRolesCalls;

static UA_UsernamePasswordLogin logins[2] = {
    {UA_STRING_STATIC("alice"), UA_STRING_STATIC("alice-pw")},
    {UA_STRING_STATIC("bob"), UA_STRING_STATIC("bob-pw")}};

static UA_StatusCode
getUserGroups(UA_Server *s, UA_AccessControl *ac, const UA_NodeId *sessionId,
              void *sessionContext, UA_String **groups, size_t *groupsSize) {
    UA_String group = UA_STRING("operators");
    *groupsSize = 1;
    return UA_Array_copy(&group, 1, (void**)groups, &UA_TYPES[UA_TYPES_STRING]);
}

static UA_StatusCode
getUserTokenRoles(UA_Server *s, UA_AccessControl *ac, const UA_NodeId *sessionId,
                  void *sessionContext, UA_String **claims, size_t *claimsSize) {
    tokenRolesCalls++;
    UA_String claim = UA_STRING(TOKEN_CLAIM);
    *claimsSize = 1;
    return UA_Array_copy(&claim, 1, (void**)claims, &UA_TYPES[UA_TYPES_STRING]);
}

/* The default AccessControl does not accept IssuedIdentityTokens */
static UA_StatusCode (*defaultActivateSession)(UA_Server*, UA_AccessControl*,
    const UA_EndpointDescription*, const UA_ByteString*, const UA_NodeId*,
    const UA_ExtensionObject*, void**);

static UA_StatusCode
activateSession(UA_Server *s, UA_AccessControl *ac,
                const UA_EndpointDescription *ed, const UA_ByteString *cert,
                const UA_NodeId *sessionId, const UA_ExtensionObject *token,
                void **sessionContext) {
    if(token->content.decoded.type == &UA_TYPES[UA_TYPES_ISSUEDIDENTITYTOKEN])
        return UA_STATUSCODE_GOOD;
    return defaultActivateSession(s, ac, ed, cert, sessionId, token,
                                  sessionContext);
}

/* The server is created from the configuration, so that the configured
 * wellKnownRoleMappings apply */
static void
setupWithMappings(UA_Role *mappings, size_t mappingsSize) {
    tokenRolesCalls = 0;
    UA_ServerConfig config;
    memset(&config, 0, sizeof(config));
    config.logging = UA_Log_Stdout_new(UA_LOGLEVEL_WARNING);
    ck_assert_uint_eq(UA_ServerConfig_setMinimal(&config, 0, NULL), UA_STATUSCODE_GOOD);
    config.tcpEnabled = false;
    config.allowNonePolicyPassword = true;
    config.wellKnownRoleMappings = mappings;
    config.wellKnownRoleMappingsSize = mappingsSize;
    ck_assert_uint_eq(UA_AccessControl_default(&config, true, NULL, 2, logins),
                      UA_STATUSCODE_GOOD);
    UA_UserTokenPolicy issued;
    UA_UserTokenPolicy_init(&issued);
    issued.policyId = UA_STRING("issued");
    issued.tokenType = UA_USERTOKENTYPE_ISSUEDTOKEN;
    ck_assert_uint_eq(UA_Array_appendCopy((void**)&config.accessControl.userTokenPolicies,
                                          &config.accessControl.userTokenPoliciesSize,
                                          &issued, &UA_TYPES[UA_TYPES_USERTOKENPOLICY]),
                      UA_STATUSCODE_GOOD);
    defaultActivateSession = config.accessControl.activateSession;
    config.accessControl.activateSession = activateSession;
    config.accessControl.getUserGroups = getUserGroups;
    config.accessControl.getUserTokenRoles = getUserTokenRoles;
    rbacAddEndpointModes(&config);
    server = UA_Server_newWithConfig(&config);
    ck_assert_ptr_nonnull(server);
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
    rbacChannelInit(server, &plain, UA_MESSAGESECURITYMODE_NONE, NULL);
    rbacChannelInit(server, &secure, UA_MESSAGESECURITYMODE_SIGNANDENCRYPT, NULL);
}

static void setup(void) {
    setupWithMappings(NULL, 0);
}

/* The C example of rbac.rst: the user alice is mapped to Operator */
static void setupOperatorMapping(void) {
    UA_Role *op = (UA_Role*)UA_calloc(1, sizeof(UA_Role));
    UA_Role_init(op);
    op->roleName = UA_QUALIFIEDNAME_ALLOC(0, "Operator");
    op->identityMappingRules = UA_IdentityMappingRuleType_new();
    op->identityMappingRulesSize = 1;
    op->identityMappingRules[0].criteriaType = UA_IDENTITYCRITERIATYPE_USERNAME;
    op->identityMappingRules[0].criteria = UA_STRING_ALLOC("alice");
    setupWithMappings(op, 1); /* freed with the config */
}

static void teardown(void) {
    secure.transport = UA_SECURECHANNEL_TRANSPORT_UACP; /* An HTTP case failed */
    UA_Server_run_shutdown(server);
    UA_Server_delete(server);
    UA_SecureChannel_clear(&plain);
    UA_SecureChannel_clear(&secure);
}

typedef enum {LOGIN_EMPTY, LOGIN_ANONYMOUS, LOGIN_ALICE, LOGIN_ISSUED} Login;

static UA_StatusCode
login(Login kind, const char *password, UA_NodeId *sessionId) {
    UA_AnonymousIdentityToken anonymous;
    UA_AnonymousIdentityToken_init(&anonymous);
    UA_UserNameIdentityToken userName;
    UA_UserNameIdentityToken_init(&userName);
    userName.userName = UA_STRING("alice");
    userName.password = UA_STRING((char*)(uintptr_t)password);
    UA_IssuedIdentityToken issued;
    UA_IssuedIdentityToken_init(&issued);
    issued.tokenData = UA_BYTESTRING("access-token");
    switch(kind) {
    case LOGIN_EMPTY:
        return rbacLogin(server, &plain, NULL, NULL, sessionId);
    case LOGIN_ANONYMOUS:
        return rbacLogin(server, &plain, &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN],
                         &anonymous, sessionId);
    case LOGIN_ALICE:
        return rbacLogin(server, &plain, &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN],
                         &userName, sessionId);
    default:
        return rbacLogin(server, &secure, &UA_TYPES[UA_TYPES_ISSUEDIDENTITYTOKEN],
                         &issued, sessionId);
    }
}

/* Each identity mapping rule against the Sessions it matches and those it does
 * not. The Role criterion is a claim of an access token, never another Role. */
static const struct {
    UA_IdentityCriteriaType type;
    const char *criteria;
    Login login;
    UA_Boolean granted;
} criteriaCases[] = {
    {UA_IDENTITYCRITERIATYPE_ANONYMOUS, NULL, LOGIN_ANONYMOUS, true},
    {UA_IDENTITYCRITERIATYPE_ANONYMOUS, NULL, LOGIN_EMPTY, true},
    {UA_IDENTITYCRITERIATYPE_ANONYMOUS, NULL, LOGIN_ALICE, false},
    {UA_IDENTITYCRITERIATYPE_AUTHENTICATEDUSER, NULL, LOGIN_EMPTY, false},
    {UA_IDENTITYCRITERIATYPE_AUTHENTICATEDUSER, NULL, LOGIN_ALICE, true},
    {UA_IDENTITYCRITERIATYPE_AUTHENTICATEDUSER, NULL, LOGIN_ISSUED, true},
    {UA_IDENTITYCRITERIATYPE_USERNAME, "alice", LOGIN_ALICE, true},
    {UA_IDENTITYCRITERIATYPE_USERNAME, "bob", LOGIN_ALICE, false},
    {UA_IDENTITYCRITERIATYPE_GROUPID, "operators", LOGIN_ALICE, true},
    {UA_IDENTITYCRITERIATYPE_GROUPID, "admins", LOGIN_ALICE, false},
    {UA_IDENTITYCRITERIATYPE_ROLE, TOKEN_CLAIM, LOGIN_ISSUED, true},
    {UA_IDENTITYCRITERIATYPE_ROLE, TOKEN_CLAIM, LOGIN_ALICE, false},
    {UA_IDENTITYCRITERIATYPE_ROLE, "AuthenticatedUser", LOGIN_ISSUED, false},
    {UA_IDENTITYCRITERIATYPE_TRUSTEDAPPLICATION, NULL, LOGIN_ISSUED, false},
    {UA_IDENTITYCRITERIATYPE_APPLICATION, "urn:open62541.unittest.client",
     LOGIN_ISSUED, false}
};

START_TEST(criteria_matchActivatedSession) {
    UA_IdentityCriteriaType type = criteriaCases[_i].type;
    UA_NodeId roleId = rbacAddRole(server, "CriteriaRole", type,
                                   criteriaCases[_i].criteria);
    UA_NodeId sessionId;
    ck_assert_uint_eq(login(criteriaCases[_i].login, "alice-pw", &sessionId),
                      UA_STATUSCODE_GOOD);
    ck_assert(rbacHasRole(server, &sessionId,
                          UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS)));
    ck_assert_int_eq(rbacHasRole(server, &sessionId, roleId),
                     criteriaCases[_i].granted);
    /* Only an IssuedIdentityToken is asked for its Role claims */
    ck_assert_uint_eq(tokenRolesCalls,
                      criteriaCases[_i].login == LOGIN_ISSUED ? 1 : 0);
    UA_NodeId_clear(&roleId);
} END_TEST

/* The certificate criteria against the identity captured at ActivateSession.
 * The X509 user token is covered end-to-end in check_client_authentication. */
START_TEST(criteria_matchCertificateIdentity) {
    const char *thumb = "00112233445566778899AABBCCDDEEFF00112233";
    const char *subject = "CN=\"M\xC3\xBCller\"/O=\"M\xC3\xBCller GmbH\"";
    UA_NodeId thumbRole =
        rbacAddRole(server, "ThumbRole", UA_IDENTITYCRITERIATYPE_THUMBPRINT, thumb);
    UA_NodeId subjectRole =
        rbacAddRole(server, "SubjectRole", UA_IDENTITYCRITERIATYPE_X509SUBJECT, subject);
    UA_NodeId appRole = rbacAddRole(server, "AppRole",
                                    UA_IDENTITYCRITERIATYPE_APPLICATION, "urn:app");

    UA_SessionIdentityContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.userThumbprint = UA_STRING("00112233445566778899aabbccddeeff00112233");
    ctx.userIssuer = UA_STRING((char*)(uintptr_t)subject);
    ctx.applicationUri = UA_STRING("urn:app");
    size_t rolesSize = 0;
    UA_NodeId *roles = NULL;
    lockServer(server);
    UA_StatusCode res = UA_Server_evaluateSessionRoles(server, &ctx, &rolesSize, &roles);
    unlockServer(server);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    UA_Boolean hasThumb = false, hasSubject = false, hasApp = false;
    for(size_t i = 0; i < rolesSize; i++) {
        hasThumb |= UA_NodeId_equal(&roles[i], &thumbRole);
        hasSubject |= UA_NodeId_equal(&roles[i], &subjectRole);
        hasApp |= UA_NodeId_equal(&roles[i], &appRole);
    }
    UA_Array_delete(roles, rolesSize, &UA_TYPES[UA_TYPES_NODEID]);
    ck_assert(hasThumb);   /* The case of the hex digits does not matter */
    ck_assert(hasSubject); /* The issuer matches as well */
    ck_assert(!hasApp);    /* The ApplicationUri of an untrusted client */
} END_TEST

/* The criteria formats of Part 18 §4.4.3 are enforced when a Role is added */
START_TEST(criteria_invalidRejected) {
    static const struct {
        UA_IdentityCriteriaType type;
        const char *criteria;
    } invalid[] = {
        {UA_IDENTITYCRITERIATYPE_THUMBPRINT, "AB:CD:EF"},
        {UA_IDENTITYCRITERIATYPE_THUMBPRINT, "00112233445566778899aabbccddeeff00112233"},
        {UA_IDENTITYCRITERIATYPE_USERNAME, ""},
        {UA_IDENTITYCRITERIATYPE_ANONYMOUS, "x"},
        {UA_IDENTITYCRITERIATYPE_X509SUBJECT, "alice"},
        {UA_IDENTITYCRITERIATYPE_X509SUBJECT, "CN=\"a\tb\""},
        {UA_IDENTITYCRITERIATYPE_X509SUBJECT, "CN=\"\xC3\""},
        {UA_IDENTITYCRITERIATYPE_X509SUBJECT, "CN=\"\""},
        {UA_IDENTITYCRITERIATYPE_X509SUBJECT, "CN=\"a\"/"},
        {UA_IDENTITYCRITERIATYPE_X509SUBJECT, "cn=\"a\""},
        {UA_IDENTITYCRITERIATYPE_X509SUBJECT, "CN=\"a\"/E=\"x\""},
        {UA_IDENTITYCRITERIATYPE_X509SUBJECT, "O=\"a\"/CN=\"b\""}
    };
    for(size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        UA_IdentityMappingRuleType rule;
        UA_IdentityMappingRuleType_init(&rule);
        rule.criteriaType = invalid[i].type;
        rule.criteria = UA_STRING((char*)(uintptr_t)invalid[i].criteria);
        UA_Role role;
        UA_Role_init(&role);
        role.roleName = UA_QUALIFIEDNAME(1, "InvalidRole");
        role.identityMappingRules = &rule;
        role.identityMappingRulesSize = 1;
        ck_assert_msg(UA_Server_addRole(server, &role, NULL) ==
                      UA_STATUSCODE_BADINVALIDARGUMENT, "case %u", (unsigned)i);
    }
    /* All names of Table 10 in the order of the table, a name may repeat */
    rbacAddRole(server, "AllNamesRole", UA_IDENTITYCRITERIATYPE_X509SUBJECT,
                "CN=\"a\"/O=\"b\"/OU=\"c\"/OU=\"c2\"/DC=\"d\"/L=\"e\"/S=\"f\"/"
                "C=\"DE\"/dnQualifier=\"g\"/serialNumber=\"h\"");
} END_TEST

/* The Application filter of a Role. An include list needs the ApplicationUri
 * of a trusted client certificate and an empty include list grants nothing. */
START_TEST(applicationFilter_evaluated) {
    UA_String allowed = UA_STRING("urn:allowed");
    UA_IdentityMappingRuleType rule;
    UA_IdentityMappingRuleType_init(&rule);
    rule.criteriaType = UA_IDENTITYCRITERIATYPE_AUTHENTICATEDUSER;
    UA_Role role;
    UA_Role_init(&role);
    role.identityMappingRules = &rule;
    role.identityMappingRulesSize = 1;
    UA_NodeId ids[3];
    const char *names[3] = {"Include", "Exclude", "EmptyInclude"};
    for(size_t i = 0; i < 3; i++) {
        role.roleName = UA_QUALIFIEDNAME(1, (char*)(uintptr_t)names[i]);
        role.applications = (i < 2) ? &allowed : NULL;
        role.applicationsSize = (i < 2) ? 1 : 0;
        role.applicationsExclude = (i == 1);
        ck_assert_uint_eq(UA_Server_addRole(server, &role, &ids[i]),
                          UA_STATUSCODE_GOOD);
    }

    static const struct {
        const char *uri;
        UA_Boolean trusted;
        UA_Boolean granted[3];
    } cases[] = {
        {"urn:allowed", true, {true, false, false}},
        {"urn:other", true, {false, true, false}},
        {"urn:allowed", false, {false, false, false}}
    };
    for(size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        UA_SessionIdentityContext ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.applicationUri = UA_STRING((char*)(uintptr_t)cases[c].uri);
        ctx.trustedApplication = cases[c].trusted;
        size_t rolesSize = 0;
        UA_NodeId *roles = NULL;
        lockServer(server);
        ck_assert_uint_eq(UA_Server_evaluateSessionRoles(server, &ctx, &rolesSize,
                                                         &roles), UA_STATUSCODE_GOOD);
        unlockServer(server);
        for(size_t i = 0; i < 3; i++) {
            UA_Boolean found = false;
            for(size_t j = 0; j < rolesSize; j++)
                found |= UA_NodeId_equal(&roles[j], &ids[i]);
            ck_assert_msg(found == cases[c].granted[i], "case %u role %s",
                          (unsigned)c, names[i]);
        }
        UA_Array_delete(roles, rolesSize, &UA_TYPES[UA_TYPES_NODEID]);
    }
} END_TEST

/* HTTPS with policy None is SignAndEncrypt, but the certificate of
 * CreateSession is ignored (Part 4 §5.6.2.2) and identifies no application */
START_TEST(trustedApplication_notFromIgnoredCertificate) {
    UA_NodeId appRole = rbacAddRole(server, "AppRole", UA_IDENTITYCRITERIATYPE_APPLICATION,
                                    "urn:unvalidated");
    secure.transport = UA_SECURECHANNEL_TRANSPORT_HTTP;
    UA_CreateSessionRequest request;
    UA_CreateSessionRequest_init(&request);
    request.requestedSessionTimeout = 60000.0;
    request.clientDescription.applicationUri = UA_STRING("urn:unvalidated");
    request.clientCertificate = UA_BYTESTRING("not-a-certificate");
    UA_CreateSessionResponse response;
    UA_CreateSessionResponse_init(&response);
    lockServer(server);
    Service_CreateSession(server, &secure, &request, &response);
    unlockServer(server);
    ck_assert_uint_eq(response.responseHeader.serviceResult, UA_STATUSCODE_GOOD);
    UA_NodeId sessionId = response.sessionId;
    UA_CreateSessionResponse_clear(&response);
    UA_StatusCode res = rbacActivate(server, &secure, &sessionId, NULL, NULL);
    secure.transport = UA_SECURECHANNEL_TRANSPORT_UACP; /* Not a real HTTP channel */
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    ck_assert(!rbacHasRole(server, &sessionId,
                           UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_TRUSTEDAPPLICATION)));
    ck_assert(!rbacHasRole(server, &sessionId, appRole));
    UA_NodeId_clear(&appRole);
} END_TEST

/* An empty token is the anonymous login (Part 4 §5.7.3), also when the
 * activated Session is re-activated with it */
START_TEST(emptyToken_isAnonymous) {
    UA_NodeId sessionId;
    ck_assert_uint_eq(login(LOGIN_EMPTY, NULL, &sessionId), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(rbacActivate(server, &plain, &sessionId, NULL, NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert(rbacHasRole(server, &sessionId,
                          UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS)));
    ck_assert(!rbacHasRole(server, &sessionId,
                           UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_AUTHENTICATEDUSER)));
} END_TEST

/* A rejected re-activation leaves the identity of the Session unchanged. The
 * next re-evaluation of the RoleSet uses the identity of the last success. */
START_TEST(rejectedReactivation_keepsIdentity) {
    UA_NodeId aliceRole =
        rbacAddRole(server, "AliceRole", UA_IDENTITYCRITERIATYPE_USERNAME, "alice");
    UA_NodeId sessionId;
    ck_assert_uint_eq(login(LOGIN_ALICE, "alice-pw", &sessionId), UA_STATUSCODE_GOOD);

    UA_UserNameIdentityToken token;
    UA_UserNameIdentityToken_init(&token);
    token.userName = UA_STRING("alice");
    token.password = UA_STRING("wrong");
    ck_assert_uint_eq(rbacActivate(server, &plain, &sessionId,
                                   &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN], &token),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    token.userName = UA_STRING("bob");
    token.password = UA_STRING("bob-pw");
    ck_assert_uint_eq(rbacActivate(server, &plain, &sessionId,
                                   &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN], &token),
                      UA_STATUSCODE_BADIDENTITYCHANGENOTSUPPORTED);

    UA_NodeId bobRole =
        rbacAddRole(server, "BobRole", UA_IDENTITYCRITERIATYPE_USERNAME, "bob");
    ck_assert(rbacHasRole(server, &sessionId, aliceRole));
    ck_assert(!rbacHasRole(server, &sessionId, bobRole));
    UA_NodeId_clear(&aliceRole);
    UA_NodeId_clear(&bobRole);
} END_TEST

/* Every change of the RoleSet re-evaluates the active Sessions (Part 18
 * §4.4.1): adding, updating and removing a Role */
START_TEST(roleSetChange_reevaluatesSessions) {
    UA_NodeId sessionId;
    ck_assert_uint_eq(login(LOGIN_ALICE, "alice-pw", &sessionId), UA_STATUSCODE_GOOD);
    UA_NodeId roleId =
        rbacAddRole(server, "LateRole", UA_IDENTITYCRITERIATYPE_USERNAME, "alice");
    ck_assert(rbacHasRole(server, &sessionId, roleId));

    UA_Role role;
    ck_assert_uint_eq(UA_Server_getRoleById(server, roleId, &role), UA_STATUSCODE_GOOD);
    UA_String_clear(&role.identityMappingRules[0].criteria);
    role.identityMappingRules[0].criteria = UA_STRING_ALLOC("bob");
    ck_assert_uint_eq(UA_Server_updateRole(server, &role), UA_STATUSCODE_GOOD);
    ck_assert(!rbacHasRole(server, &sessionId, roleId));

    role.identityMappingRules[0].criteriaType =
        UA_IDENTITYCRITERIATYPE_AUTHENTICATEDUSER;
    UA_String_clear(&role.identityMappingRules[0].criteria);
    ck_assert_uint_eq(UA_Server_updateRole(server, &role), UA_STATUSCODE_GOOD);
    ck_assert(rbacHasRole(server, &sessionId, roleId));

    ck_assert_uint_eq(UA_Server_removeRole(server, role.roleName), UA_STATUSCODE_GOOD);
    ck_assert(!rbacHasRole(server, &sessionId, roleId));
    UA_Role_clear(&role);
    UA_NodeId_clear(&roleId);
} END_TEST

/* Roles pinned by the "roles" attribute survive RoleSet changes except their
 * removal. Deleting the attribute returns to the identity mapping rules. */
START_TEST(pinnedRoles_surviveRoleSetChange) {
    UA_NodeId aliceRole =
        rbacAddRole(server, "AliceRole", UA_IDENTITYCRITERIATYPE_USERNAME, "alice");
    UA_NodeId manualRole = rbacAddRole(server, "ManualRole", RBAC_NO_RULE, NULL);
    UA_NodeId sessionId;
    ck_assert_uint_eq(login(LOGIN_ALICE, "alice-pw", &sessionId), UA_STATUSCODE_GOOD);
    UA_NodeId observer = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_OBSERVER);
    UA_NodeId pinned[2] = {observer, manualRole};
    rbacSetRoles(server, &sessionId, 2, pinned);

    UA_NodeId probeRole =
        rbacAddRole(server, "ProbeRole", UA_IDENTITYCRITERIATYPE_USERNAME, "alice");
    ck_assert(!rbacHasRole(server, &sessionId, probeRole));
    ck_assert(!rbacHasRole(server, &sessionId, aliceRole));
    ck_assert(rbacHasRole(server, &sessionId, manualRole));

    ck_assert_uint_eq(UA_Server_removeRole(server, UA_QUALIFIEDNAME(1, "ManualRole")),
                      UA_STATUSCODE_GOOD);
    ck_assert(!rbacHasRole(server, &sessionId, manualRole));
    ck_assert(rbacHasRole(server, &sessionId, observer));

    ck_assert_uint_eq(UA_Server_deleteSessionAttribute(server, &sessionId,
                                                       UA_QUALIFIEDNAME(0, "roles")),
                      UA_STATUSCODE_GOOD);
    ck_assert(rbacHasRole(server, &sessionId, aliceRole));
    ck_assert(rbacHasRole(server, &sessionId, probeRole));
    ck_assert(!rbacHasRole(server, &sessionId, observer));
    UA_NodeId_clear(&aliceRole);
    UA_NodeId_clear(&manualRole);
    UA_NodeId_clear(&probeRole);
} END_TEST

/* UA_Server_updateRole identifies the Role by roleId, by roleName or by both.
 * The stored roleName stays when the update carries none. */
START_TEST(updateRole_identifiedByEitherKey) {
    UA_Role role;
    UA_Role_init(&role);
    role.roleId = UA_NODEID_NUMERIC(1, 62500);
    role.roleName = UA_QUALIFIEDNAME(1, "UpdateKeyRole");
    role.applicationsExclude = true;
    ck_assert_uint_eq(UA_Server_addRole(server, &role, NULL), UA_STATUSCODE_GOOD);

    UA_Role update;
    UA_Role_init(&update);
    update.roleId = role.roleId;
    update.applicationsExclude = false;
    ck_assert_uint_eq(UA_Server_updateRole(server, &update), UA_STATUSCODE_GOOD);
    UA_Role fetched;
    ck_assert_uint_eq(UA_Server_getRoleById(server, role.roleId, &fetched),
                      UA_STATUSCODE_GOOD);
    ck_assert(!fetched.applicationsExclude);
    ck_assert(UA_QualifiedName_equal(&fetched.roleName, &role.roleName));
    UA_Role_clear(&fetched);

    UA_Role_init(&update);
    update.roleName = role.roleName;
    ck_assert_uint_eq(UA_Server_updateRole(server, &update), UA_STATUSCODE_GOOD);
    UA_Role_init(&update);
    ck_assert_uint_eq(UA_Server_updateRole(server, &update),
                      UA_STATUSCODE_BADINVALIDARGUMENT);
    /* addRole still requires a roleName */
    update.roleId = UA_NODEID_NUMERIC(1, 62501);
    ck_assert_uint_eq(UA_Server_addRole(server, &update, NULL),
                      UA_STATUSCODE_BADINVALIDARGUMENT);
} END_TEST

/* wellKnownRoleMappings set the rules of the well-known Roles */
START_TEST(wellKnownRoleMappings_evaluated) {
    UA_NodeId operatorRole = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_OPERATOR);
    UA_NodeId aliceSession, anonymousSession;
    ck_assert_uint_eq(login(LOGIN_ALICE, "alice-pw", &aliceSession), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(login(LOGIN_EMPTY, NULL, &anonymousSession), UA_STATUSCODE_GOOD);
    ck_assert(rbacHasRole(server, &aliceSession, operatorRole));
    ck_assert(!rbacHasRole(server, &anonymousSession, operatorRole));
} END_TEST

static Suite *testSuite_rbacIdentity(void) {
    Suite *s = suite_create("RBAC Session identity");
    TCase *tc = tcase_create("Identity mapping");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_loop_test(tc, criteria_matchActivatedSession, 0,
                        sizeof(criteriaCases) / sizeof(criteriaCases[0]));
    tcase_add_test(tc, criteria_matchCertificateIdentity);
    tcase_add_test(tc, criteria_invalidRejected);
    tcase_add_test(tc, applicationFilter_evaluated);
    tcase_add_test(tc, trustedApplication_notFromIgnoredCertificate);
    tcase_add_test(tc, emptyToken_isAnonymous);
    tcase_add_test(tc, rejectedReactivation_keepsIdentity);
    tcase_add_test(tc, roleSetChange_reevaluatesSessions);
    tcase_add_test(tc, pinnedRoles_surviveRoleSetChange);
    tcase_add_test(tc, updateRole_identifiedByEitherKey);
    suite_add_tcase(s, tc);

    TCase *tc_mappings = tcase_create("Well-known Role mappings");
    tcase_add_checked_fixture(tc_mappings, setupOperatorMapping, teardown);
    tcase_add_test(tc_mappings, wellKnownRoleMappings_evaluated);
    suite_add_tcase(s, tc_mappings);
    return s;
}

int main(void) {
    SRunner *sr = srunner_create(testSuite_rbacIdentity());
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
