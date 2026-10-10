/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

/* TrustedApplication and the Application criterion end-to-end (Part 18
 * §4.4.3). The criterion is the ApplicationUri of the client certificate. The
 * server tolerates a client that declares another ApplicationUri than its
 * certificate (allowAllCertificateUris = WARN). The declared URI must not grant
 * a Role, neither by an Application rule nor by the Applications filter. */

#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/certificategroup_default.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>

#include "client/ua_client_internal.h"

#include <check.h>
#include <stdlib.h>

#include "certificates.h"
#include "test_helpers.h"

/* The only port of this file */
#define SERVER_URL "opc.tcp://localhost:4862"
#define CERT_URI "urn:cert"
#define DECLARED_URI "urn:declared"
#define BASIC256SHA256 "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"

static UA_Server *server;
static UA_NodeId roles[4]; /* Application rule and filter for each URI */

static UA_NodeId
addApplicationRole(const char *name, const char *uri, UA_Boolean filter) {
    UA_IdentityMappingRuleType rule;
    UA_IdentityMappingRuleType_init(&rule);
    rule.criteriaType = filter ? UA_IDENTITYCRITERIATYPE_ANONYMOUS :
        UA_IDENTITYCRITERIATYPE_APPLICATION;
    if(!filter)
        rule.criteria = UA_STRING((char*)(uintptr_t)uri);
    UA_String application = UA_STRING((char*)(uintptr_t)uri);
    UA_Role role;
    UA_Role_init(&role);
    role.roleName = UA_QUALIFIEDNAME(1, (char*)(uintptr_t)name);
    role.identityMappingRules = &rule;
    role.identityMappingRulesSize = 1;
    if(filter) {
        role.applications = &application;
        role.applicationsSize = 1;
        role.applicationsExclude = false;
    }
    UA_NodeId roleId = UA_NODEID_NULL;
    ck_assert_uint_eq(UA_Server_addRole(server, &role, &roleId), UA_STATUSCODE_GOOD);
    return roleId;
}

static void setup(void) {
    UA_ByteString certificate = {CERT_DER_LENGTH, CERT_DER_DATA};
    UA_ByteString privateKey = {KEY_DER_LENGTH, KEY_DER_DATA};
    server = UA_Server_newForUnitTestWithSecurityPolicies(
        4862, &certificate, &privateKey, NULL, 0, NULL, 0, NULL, 0);
    ck_assert(server != NULL);
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_CertificateGroup_AcceptAll(&config->secureChannelPKI);
    UA_CertificateGroup_AcceptAll(&config->sessionPKI);
    UA_String_clear(&config->applicationDescription.applicationUri);
    config->applicationDescription.applicationUri =
        UA_STRING_ALLOC("urn:open62541.unconfigured.application");
    config->allowAllCertificateUris = UA_RULEHANDLING_WARN;
    roles[0] = addApplicationRole("CertRule", CERT_URI, false);
    roles[1] = addApplicationRole("CertFilter", CERT_URI, true);
    roles[2] = addApplicationRole("DeclaredRule", DECLARED_URI, false);
    roles[3] = addApplicationRole("DeclaredFilter", DECLARED_URI, true);
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
}

static void teardown(void) {
    UA_Server_run_shutdown(server);
    for(size_t i = 0; i < 4; i++)
        UA_NodeId_clear(&roles[i]);
    UA_Server_delete(server);
}

/* Connect anonymously with a new certificate with the subjectAltName URIs. The
 * client declares DECLARED_URI. The server is iterated in this thread. */
static UA_Client *
connectWithCertificate(const char *const *san, size_t sanSize,
                       UA_MessageSecurityMode mode) {
    UA_String subject[2] = {UA_STRING_STATIC("O=open62541"),
                            UA_STRING_STATIC("CN=RBAC Application Test")};
    UA_String sanStrings[3];
    for(size_t i = 0; i < sanSize; i++)
        sanStrings[i] = UA_STRING((char*)(uintptr_t)san[i]);
    UA_KeyValueMap *kvm = UA_KeyValueMap_new();
    UA_UInt16 keyLength = 2048;
    UA_KeyValueMap_setScalar(kvm, UA_QUALIFIEDNAME(0, "key-size-bits"),
                             (void *)&keyLength, &UA_TYPES[UA_TYPES_UINT16]);
    UA_ByteString clientKey = UA_BYTESTRING_NULL;
    UA_ByteString clientCert = UA_BYTESTRING_NULL;
    ck_assert_uint_eq(UA_CreateCertificate(UA_Log_Stdout, subject, 2, sanStrings,
                                           sanSize, UA_CERTIFICATEFORMAT_DER, kvm,
                                           &clientKey, &clientCert),
                      UA_STATUSCODE_GOOD);
    UA_KeyValueMap_delete(kvm);

    UA_Client *client = UA_Client_newForUnitTest();
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    ck_assert_uint_eq(UA_ClientConfig_setDefaultEncryption(cc, clientCert, clientKey,
                                                           NULL, 0, NULL, 0),
                      UA_STATUSCODE_GOOD);
    UA_ByteString_clear(&clientCert);
    UA_ByteString_clear(&clientKey);
    UA_CertificateGroup_AcceptAll(&cc->certificateVerification);
    cc->securityMode = mode;
    UA_String_clear(&cc->securityPolicyUri);
    cc->securityPolicyUri = (mode == UA_MESSAGESECURITYMODE_NONE) ?
        UA_STRING_ALLOC("http://opcfoundation.org/UA/SecurityPolicy#None") :
        UA_STRING_ALLOC(BASIC256SHA256);
    UA_String_clear(&cc->clientDescription.applicationUri);
    cc->clientDescription.applicationUri = UA_STRING_ALLOC(DECLARED_URI);

    ck_assert_uint_eq(UA_Client_connectAsync(client, SERVER_URL), UA_STATUSCODE_GOOD);
    UA_SessionState state = UA_SESSIONSTATE_CLOSED;
    UA_StatusCode status = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < 1000 && state != UA_SESSIONSTATE_ACTIVATED &&
            status == UA_STATUSCODE_GOOD; i++) {
        UA_Server_run_iterate(server, false);
        UA_Client_run_iterate(client, 1);
        UA_Client_getState(client, NULL, &state, &status);
    }
    ck_assert_uint_eq(state, UA_SESSIONSTATE_ACTIVATED);
    return client;
}

static void
checkRoles(UA_Client *client, UA_Boolean trusted, const UA_Boolean *granted) {
    UA_Variant v;
    ck_assert_uint_eq(UA_Server_getSessionAttributeCopy(server, &client->sessionId,
                                                        UA_QUALIFIEDNAME(0, "roles"),
                                                        &v), UA_STATUSCODE_GOOD);
    const UA_NodeId trustedApplication =
        UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_TRUSTEDAPPLICATION);
    for(size_t r = 0; r < 5; r++) {
        const UA_NodeId *role = (r < 4) ? &roles[r] : &trustedApplication;
        UA_Boolean found = false;
        for(size_t i = 0; i < v.arrayLength; i++)
            found |= UA_NodeId_equal(&((UA_NodeId*)v.data)[i], role);
        ck_assert_msg(found == ((r < 4) ? granted[r] : trusted), "role %u", (unsigned)r);
    }
    UA_Variant_clear(&v);
    UA_Client_disconnectAsync(client);
    for(size_t i = 0; i < 100; i++) {
        UA_Server_run_iterate(server, false);
        UA_Client_run_iterate(client, 1);
    }
    UA_Client_delete(client);
}

/* The Application criterion is taken from the certificate, not from the
 * ApplicationDescription of CreateSession */
START_TEST(applicationCriterion_fromCertificate) {
    const char *san[2] = {"URI:" CERT_URI, "DNS:localhost"};
    const UA_Boolean granted[4] = {true, true, false, false};
    checkRoles(connectWithCertificate(san, 2, UA_MESSAGESECURITYMODE_SIGNANDENCRYPT),
               true, granted);
} END_TEST

/* A certificate with more than one URI has no ApplicationUri (Part 6 §6.2.2).
 * The application is still trusted. */
START_TEST(applicationCriterion_ambiguousCertificate) {
    const char *san[3] = {"URI:" DECLARED_URI, "URI:" CERT_URI, "DNS:localhost"};
    const UA_Boolean granted[4] = {false, false, false, false};
    checkRoles(connectWithCertificate(san, 3, UA_MESSAGESECURITYMODE_SIGNANDENCRYPT),
               true, granted);
} END_TEST

/* Without a signed SecureChannel the certificate is not validated: neither
 * TrustedApplication nor an Application criterion */
START_TEST(applicationCriterion_policyNone) {
    const char *san[2] = {"URI:" CERT_URI, "DNS:localhost"};
    const UA_Boolean granted[4] = {false, false, false, false};
    checkRoles(connectWithCertificate(san, 2, UA_MESSAGESECURITYMODE_NONE),
               false, granted);
} END_TEST

static Suite *
testSuite_rbacApplication(void) {
    Suite *s = suite_create("RBAC Application criterion");
    TCase *tc = tcase_create("ApplicationUri from the client certificate");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, applicationCriterion_fromCertificate);
    tcase_add_test(tc, applicationCriterion_ambiguousCertificate);
    tcase_add_test(tc, applicationCriterion_policyNone);
    suite_add_tcase(s, tc);
    return s;
}

int main(void) {
    Suite *s = testSuite_rbacApplication();
    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
