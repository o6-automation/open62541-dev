/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */
/*
 * This example demonstrates how to configure Role-Based Access Control (RBAC)
 * in an OPC UA server using:
 * 1. User authentication via username/password, backed by an in-memory
 *    UserManagement provider (Server/ServerConfiguration/UserManagement)
 * 2. Identity mapping for the well-known roles from the server configuration
 * 3. Adding a custom role at runtime through the C API
 * 4. Extending the namespace default role permissions (OPC UA Part 5, 6.3.13)
 * 5. Explicit per-node role permissions with recursive flag
 * 6. Demo Nodes in an "AccessPermissions" folder of namespace 1, each with
 *    its own RolePermissions or AccessRestrictions
 *
 * Usage: server_rbac [--port N] [<server-cert.der> <server-key.der>
 *                                [<trustlist-cert.der> ...]]
 *
 * Built with encryption, the server offers SecurityPolicy None and
 * Basic256Sha256, Aes128Sha256RsaOaep and Aes256Sha256RsaPss with
 * SignAndEncrypt. Without a certificate a self-signed one is created at
 * startup. Without a trust list every client certificate is accepted, which
 * is meant for the demo only.
 *
 * Roles are assigned to a Session by matching its identity against the
 * IdentityCriteriaType entries of every role (OPC UA Part 18, 4.4.2):
 * - Anonymous: Matches anonymous sessions
 * - AuthenticatedUser: Matches any authenticated (non-anonymous) session
 * - UserName: Matches if the username equals the criteria string
 *
 * The well-known roles are registered by the server itself, but - apart from
 * Anonymous, AuthenticatedUser and TrustedApplication - none of them has a
 * default identity mapping. Without configuring one, no Session is ever
 * granted ConfigureAdmin or SecurityAdmin. That is what Step 2 is for.
 */

#include <open62541/plugin/accesscontrol.h>
#include <open62541/plugin/accesscontrol_default.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#ifdef UA_ENABLE_ENCRYPTION
#include <open62541/plugin/certificategroup_default.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/securitypolicy.h>
#endif

#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

static volatile UA_Boolean running = true;

static void stopHandler(int sig) {
    (void)sig;
    running = false;
}

/*************************************/
/* In-memory UserManagement provider */
/*************************************/

/* The AccessControl hooks below back the UserManagement Object of OPC UA Part
 * 18 §5 (Server/ServerConfiguration/UserManagement). The server checks the
 * caller's Roles and the Method arguments; the provider only stores the users.
 * A real provider stores salted password hashes, persists them and limits
 * the login attempts. */
#define DEMO_MAX_USERS 16

typedef struct {
    UA_String userName;
    UA_String password;
    UA_UserConfigurationMask configuration;
    UA_String description;
} DemoUser;

static DemoUser demoUsers[DEMO_MAX_USERS];
static size_t demoUsersSize;

static DemoUser *
findDemoUser(const UA_String *userName) {
    for(size_t i = 0; i < demoUsersSize; i++) {
        if(UA_String_equal(&demoUsers[i].userName, userName))
            return &demoUsers[i];
    }
    return NULL;
}

/* Compare the password in constant time, so that the response time does not
 * reveal how many leading characters match */
static UA_Boolean
checkDemoPassword(const DemoUser *user, const UA_ByteString *password) {
    return (password->length > 0 && user->password.length == password->length &&
            UA_constantTimeEqual(user->password.data, password->data,
                                 password->length));
}

static UA_StatusCode
addDemoUser(const UA_String *userName, const UA_String *password,
            UA_UserConfigurationMask configuration, const UA_String *description) {
    if(findDemoUser(userName))
        return UA_STATUSCODE_BADALREADYEXISTS;
    if(demoUsersSize >= DEMO_MAX_USERS)
        return UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
    DemoUser *u = &demoUsers[demoUsersSize];
    memset(u, 0, sizeof(DemoUser));
    UA_StatusCode res = UA_String_copy(userName, &u->userName);
    res |= UA_String_copy(password, &u->password);
    res |= UA_String_copy(description, &u->description);
    if(res != UA_STATUSCODE_GOOD) {
        UA_String_clear(&u->userName);
        UA_String_clear(&u->password);
        UA_String_clear(&u->description);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    u->configuration = configuration;
    demoUsersSize++;
    return UA_STATUSCODE_GOOD;
}

static void
clearDemoUsers(void) {
    for(size_t i = 0; i < demoUsersSize; i++) {
        UA_String_clear(&demoUsers[i].userName);
        UA_String_clear(&demoUsers[i].password);
        UA_String_clear(&demoUsers[i].description);
    }
    demoUsersSize = 0;
}

/* Login of the default AccessControl plugin. Anonymous logins have no user
 * name. */
static UA_StatusCode
demoLogin(const UA_String *userName, const UA_ByteString *password,
          size_t usernamePasswordLoginSize,
          const UA_UsernamePasswordLogin *usernamePasswordLogin,
          void **sessionContext, void *loginContext) {
    if(userName->length == 0 && password->length == 0)
        return UA_STATUSCODE_GOOD;
    const DemoUser *u = findDemoUser(userName);
    if(!u || !checkDemoPassword(u, password) ||
       (u->configuration & UA_USERCONFIGURATIONMASK_DISABLED))
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
demoGetUsers(UA_Server *server, UA_AccessControl *ac,
             UA_UserManagementDataType **users, size_t *usersSize) {
    *users = NULL;
    *usersSize = 0;
    if(demoUsersSize == 0)
        return UA_STATUSCODE_GOOD;
    UA_UserManagementDataType *out = (UA_UserManagementDataType*)
        UA_Array_new(demoUsersSize, &UA_TYPES[UA_TYPES_USERMANAGEMENTDATATYPE]);
    if(!out)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < demoUsersSize; i++) {
        res |= UA_String_copy(&demoUsers[i].userName, &out[i].userName);
        res |= UA_String_copy(&demoUsers[i].description, &out[i].description);
        out[i].userConfiguration = demoUsers[i].configuration;
    }
    if(res != UA_STATUSCODE_GOOD) {
        UA_Array_delete(out, demoUsersSize, &UA_TYPES[UA_TYPES_USERMANAGEMENTDATATYPE]);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    *users = out;
    *usersSize = demoUsersSize;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
demoGetPasswordPolicy(UA_Server *server, UA_AccessControl *ac, UA_Range *length,
                      UA_PasswordOptionsMask *options,
                      UA_LocalizedText *restrictions) {
    length->low = 8.0;
    length->high = 64.0;
    *options = UA_PASSWORDOPTIONSMASK_SUPPORTINITIALPASSWORDCHANGE |
        UA_PASSWORDOPTIONSMASK_SUPPORTDISABLEUSER |
        UA_PASSWORDOPTIONSMASK_SUPPORTDISABLEDELETEFORUSER |
        UA_PASSWORDOPTIONSMASK_SUPPORTNOCHANGEFORUSER |
        UA_PASSWORDOPTIONSMASK_SUPPORTDESCRIPTIONFORUSER;
    *restrictions = UA_LOCALIZEDTEXT_ALLOC("en-US", "8 to 64 characters");
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
demoGetUserConfiguration(UA_Server *server, UA_AccessControl *ac,
                         const UA_String *userName,
                         UA_UserConfigurationMask *configuration) {
    const DemoUser *u = findDemoUser(userName);
    if(!u)
        return UA_STATUSCODE_BADNOTFOUND;
    *configuration = u->configuration;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
demoAddUser(UA_Server *server, UA_AccessControl *ac, const UA_String *userName,
            const UA_String *password, UA_UserConfigurationMask configuration,
            const UA_String *description) {
    return addDemoUser(userName, password, configuration, description);
}

static UA_StatusCode
demoModifyUser(UA_Server *server, UA_AccessControl *ac, const UA_String *userName,
               UA_Boolean modifyPassword, const UA_String *password,
               UA_Boolean modifyConfiguration,
               UA_UserConfigurationMask configuration,
               UA_Boolean modifyDescription, const UA_String *description) {
    DemoUser *u = findDemoUser(userName);
    if(!u)
        return UA_STATUSCODE_BADNOTFOUND;
    UA_String newPassword = UA_STRING_NULL;
    UA_String newDescription = UA_STRING_NULL;
    if((modifyPassword && UA_String_copy(password, &newPassword) != UA_STATUSCODE_GOOD) ||
       (modifyDescription &&
        UA_String_copy(description, &newDescription) != UA_STATUSCODE_GOOD)) {
        UA_String_clear(&newPassword);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    if(modifyPassword) {
        UA_String_clear(&u->password);
        u->password = newPassword;
    }
    if(modifyDescription) {
        UA_String_clear(&u->description);
        u->description = newDescription;
    }
    if(modifyConfiguration)
        u->configuration = configuration;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
demoRemoveUser(UA_Server *server, UA_AccessControl *ac, const UA_String *userName) {
    DemoUser *u = findDemoUser(userName);
    if(!u)
        return UA_STATUSCODE_BADNOTFOUND;
    UA_String_clear(&u->userName);
    UA_String_clear(&u->password);
    UA_String_clear(&u->description);
    size_t idx = (size_t)(u - demoUsers);
    for(size_t i = idx; i + 1 < demoUsersSize; i++)
        demoUsers[i] = demoUsers[i + 1];
    demoUsersSize--;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
demoChangePassword(UA_Server *server, UA_AccessControl *ac,
                   const UA_String *userName, const UA_String *oldPassword,
                   const UA_String *newPassword) {
    DemoUser *u = findDemoUser(userName);
    if(!u || !checkDemoPassword(u, oldPassword))
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    UA_String copy;
    if(UA_String_copy(newPassword, &copy) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_String_clear(&u->password);
    u->password = copy;
    return UA_STATUSCODE_GOOD;
}

/*******************/
/* Server security */
/*******************/

#ifdef UA_ENABLE_ENCRYPTION
/* Load the server certificate and key, or create a self-signed certificate
 * for this run of the demo */
static UA_StatusCode
loadOrCreateCertificate(const char *certPath, const char *keyPath,
                        UA_ByteString *certificate, UA_ByteString *privateKey) {
    if(certPath) {
        *certificate = loadFile(certPath);
        *privateKey = loadFile(keyPath);
        if(certificate->length == 0 || privateKey->length == 0) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                         "Could not load the certificate %s or the key %s",
                         certPath, keyPath);
            return UA_STATUSCODE_BADNOTFOUND;
        }
        return UA_STATUSCODE_GOOD;
    }

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "No server certificate given. Creating a self-signed "
                "certificate for this run.");
    UA_String subject[3] = {UA_STRING_STATIC("C=DE"),
                            UA_STRING_STATIC("O=SampleOrganization"),
                            UA_STRING_STATIC("CN=open62541 RBAC Demo Server")};
    /* The URI must match the ApplicationUri of the server */
    UA_String subjectAltName[2] = {
        UA_STRING_STATIC("DNS:localhost"),
        UA_STRING_STATIC("URI:urn:open62541.unconfigured.application")};
    UA_KeyValueMap *kvm = UA_KeyValueMap_new();
    if(!kvm)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_UInt16 expiresIn = 14;
    UA_KeyValueMap_setScalar(kvm, UA_QUALIFIEDNAME(0, "expires-in-days"),
                             (void *)&expiresIn, &UA_TYPES[UA_TYPES_UINT16]);
    UA_StatusCode res =
        UA_CreateCertificate(UA_Log_Stdout, subject, 3, subjectAltName, 2,
                             UA_CERTIFICATEFORMAT_DER, kvm, privateKey, certificate);
    UA_KeyValueMap_delete(kvm);
    if(res != UA_STATUSCODE_GOOD)
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Creating the certificate failed: %s", UA_StatusCode_name(res));
    return res;
}

/* Restrict SecureChannels and X509 user tokens to the trusted client
 * certificates */
static UA_StatusCode
setTrustList(UA_ServerConfig *config, size_t pathsSize, char **paths) {
    UA_TrustListDataType list;
    UA_TrustListDataType_init(&list);
    list.specifiedLists = UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES;
    list.trustedCertificates = (UA_ByteString*)
        UA_Array_new(pathsSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(!list.trustedCertificates)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    list.trustedCertificatesSize = pathsSize;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < pathsSize; i++) {
        list.trustedCertificates[i] = loadFile(paths[i]);
        if(list.trustedCertificates[i].length == 0) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                         "Could not load the trusted certificate %s", paths[i]);
            res = UA_STATUSCODE_BADNOTFOUND;
        }
    }
    if(res == UA_STATUSCODE_GOOD) {
        UA_NodeId appGroup =
            UA_NS0ID(SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
        res = UA_CertificateGroup_Memorystore(&config->secureChannelPKI, &appGroup,
                                              &list, config->logging, NULL);
    }
    if(res == UA_STATUSCODE_GOOD) {
        UA_NodeId userGroup =
            UA_NS0ID(SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP);
        res = UA_CertificateGroup_Memorystore(&config->sessionPKI, &userGroup,
                                              &list, config->logging, NULL);
    }
    UA_TrustListDataType_clear(&list);
    return res;
}

/* SecurityPolicy None (for discovery and anonymous access) and the secure
 * SecurityPolicies with SignAndEncrypt */
static UA_StatusCode
configureEncryption(UA_ServerConfig *config, UA_UInt16 port,
                    size_t argsSize, char **args) {
    if(argsSize == 1) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "The server certificate needs its private key");
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    UA_ByteString certificate = UA_BYTESTRING_NULL;
    UA_ByteString privateKey = UA_BYTESTRING_NULL;
    UA_StatusCode res =
        loadOrCreateCertificate((argsSize >= 2) ? args[0] : NULL,
                                (argsSize >= 2) ? args[1] : NULL,
                                &certificate, &privateKey);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_ServerConfig_setBasics_withPort(config, port);

    /* setBasics installs a certificate check that accepts everything */
    if(res == UA_STATUSCODE_GOOD) {
        if(argsSize > 2) {
            res = setTrustList(config, argsSize - 2, &args[2]);
        } else {
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                           "No trust list given: the server ACCEPTS ALL client "
                           "certificates. This is for the demo only. Pass the "
                           "trusted client certificates as arguments.");
        }
    }

    if(res == UA_STATUSCODE_GOOD)
        res = UA_ServerConfig_addSecurityPolicyNone(config, &certificate);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_ServerConfig_addSecurityPolicyBasic256Sha256(config, &certificate,
                                                              &privateKey);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_ServerConfig_addSecurityPolicyAes128Sha256RsaOaep(config, &certificate,
                                                                   &privateKey);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_ServerConfig_addSecurityPolicyAes256Sha256RsaPss(config, &certificate,
                                                                  &privateKey);
    for(size_t i = 0; res == UA_STATUSCODE_GOOD && i < config->securityPoliciesSize; i++) {
        const UA_String *uri = &config->securityPolicies[i].policyUri;
        UA_MessageSecurityMode mode =
            (UA_String_equal(uri, &UA_SECURITY_POLICY_NONE_URI)) ?
            UA_MESSAGESECURITYMODE_NONE : UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
        res = UA_ServerConfig_addEndpoint(config, *uri, mode);
    }

    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    return res;
}
#endif /* UA_ENABLE_ENCRYPTION */

/*****************************/
/* AccessPermissions folder  */
/*****************************/

#define ROLE(name) UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_##name)

static UA_UInt32 operatorCalls;

static UA_StatusCode
operatorMethodCallback(UA_Server *server,
                       const UA_NodeId *sessionId, void *sessionContext,
                       const UA_NodeId *methodId, void *methodContext,
                       const UA_NodeId *objectId, void *objectContext,
                       size_t inputSize, const UA_Variant *input,
                       size_t outputSize, UA_Variant *output) {
    operatorCalls++;
    return UA_Variant_setScalarCopy(&output[0], &operatorCalls,
                                    &UA_TYPES[UA_TYPES_UINT32]);
}

/* Add a Variable to the AccessPermissions folder. Its RolePermissions replace
 * the namespace default: the Roles that are not listed get no permission on
 * the Node. Every Session holds the Anonymous Role. */
static UA_StatusCode
addDemoVariable(UA_Server *server, const char *name, const UA_Variant *value,
                UA_Byte accessLevel, size_t rolePermissionsSize,
                const UA_RolePermission *rolePermissions,
                UA_AccessRestrictionType accessRestrictions) {
    char id[64];
    snprintf(id, sizeof(id), "AccessPermissions.%s", name);
    UA_NodeId nodeId = UA_NODEID_STRING(1, id);

    UA_VariableAttributes attr = UA_VariableAttributes_default;
    attr.displayName = UA_LOCALIZEDTEXT("en-US", (char*)(uintptr_t)name);
    attr.dataType = value->type->typeId;
    attr.valueRank = UA_VALUERANK_SCALAR;
    attr.accessLevel = accessLevel;
    attr.value = *value;
    UA_StatusCode res =
        UA_Server_addVariableNode(server, nodeId,
                                  UA_NODEID_STRING(1, "AccessPermissions"),
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                                  UA_QUALIFIEDNAME(1, (char*)(uintptr_t)name),
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                                  attr, NULL, NULL);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_Server_setNodeRolePermissions(server, nodeId, rolePermissionsSize,
                                               rolePermissions, false, NULL);
    if(res == UA_STATUSCODE_GOOD && accessRestrictions != 0)
        res = UA_Server_setNodeAccessRestrictions(server, nodeId, accessRestrictions);
    if(res != UA_STATUSCODE_GOOD)
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Adding the demo Variable %s failed: %s", name,
                     UA_StatusCode_name(res));
    return res;
}

/* Demo Nodes in the spirit of the AccessPermission folder of the UA demo
 * servers: what a Session may do depends on its Roles and on the security of
 * its SecureChannel */
static UA_StatusCode
addAccessPermissionsFolder(UA_Server *server, const UA_NodeId operatorRoleId) {
    const UA_PermissionType B = UA_PERMISSIONTYPE_BROWSE;
    const UA_PermissionType R = UA_PERMISSIONTYPE_READ;
    const UA_PermissionType W = UA_PERMISSIONTYPE_WRITE;
    const UA_PermissionType C = UA_PERMISSIONTYPE_CALL;
    const UA_Byte RW = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;

    /* The folder is browsable for everyone. The Method on it is called with
     * the folder as the Object, which needs the Call permission as well. */
    UA_ObjectAttributes oAttr = UA_ObjectAttributes_default;
    oAttr.displayName = UA_LOCALIZEDTEXT("en-US", "AccessPermissions");
    UA_NodeId folderId = UA_NODEID_STRING(1, "AccessPermissions");
    UA_StatusCode res =
        UA_Server_addObjectNode(server, folderId,
                                UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                                UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                                UA_QUALIFIEDNAME(1, "AccessPermissions"),
                                UA_NODEID_NUMERIC(0, UA_NS0ID_FOLDERTYPE),
                                oAttr, NULL, NULL);
    const UA_RolePermission folderRp[2] = {
        {ROLE(ANONYMOUS), B}, {operatorRoleId, B | C}};
    if(res == UA_STATUSCODE_GOOD)
        res = UA_Server_setNodeRolePermissions(server, folderId, 2, folderRp,
                                               false, NULL);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* Readable by every Session, also an anonymous one */
    UA_Int32 i32 = 42;
    UA_Variant v;
    UA_Variant_setScalar(&v, &i32, &UA_TYPES[UA_TYPES_INT32]);
    const UA_RolePermission anonymousRp[1] = {{ROLE(ANONYMOUS), B | R}};
    res = addDemoVariable(server, "AnonymousReadable", &v,
                          UA_ACCESSLEVELMASK_READ, 1, anonymousRp, 0);

    /* Readable by everyone, writable by authenticated users */
    const UA_RolePermission authRp[2] = {
        {ROLE(ANONYMOUS), B | R}, {ROLE(AUTHENTICATEDUSER), B | R | W}};
    if(res == UA_STATUSCODE_GOOD)
        res = addDemoVariable(server, "AuthenticatedWritable", &v, RW, 2, authRp, 0);

    /* Visible to everyone, readable and writable by the OperatorRole */
    UA_Double dbl = 3.14;
    UA_Variant_setScalar(&v, &dbl, &UA_TYPES[UA_TYPES_DOUBLE]);
    const UA_RolePermission operatorRp[2] = {
        {ROLE(ANONYMOUS), B}, {operatorRoleId, B | R | W}};
    if(res == UA_STATUSCODE_GOOD)
        res = addDemoVariable(server, "OperatorOnly", &v, RW, 2, operatorRp, 0);

    /* Visible to everyone, readable and writable by SecurityAdmin ('admin') */
    UA_String str = UA_STRING("admin data");
    UA_Variant_setScalar(&v, &str, &UA_TYPES[UA_TYPES_STRING]);
    const UA_RolePermission adminRp[2] = {
        {ROLE(ANONYMOUS), B}, {ROLE(SECURITYADMIN), B | R | W}};
    if(res == UA_STATUSCODE_GOOD)
        res = addDemoVariable(server, "AdminOnly", &v, RW, 2, adminRp, 0);

    /* Readable by everyone, but only over an encrypted SecureChannel */
    str = UA_STRING("encrypted data");
    if(res == UA_STATUSCODE_GOOD)
        res = addDemoVariable(server, "EncryptedOnly", &v, UA_ACCESSLEVELMASK_READ,
                              1, anonymousRp,
                              UA_ACCESSRESTRICTIONTYPE_ENCRYPTIONREQUIRED);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* A Method that only the OperatorRole may call */
    UA_Argument output;
    UA_Argument_init(&output);
    output.name = UA_STRING("CallCount");
    output.description = UA_LOCALIZEDTEXT("en-US", "Number of calls so far");
    output.dataType = UA_TYPES[UA_TYPES_UINT32].typeId;
    output.valueRank = UA_VALUERANK_SCALAR;
    UA_MethodAttributes mAttr = UA_MethodAttributes_default;
    mAttr.displayName = UA_LOCALIZEDTEXT("en-US", "OperatorMethod");
    mAttr.executable = true;
    mAttr.userExecutable = true;
    UA_NodeId methodId = UA_NODEID_STRING(1, "AccessPermissions.OperatorMethod");
    res = UA_Server_addMethodNodeEx(server, methodId, folderId,
                                    UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                    UA_QUALIFIEDNAME(1, "OperatorMethod"), mAttr,
                                    operatorMethodCallback, 0, NULL, UA_NODEID_NULL,
                                    NULL, 1, &output,
                                    UA_NODEID_STRING(1, "AccessPermissions.OperatorMethod.OutputArguments"),
                                    NULL, NULL, NULL);
    const UA_RolePermission methodRp[2] = {
        {ROLE(ANONYMOUS), B}, {operatorRoleId, B | C}};
    if(res == UA_STATUSCODE_GOOD)
        res = UA_Server_setNodeRolePermissions(server, methodId, 2, methodRp,
                                               false, NULL);
    return res;
}

int main(int argc, char **argv) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    /* Parse the arguments: [--port N] [<cert> <key> [<trustlist>...]] */
    UA_UInt16 port = 4840;
    char **args = (char**)UA_calloc((size_t)argc, sizeof(char*));
    size_t argsSize = 0;
    if(!args)
        return EXIT_FAILURE;
    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            char *end = NULL;
            long p = strtol(argv[++i], &end, 10);
            if(!end || *end != 0 || p <= 0 || p > 65535) {
                UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                             "Invalid port %s", argv[i]);
                UA_free(args);
                return EXIT_FAILURE;
            }
            port = (UA_UInt16)p;
            continue;
        }
        if(argv[i][0] == '-') {
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "Usage: %s [--port N] [<server-cert.der> <server-key.der> "
                        "[<trustlist-cert.der> ...]]", argv[0]);
            UA_free(args);
            return (strcmp(argv[i], "--help") == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
        }
        args[argsSize++] = argv[i];
    }

    /* Step 1: Configure the server with username/password authentication */
    UA_ServerConfig config;
    memset(&config, 0, sizeof(UA_ServerConfig));
#ifdef UA_ENABLE_ENCRYPTION
    UA_StatusCode retval = configureEncryption(&config, port, argsSize, args);
    /* Passwords are encrypted with the server certificate (the UserTokenPolicy
     * of the None endpoint names a secure SecurityPolicy). They are never
     * sent in the clear. */
    config.allowNonePolicyPassword = false;
#else
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(argsSize > 0) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Certificates are given, but the server is built "
                     "without encryption");
        retval = UA_STATUSCODE_BADNOTSUPPORTED;
    }
    if(retval == UA_STATUSCODE_GOOD)
        retval = UA_ServerConfig_setMinimal(&config, port, NULL);
    /* Without encryption the password can only be sent in the clear. This is
     * allowed for the demo only. */
    config.allowNonePolicyPassword = true;
#endif
    UA_free(args);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_ServerConfig_clear(&config);
        return EXIT_FAILURE;
    }

    /* Strict RBAC is the default (allPermissionsForAnonymous = false): nodes
     * without explicit RolePermissions or namespace defaults use the namespace
     * templates of the configuration (config.namespaceZeroDefaultRolePermissions
     * and config.namespaceDefaultRolePermissions, see
     * UA_ServerConfig_setDefaultNamespacePermissions). Setting the flag to
     * true restores the legacy mode, where such nodes are unrestricted. It is
     * set explicitly here for clarity. */
    config.allPermissionsForAnonymous = false;
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "RBAC Mode: allPermissionsForAnonymous = %s",
                config.allPermissionsForAnonymous ? "true (INSECURE)" : "false (secure)");

    /* Configure users for authentication. They seed the UserManagement
     * provider, which then decides every login. */
    UA_UsernamePasswordLogin logins[3] = {
        {UA_STRING_STATIC("admin"), UA_STRING_STATIC("admin123")},
        {UA_STRING_STATIC("operator"), UA_STRING_STATIC("operator123")},
        {UA_STRING_STATIC("guest"), UA_STRING_STATIC("guest123")}
    };
    for(size_t i = 0; i < 3 && retval == UA_STATUSCODE_GOOD; i++) {
        UA_String description = UA_STRING("demo user");
        retval = addDemoUser(&logins[i].username, &logins[i].password,
                             UA_USERCONFIGURATIONMASK_NONE, &description);
    }

    /* Setup access control with the users (allow anonymous too for demo).
     * The login list announces the UserName token; the login callback checks
     * the credentials against the provider. */
    if(retval == UA_STATUSCODE_GOOD)
        retval = UA_AccessControl_defaultWithLoginCallback(&config, true, NULL, 3,
                                                           logins, demoLogin, NULL);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Failed to configure access control: %s", UA_StatusCode_name(retval));
        UA_ServerConfig_clear(&config);
        clearDemoUsers();
        return EXIT_FAILURE;
    }

    /* The UserManagement hooks must be in the configuration handed to
     * UA_Server_newWithConfig: the server binds the UserManagement Object
     * while it is created. They are set after UA_AccessControl_default*,
     * which reinitializes the AccessControl plugin. */
    config.accessControl.getUsers = demoGetUsers;
    config.accessControl.getPasswordPolicy = demoGetPasswordPolicy;
    config.accessControl.getUserConfiguration = demoGetUserConfiguration;
    config.accessControl.addUser = demoAddUser;
    config.accessControl.modifyUser = demoModifyUser;
    config.accessControl.removeUser = demoRemoveUser;
    config.accessControl.changePassword = demoChangePassword;

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "Configured users: admin, operator, guest and anonymous");

    /* Step 2: Give the well-known roles an identity mapping.
     *
     * config.wellKnownRoleMappings is applied to the roles the server registers
     * during startup, so the mapping is in place before the first Session is
     * activated. Each entry names its target by roleName (or roleId) and
     * replaces that role's mapping rules and filters.
     *
     * 'admin' is mapped to both ConfigureAdmin - whose permissions arrive
     * indirectly through the namespace default templates (Step 4) - and
     * SecurityAdmin,
     * which is the role the RoleSet management Methods require. There is no
     * default SecurityAdmin, so without this no client could ever administer
     * the RoleSet over the wire.
     *
     * The mandatory Anonymous, AuthenticatedUser and TrustedApplication roles
     * cannot be remapped; an entry for one of them is rejected. */
    {
        const char *adminRoles[2] = {"ConfigureAdmin", "SecurityAdmin"};
        UA_Role *mappings = (UA_Role*)UA_calloc(2, sizeof(UA_Role));
        if(!mappings) {
            UA_ServerConfig_clear(&config);
            clearDemoUsers();
            return EXIT_FAILURE;
        }
        for(size_t i = 0; i < 2; i++) {
            UA_Role_init(&mappings[i]);
            mappings[i].roleName = UA_QUALIFIEDNAME_ALLOC(0, adminRoles[i]);
            mappings[i].identityMappingRules = (UA_IdentityMappingRuleType*)
                UA_calloc(1, sizeof(UA_IdentityMappingRuleType));
            if(!mappings[i].identityMappingRules)
                continue;
            UA_IdentityMappingRuleType_init(&mappings[i].identityMappingRules[0]);
            mappings[i].identityMappingRules[0].criteriaType =
                UA_IDENTITYCRITERIATYPE_USERNAME;
            mappings[i].identityMappingRules[0].criteria = UA_STRING_ALLOC("admin");
            mappings[i].identityMappingRulesSize = 1;
        }
        /* Ownership moves to the config; UA_ServerConfig_clear frees it */
        config.wellKnownRoleMappings = mappings;
        config.wellKnownRoleMappingsSize = 2;
    }

    /* Create the server. The well-known roles are registered and the mappings
     * configured above are applied during creation. */
    UA_Server *server = UA_Server_newWithConfig(&config);
    if(!server) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Failed to create server");
        clearDemoUsers();
        return EXIT_FAILURE;
    }

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "Mapped 'admin' to the ConfigureAdmin and SecurityAdmin roles");

    UA_NodeId configureAdminRoleId = UA_NODEID_NULL;
    {
        UA_Role confAdminRole;
        if(UA_Server_getRole(server, UA_QUALIFIEDNAME(0, "ConfigureAdmin"),
                             &confAdminRole) == UA_STATUSCODE_GOOD) {
            UA_NodeId_copy(&confAdminRole.roleId, &configureAdminRoleId);
            UA_Role_clear(&confAdminRole);
        }
    }

    /* Step 3: Add a custom role at runtime, the counterpart to Step 2.
     * Custom roles can also be defined up front in config.roles (or under the
     * "rbac" key of a JSON server configuration); those are protected and
     * cannot be removed again at runtime. Roles added here can. Either way the
     * identity mapping rules are what decide who is granted the role. */
    UA_Role operatorRole;
    UA_Role_init(&operatorRole);
    operatorRole.roleName = UA_QUALIFIEDNAME(0, "OperatorRole");

    UA_NodeId operatorRoleId;
    retval = UA_Server_addRole(server, &operatorRole, &operatorRoleId);

    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Failed to add OperatorRole: %s", UA_StatusCode_name(retval));
        UA_Server_delete(server);
        clearDemoUsers();
        return EXIT_FAILURE;
    }

    /* Add UserName identity mapping for "operator" user */
    {
        UA_Role updRole;
        retval = UA_Server_getRoleById(server, operatorRoleId, &updRole);
        if(retval == UA_STATUSCODE_GOOD) {
            UA_IdentityMappingRuleType *rules = (UA_IdentityMappingRuleType*)
                UA_realloc(updRole.identityMappingRules,
                           (updRole.identityMappingRulesSize + 1) *
                           sizeof(UA_IdentityMappingRuleType));
            if(rules) {
                updRole.identityMappingRules = rules;
                UA_IdentityMappingRuleType_init(&rules[updRole.identityMappingRulesSize]);
                rules[updRole.identityMappingRulesSize].criteriaType =
                    UA_IDENTITYCRITERIATYPE_USERNAME;
                rules[updRole.identityMappingRulesSize].criteria =
                    UA_STRING_ALLOC("operator");
                updRole.identityMappingRulesSize++;
                retval = UA_Server_updateRole(server, &updRole);
            } else {
                retval = UA_STATUSCODE_BADOUTOFMEMORY;
            }
            UA_Role_clear(&updRole);
        }
        if(retval == UA_STATUSCODE_GOOD) {
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "OperatorRole added with UserName criteria for 'operator'");
        } else {
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                           "Failed to add identity rule: %s", UA_StatusCode_name(retval));
        }
    }

    /* Step 4: Extend the namespace default permissions of namespace 1.
     * Per OPC UA Part 5 (6.3.13), if a node has no explicit RolePermissions,
     * the DefaultRolePermissions of its namespace apply. Without an explicit
     * default the server uses the templates of the configuration (Part 3,
     * Table 2; see UA_ServerConfig_setDefaultNamespacePermissions). They give
     * the well-known roles their baseline permissions: every Session reads the
     * Server Object in Namespace Zero (NamespaceArray, ServerStatus, ...) and
     * browses namespace 1, ConfigureAdmin manages namespace 1. An explicit
     * default replaces the template, so start from the current default and
     * add the custom OperatorRole to it. Namespace Zero keeps its template. */
    {
        size_t nsDefaultsSize = 0;
        UA_RolePermission *nsDefaults = NULL;
        retval = UA_Server_getNamespaceDefaultRolePermissions(server, 1,
                                                              &nsDefaultsSize,
                                                              &nsDefaults);
        UA_RolePermission *extended = NULL;
        if(retval == UA_STATUSCODE_GOOD) {
            extended = (UA_RolePermission*)
                UA_realloc(nsDefaults, (nsDefaultsSize + 1) * sizeof(UA_RolePermission));
            if(!extended)
                retval = UA_STATUSCODE_BADOUTOFMEMORY;
        }
        if(retval == UA_STATUSCODE_GOOD) {
            nsDefaults = extended;
            nsDefaults[nsDefaultsSize].roleId = operatorRoleId; /* not owned */
            nsDefaults[nsDefaultsSize].permissions =
                UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ |
                UA_PERMISSIONTYPE_WRITE | UA_PERMISSIONTYPE_CALL;
            retval = UA_Server_setNamespaceDefaultRolePermissions(server, 1,
                                                                  nsDefaultsSize + 1,
                                                                  nsDefaults);
        }
        for(size_t i = 0; i < nsDefaultsSize; i++)
            UA_NodeId_clear(&nsDefaults[i].roleId);
        UA_free(nsDefaults);
        if(retval == UA_STATUSCODE_GOOD) {
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "NS1 default extended: OperatorRole=BROWSE|READ|WRITE|CALL");
        } else {
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                           "Failed to extend the NS1 default: %s",
                           UA_StatusCode_name(retval));
        }
    }

    /* Step 5: Configure explicit permissions on ServerStatus.
     * Explicit RolePermissions replace the namespace default for the node.
     * All roles that need access must be listed - including Anonymous, which
     * every Session holds, so that every client still reads the
     * ServerStatus. */
    UA_NodeId serverStatusId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERSTATUS);
    UA_UInt32 publicPermissions = UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ;
    UA_UInt32 permissions = UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ |
                            UA_PERMISSIONTYPE_READROLEPERMISSIONS;
    retval = UA_Server_addRolePermissions(server, serverStatusId,
                                          UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS),
                                          publicPermissions, false, false);

    /* Add permissions for OperatorRole on ServerStatus */
    if(retval == UA_STATUSCODE_GOOD)
        retval = UA_Server_addRolePermissions(server, serverStatusId, operatorRoleId,
                                              permissions, false, false);
    if(retval == UA_STATUSCODE_GOOD) {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "ServerStatus: BROWSE|READ for everyone, "
                    "BROWSE|READ|READROLEPERMISSIONS for OperatorRole");
    }

    /* ConfigureAdmin needs explicit listing since node-level overrides defaults */
    if(!UA_NodeId_isNull(&configureAdminRoleId)) {
        retval = UA_Server_addRolePermissions(server, serverStatusId,
                                              configureAdminRoleId,
                                              UA_PERMISSIONTYPE_ALL, false, false);
        if(retval == UA_STATUSCODE_GOOD) {
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "Added ALL permissions for ConfigureAdmin on ServerStatus");
        }
    }

    /* Step 6: Configure permissions on BuildInfo node with recursive flag */
    UA_NodeId buildInfoId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERSTATUS_BUILDINFO);
    UA_UInt32 buildInfoPermissions = UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ |
                                     UA_PERMISSIONTYPE_READROLEPERMISSIONS |
                                     UA_PERMISSIONTYPE_WRITE;

    /* The new RolePermissions of BuildInfo and its children replace the
     * namespace default as well. Keep them readable for everyone. */
    retval = UA_Server_addRolePermissions(server, buildInfoId,
                                          UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS),
                                          publicPermissions, false, true);

    /* Add permissions for OperatorRole on BuildInfo and all its children (recursive) */
    if(retval == UA_STATUSCODE_GOOD)
        retval = UA_Server_addRolePermissions(server, buildInfoId, operatorRoleId,
                                              buildInfoPermissions, false, true);
    if(retval == UA_STATUSCODE_GOOD) {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Added BROWSE|READ|READROLEPERMISSIONS|WRITE permissions for "
                    "OperatorRole on BuildInfo (recursive)");
    } else {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Failed to add recursive permissions for OperatorRole on BuildInfo: %s",
                     UA_StatusCode_name(retval));
    }

    /* Add all permissions for ConfigureAdmin on BuildInfo and children (recursive) */
    if(!UA_NodeId_isNull(&configureAdminRoleId)) {
        retval = UA_Server_addRolePermissions(server, buildInfoId,
                                              configureAdminRoleId,
                                              UA_PERMISSIONTYPE_ALL, false, true);
        if(retval == UA_STATUSCODE_GOOD) {
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "Added ALL permissions for ConfigureAdmin on BuildInfo "
                        "(recursive)");
        }
    }

    /* Verify one child node has permissions set (recursive example) */
    UA_NodeId productUriId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERSTATUS_BUILDINFO_PRODUCTURI);
    size_t rpSize = 0;
    UA_RolePermission *rpArr = NULL;
    retval = UA_Server_getNodeRolePermissions(server, productUriId, &rpSize, &rpArr);
    if(retval == UA_STATUSCODE_GOOD && rpSize > 0) {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "BuildInfo.ProductUri has %zu role permission entries (via recursive flag)",
                    rpSize);
        UA_Array_delete(rpArr, rpSize, &UA_TYPES[UA_TYPES_ROLEPERMISSIONTYPE]);
    }

    /* Print all available roles */
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "\n=== Available Roles ===");
    size_t allRolesSize = 0;
    UA_QualifiedName *allRoleNames = NULL;
    retval = UA_Server_getRoles(server, &allRolesSize, &allRoleNames);
    if(retval == UA_STATUSCODE_GOOD) {
        for(size_t i = 0; i < allRolesSize; i++) {
            UA_Role role;
            UA_StatusCode res = UA_Server_getRole(server, allRoleNames[i], &role);
            if(res == UA_STATUSCODE_GOOD) {
                UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                            "  %.*s - %zu identity rule(s)",
                            (int)role.roleName.name.length, role.roleName.name.data,
                            role.identityMappingRulesSize);
                for(size_t j = 0; j < role.identityMappingRulesSize; j++) {
                    const char *criteriaTypeName = "Unknown";
                    switch(role.identityMappingRules[j].criteriaType) {
                        case UA_IDENTITYCRITERIATYPE_ANONYMOUS:
                            criteriaTypeName = "Anonymous"; break;
                        case UA_IDENTITYCRITERIATYPE_AUTHENTICATEDUSER:
                            criteriaTypeName = "AuthenticatedUser"; break;
                        case UA_IDENTITYCRITERIATYPE_USERNAME:
                            criteriaTypeName = "UserName"; break;
                        case UA_IDENTITYCRITERIATYPE_THUMBPRINT:
                            criteriaTypeName = "Thumbprint"; break;
                        case UA_IDENTITYCRITERIATYPE_ROLE:
                            criteriaTypeName = "Role"; break;
                        case UA_IDENTITYCRITERIATYPE_GROUPID:
                            criteriaTypeName = "GroupId"; break;
                        case UA_IDENTITYCRITERIATYPE_APPLICATION:
                            criteriaTypeName = "Application"; break;
                        case UA_IDENTITYCRITERIATYPE_X509SUBJECT:
                            criteriaTypeName = "X509Subject"; break;
                        case UA_IDENTITYCRITERIATYPE_TRUSTEDAPPLICATION:
                            criteriaTypeName = "TrustedApplication"; break;
                        default: break;
                    }
                    if(role.identityMappingRules[j].criteria.length > 0) {
                        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                                    "      -> %s: '%.*s'", criteriaTypeName,
                                    (int)role.identityMappingRules[j].criteria.length,
                                    role.identityMappingRules[j].criteria.data);
                    } else {
                        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                                    "      -> %s", criteriaTypeName);
                    }
                }
                UA_Role_clear(&role);
            }
            UA_QualifiedName_clear(&allRoleNames[i]);
        }
        UA_free(allRoleNames);
    }

    /* Step 7: Demo Nodes with their own RolePermissions */
    retval = addAccessPermissionsFolder(server, operatorRoleId);
    if(retval == UA_STATUSCODE_GOOD)
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Added the folder Objects/AccessPermissions (ns=1)");

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "\n=== Role Assignment ===\n"
                "When clients connect, roles are automatically assigned based on:\n"
                "  - Anonymous login -> Anonymous role\n"
                "  - user 'admin'    -> ConfigureAdmin + SecurityAdmin + "
                "AuthenticatedUser\n"
                "  - user 'operator' -> OperatorRole + AuthenticatedUser\n"
                "  - user 'guest'    -> AuthenticatedUser only\n"
                "Every Session additionally holds the Anonymous role.");

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "\n=== Objects/AccessPermissions (ns=1) ===\n"
                "  AnonymousReadable      read: everyone\n"
                "  AuthenticatedWritable  read: everyone, write: authenticated users\n"
                "  OperatorOnly           read/write: OperatorRole ('operator')\n"
                "  AdminOnly              read/write: SecurityAdmin ('admin')\n"
                "  EncryptedOnly          read: everyone over SignAndEncrypt\n"
                "  OperatorMethod         call: OperatorRole ('operator')");

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "\n=== Administering the RoleSet and the users ===\n"
                "The RoleSet Methods (AddRole, AddIdentity, ...) and the\n"
                "UserManagement Methods (AddUser, ModifyUser, ...) require the\n"
                "SecurityAdmin role ('admin') AND an encrypted SecureChannel.\n"
                "Over SecurityPolicy None they answer BadSecurityModeInsufficient.");

    /* Run the server until interrupted */
    retval = UA_Server_run_startup(server);
    if(retval == UA_STATUSCODE_GOOD) {
        UA_ServerConfig *sc = UA_Server_getConfig(server);
        for(size_t i = 0; i < sc->applicationDescription.discoveryUrlsSize; i++)
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "Server is running at %S",
                        sc->applicationDescription.discoveryUrls[i]);
        for(size_t i = 0; i < sc->endpointsSize; i++) {
            const char *mode = "None";
            if(sc->endpoints[i].securityMode == UA_MESSAGESECURITYMODE_SIGN)
                mode = "Sign";
            else if(sc->endpoints[i].securityMode ==
                    UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
                mode = "SignAndEncrypt";
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "  Endpoint %S (%s)",
                        sc->endpoints[i].securityPolicyUri, mode);
        }
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Users: admin/admin123, operator/operator123, guest/guest123 "
                    "and anonymous");
#ifdef UA_ENABLE_ENCRYPTION
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Passwords are always encrypted: log in over a SignAndEncrypt "
                    "endpoint, or over None with a client certificate");
#endif
        while(running)
            UA_Server_run_iterate(server, true);
        retval = UA_Server_run_shutdown(server);
    }

    UA_NodeId_clear(&operatorRoleId);
    UA_NodeId_clear(&configureAdminRoleId);
    UA_Server_delete(server);
    clearDemoUsers();

    return retval == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}
