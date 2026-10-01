/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

/* The default RolePermissions of the namespaces: the templates of the server
 * configuration in strict mode and the NamespaceMetadata Objects that publish
 * them. Uses in-process Sessions; the server has no TCP listener. */

#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/nodeids.h>

#include "server/ua_server_internal.h"
#include "server/ua_server_rbac.h"
#include "server/ua_services.h"
#include "server/ua_subscription.h"

#include "test_helpers.h"

#include <check.h>
#include <stdlib.h>

#define ROLE(id) UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_##id)

#define B   UA_PERMISSIONTYPE_BROWSE
#define R   UA_PERMISSIONTYPE_READ
#define W   UA_PERMISSIONTYPE_WRITE
#define WA  UA_PERMISSIONTYPE_WRITEATTRIBUTE
#define C   UA_PERMISSIONTYPE_CALL
#define RE  UA_PERMISSIONTYPE_RECEIVEEVENTS
#define RH  UA_PERMISSIONTYPE_READHISTORY
#define RRP UA_PERMISSIONTYPE_READROLEPERMISSIONS
#define AN  UA_PERMISSIONTYPE_ADDNODE
#define ARF UA_PERMISSIONTYPE_ADDREFERENCE
#define RRF UA_PERMISSIONTYPE_REMOVEREFERENCE

static UA_Server *server = NULL;

static UA_Server *
newServer(UA_Boolean strict) {
    UA_Server *s = UA_Server_newForUnitTest();
    ck_assert(s != NULL);
    UA_ServerConfig *config = UA_Server_getConfig(s);
    config->tcpEnabled = false;
    config->allPermissionsForAnonymous = !strict;
    ck_assert_uint_eq(UA_Server_run_startup(s), UA_STATUSCODE_GOOD);
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

static UA_Session *
createSessionWithRole(const UA_NodeId role) {
    return createSessionWithRoles(1, &role);
}

static UA_NodeId
addObject(UA_UInt16 ns, const char *name) {
    UA_ObjectAttributes attr = UA_ObjectAttributes_default;
    attr.displayName = UA_LOCALIZEDTEXT("en-US", (char*)(uintptr_t)name);
    UA_NodeId nodeId = UA_NODEID_STRING(ns, (char*)(uintptr_t)name);
    ck_assert_uint_eq(UA_Server_addObjectNode(server, nodeId, UA_NS0ID(OBJECTSFOLDER),
                                              UA_NS0ID(ORGANIZES),
                                              UA_QUALIFIEDNAME(ns, (char*)(uintptr_t)name),
                                              UA_NS0ID(BASEOBJECTTYPE),
                                              attr, NULL, NULL),
                      UA_STATUSCODE_GOOD);
    return nodeId;
}

static UA_PermissionType
effective(const UA_Session *session, const UA_NodeId nodeId) {
    UA_PermissionType permissions = 0;
    ck_assert_uint_eq(UA_Server_getEffectivePermissions(server, &session->sessionId,
                                                        &nodeId, &permissions),
                      UA_STATUSCODE_GOOD);
    return permissions;
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

static UA_StatusCode
readStatusAs(UA_Session *session, const UA_NodeId nodeId, UA_UInt32 attributeId) {
    UA_DataValue dv = readAs(session, nodeId, attributeId);
    UA_StatusCode res = (dv.hasStatus) ? dv.status : UA_STATUSCODE_GOOD;
    UA_DataValue_clear(&dv);
    return res;
}

/* The value (attribute or Variable) is a RolePermissionType array with the
 * expected entries */
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

/*****************************************/
/* Namespace Default RolePermission Templates */
/*****************************************/

/* Namespace Zero: Browse, Read, Call and ReceiveEvents for everybody. Only
 * ConfigureAdmin writes (the non-security configuration) and adds or removes
 * References. The Observer-like Roles may additionally read history. */
START_TEST(template_namespaceZero) {
    const UA_NodeId serverStatus = UA_NS0ID(SERVER_SERVERSTATUS);
    UA_Session *anonymous = createSessionWithRole(ROLE(ANONYMOUS));
    ck_assert_uint_eq(effective(anonymous, serverStatus), B | R | C | RE);

    UA_Session *operatorSession = createSessionWithRole(ROLE(OPERATOR));
    ck_assert_uint_eq(effective(operatorSession, serverStatus), B | R | C | RH | RE);

    UA_Session *securityAdmin = createSessionWithRole(ROLE(SECURITYADMIN));
    ck_assert_uint_eq(effective(securityAdmin, serverStatus), B | R | C | RE | RRP);

    UA_Session *configureAdmin = createSessionWithRole(ROLE(CONFIGUREADMIN));
    UA_PermissionType ca = effective(configureAdmin, serverStatus);
    ck_assert_uint_eq(ca, B | R | W | WA | C | RE | ARF | RRF);
    ck_assert(!(ca & AN));
    ck_assert(!(ca & UA_PERMISSIONTYPE_DELETENODE));
    ck_assert(!(effective(operatorSession, serverStatus) & (W | WA | ARF | RRF)));

    /* The security configuration keeps its own RolePermissions */
    const UA_NodeId roleSet = UA_NS0ID(SERVER_SERVERCAPABILITIES_ROLESET);
    const UA_NodeId auditEventType = UA_NS0ID(AUDITEVENTTYPE);
    const UA_NodeId addIdentity = UA_NS0ID(ROLETYPE_ADDIDENTITY);
    ck_assert(!(effective(configureAdmin, roleSet) & (ARF | RRF)));
    ck_assert(!(effective(configureAdmin, auditEventType) & (ARF | RRF)));
    ck_assert(!(effective(configureAdmin, addIdentity) & (ARF | RRF)));
} END_TEST

static UA_StatusCode
addObjectAs(UA_Session *session, const UA_NodeId nodeId, const UA_NodeId parentId) {
    UA_ObjectAttributes attr = UA_ObjectAttributes_default;
    attr.displayName = UA_LOCALIZEDTEXT("en-US", "Added");
    UA_AddNodesItem item;
    UA_AddNodesItem_init(&item);
    item.parentNodeId.nodeId = parentId;
    item.referenceTypeId = UA_NS0ID(ORGANIZES);
    item.requestedNewNodeId.nodeId = nodeId;
    item.browseName = UA_QUALIFIEDNAME(1, "Added");
    item.nodeClass = UA_NODECLASS_OBJECT;
    item.typeDefinition.nodeId = UA_NS0ID(BASEOBJECTTYPE);
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
    UA_AddNodesResponse_clear(&response);
    return res;
}

/* AddNodes adds a Reference from the parent and needs AddReference there.
 * ConfigureAdmin has it in Namespace Zero, so it can add the Nodes of its
 * namespace below the ObjectsFolder. Operator cannot. */
START_TEST(template_configureAdminAddsBelowObjectsFolder) {
    const UA_NodeId objectsFolder = UA_NS0ID(OBJECTSFOLDER);
    const UA_NodeId nodeId = UA_NODEID_STRING(1, "Added");
    UA_NodeClass nodeClass;

    UA_Session *operatorSession = createSessionWithRole(ROLE(OPERATOR));
    ck_assert_uint_eq(addObjectAs(operatorSession, nodeId, objectsFolder),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert_uint_eq(UA_Server_readNodeClass(server, nodeId, &nodeClass),
                      UA_STATUSCODE_BADNODEIDUNKNOWN);

    UA_Session *configureAdmin = createSessionWithRole(ROLE(CONFIGUREADMIN));
    ck_assert_uint_eq(addObjectAs(configureAdmin, nodeId, objectsFolder),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_readNodeClass(server, nodeId, &nodeClass),
                      UA_STATUSCODE_GOOD);
} END_TEST

/* The other namespaces: Anonymous may only browse, authenticated users read,
 * Operators write and call, ConfigureAdmin manages the address space */
START_TEST(template_namespaceOne) {
    UA_NodeId nodeId = addObject(1, "TemplateNode");

    UA_Session *anonymous = createSessionWithRole(ROLE(ANONYMOUS));
    ck_assert_uint_eq(effective(anonymous, nodeId), B);

    const UA_NodeId userRoles[2] = {ROLE(ANONYMOUS), ROLE(AUTHENTICATEDUSER)};
    UA_Session *user = createSessionWithRoles(2, userRoles);
    ck_assert_uint_eq(effective(user, nodeId), B | R);

    UA_Session *operatorSession = createSessionWithRole(ROLE(OPERATOR));
    UA_PermissionType op = effective(operatorSession, nodeId);
    ck_assert_uint_eq(op & (W | C), W | C);
    ck_assert(!(op & AN));

    UA_Session *configureAdmin = createSessionWithRole(ROLE(CONFIGUREADMIN));
    UA_PermissionType ns = 0;
    ck_assert_uint_eq(UA_Server_getEffectiveNamespacePermissions(
                          server, &configureAdmin->sessionId, 1, &ns),
                      UA_STATUSCODE_GOOD);
    ck_assert(ns & AN);
    ck_assert(effective(configureAdmin, nodeId) & UA_PERMISSIONTYPE_DELETENODE);
} END_TEST

/* An explicit namespace default beats the template. Removing it falls back to
 * the template again. */
START_TEST(template_explicitDefaultWins) {
    UA_NodeId nodeId = addObject(1, "ExplicitDefault");
    UA_Session *anonymous = createSessionWithRole(ROLE(ANONYMOUS));
    ck_assert_uint_eq(effective(anonymous, nodeId), B);

    UA_RolePermission entry = {ROLE(ANONYMOUS), B | R};
    ck_assert_uint_eq(UA_Server_setNamespaceDefaultRolePermissions(server, 1, 1,
                                                                   &entry),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(effective(anonymous, nodeId), B | R);

    /* The getter reports the explicit default */
    size_t entriesSize = 0;
    UA_RolePermission *entries = NULL;
    ck_assert_uint_eq(UA_Server_getNamespaceDefaultRolePermissions(
                          server, 1, &entriesSize, &entries),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(entriesSize, 1);
    UA_NodeId_clear(&entries[0].roleId);
    UA_free(entries);

    /* An explicit empty default denies everything, the template does not
     * apply */
    ck_assert_uint_eq(UA_Server_setNamespaceDefaultRolePermissions(server, 1, 0,
                                                                   NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(effective(anonymous, nodeId), 0);

    ck_assert_uint_eq(UA_Server_removeNamespaceDefaultRolePermissions(server, 1),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(effective(anonymous, nodeId), B);

    /* Without an explicit default the getter reports the template */
    const UA_RolePermissionSet *tmpl =
        &UA_Server_getConfig(server)->namespaceDefaultRolePermissions;
    ck_assert_uint_eq(UA_Server_getNamespaceDefaultRolePermissions(
                          server, 1, &entriesSize, &entries),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(entriesSize, tmpl->rolePermissionsSize);
    for(size_t i = 0; i < entriesSize; i++)
        UA_NodeId_clear(&entries[i].roleId);
    UA_free(entries);
} END_TEST

/* A namespace added at runtime uses the template without configuration */
START_TEST(template_runtimeNamespace) {
    UA_UInt16 ns = UA_Server_addNamespace(server, "urn:rbac:template:runtime");
    ck_assert_uint_gt(ns, 1);
    UA_NodeId nodeId = addObject(ns, "RuntimeNamespaceNode");

    UA_Session *anonymous = createSessionWithRole(ROLE(ANONYMOUS));
    ck_assert_uint_eq(effective(anonymous, nodeId), B);
    UA_Session *operatorSession = createSessionWithRole(ROLE(OPERATOR));
    ck_assert_uint_eq(effective(operatorSession, nodeId) & (W | C), W | C);
} END_TEST

/* The RolePermission attributes of a Node without override: RolePermissions
 * is empty (no override), UserRolePermissions the template filtered to the
 * Session's Roles */
START_TEST(template_attributes) {
    UA_NodeId nodeId = addObject(1, "InheritsTemplate");

    UA_Session *securityAdmin = createSessionWithRole(ROLE(SECURITYADMIN));
    expectRolePermissions(securityAdmin, nodeId, UA_ATTRIBUTEID_ROLEPERMISSIONS,
                          0, NULL);
    UA_RolePermission secAdminEntry = {ROLE(SECURITYADMIN), B | R | RRP};
    expectRolePermissions(securityAdmin, nodeId, UA_ATTRIBUTEID_USERROLEPERMISSIONS,
                          1, &secAdminEntry);

    /* Without ReadRolePermissions only UserRolePermissions is readable */
    const UA_NodeId userRoles[2] = {ROLE(ANONYMOUS), ROLE(AUTHENTICATEDUSER)};
    UA_Session *user = createSessionWithRoles(2, userRoles);
    ck_assert_uint_eq(readStatusAs(user, nodeId, UA_ATTRIBUTEID_ROLEPERMISSIONS),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    UA_RolePermission userEntries[2] = {{ROLE(ANONYMOUS), B},
                                        {ROLE(AUTHENTICATEDUSER), B | R}};
    expectRolePermissions(user, nodeId, UA_ATTRIBUTEID_USERROLEPERMISSIONS,
                          2, userEntries);

    /* A Role without a template entry gets an empty list */
    UA_Role role;
    UA_Role_init(&role);
    role.roleName = UA_QUALIFIEDNAME(1, "NoTemplateEntry");
    role.customConfiguration = true; /* Assigned through the session API */
    UA_NodeId roleId;
    ck_assert_uint_eq(UA_Server_addRole(server, &role, &roleId), UA_STATUSCODE_GOOD);
    UA_Session *custom = createSessionWithRoles(1, &roleId);
    ck_assert_uint_eq(readStatusAs(custom, nodeId, UA_ATTRIBUTEID_USERROLEPERMISSIONS),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    UA_NodeId_clear(&roleId);
} END_TEST

/* Legacy mode (allPermissionsForAnonymous) ignores the templates */
START_TEST(template_ignoredInLegacyMode) {
    UA_NodeId nodeId = addObject(1, "LegacyNode");
    ck_assert(UA_Server_getConfig(server)->namespaceDefaultRolePermissions.
              rolePermissionsSize > 0);
    UA_Session *anonymous = createSessionWithRole(ROLE(ANONYMOUS));
    ck_assert_uint_eq(effective(anonymous, nodeId), UA_PERMISSIONTYPE_ALL);
    ck_assert_uint_eq(effective(anonymous, UA_NS0ID(SERVER_SERVERSTATUS)),
                      UA_PERMISSIONTYPE_ALL);
    ck_assert_uint_eq(readStatusAs(anonymous, nodeId, UA_ATTRIBUTEID_ROLEPERMISSIONS),
                      UA_STATUSCODE_BADATTRIBUTEIDINVALID);

    size_t entriesSize = 1;
    UA_RolePermission *entries = NULL;
    ck_assert_uint_eq(UA_Server_getNamespaceDefaultRolePermissions(
                          server, 1, &entriesSize, &entries),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(entriesSize, 0);

    /* Switching to strict mode applies them at once */
    UA_Server_getConfig(server)->allPermissionsForAnonymous = false;
    ck_assert_uint_eq(effective(anonymous, nodeId), B);
    UA_Server_getConfig(server)->allPermissionsForAnonymous = true;
} END_TEST

/* A template that names an unknown Role aborts the startup */
START_TEST(template_unknownRoleRejected) {
    for(size_t ns = 0; ns < 2; ns++) {
        UA_ServerConfig sc;
        memset(&sc, 0, sizeof(UA_ServerConfig));
        sc.logging = UA_Log_Stdout_new(UA_LOGLEVEL_INFO);
        ck_assert_uint_eq(UA_ServerConfig_setMinimal(&sc, 0, NULL),
                          UA_STATUSCODE_GOOD);
        UA_RolePermissionSet *tmpl = (ns == 0) ?
            &sc.namespaceZeroDefaultRolePermissions :
            &sc.namespaceDefaultRolePermissions;
        UA_RolePermission *grown = (UA_RolePermission*)
            UA_realloc(tmpl->rolePermissions,
                       (tmpl->rolePermissionsSize + 1) * sizeof(UA_RolePermission));
        ck_assert_ptr_ne(grown, NULL);
        tmpl->rolePermissions = grown;
        grown[tmpl->rolePermissionsSize].roleId = UA_NODEID_NUMERIC(1, 99999);
        grown[tmpl->rolePermissionsSize].permissions = B;
        tmpl->rolePermissionsSize++;
        ck_assert_ptr_eq(UA_Server_newWithConfig(&sc), NULL);
    }

    /* A custom config Role may be used */
    UA_ServerConfig sc;
    memset(&sc, 0, sizeof(UA_ServerConfig));
    sc.logging = UA_Log_Stdout_new(UA_LOGLEVEL_INFO);
    ck_assert_uint_eq(UA_ServerConfig_setMinimal(&sc, 0, NULL), UA_STATUSCODE_GOOD);
    sc.roles = (UA_Role*)UA_calloc(1, sizeof(UA_Role));
    ck_assert_ptr_ne(sc.roles, NULL);
    sc.rolesSize = 1;
    UA_Role_init(&sc.roles[0]);
    sc.roles[0].roleId = UA_NODEID_NUMERIC(1, 99999);
    sc.roles[0].roleName = UA_QUALIFIEDNAME_ALLOC(1, "TemplateRole");
    UA_RolePermissionSet_clear(&sc.namespaceDefaultRolePermissions);
    sc.namespaceDefaultRolePermissions.rolePermissions =
        (UA_RolePermission*)UA_calloc(1, sizeof(UA_RolePermission));
    ck_assert_ptr_ne(sc.namespaceDefaultRolePermissions.rolePermissions, NULL);
    sc.namespaceDefaultRolePermissions.rolePermissionsSize = 1;
    sc.namespaceDefaultRolePermissions.rolePermissions[0].roleId =
        UA_NODEID_NUMERIC(1, 99999);
    sc.namespaceDefaultRolePermissions.rolePermissions[0].permissions = B;
    UA_Server *s = UA_Server_newWithConfig(&sc);
    ck_assert_ptr_ne(s, NULL);
    UA_Server_delete(s);
} END_TEST

/*****************************/
/* NamespaceMetadata Objects */
/*****************************/

/* The NamespaceMetadata Objects under Server/Namespaces whose NamespaceUri is
 * the URI */
static size_t
findMetadataObjects(const UA_String uri, UA_NodeId *first) {
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = UA_NS0ID(SERVER_NAMESPACES);
    bd.referenceTypeId = UA_NS0ID(HASCOMPONENT);
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.nodeClassMask = UA_NODECLASS_OBJECT;
    bd.resultMask = UA_BROWSERESULTMASK_TYPEDEFINITION;
    UA_BrowseResult br = UA_Server_browse(server, 0, &bd);
    ck_assert_uint_eq(br.statusCode, UA_STATUSCODE_GOOD);
    size_t found = 0;
    for(size_t i = 0; i < br.referencesSize; i++) {
        const UA_ReferenceDescription *rd = &br.references[i];
        UA_NodeId nmType = UA_NS0ID(NAMESPACEMETADATATYPE);
        if(!UA_NodeId_equal(&rd->typeDefinition.nodeId, &nmType))
            continue;
        UA_Variant v;
        UA_Variant_init(&v);
        if(UA_Server_readObjectProperty(server, rd->nodeId.nodeId,
                                        UA_QUALIFIEDNAME(0, "NamespaceUri"),
                                        &v) == UA_STATUSCODE_GOOD &&
           UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_STRING]) &&
           UA_String_equal((UA_String*)v.data, &uri)) {
            if(found == 0 && first)
                UA_NodeId_copy(&rd->nodeId.nodeId, first);
            found++;
        }
        UA_Variant_clear(&v);
    }
    UA_BrowseResult_clear(&br);
    return found;
}

static UA_String
namespaceUri(UA_UInt16 ns) {
    UA_String uri = UA_STRING_NULL;
    ck_assert_uint_eq(UA_Server_getNamespaceByIndex(server, ns, &uri),
                      UA_STATUSCODE_GOOD);
    return uri;
}

/* The NodeId of a Property of the Object, or the null NodeId */
static UA_NodeId
findProperty(const UA_NodeId objectId, const char *name) {
    UA_QualifiedName qn = UA_QUALIFIEDNAME(0, (char*)(uintptr_t)name);
    UA_BrowsePathResult bpr =
        UA_Server_browseSimplifiedBrowsePath(server, objectId, 1, &qn);
    UA_NodeId id = UA_NODEID_NULL;
    if(bpr.statusCode == UA_STATUSCODE_GOOD && bpr.targetsSize == 1)
        UA_NodeId_copy(&bpr.targets[0].targetId.nodeId, &id);
    UA_BrowsePathResult_clear(&bpr);
    return id;
}

static UA_NodeId
metadataObject(UA_UInt16 ns) {
    UA_String uri = namespaceUri(ns);
    UA_NodeId objectId = UA_NODEID_NULL;
    ck_assert_uint_eq(findMetadataObjects(uri, &objectId), 1);
    UA_String_clear(&uri);
    return objectId;
}

static UA_NodeId
metadataProperty(UA_UInt16 ns, const char *name) {
    UA_NodeId objectId = metadataObject(ns);
    UA_NodeId propertyId = findProperty(objectId, name);
    UA_NodeId_clear(&objectId);
    return propertyId;
}

static UA_Boolean
nodeExists(const UA_NodeId nodeId) {
    UA_NodeClass nodeClass;
    return (UA_Server_readNodeClass(server, nodeId, &nodeClass) == UA_STATUSCODE_GOOD);
}

/* The Server creates the Object for ns=1 with the mandatory Properties */
START_TEST(metadata_createdForNamespaceOne) {
    UA_String uri = namespaceUri(1);
    UA_NodeId objectId = UA_NODEID_NULL;
    ck_assert_uint_eq(findMetadataObjects(uri, &objectId), 1);
    ck_assert_uint_eq(objectId.namespaceIndex, 0);

    UA_QualifiedName bn;
    ck_assert_uint_eq(UA_Server_readBrowseName(server, objectId, &bn),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(bn.namespaceIndex, 1);
    ck_assert(UA_String_equal(&bn.name, &uri));
    UA_QualifiedName_clear(&bn);

    UA_Variant v;
    UA_Variant_init(&v);
    ck_assert_uint_eq(UA_Server_readObjectProperty(server, objectId,
                          UA_QUALIFIEDNAME(0, "NamespaceVersion"), &v),
                      UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_STRING]));
    ck_assert_uint_eq(((UA_String*)v.data)->length, 0);
    UA_Variant_clear(&v);
    ck_assert_uint_eq(UA_Server_readObjectProperty(server, objectId,
                          UA_QUALIFIEDNAME(0, "NamespacePublicationDate"), &v),
                      UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_DATETIME]));
    UA_Variant_clear(&v);
    ck_assert_uint_eq(UA_Server_readObjectProperty(server, objectId,
                          UA_QUALIFIEDNAME(0, "IsNamespaceSubset"), &v),
                      UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_BOOLEAN]));
    ck_assert(!*(UA_Boolean*)v.data);
    UA_Variant_clear(&v);
    ck_assert_uint_eq(UA_Server_readObjectProperty(server, objectId,
                          UA_QUALIFIEDNAME(0, "StaticNodeIdTypes"), &v),
                      UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_IDTYPE]));
    ck_assert_uint_eq(v.arrayLength, 0);
    UA_Variant_clear(&v);
    ck_assert_uint_eq(UA_Server_readObjectProperty(server, objectId,
                          UA_QUALIFIEDNAME(0, "StaticNumericNodeIdRange"), &v),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(v.arrayLength, 0);
    UA_Variant_clear(&v);
    ck_assert_uint_eq(UA_Server_readObjectProperty(server, objectId,
                          UA_QUALIFIEDNAME(0, "StaticStringNodeIdPattern"), &v),
                      UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_STRING]));
    UA_Variant_clear(&v);

    /* Strict mode: all three permission Properties are published */
    const char *props[3] = {"DefaultRolePermissions", "DefaultUserRolePermissions",
                            "DefaultAccessRestrictions"};
    for(size_t i = 0; i < 3; i++) {
        UA_NodeId propertyId = findProperty(objectId, props[i]);
        ck_assert_msg(!UA_NodeId_isNull(&propertyId), "%s missing", props[i]);
        UA_NodeId_clear(&propertyId);
    }

    /* Startup again does not duplicate anything */
    ck_assert_uint_eq(UA_Server_run_shutdown(server), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(findMetadataObjects(uri, NULL), 1);
    UA_NodeId propertyId = findProperty(objectId, "DefaultRolePermissions");
    ck_assert(!UA_NodeId_isNull(&propertyId));
    UA_NodeId_clear(&propertyId);

    UA_NodeId_clear(&objectId);
    UA_String_clear(&uri);
} END_TEST

/* Add a NamespaceMetadata Object like a companion nodeset does: with NodeIds
 * in its own namespace and without the permission Properties */
static UA_NodeId
addNodesetMetadataObject(UA_UInt16 ns, const char *uri, const char *browseName) {
    UA_ObjectAttributes attr = UA_ObjectAttributes_default;
    attr.displayName = UA_LOCALIZEDTEXT("", (char*)(uintptr_t)browseName);
    UA_NodeId objectId;
    ck_assert_uint_eq(UA_Server_addObjectNode(server, UA_NODEID_NUMERIC(ns, 15001),
                          UA_NS0ID(SERVER_NAMESPACES), UA_NS0ID(HASCOMPONENT),
                          UA_QUALIFIEDNAME(ns, (char*)(uintptr_t)browseName),
                          UA_NS0ID(NAMESPACEMETADATATYPE), attr, NULL, &objectId),
                      UA_STATUSCODE_GOOD);
    UA_String uriStr = UA_STRING((char*)(uintptr_t)uri);
    UA_Variant v;
    UA_Variant_setScalar(&v, &uriStr, &UA_TYPES[UA_TYPES_STRING]);
    ck_assert_uint_eq(UA_Server_writeObjectProperty(server, objectId,
                          UA_QUALIFIEDNAME(0, "NamespaceUri"), v),
                      UA_STATUSCODE_GOOD);
    return objectId;
}

/* An Object that a nodeset brought along before the startup is adopted. It
 * stays readable under the namespace template. */
START_TEST(metadata_adoptsNodesetObject) {
    server = UA_Server_newForUnitTest();
    ck_assert(server != NULL);
    UA_ServerConfig *config = UA_Server_getConfig(server);
    config->tcpEnabled = false;
    config->allPermissionsForAnonymous = false;
    const char *uri = "urn:rbac:metadata:nodeset";
    UA_UInt16 ns = UA_Server_addNamespace(server, uri);
    UA_NodeId objectId = addNodesetMetadataObject(ns, uri, "SomeModel");
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);

    UA_NodeId found = UA_NODEID_NULL;
    ck_assert_uint_eq(findMetadataObjects(UA_STRING((char*)(uintptr_t)uri), &found), 1);
    ck_assert(UA_NodeId_equal(&found, &objectId));
    UA_NodeId_clear(&found);

    UA_NodeId dar = findProperty(objectId, "DefaultAccessRestrictions");
    ck_assert(!UA_NodeId_isNull(&dar));
    UA_NodeId durp = findProperty(objectId, "DefaultUserRolePermissions");
    ck_assert(!UA_NodeId_isNull(&durp));
    UA_NodeId nsUri = findProperty(objectId, "NamespaceUri");
    ck_assert_uint_eq(nsUri.namespaceIndex, ns);

    /* The template of the namespace lets Anonymous only browse. The adopted
     * Object and its Properties stay readable. */
    UA_Session *anonymous = createSessionWithRole(ROLE(ANONYMOUS));
    ck_assert_uint_eq(readStatusAs(anonymous, nsUri, UA_ATTRIBUTEID_VALUE),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(readStatusAs(anonymous, objectId, UA_ATTRIBUTEID_DISPLAYNAME),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(readStatusAs(anonymous, dar, UA_ATTRIBUTEID_VALUE),
                      UA_STATUSCODE_GOOD);
    UA_NodeId drp = findProperty(objectId, "DefaultRolePermissions");
    ck_assert_uint_eq(readStatusAs(anonymous, drp, UA_ATTRIBUTEID_VALUE),
                      UA_STATUSCODE_BADUSERACCESSDENIED);

    UA_NodeId_clear(&drp);
    UA_NodeId_clear(&nsUri);
    UA_NodeId_clear(&durp);
    UA_NodeId_clear(&dar);
    UA_NodeId_clear(&objectId);
    teardown();
} END_TEST

/* Add a NamespaceMetadata Object like addNodesetMetadataObject, with the
 * optional DefaultRolePermissions Property, and give the Object and all its
 * Properties AccessRestrictions */
static UA_NodeId
addNodesetMetadataObjectWithAccessRestrictions(UA_UInt16 ns, const char *uri,
                                               UA_AccessRestrictionType ar) {
    UA_NodeId objectId = addNodesetMetadataObject(ns, uri, "SomeModel");

    UA_VariableAttributes attr = UA_VariableAttributes_default;
    attr.displayName = UA_LOCALIZEDTEXT("", "DefaultRolePermissions");
    attr.dataType = UA_TYPES[UA_TYPES_ROLEPERMISSIONTYPE].typeId;
    attr.valueRank = UA_VALUERANK_ONE_DIMENSION;
    UA_UInt32 arrayDims = 0;
    attr.arrayDimensionsSize = 1;
    attr.arrayDimensions = &arrayDims;
    UA_Variant_setArray(&attr.value, NULL, 0, &UA_TYPES[UA_TYPES_ROLEPERMISSIONTYPE]);
    ck_assert_uint_eq(UA_Server_addVariableNode(server, UA_NODEID_NUMERIC(ns, 15002),
                          objectId, UA_NS0ID(HASPROPERTY),
                          UA_QUALIFIEDNAME(0, "DefaultRolePermissions"),
                          UA_NS0ID(PROPERTYTYPE), attr, NULL, NULL),
                      UA_STATUSCODE_GOOD);

    ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server, objectId, ar),
                      UA_STATUSCODE_GOOD);
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = objectId;
    bd.referenceTypeId = UA_NS0ID(HASPROPERTY);
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    UA_BrowseResult br = UA_Server_browse(server, 0, &bd);
    ck_assert_uint_eq(br.statusCode, UA_STATUSCODE_GOOD);
    ck_assert_uint_ge(br.referencesSize, 2);
    for(size_t i = 0; i < br.referencesSize; i++)
        ck_assert_uint_eq(UA_Server_setNodeAccessRestrictions(server,
                              br.references[i].nodeId.nodeId, ar),
                          UA_STATUSCODE_GOOD);
    UA_BrowseResult_clear(&br);
    return objectId;
}

static void
assertAccessRestrictions(const UA_NodeId nodeId, UA_AccessRestrictionType ar) {
    UA_AccessRestrictionType out = UA_ACCESSRESTRICTIONTYPE_NONE;
    ck_assert_uint_eq(UA_Server_getNodeAccessRestrictions(server, nodeId, &out),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(out, ar);
}

/* The AccessRestrictions of a Node live in its shared RolePermission entry.
 * A Node with only AccessRestrictions has no RolePermissions of its own: the
 * adopted Object and its Properties (also a DefaultRolePermissions Property
 * the nodeset brought along) are protected and keep their AccessRestrictions.
 * SessionRequired does not affect the local test Sessions, so RBAC decides. */
START_TEST(metadata_adoptsNodesetObjectWithAccessRestrictions) {
    server = UA_Server_newForUnitTest();
    ck_assert(server != NULL);
    UA_ServerConfig *config = UA_Server_getConfig(server);
    config->tcpEnabled = false;
    config->allPermissionsForAnonymous = false;
    const UA_AccessRestrictionType ar = UA_ACCESSRESTRICTIONTYPE_SESSIONREQUIRED;

    /* Under the template, which lets Anonymous only browse */
    const char *uri = "urn:rbac:metadata:nodeset-ar";
    UA_UInt16 ns = UA_Server_addNamespace(server, uri);
    UA_NodeId objectId = addNodesetMetadataObjectWithAccessRestrictions(ns, uri, ar);

    /* Under a namespace default that lets Anonymous read everything */
    const char *openUri = "urn:rbac:metadata:nodeset-ar-open";
    UA_UInt16 openNs = UA_Server_addNamespace(server, openUri);
    UA_NodeId openObjectId =
        addNodesetMetadataObjectWithAccessRestrictions(openNs, openUri, ar);
    const UA_RolePermission openDefault[1] = {{ROLE(ANONYMOUS), B | R}};
    ck_assert_uint_eq(UA_Server_setNamespaceDefaultRolePermissions(server, openNs,
                                                                   1, openDefault),
                      UA_STATUSCODE_GOOD);

    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);

    /* The Object and its Properties stay readable under the template */
    UA_Session *anonymous = createSessionWithRole(ROLE(ANONYMOUS));
    UA_NodeId nsUri = findProperty(objectId, "NamespaceUri");
    ck_assert_uint_eq(nsUri.namespaceIndex, ns);
    ck_assert_uint_eq(readStatusAs(anonymous, nsUri, UA_ATTRIBUTEID_VALUE),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(readStatusAs(anonymous, objectId, UA_ATTRIBUTEID_DISPLAYNAME),
                      UA_STATUSCODE_GOOD);
    UA_NodeId drp = findProperty(objectId, "DefaultRolePermissions");
    const UA_NodeId nodesetDrp = UA_NODEID_NUMERIC(ns, 15002);
    ck_assert(UA_NodeId_equal(&drp, &nodesetDrp));
    ck_assert_uint_eq(readStatusAs(anonymous, drp, UA_ATTRIBUTEID_VALUE),
                      UA_STATUSCODE_BADUSERACCESSDENIED);

    /* The adopted DefaultRolePermissions is readable by administrators only,
     * also where the namespace default lets Anonymous read */
    UA_NodeId openDrp = findProperty(openObjectId, "DefaultRolePermissions");
    const UA_NodeId openNodesetDrp = UA_NODEID_NUMERIC(openNs, 15002);
    ck_assert(UA_NodeId_equal(&openDrp, &openNodesetDrp));
    ck_assert_uint_eq(readStatusAs(anonymous, openDrp, UA_ATTRIBUTEID_VALUE),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    UA_NodeId openNsUri = findProperty(openObjectId, "NamespaceUri");
    ck_assert_uint_eq(readStatusAs(anonymous, openNsUri, UA_ATTRIBUTEID_VALUE),
                      UA_STATUSCODE_GOOD);

    /* The Nodes keep their AccessRestrictions */
    assertAccessRestrictions(objectId, ar);
    assertAccessRestrictions(nsUri, ar);
    assertAccessRestrictions(drp, ar);
    assertAccessRestrictions(openObjectId, ar);
    assertAccessRestrictions(openDrp, ar);

    UA_NodeId_clear(&openNsUri);
    UA_NodeId_clear(&openDrp);
    UA_NodeId_clear(&drp);
    UA_NodeId_clear(&nsUri);
    UA_NodeId_clear(&openObjectId);
    UA_NodeId_clear(&objectId);
    teardown();
} END_TEST

/* A namespace added at runtime is published after the next iteration. An
 * Object added right after the namespace (by a nodeset) is adopted. */
START_TEST(metadata_runtimeNamespace) {
    const char *uri = "urn:rbac:metadata:runtime";
    UA_UInt16 ns = UA_Server_addNamespace(server, uri);
    ck_assert_uint_eq(findMetadataObjects(UA_STRING((char*)(uintptr_t)uri), NULL), 0);
    UA_Server_run_iterate(server, false);
    UA_NodeId objectId = metadataObject(ns);
    UA_NodeId dar = findProperty(objectId, "DefaultAccessRestrictions");
    ck_assert(!UA_NodeId_isNull(&dar));
    UA_NodeId_clear(&dar);
    UA_NodeId_clear(&objectId);

    /* Adding the namespace again changes nothing */
    ck_assert_uint_eq(UA_Server_addNamespace(server, uri), ns);
    UA_Server_run_iterate(server, false);
    ck_assert_uint_eq(findMetadataObjects(UA_STRING((char*)(uintptr_t)uri), NULL), 1);

    const char *nodesetUri = "urn:rbac:metadata:runtime-nodeset";
    UA_UInt16 nodesetNs = UA_Server_addNamespace(server, nodesetUri);
    UA_NodeId nodesetObject = addNodesetMetadataObject(nodesetNs, nodesetUri,
                                                       "RuntimeModel");
    UA_Server_run_iterate(server, false);
    UA_NodeId found = UA_NODEID_NULL;
    ck_assert_uint_eq(findMetadataObjects(UA_STRING((char*)(uintptr_t)nodesetUri),
                                          &found), 1);
    ck_assert(UA_NodeId_equal(&found, &nodesetObject));
    UA_NodeId_clear(&found);
    UA_NodeId_clear(&nodesetObject);

    /* A namespace added and not yet published when the server shuts down is
     * published at the next startup */
    UA_UInt16 lateNs = UA_Server_addNamespace(server, "urn:rbac:metadata:late");
    ck_assert_uint_eq(UA_Server_run_shutdown(server), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
    objectId = metadataObject(lateNs);
    UA_NodeId_clear(&objectId);
} END_TEST

/* DefaultUserRolePermissions is filtered to the Roles of the reading Session */
START_TEST(metadata_userRolePermissionsFiltered) {
    UA_NodeId durp = metadataProperty(1, "DefaultUserRolePermissions");
    ck_assert(!UA_NodeId_isNull(&durp));

    const UA_NodeId userRoles[2] = {ROLE(ANONYMOUS), ROLE(AUTHENTICATEDUSER)};
    UA_Session *user = createSessionWithRoles(2, userRoles);
    UA_RolePermission userEntries[2] = {{ROLE(ANONYMOUS), B},
                                        {ROLE(AUTHENTICATEDUSER), B | R}};
    expectRolePermissions(user, durp, UA_ATTRIBUTEID_VALUE, 2, userEntries);

    UA_Session *securityAdmin = createSessionWithRole(ROLE(SECURITYADMIN));
    UA_RolePermission secAdminEntry = {ROLE(SECURITYADMIN), B | R | RRP};
    expectRolePermissions(securityAdmin, durp, UA_ATTRIBUTEID_VALUE,
                          1, &secAdminEntry);

    /* Namespace Zero */
    UA_Session *anonymous = createSessionWithRole(ROLE(ANONYMOUS));
    UA_RolePermission anonymousEntry = {ROLE(ANONYMOUS), B | R | C | RE};
    expectRolePermissions(anonymous,
                          UA_NS0ID(OPCUANAMESPACEMETADATA_DEFAULTUSERROLEPERMISSIONS),
                          UA_ATTRIBUTEID_VALUE, 1, &anonymousEntry);

    /* An explicit default replaces the template */
    UA_RolePermission entry = {ROLE(AUTHENTICATEDUSER), B};
    ck_assert_uint_eq(UA_Server_setNamespaceDefaultRolePermissions(server, 1, 1,
                                                                   &entry),
                      UA_STATUSCODE_GOOD);
    expectRolePermissions(user, durp, UA_ATTRIBUTEID_VALUE, 1, &entry);
    UA_NodeId_clear(&durp);
} END_TEST

static UA_AccessRestrictionType
readAccessRestrictionsProperty(const UA_NodeId propertyId) {
    UA_Variant v;
    UA_Variant_init(&v);
    ck_assert_uint_eq(UA_Server_readValue(server, propertyId, &v),
                      UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_ACCESSRESTRICTIONTYPE]));
    UA_AccessRestrictionType ar = *(UA_AccessRestrictionType*)v.data;
    UA_Variant_clear(&v);
    return ar;
}

/* DefaultAccessRestrictions reads the namespace default */
START_TEST(metadata_accessRestrictionsFollowSetter) {
    UA_NodeId dar = metadataProperty(1, "DefaultAccessRestrictions");
    ck_assert(!UA_NodeId_isNull(&dar));
    const UA_NodeId ns0Dar = UA_NS0ID(OPCUANAMESPACEMETADATA_DEFAULTACCESSRESTRICTIONS);
    ck_assert_uint_eq(readAccessRestrictionsProperty(dar),
                      UA_ACCESSRESTRICTIONTYPE_NONE);

    ck_assert_uint_eq(UA_Server_setNamespaceDefaultAccessRestrictions(server, 1,
                          UA_ACCESSRESTRICTIONTYPE_SIGNINGREQUIRED),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(readAccessRestrictionsProperty(dar),
                      UA_ACCESSRESTRICTIONTYPE_SIGNINGREQUIRED);
    ck_assert_uint_eq(readAccessRestrictionsProperty(ns0Dar),
                      UA_ACCESSRESTRICTIONTYPE_NONE);

    ck_assert_uint_eq(UA_Server_setNamespaceDefaultAccessRestrictions(server, 0,
                          UA_ACCESSRESTRICTIONTYPE_SESSIONREQUIRED),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(readAccessRestrictionsProperty(ns0Dar),
                      UA_ACCESSRESTRICTIONTYPE_SESSIONREQUIRED);

    ck_assert_uint_eq(UA_Server_removeNamespaceDefaultAccessRestrictions(server, 1),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_removeNamespaceDefaultAccessRestrictions(server, 0),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(readAccessRestrictionsProperty(dar),
                      UA_ACCESSRESTRICTIONTYPE_NONE);
    ck_assert_uint_eq(readAccessRestrictionsProperty(ns0Dar),
                      UA_ACCESSRESTRICTIONTYPE_NONE);
    UA_NodeId_clear(&dar);
} END_TEST

/* DefaultRolePermissions is readable by administrators only (Part 3 §5.2.9) */
START_TEST(metadata_defaultRolePermissionsAdminOnly) {
    UA_NodeId drp = metadataProperty(1, "DefaultRolePermissions");
    ck_assert(!UA_NodeId_isNull(&drp));
    const UA_NodeId ns0Drp = UA_NS0ID(OPCUANAMESPACEMETADATA_DEFAULTROLEPERMISSIONS);
    const UA_NodeId props[2] = {drp, ns0Drp};

    const UA_NodeId nonAdminRoles[4] = {ROLE(ANONYMOUS), ROLE(AUTHENTICATEDUSER),
                                        ROLE(OPERATOR), ROLE(CONFIGUREADMIN)};
    UA_Session *nonAdmin = createSessionWithRoles(4, nonAdminRoles);
    UA_Session *securityAdmin = createSessionWithRole(ROLE(SECURITYADMIN));
    for(size_t i = 0; i < 2; i++) {
        ck_assert_uint_eq(readStatusAs(nonAdmin, props[i], UA_ATTRIBUTEID_VALUE),
                          UA_STATUSCODE_BADUSERACCESSDENIED);
        /* Still browsable */
        ck_assert_uint_eq(readStatusAs(nonAdmin, props[i], UA_ATTRIBUTEID_BROWSENAME),
                          UA_STATUSCODE_GOOD);
        ck_assert_uint_eq(readStatusAs(securityAdmin, props[i], UA_ATTRIBUTEID_VALUE),
                          UA_STATUSCODE_GOOD);
        ck_assert_uint_eq(readStatusAs(securityAdmin, props[i],
                                       UA_ATTRIBUTEID_ROLEPERMISSIONS),
                          UA_STATUSCODE_GOOD);
    }

    /* SecurityAdmin reads the complete template */
    const UA_RolePermissionSet *tmpl =
        &UA_Server_getConfig(server)->namespaceDefaultRolePermissions;
    expectRolePermissions(securityAdmin, drp, UA_ATTRIBUTEID_VALUE,
                          tmpl->rolePermissionsSize, tmpl->rolePermissions);
    UA_NodeId_clear(&drp);
} END_TEST

/* Legacy mode publishes the RolePermission Properties only for a namespace
 * with an explicit default. DefaultAccessRestrictions is always present. */
START_TEST(metadata_legacyPropertiesFollowModel) {
    const UA_NodeId ns0Drp = UA_NS0ID(OPCUANAMESPACEMETADATA_DEFAULTROLEPERMISSIONS);
    const UA_NodeId ns0Durp = UA_NS0ID(OPCUANAMESPACEMETADATA_DEFAULTUSERROLEPERMISSIONS);
    const UA_NodeId ns0Dar = UA_NS0ID(OPCUANAMESPACEMETADATA_DEFAULTACCESSRESTRICTIONS);
    ck_assert(!nodeExists(ns0Drp));
    ck_assert(!nodeExists(ns0Durp));
    ck_assert(nodeExists(ns0Dar));

    UA_NodeId ns1Object = metadataObject(1);
    UA_NodeId ns1Drp = findProperty(ns1Object, "DefaultRolePermissions");
    ck_assert(UA_NodeId_isNull(&ns1Drp));
    UA_NodeId ns1Dar = findProperty(ns1Object, "DefaultAccessRestrictions");
    ck_assert(!UA_NodeId_isNull(&ns1Dar));
    UA_NodeId_clear(&ns1Dar);

    /* A default for Namespace Zero brings back the standard NodeIds */
    UA_RolePermission entry = {ROLE(OBSERVER), B | R};
    ck_assert_uint_eq(UA_Server_setNamespaceDefaultRolePermissions(server, 0, 1,
                                                                   &entry),
                      UA_STATUSCODE_GOOD);
    ck_assert(nodeExists(ns0Drp));
    ck_assert(nodeExists(ns0Durp));
    UA_Variant v;
    UA_Variant_init(&v);
    ck_assert_uint_eq(UA_Server_readValue(server, ns0Drp, &v), UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_ROLEPERMISSIONTYPE]));
    ck_assert_uint_eq(v.arrayLength, 1);
    UA_Variant_clear(&v);

    /* The Property is protected in legacy mode as well */
    UA_Session *anonymous = createSessionWithRole(ROLE(ANONYMOUS));
    ck_assert_uint_eq(readStatusAs(anonymous, ns0Drp, UA_ATTRIBUTEID_VALUE),
                      UA_STATUSCODE_BADUSERACCESSDENIED);

    ck_assert_uint_eq(UA_Server_setNamespaceDefaultRolePermissions(server, 1, 1,
                                                                   &entry),
                      UA_STATUSCODE_GOOD);
    ns1Drp = findProperty(ns1Object, "DefaultRolePermissions");
    ck_assert(!UA_NodeId_isNull(&ns1Drp));
    UA_NodeId_clear(&ns1Drp);

    /* Removing the defaults removes the Properties again */
    ck_assert_uint_eq(UA_Server_removeNamespaceDefaultRolePermissions(server, 0),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_removeNamespaceDefaultRolePermissions(server, 1),
                      UA_STATUSCODE_GOOD);
    ck_assert(!nodeExists(ns0Drp));
    ck_assert(!nodeExists(ns0Durp));
    ns1Drp = findProperty(ns1Object, "DefaultUserRolePermissions");
    ck_assert(UA_NodeId_isNull(&ns1Drp));
    UA_NodeId_clear(&ns1Object);
} END_TEST

/************************************/
/* Access decisions in strict mode  */
/************************************/

static UA_NodeId
addVariable(const char *name, UA_Byte accessLevel) {
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    attr.displayName = UA_LOCALIZEDTEXT("en-US", (char*)(uintptr_t)name);
    attr.accessLevel = accessLevel;
    UA_Double value = 1.0;
    UA_Variant_setScalar(&attr.value, &value, &UA_TYPES[UA_TYPES_DOUBLE]);
    UA_NodeId nodeId = UA_NODEID_STRING(1, (char*)(uintptr_t)name);
    ck_assert_uint_eq(UA_Server_addVariableNode(server, nodeId, UA_NS0ID(OBJECTSFOLDER),
                                                UA_NS0ID(ORGANIZES),
                                                UA_QUALIFIEDNAME(1, (char*)(uintptr_t)name),
                                                UA_NS0ID(BASEDATAVARIABLETYPE),
                                                attr, NULL, NULL),
                      UA_STATUSCODE_GOOD);
    return nodeId;
}

/* Write a value with a SourceTimestamp and a status, as a Client does that
 * forwards a measurement */
static UA_StatusCode
writeMeasurementAs(UA_Session *session, const UA_NodeId nodeId) {
    UA_Double value = 2.0;
    UA_WriteValue wv;
    UA_WriteValue_init(&wv);
    wv.nodeId = nodeId;
    wv.attributeId = UA_ATTRIBUTEID_VALUE;
    wv.value.hasValue = true;
    UA_Variant_setScalar(&wv.value.value, &value, &UA_TYPES[UA_TYPES_DOUBLE]);
    wv.value.hasSourceTimestamp = true;
    wv.value.sourceTimestamp = UA_DateTime_now();
    wv.value.hasStatus = true;
    wv.value.status = UA_STATUSCODE_UNCERTAINLASTUSABLEVALUE;
    UA_StatusCode res = UA_STATUSCODE_BADINTERNALERROR;
    lockServer(server);
    Operation_Write(server, session, &wv, &res);
    unlockServer(server);
    return res;
}

/* The Write permission covers the status and the timestamps of the Value. The
 * AccessLevel of the Variable still decides whether they can be written. */
START_TEST(strict_writeWithSourceTimestamp) {
    const UA_Byte full = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE |
        UA_ACCESSLEVELMASK_STATUSWRITE | UA_ACCESSLEVELMASK_TIMESTAMPWRITE |
        UA_ACCESSLEVELMASK_SEMANTICCHANGE;
    UA_NodeId measurement = addVariable("Measurement", full);
    UA_NodeId plain = addVariable("Plain", UA_ACCESSLEVELMASK_READ |
                                  UA_ACCESSLEVELMASK_WRITE);

    const UA_NodeId opRoles[2] = {ROLE(ANONYMOUS), ROLE(OPERATOR)};
    const UA_NodeId obsRoles[2] = {ROLE(ANONYMOUS), ROLE(OBSERVER)};
    UA_Session *op = createSessionWithRoles(2, opRoles);
    UA_Session *obs = createSessionWithRoles(2, obsRoles);
    ck_assert_uint_eq(writeMeasurementAs(op, measurement), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(writeMeasurementAs(obs, measurement),
                      UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert_uint_eq(writeMeasurementAs(op, plain),
                      UA_STATUSCODE_BADWRITENOTSUPPORTED);

    /* UserAccessLevel: Write maps to the three write bits, SemanticChange
     * passes through from the AccessLevel */
    UA_DataValue dv = readAs(op, measurement, UA_ATTRIBUTEID_USERACCESSLEVEL);
    ck_assert(UA_Variant_hasScalarType(&dv.value, &UA_TYPES[UA_TYPES_BYTE]));
    ck_assert_uint_eq(*(UA_Byte*)dv.value.data, full);
    UA_DataValue_clear(&dv);
    dv = readAs(obs, measurement, UA_ATTRIBUTEID_USERACCESSLEVEL);
    ck_assert(UA_Variant_hasScalarType(&dv.value, &UA_TYPES[UA_TYPES_BYTE]));
    ck_assert_uint_eq(*(UA_Byte*)dv.value.data,
                      UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_SEMANTICCHANGE);
    UA_DataValue_clear(&dv);
}
END_TEST

/* Legacy mode: an unconfigured Node grants every AccessLevel bit */
START_TEST(legacy_writeWithSourceTimestamp) {
    UA_NodeId measurement =
        addVariable("Measurement", UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE |
                    UA_ACCESSLEVELMASK_STATUSWRITE | UA_ACCESSLEVELMASK_TIMESTAMPWRITE);
    UA_Session *anon = createSessionWithRole(ROLE(ANONYMOUS));
    ck_assert_uint_eq(writeMeasurementAs(anon, measurement), UA_STATUSCODE_GOOD);
}
END_TEST

/* An unknown Node is not denied, so the service reports Bad_NodeIdUnknown.
 * Any other error of the permission lookup denies. */
START_TEST(accessControl_errorHandling) {
    UA_Session *anon = createSessionWithRole(ROLE(ANONYMOUS));
    UA_AccessControl *ac = &UA_Server_getConfig(server)->accessControl;
    const UA_NodeId unknown = UA_NODEID_STRING(1, "Unknown");
    ck_assert(ac->allowBrowseNode(server, ac, &anon->sessionId, NULL, &unknown, NULL));
    ck_assert(ac->getUserExecutable(server, ac, &anon->sessionId, NULL, &unknown, NULL));
    ck_assert_uint_ne(ac->getUserAccessLevel(server, ac, &anon->sessionId, NULL,
                                             &unknown, NULL) & UA_ACCESSLEVELMASK_WRITE, 0);

    UA_DeleteNodesItem del;
    UA_DeleteNodesItem_init(&del);
    del.nodeId = unknown;
    ck_assert(ac->allowDeleteNode(server, ac, &anon->sessionId, NULL, &del));
    UA_DeleteNodesRequest delRequest;
    UA_DeleteNodesRequest_init(&delRequest);
    delRequest.nodesToDeleteSize = 1;
    delRequest.nodesToDelete = &del;
    UA_DeleteNodesResponse delResponse;
    UA_DeleteNodesResponse_init(&delResponse);
    lockServer(server);
    Service_DeleteNodes(server, anon, &delRequest, &delResponse);
    unlockServer(server);
    ck_assert_uint_eq(delResponse.resultsSize, 1);
    ck_assert_uint_eq(delResponse.results[0], UA_STATUSCODE_BADNODEIDUNKNOWN);
    UA_DeleteNodesResponse_clear(&delResponse);

    /* An unknown namespace is reported by AddNodes */
    UA_AddNodesItem add;
    UA_AddNodesItem_init(&add);
    add.requestedNewNodeId.nodeId = UA_NODEID_NUMERIC(99, 1);
    ck_assert(ac->allowAddNode(server, ac, &anon->sessionId, NULL, &add));

    /* A known Node in strict mode: denied without the permission */
    const UA_NodeId object = addObject(1, "Restricted");
    ck_assert(!ac->getUserExecutable(server, ac, &anon->sessionId, NULL, &object, NULL));

    /* An invalid lookup denies, in strict and in legacy mode */
    ck_assert(!ac->allowBrowseNode(server, ac, &anon->sessionId, NULL, NULL, NULL));
    UA_Server_getConfig(server)->allPermissionsForAnonymous = true;
    ck_assert(!ac->allowBrowseNode(server, ac, &anon->sessionId, NULL, NULL, NULL));
    ck_assert_uint_eq(ac->getUserAccessLevel(server, ac, &anon->sessionId, NULL,
                                             NULL, NULL) &
                      (UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE), 0);
    ck_assert(ac->allowBrowseNode(server, ac, &anon->sessionId, NULL, &object, NULL));
}
END_TEST

#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
/* An event MonitoredItem of the Session on the Server Object */
static UA_MonitoredItem *
createServerEventItem(UA_Session *session) {
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
    item.itemToMonitor.nodeId = UA_NS0ID(SERVER);
    item.itemToMonitor.attributeId = UA_ATTRIBUTEID_EVENTNOTIFIER;
    item.monitoringMode = UA_MONITORINGMODE_REPORTING;
    item.requestedParameters.queueSize = 10;
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
    ck_assert_uint_eq(response.resultsSize, 1);
    ck_assert_uint_eq(response.results[0].statusCode, UA_STATUSCODE_GOOD);
    UA_Subscription *sub = getSubscriptionById(server, subResponse.subscriptionId);
    ck_assert_ptr_ne(sub, NULL);
    UA_MonitoredItem *mon =
        UA_Subscription_getMonitoredItem(sub, response.results[0].monitoredItemId);
    ck_assert_ptr_ne(mon, NULL);
    unlockServer(server);
    UA_CreateMonitoredItemsResponse_clear(&response);
    UA_CreateSubscriptionResponse_clear(&subResponse);
    return mon;
}

/* Trigger an Event and return how many of the MonitoredItems received it */
static size_t
triggerEvent(const UA_NodeId eventType, const UA_NodeId sourceNode,
             UA_MonitoredItem **mons, size_t monsSize) {
    size_t before[4];
    lockServer(server);
    for(size_t i = 0; i < monsSize; i++)
        before[i] = mons[i]->queueSize;
    unlockServer(server);

    UA_EventDescription ed;
    memset(&ed, 0, sizeof(ed));
    ed.eventType = eventType;
    ed.sourceNode = sourceNode;
    ed.severity = 100;
    ed.message = UA_LOCALIZEDTEXT("en-US", "event");
    ck_assert_uint_eq(UA_Server_createEventEx(server, &ed, NULL), UA_STATUSCODE_GOOD);

    size_t received = 0;
    lockServer(server);
    for(size_t i = 0; i < monsSize; i++)
        received += (mons[i]->queueSize > before[i]) ? 1 : 0;
    unlockServer(server);
    return received;
}

/* ReceiveEvents is needed on the EventType and on the SourceNode */
START_TEST(strict_receiveEventsOnTypeAndSource) {
    const UA_NodeId obsRoles[2] = {ROLE(ANONYMOUS), ROLE(OBSERVER)};
    const UA_NodeId secRoles[2] = {ROLE(ANONYMOUS), ROLE(SECURITYADMIN)};
    UA_Session *obs = createSessionWithRoles(2, obsRoles);
    UA_Session *sec = createSessionWithRoles(2, secRoles);
    UA_MonitoredItem *obsItem = createServerEventItem(obs);
    UA_MonitoredItem *secItem = createServerEventItem(sec);

    /* The ns=1 template grants ReceiveEvents to Observer, not SecurityAdmin */
    const UA_NodeId source = addObject(1, "Source");
    const UA_NodeId baseEvent = UA_NS0ID(BASEEVENTTYPE);
    ck_assert_uint_eq(triggerEvent(baseEvent, source, &obsItem, 1), 1);
    ck_assert_uint_eq(triggerEvent(baseEvent, source, &secItem, 1), 0);

    /* The SourceNode withdraws the bit */
    const UA_RolePermission noEvents[] = {{ROLE(OBSERVER), B | R}};
    ck_assert_uint_eq(UA_Server_setNodeRolePermissions(server, source, 1, noEvents,
                                                       false, NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(triggerEvent(baseEvent, source, &obsItem, 1), 0);
    ck_assert_uint_eq(UA_Server_removeNodeRolePermissions(server, source, false),
                      UA_STATUSCODE_GOOD);

    /* The EventType withdraws the bit: the audit trail is for SecurityAdmin */
    const UA_NodeId serverObject = UA_NS0ID(SERVER);
    const UA_NodeId auditEvent = UA_NS0ID(AUDITEVENTTYPE);
    ck_assert_uint_eq(triggerEvent(auditEvent, serverObject, &obsItem, 1), 0);
    ck_assert_uint_eq(triggerEvent(auditEvent, serverObject, &secItem, 1), 1);

    /* A SourceNode outside the AddressSpace is evaluated with the default of
     * its namespace, here the ns=1 template */
    const UA_NodeId missing = UA_NODEID_STRING(1, "Missing");
    ck_assert_uint_eq(triggerEvent(baseEvent, missing, &obsItem, 1), 1);
    ck_assert_uint_eq(triggerEvent(baseEvent, missing, &secItem, 1), 0);
}
END_TEST

/* Legacy mode: Nodes without RolePermissions grant ReceiveEvents to all */
START_TEST(legacy_receiveEvents) {
    UA_Session *anon = createSessionWithRole(ROLE(ANONYMOUS));
    UA_MonitoredItem *item = createServerEventItem(anon);
    const UA_NodeId source = addObject(1, "Source");
    ck_assert_uint_eq(triggerEvent(UA_NS0ID(BASEEVENTTYPE), source, &item, 1), 1);
    ck_assert_uint_eq(triggerEvent(UA_NS0ID(AUDITEVENTTYPE), UA_NS0ID(SERVER),
                                   &item, 1), 1);

    /* An explicit override is enforced */
    const UA_RolePermission noEvents[] = {{ROLE(ANONYMOUS), B | R}};
    ck_assert_uint_eq(UA_Server_setNodeRolePermissions(server, source, 1, noEvents,
                                                       false, NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(triggerEvent(UA_NS0ID(BASEEVENTTYPE), source, &item, 1), 0);
}
END_TEST
#endif /* UA_ENABLE_SUBSCRIPTIONS_EVENTS */

static Suite *testSuite_rbacNamespaces(void) {
    Suite *s = suite_create("RBAC namespaces");

    TCase *tc_strict = tcase_create("Templates (strict)");
    tcase_add_checked_fixture(tc_strict, setupStrict, teardown);
    tcase_add_test(tc_strict, template_namespaceZero);
    tcase_add_test(tc_strict, template_namespaceOne);
    tcase_add_test(tc_strict, template_configureAdminAddsBelowObjectsFolder);
    tcase_add_test(tc_strict, template_explicitDefaultWins);
    tcase_add_test(tc_strict, template_runtimeNamespace);
    tcase_add_test(tc_strict, template_attributes);
    suite_add_tcase(s, tc_strict);

    TCase *tc_legacy = tcase_create("Templates (legacy)");
    tcase_add_checked_fixture(tc_legacy, setupLegacy, teardown);
    tcase_add_test(tc_legacy, template_ignoredInLegacyMode);
    suite_add_tcase(s, tc_legacy);

    TCase *tc_config = tcase_create("Template configuration");
    tcase_add_test(tc_config, template_unknownRoleRejected);
    suite_add_tcase(s, tc_config);

    TCase *tc_metadata = tcase_create("NamespaceMetadata (strict)");
    tcase_add_checked_fixture(tc_metadata, setupStrict, teardown);
    tcase_add_test(tc_metadata, metadata_createdForNamespaceOne);
    tcase_add_test(tc_metadata, metadata_runtimeNamespace);
    tcase_add_test(tc_metadata, metadata_userRolePermissionsFiltered);
    tcase_add_test(tc_metadata, metadata_accessRestrictionsFollowSetter);
    tcase_add_test(tc_metadata, metadata_defaultRolePermissionsAdminOnly);
    suite_add_tcase(s, tc_metadata);

    TCase *tc_adopt = tcase_create("NamespaceMetadata adoption");
    tcase_add_test(tc_adopt, metadata_adoptsNodesetObject);
    tcase_add_test(tc_adopt, metadata_adoptsNodesetObjectWithAccessRestrictions);
    suite_add_tcase(s, tc_adopt);

    TCase *tc_access = tcase_create("Access decisions (strict)");
    tcase_add_checked_fixture(tc_access, setupStrict, teardown);
    tcase_add_test(tc_access, strict_writeWithSourceTimestamp);
    tcase_add_test(tc_access, accessControl_errorHandling);
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    tcase_add_test(tc_access, strict_receiveEventsOnTypeAndSource);
#endif
    suite_add_tcase(s, tc_access);

    TCase *tc_accessLegacy = tcase_create("Access decisions (legacy)");
    tcase_add_checked_fixture(tc_accessLegacy, setupLegacy, teardown);
    tcase_add_test(tc_accessLegacy, legacy_writeWithSourceTimestamp);
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    tcase_add_test(tc_accessLegacy, legacy_receiveEvents);
#endif
    suite_add_tcase(s, tc_accessLegacy);

    TCase *tc_metaLegacy = tcase_create("NamespaceMetadata (legacy)");
    tcase_add_checked_fixture(tc_metaLegacy, setupLegacy, teardown);
    tcase_add_test(tc_metaLegacy, metadata_legacyPropertiesFollowModel);
    suite_add_tcase(s, tc_metaLegacy);

    return s;
}

int main(void) {
    Suite *s = testSuite_rbacNamespaces();
    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
