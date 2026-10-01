/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2025-2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#include <open62541/server.h>
#include <open62541/nodeids.h>
#include <open62541/plugin/accesscontrol.h>
#include "ua_server_internal.h"

#ifdef UA_ENABLE_RBAC

#include "ua_server_rbac.h"

/* RBAC NS0 information model integration.
 * Known RBAC limitations are documented in ua_server_rbac.c. */

/* Resolve the Object owning a property (inverse HasProperty), so the data
 * source callbacks need no per-node context to release on node deletion. Used
 * for the Properties of the Role and NamespaceMetadata Objects. */
static UA_StatusCode
getParentOfProperty(UA_Server *server, const UA_NodeId *propertyId,
                    UA_NodeId *parentId) {
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = *propertyId;
    bd.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY);
    bd.includeSubtypes = false;
    bd.browseDirection = UA_BROWSEDIRECTION_INVERSE;
    bd.nodeClassMask = UA_NODECLASS_OBJECT;
    bd.resultMask = UA_BROWSERESULTMASK_NONE;

    UA_BrowseResult br = UA_Server_browse(server, 1, &bd);
    UA_StatusCode res = br.statusCode;
    if(res == UA_STATUSCODE_GOOD) {
        if(br.referencesSize > 0)
            res = UA_NodeId_copy(&br.references[0].nodeId.nodeId, parentId);
        else
            res = UA_STATUSCODE_BADNOTFOUND;
    }
    UA_BrowseResult_clear(&br);
    return res;
}

/* Find the Variable child with the given BrowseName name */
static UA_StatusCode
findPropertyChild(UA_Server *server, const UA_NodeId parentId,
                  const char *name, UA_NodeId *childId) {
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = parentId;
    bd.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY);
    bd.includeSubtypes = false;
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.nodeClassMask = UA_NODECLASS_VARIABLE;
    bd.resultMask = UA_BROWSERESULTMASK_BROWSENAME;

    UA_BrowseResult br = UA_Server_browse(server, 100, &bd);
    UA_StatusCode res = br.statusCode;
    if(res == UA_STATUSCODE_GOOD) {
        res = UA_STATUSCODE_BADNOTFOUND;
        UA_String nameStr = UA_STRING((char*)(uintptr_t)name);
        for(size_t i = 0; i < br.referencesSize; i++) {
            if(UA_String_equal(&br.references[i].browseName.name, &nameStr)) {
                res = UA_NodeId_copy(&br.references[i].nodeId.nodeId, childId);
                break;
            }
        }
    }
    UA_BrowseResult_clear(&br);
    return res;
}

static UA_StatusCode
findMethodChild(UA_Server *server, const UA_NodeId parentId,
                const char *name, UA_NodeId *childId) {
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = parentId;
    bd.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT);
    bd.includeSubtypes = false;
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.nodeClassMask = UA_NODECLASS_METHOD;
    bd.resultMask = UA_BROWSERESULTMASK_BROWSENAME;

    UA_BrowseResult br = UA_Server_browse(server, 100, &bd);
    UA_StatusCode res = br.statusCode;
    if(res == UA_STATUSCODE_GOOD) {
        res = UA_STATUSCODE_BADNOTFOUND;
        UA_String nameStr = UA_STRING((char*)(uintptr_t)name);
        for(size_t i = 0; i < br.referencesSize; i++) {
            if(UA_String_equal(&br.references[i].browseName.name, &nameStr)) {
                res = UA_NodeId_copy(&br.references[i].nodeId.nodeId, childId);
                break;
            }
        }
    }
    UA_BrowseResult_clear(&br);
    return res;
}

/* Resolve the namespace whose NamespaceMetadata Object owns the Property */
static UA_StatusCode
getNamespaceOfProperty(UA_Server *server, const UA_NodeId *propertyId,
                       UA_UInt16 *namespaceIndex) {
    UA_NodeId objectId;
    UA_StatusCode res = getParentOfProperty(server, propertyId, &objectId);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    res = UA_STATUSCODE_BADNOTFOUND;
    lockServer(server);
    for(size_t i = 0; i < server->namespaceMetadataSize; i++) {
        if(UA_NodeId_equal(&server->namespaceMetadata[i].objectId, &objectId)) {
            *namespaceIndex = (UA_UInt16)i;
            res = UA_STATUSCODE_GOOD;
            break;
        }
    }
    unlockServer(server);
    UA_NodeId_clear(&objectId);
    return res;
}

static UA_StatusCode
readNamespacePermissions(UA_Server *server, const UA_NodeId *sessionId,
                         const UA_NodeId *nodeId, UA_Boolean userOnly,
                         UA_DataValue *value) {
    UA_UInt16 namespaceIndex = 0;
    UA_StatusCode res = getNamespaceOfProperty(server, nodeId, &namespaceIndex);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_RolePermissionType *out = NULL;
    size_t outSize = 0;
    lockServer(server);
    size_t entriesSize = 0;
    const UA_RolePermission *entries = NULL;
    getNamespaceRolePermissionModel(server, namespaceIndex, &entriesSize, &entries);
    if(userOnly) {
        /* DefaultUserRolePermissions: filtered to the Session's Roles */
        const UA_Session *session = sessionId ?
            getSessionById(server, sessionId) : NULL;
        res = filterRolePermissionsForSession(session, entriesSize, entries,
                                              &outSize, &out);
    } else if(entriesSize > 0) {
        /* DefaultRolePermissions: the complete list */
        out = (UA_RolePermissionType*)
            UA_Array_new(entriesSize, &UA_TYPES[UA_TYPES_ROLEPERMISSIONTYPE]);
        if(out) {
            outSize = entriesSize;
            for(size_t i = 0; i < entriesSize; i++) {
                res = UA_NodeId_copy(&entries[i].roleId, &out[i].roleId);
                if(res != UA_STATUSCODE_GOOD)
                    break;
                out[i].permissions = entries[i].permissions;
            }
        } else {
            res = UA_STATUSCODE_BADOUTOFMEMORY;
        }
    }
    unlockServer(server);

    if(res != UA_STATUSCODE_GOOD) {
        UA_Array_delete(out, outSize, &UA_TYPES[UA_TYPES_ROLEPERMISSIONTYPE]);
        return res;
    }
    UA_Variant_setArray(&value->value, out, outSize,
                        &UA_TYPES[UA_TYPES_ROLEPERMISSIONTYPE]);
    value->hasValue = true;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
readNamespaceDefaultRolePermissions(UA_Server *server,
                                    const UA_NodeId *sessionId,
                                    void *sessionContext,
                                    const UA_NodeId *nodeId, void *nodeContext,
                                    UA_Boolean includeSourceTimeStamp,
                                    const UA_NumericRange *range,
                                    UA_DataValue *value) {
    return readNamespacePermissions(server, sessionId, nodeId, false, value);
}

static UA_StatusCode
readNamespaceDefaultUserRolePermissions(UA_Server *server,
                                        const UA_NodeId *sessionId,
                                        void *sessionContext,
                                        const UA_NodeId *nodeId,
                                        void *nodeContext,
                                        UA_Boolean includeSourceTimeStamp,
                                        const UA_NumericRange *range,
                                        UA_DataValue *value) {
    return readNamespacePermissions(server, sessionId, nodeId, true, value);
}

static UA_StatusCode
readNamespaceDefaultAccessRestrictions(UA_Server *server,
                                       const UA_NodeId *sessionId,
                                       void *sessionContext,
                                       const UA_NodeId *nodeId,
                                       void *nodeContext,
                                       UA_Boolean includeSourceTimeStamp,
                                       const UA_NumericRange *range,
                                       UA_DataValue *value) {
    UA_UInt16 namespaceIndex = 0;
    UA_StatusCode res = getNamespaceOfProperty(server, nodeId, &namespaceIndex);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_AccessRestrictionType restrictions = UA_ACCESSRESTRICTIONTYPE_NONE;
    lockServer(server);
    if(server->namespaceMetadata && namespaceIndex < server->namespaceMetadataSize &&
       server->namespaceMetadata[namespaceIndex].hasDefaultAccessRestrictions)
        restrictions = server->namespaceMetadata[namespaceIndex].defaultAccessRestrictions;
    unlockServer(server);

    res = UA_Variant_setScalarCopy(&value->value, &restrictions,
                                   &UA_TYPES[UA_TYPES_ACCESSRESTRICTIONTYPE]);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    value->hasValue = true;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
ensureRoleTypeMethods(UA_Server *server, const UA_NodeId *roleId,
                      UA_Boolean applyPermissions);

static UA_StatusCode
readRoleIdentities(UA_Server *server, const UA_NodeId *sessionId,
                   void *sessionContext,
                   const UA_NodeId *nodeId, void *nodeContext,
                   UA_Boolean includeSourceTimeStamp,
                   const UA_NumericRange *range,
                   UA_DataValue *value) {
    UA_NodeId roleId;
    UA_StatusCode res = getParentOfProperty(server, nodeId, &roleId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_Role role;
    res = UA_Server_getRoleById(server, roleId, &role);
    UA_NodeId_clear(&roleId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_Variant_setArrayCopy(&value->value, role.identityMappingRules,
                            role.identityMappingRulesSize,
                            &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE]);
    value->hasValue = true;
    UA_Role_clear(&role);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
readRoleApplications(UA_Server *server, const UA_NodeId *sessionId,
                     void *sessionContext,
                     const UA_NodeId *nodeId, void *nodeContext,
                     UA_Boolean includeSourceTimeStamp,
                     const UA_NumericRange *range,
                     UA_DataValue *value) {
    UA_NodeId roleId;
    UA_StatusCode res = getParentOfProperty(server, nodeId, &roleId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_Role role;
    res = UA_Server_getRoleById(server, roleId, &role);
    UA_NodeId_clear(&roleId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_Variant_setArrayCopy(&value->value, role.applications,
                            role.applicationsSize,
                            &UA_TYPES[UA_TYPES_STRING]);
    value->hasValue = true;
    UA_Role_clear(&role);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
readRoleEndpoints(UA_Server *server, const UA_NodeId *sessionId,
                  void *sessionContext,
                  const UA_NodeId *nodeId, void *nodeContext,
                  UA_Boolean includeSourceTimeStamp,
                  const UA_NumericRange *range,
                  UA_DataValue *value) {
    UA_NodeId roleId;
    UA_StatusCode res = getParentOfProperty(server, nodeId, &roleId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_Role role;
    res = UA_Server_getRoleById(server, roleId, &role);
    UA_NodeId_clear(&roleId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_Variant_setArrayCopy(&value->value, role.endpoints,
                            role.endpointsSize,
                            &UA_TYPES[UA_TYPES_ENDPOINTTYPE]);
    value->hasValue = true;
    UA_Role_clear(&role);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
readRoleApplicationsExclude(UA_Server *server, const UA_NodeId *sessionId,
                            void *sessionContext,
                            const UA_NodeId *nodeId, void *nodeContext,
                            UA_Boolean includeSourceTimeStamp,
                            const UA_NumericRange *range,
                            UA_DataValue *value) {
    UA_NodeId roleId;
    UA_StatusCode res = getParentOfProperty(server, nodeId, &roleId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_Role role;
    res = UA_Server_getRoleById(server, roleId, &role);
    UA_NodeId_clear(&roleId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_Variant_setScalarCopy(&value->value, &role.applicationsExclude,
                             &UA_TYPES[UA_TYPES_BOOLEAN]);
    value->hasValue = true;
    UA_Role_clear(&role);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
writeRoleApplicationsExclude(UA_Server *server, const UA_NodeId *sessionId,
                             void *sessionContext,
                             const UA_NodeId *nodeId, void *nodeContext,
                             const UA_NumericRange *range,
                             const UA_DataValue *value) {
    if(range)
        return UA_STATUSCODE_BADINDEXRANGEINVALID;
    if(!value || !value->hasValue ||
       value->value.type != &UA_TYPES[UA_TYPES_BOOLEAN] ||
       !UA_Variant_isScalar(&value->value))
        return UA_STATUSCODE_BADTYPEMISMATCH;

    UA_NodeId roleId;
    UA_StatusCode res = getParentOfProperty(server, nodeId, &roleId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_Role role;
    res = UA_Server_getRoleById(server, roleId, &role);
    UA_NodeId_clear(&roleId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    role.applicationsExclude = *(UA_Boolean*)value->value.data;
    res = UA_Server_updateRole(server, &role);
    UA_Role_clear(&role);
    return res;
}

static UA_StatusCode
readRoleEndpointsExclude(UA_Server *server, const UA_NodeId *sessionId,
                         void *sessionContext,
                         const UA_NodeId *nodeId, void *nodeContext,
                         UA_Boolean includeSourceTimeStamp,
                         const UA_NumericRange *range,
                         UA_DataValue *value) {
    UA_NodeId roleId;
    UA_StatusCode res = getParentOfProperty(server, nodeId, &roleId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_Role role;
    res = UA_Server_getRoleById(server, roleId, &role);
    UA_NodeId_clear(&roleId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_Variant_setScalarCopy(&value->value, &role.endpointsExclude,
                             &UA_TYPES[UA_TYPES_BOOLEAN]);
    value->hasValue = true;
    UA_Role_clear(&role);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
writeRoleEndpointsExclude(UA_Server *server, const UA_NodeId *sessionId,
                          void *sessionContext,
                          const UA_NodeId *nodeId, void *nodeContext,
                          const UA_NumericRange *range,
                          const UA_DataValue *value) {
    if(range)
        return UA_STATUSCODE_BADINDEXRANGEINVALID;
    if(!value || !value->hasValue ||
       value->value.type != &UA_TYPES[UA_TYPES_BOOLEAN] ||
       !UA_Variant_isScalar(&value->value))
        return UA_STATUSCODE_BADTYPEMISMATCH;

    UA_NodeId roleId;
    UA_StatusCode res = getParentOfProperty(server, nodeId, &roleId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_Role role;
    res = UA_Server_getRoleById(server, roleId, &role);
    UA_NodeId_clear(&roleId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    role.endpointsExclude = *(UA_Boolean*)value->value.data;
    res = UA_Server_updateRole(server, &role);
    UA_Role_clear(&role);
    return res;
}

static UA_StatusCode
readRoleCustomConfiguration(UA_Server *server, const UA_NodeId *sessionId,
                            void *sessionContext,
                            const UA_NodeId *nodeId, void *nodeContext,
                            UA_Boolean includeSourceTimeStamp,
                            const UA_NumericRange *range,
                            UA_DataValue *value) {
    UA_NodeId roleId;
    UA_StatusCode res = getParentOfProperty(server, nodeId, &roleId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_Role role;
    res = UA_Server_getRoleById(server, roleId, &role);
    UA_NodeId_clear(&roleId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_Variant_setScalarCopy(&value->value, &role.customConfiguration,
                             &UA_TYPES[UA_TYPES_BOOLEAN]);
    value->hasValue = true;
    UA_Role_clear(&role);
    return UA_STATUSCODE_GOOD;
}

/* Add Role object to NS0. The role->roleId must already be set by the
 * caller. Identities is mandatory, Applications and Endpoints are added
 * as optional properties with DataSources. */
UA_StatusCode
addRoleRepresentation(UA_Server *server, UA_Role *role) {
    if(!server || !role)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    if(UA_NodeId_isNull(&role->roleId))
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_StatusCode res = UA_STATUSCODE_GOOD;

    /* Add Role object instance using the pre-assigned roleId */
    UA_ObjectAttributes oAttr = UA_ObjectAttributes_default;
    oAttr.displayName.locale = UA_STRING("en-US");
    oAttr.displayName.text = role->roleName.name;
    oAttr.description = UA_LOCALIZEDTEXT("en-US", "");

    res = UA_Server_addObjectNode(server, role->roleId,
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERCAPABILITIES_ROLESET),
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                  role->roleName,
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_ROLETYPE),
                                  oAttr, NULL, NULL);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* Back the mandatory Identities property with the role registry */
    UA_NodeId identitiesNodeId;
    res = findPropertyChild(server, role->roleId, "Identities", &identitiesNodeId);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Server_deleteNode(server, role->roleId, true);
        return res;
    }

    UA_DataSource identitiesDataSource;
    identitiesDataSource.read = readRoleIdentities;
    identitiesDataSource.write = NULL;

    res = UA_Server_setVariableNode_dataSource(server, identitiesNodeId,
                                               identitiesDataSource);
    UA_NodeId_clear(&identitiesNodeId);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Server_deleteNode(server, role->roleId, true);
        return res;
    }

    /* Add optional Applications property with DataSource */
    UA_VariableAttributes vAttr = UA_VariableAttributes_default;
    vAttr.displayName = UA_LOCALIZEDTEXT("en-US", "Applications");
    vAttr.dataType = UA_TYPES[UA_TYPES_STRING].typeId;
    vAttr.valueRank = UA_VALUERANK_ONE_OR_MORE_DIMENSIONS;
    vAttr.accessLevel = UA_ACCESSLEVELMASK_READ;

    UA_DataSource applicationsDataSource;
    applicationsDataSource.read = readRoleApplications;
    applicationsDataSource.write = NULL;

    res = UA_Server_addDataSourceVariableNode(server, UA_NODEID_NULL,
                                              role->roleId,
                                              UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY),
                                              UA_QUALIFIEDNAME(0, "Applications"),
                                              UA_NODEID_NUMERIC(0, UA_NS0ID_PROPERTYTYPE),
                                              vAttr, applicationsDataSource,
                                              NULL, NULL);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Server_deleteNode(server, role->roleId, true);
        return res;
    }

    /* Add optional ApplicationsExclude property with DataSource */
    vAttr = UA_VariableAttributes_default;
    vAttr.displayName = UA_LOCALIZEDTEXT("en-US", "ApplicationsExclude");
    vAttr.dataType = UA_TYPES[UA_TYPES_BOOLEAN].typeId;
    vAttr.valueRank = UA_VALUERANK_SCALAR;
    vAttr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;

    UA_DataSource applicationsExcludeDataSource;
    applicationsExcludeDataSource.read = readRoleApplicationsExclude;
    applicationsExcludeDataSource.write = writeRoleApplicationsExclude;

    res = UA_Server_addDataSourceVariableNode(server, UA_NODEID_NULL,
                                              role->roleId,
                                              UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY),
                                              UA_QUALIFIEDNAME(0, "ApplicationsExclude"),
                                              UA_NODEID_NUMERIC(0, UA_NS0ID_PROPERTYTYPE),
                                              vAttr, applicationsExcludeDataSource,
                                              NULL, NULL);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Server_deleteNode(server, role->roleId, true);
        return res;
    }

    /* Add optional Endpoints property with DataSource */
    vAttr.displayName = UA_LOCALIZEDTEXT("en-US", "Endpoints");
    vAttr.dataType = UA_TYPES[UA_TYPES_ENDPOINTTYPE].typeId;
    vAttr.valueRank = UA_VALUERANK_ONE_OR_MORE_DIMENSIONS;
    vAttr.accessLevel = UA_ACCESSLEVELMASK_READ;

    UA_DataSource endpointsDataSource;
    endpointsDataSource.read = readRoleEndpoints;
    endpointsDataSource.write = NULL;

    res = UA_Server_addDataSourceVariableNode(server, UA_NODEID_NULL,
                                              role->roleId,
                                              UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY),
                                              UA_QUALIFIEDNAME(0, "Endpoints"),
                                              UA_NODEID_NUMERIC(0, UA_NS0ID_PROPERTYTYPE),
                                              vAttr, endpointsDataSource,
                                              NULL, NULL);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Server_deleteNode(server, role->roleId, true);
        return res;
    }

    /* Add optional EndpointsExclude property with DataSource */
    vAttr = UA_VariableAttributes_default;
    vAttr.displayName = UA_LOCALIZEDTEXT("en-US", "EndpointsExclude");
    vAttr.dataType = UA_TYPES[UA_TYPES_BOOLEAN].typeId;
    vAttr.valueRank = UA_VALUERANK_SCALAR;
    vAttr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;

    UA_DataSource endpointsExcludeDataSource;
    endpointsExcludeDataSource.read = readRoleEndpointsExclude;
    endpointsExcludeDataSource.write = writeRoleEndpointsExclude;

    res = UA_Server_addDataSourceVariableNode(server, UA_NODEID_NULL,
                                              role->roleId,
                                              UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY),
                                              UA_QUALIFIEDNAME(0, "EndpointsExclude"),
                                              UA_NODEID_NUMERIC(0, UA_NS0ID_PROPERTYTYPE),
                                              vAttr, endpointsExcludeDataSource,
                                              NULL, NULL);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Server_deleteNode(server, role->roleId, true);
        return res;
    }

    /* Add optional CustomConfiguration property with DataSource (Part 18 §4.4.1).
     * Boolean scalar; read-only. */
    vAttr = UA_VariableAttributes_default;
    vAttr.displayName = UA_LOCALIZEDTEXT("en-US", "CustomConfiguration");
    vAttr.dataType = UA_TYPES[UA_TYPES_BOOLEAN].typeId;
    vAttr.valueRank = UA_VALUERANK_SCALAR;
    vAttr.accessLevel = UA_ACCESSLEVELMASK_READ;

    UA_DataSource customConfigDataSource;
    customConfigDataSource.read = readRoleCustomConfiguration;
    customConfigDataSource.write = NULL;

    res = UA_Server_addDataSourceVariableNode(server, UA_NODEID_NULL,
                                              role->roleId,
                                              UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY),
                                              UA_QUALIFIEDNAME(0, "CustomConfiguration"),
                                              UA_NODEID_NUMERIC(0, UA_NS0ID_PROPERTYTYPE),
                                              vAttr, customConfigDataSource,
                                              NULL, NULL);
    if(res != UA_STATUSCODE_GOOD)
        UA_Server_deleteNode(server, role->roleId, true);
    if(res == UA_STATUSCODE_GOOD) {
        res = ensureRoleTypeMethods(server, &role->roleId, true);
        if(res != UA_STATUSCODE_GOOD)
            UA_Server_deleteNode(server, role->roleId, true);
    }
    return res;
}

/* Remove Role object from NS0 */
UA_StatusCode
removeRoleRepresentation(UA_Server *server, const UA_NodeId *roleId) {
    if(!server || !roleId)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    /* Only a Role Object is ours to delete. A Node that took over the NodeId
     * in the meantime is reported as "no representation" and kept. */
    UA_StatusCode res = checkRoleRepresentation(server, roleId);
    if(res == UA_STATUSCODE_BADNODEIDEXISTS) {
        UA_LOG_WARNING(server->config.logging, UA_LOGCATEGORY_SERVER,
                       "RBAC: The Node %N of the removed Role is not a RoleType "
                       "instance and is kept", *roleId);
        return UA_STATUSCODE_BADNODEIDUNKNOWN;
    }
    if(res != UA_STATUSCODE_GOOD)
        return res;
    return UA_Server_deleteNode(server, *roleId, true);
}

/* Method callbacks */

static UA_StatusCode
addRoleMethodCallback(UA_Server *server,
                      const UA_NodeId *sessionId, void *sessionContext,
                      const UA_NodeId *methodId, void *methodContext,
                      const UA_NodeId *objectId, void *objectContext,
                      size_t inputSize, const UA_Variant *input,
                      size_t outputSize, UA_Variant *output) {
    UA_StatusCode res = checkMethodOutputArguments(outputSize, 1);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_StatusCode access = checkRBACMethodAccess(server, sessionId);
    if(access != UA_STATUSCODE_GOOD)
        return access;
    if(inputSize != 2 ||
       input[0].type != &UA_TYPES[UA_TYPES_STRING] ||
       input[1].type != &UA_TYPES[UA_TYPES_STRING])
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_String *roleName = (UA_String*)input[0].data;
    UA_String *namespaceUri = (UA_String*)input[1].data;

    UA_Role role;
    UA_Role_init(&role);
    res = UA_String_copy(roleName, &role.roleName.name);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* Per specification, use NS1 if no namespaceUri is given */
    if(namespaceUri->length > 0) {
        size_t nsIdx = 0;
        res = UA_Server_getNamespaceByName(server, *namespaceUri, &nsIdx);
        if(res != UA_STATUSCODE_GOOD) {
            UA_Role_clear(&role);
            return UA_STATUSCODE_BADINVALIDARGUMENT;
        }
        role.roleName.namespaceIndex = (UA_UInt16)nsIdx;
    } else {
        role.roleName.namespaceIndex = 1;
    }

    UA_NodeId newRoleId = UA_NODEID_NULL;
    UA_StatusCode retval = UA_Server_addRole(server, &role, &newRoleId);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Role_clear(&role);
        return retval;
    }

    /* UA_Server_addRole already published the Role Object under the RoleSet
     * (Part 18 §4.2.2, §4.3). */
    retval = UA_Variant_setScalarCopy(&output[0], &newRoleId,
                                      &UA_TYPES[UA_TYPES_NODEID]);
    if(retval != UA_STATUSCODE_GOOD) {
        /* The Method reports a failure, so it must not leave the Role behind */
        UA_Server_removeRole(server, role.roleName);
    }

    UA_Role_clear(&role);
    UA_NodeId_clear(&newRoleId);
    return retval;
}

static UA_StatusCode
removeRoleMethodCallback(UA_Server *server,
                         const UA_NodeId *sessionId, void *sessionContext,
                         const UA_NodeId *methodId, void *methodContext,
                         const UA_NodeId *objectId, void *objectContext,
                         size_t inputSize, const UA_Variant *input,
                         size_t outputSize, UA_Variant *output) {
    UA_StatusCode access = checkRBACMethodAccess(server, sessionId);
    if(access != UA_STATUSCODE_GOOD)
        return access;
    if(inputSize != 1 || input[0].type != &UA_TYPES[UA_TYPES_NODEID])
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_NodeId roleId = *(UA_NodeId*)input[0].data;
    UA_Role role;
    UA_StatusCode res = UA_Server_getRoleById(server, roleId, &role);
    if(res != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADNODEIDUNKNOWN;

    UA_QualifiedName roleName;
    res = UA_QualifiedName_copy(&role.roleName, &roleName);
    UA_Role_clear(&role);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* UA_Server_removeRole also drops the published Role Object from the
     * AddressSpace (Part 18 §4.2.3, §4.3). */
    res = UA_Server_removeRole(server, roleName);
    UA_QualifiedName_clear(&roleName);
    return res;
}

static UA_StatusCode
addIdentityMethodCallback(UA_Server *server,
                          const UA_NodeId *sessionId, void *sessionContext,
                          const UA_NodeId *methodId, void *methodContext,
                          const UA_NodeId *objectId, void *objectContext,
                          size_t inputSize, const UA_Variant *input,
                          size_t outputSize, UA_Variant *output) {
    UA_StatusCode access = checkRBACMethodAccess(server, sessionId);
    if(access != UA_STATUSCODE_GOOD)
        return access;
    if(inputSize != 1 || input[0].type != &UA_TYPES[UA_TYPES_EXTENSIONOBJECT])
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_ExtensionObject *extObj = (UA_ExtensionObject*)input[0].data;
    if(!extObj->content.decoded.data ||
       extObj->content.decoded.type != &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE])
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_IdentityMappingRuleType *rule =
        (UA_IdentityMappingRuleType*)extObj->content.decoded.data;

    UA_Role role;
    UA_StatusCode res = UA_Server_getRoleById(server, *objectId, &role);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* Reject equivalent existing rules per Part 18 §4.4.5 (Bad_AlreadyExists).
     * Equality is on the full struct, not just the criteriaType, so rules that
     * differ only in criteria remain distinct. */
    for(size_t i = 0; i < role.identityMappingRulesSize; i++) {
        if(UA_IdentityMappingRuleType_equal(&role.identityMappingRules[i], rule)) {
            UA_Role_clear(&role);
            return UA_STATUSCODE_BADALREADYEXISTS;
        }
    }

    UA_IdentityMappingRuleType *newRules = (UA_IdentityMappingRuleType*)
        UA_realloc(role.identityMappingRules,
                   (role.identityMappingRulesSize + 1) *
                   sizeof(UA_IdentityMappingRuleType));
    if(!newRules) {
        UA_Role_clear(&role);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    role.identityMappingRules = newRules;
    res = UA_IdentityMappingRuleType_copy(
        rule, &role.identityMappingRules[role.identityMappingRulesSize]);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Role_clear(&role);
        return res;
    }
    role.identityMappingRulesSize++;

    res = UA_Server_updateRoleFromMethod(server, &role, sessionId, methodId,
                                         inputSize, input);
    UA_Role_clear(&role);
    return res;
}

static UA_StatusCode
removeIdentityMethodCallback(UA_Server *server,
                             const UA_NodeId *sessionId, void *sessionContext,
                             const UA_NodeId *methodId, void *methodContext,
                             const UA_NodeId *objectId, void *objectContext,
                             size_t inputSize, const UA_Variant *input,
                             size_t outputSize, UA_Variant *output) {
    UA_StatusCode access = checkRBACMethodAccess(server, sessionId);
    if(access != UA_STATUSCODE_GOOD)
        return access;
    if(inputSize != 1 || input[0].type != &UA_TYPES[UA_TYPES_EXTENSIONOBJECT])
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_ExtensionObject *extObj = (UA_ExtensionObject*)input[0].data;
    if(!extObj->content.decoded.data ||
       extObj->content.decoded.type != &UA_TYPES[UA_TYPES_IDENTITYMAPPINGRULETYPE])
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_IdentityMappingRuleType *rule =
        (UA_IdentityMappingRuleType*)extObj->content.decoded.data;

    UA_Role role;
    UA_StatusCode res = UA_Server_getRoleById(server, *objectId, &role);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* Find and remove the identity rule that matches in both criteriaType and
     * criteria; several rules may share a criteriaType. */
    size_t idx = SIZE_MAX;
    for(size_t i = 0; i < role.identityMappingRulesSize; i++) {
        if(UA_IdentityMappingRuleType_equal(&role.identityMappingRules[i], rule)) {
            idx = i;
            break;
        }
    }
    if(idx == SIZE_MAX) {
        UA_Role_clear(&role);
        return UA_STATUSCODE_BADNOTFOUND;
    }

    UA_IdentityMappingRuleType_clear(&role.identityMappingRules[idx]);
    if(idx < role.identityMappingRulesSize - 1)
        memmove(&role.identityMappingRules[idx],
                &role.identityMappingRules[idx + 1],
                (role.identityMappingRulesSize - idx - 1) *
                sizeof(UA_IdentityMappingRuleType));
    role.identityMappingRulesSize--;

    res = UA_Server_updateRoleFromMethod(server, &role, sessionId, methodId,
                                         inputSize, input);
    UA_Role_clear(&role);
    return res;
}

static UA_StatusCode
addApplicationMethodCallback(UA_Server *server,
                             const UA_NodeId *sessionId, void *sessionContext,
                             const UA_NodeId *methodId, void *methodContext,
                             const UA_NodeId *objectId, void *objectContext,
                             size_t inputSize, const UA_Variant *input,
                             size_t outputSize, UA_Variant *output) {
    UA_StatusCode access = checkRBACMethodAccess(server, sessionId);
    if(access != UA_STATUSCODE_GOOD)
        return access;
    if(inputSize != 1 || input[0].type != &UA_TYPES[UA_TYPES_STRING])
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_Role role;
    UA_StatusCode res = UA_Server_getRoleById(server, *objectId, &role);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_String *newApps = (UA_String*)
        UA_realloc(role.applications,
                   (role.applicationsSize + 1) * sizeof(UA_String));
    if(!newApps) {
        UA_Role_clear(&role);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    role.applications = newApps;
    res = UA_String_copy((UA_String*)input[0].data,
                         &role.applications[role.applicationsSize]);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Role_clear(&role);
        return res;
    }
    role.applicationsSize++;

    res = UA_Server_updateRoleFromMethod(server, &role, sessionId, methodId,
                                         inputSize, input);
    UA_Role_clear(&role);
    return res;
}

static UA_StatusCode
removeApplicationMethodCallback(UA_Server *server,
                                const UA_NodeId *sessionId, void *sessionContext,
                                const UA_NodeId *methodId, void *methodContext,
                                const UA_NodeId *objectId, void *objectContext,
                                size_t inputSize, const UA_Variant *input,
                                size_t outputSize, UA_Variant *output) {
    UA_StatusCode access = checkRBACMethodAccess(server, sessionId);
    if(access != UA_STATUSCODE_GOOD)
        return access;
    if(inputSize != 1 || input[0].type != &UA_TYPES[UA_TYPES_STRING])
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_String *uri = (UA_String*)input[0].data;

    UA_Role role;
    UA_StatusCode res = UA_Server_getRoleById(server, *objectId, &role);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    size_t idx = SIZE_MAX;
    for(size_t i = 0; i < role.applicationsSize; i++) {
        if(UA_String_equal(&role.applications[i], uri)) {
            idx = i;
            break;
        }
    }
    if(idx == SIZE_MAX) {
        UA_Role_clear(&role);
        return UA_STATUSCODE_BADNOTFOUND;
    }

    UA_String_clear(&role.applications[idx]);
    if(idx < role.applicationsSize - 1)
        memmove(&role.applications[idx], &role.applications[idx + 1],
                (role.applicationsSize - idx - 1) * sizeof(UA_String));
    role.applicationsSize--;

    res = UA_Server_updateRoleFromMethod(server, &role, sessionId, methodId,
                                         inputSize, input);
    UA_Role_clear(&role);
    return res;
}

static UA_StatusCode
addEndpointMethodCallback(UA_Server *server,
                          const UA_NodeId *sessionId, void *sessionContext,
                          const UA_NodeId *methodId, void *methodContext,
                          const UA_NodeId *objectId, void *objectContext,
                          size_t inputSize, const UA_Variant *input,
                          size_t outputSize, UA_Variant *output) {
    UA_StatusCode access = checkRBACMethodAccess(server, sessionId);
    if(access != UA_STATUSCODE_GOOD)
        return access;
    if(inputSize != 1 || input[0].type != &UA_TYPES[UA_TYPES_EXTENSIONOBJECT])
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_ExtensionObject *extObj = (UA_ExtensionObject*)input[0].data;
    if(!extObj->content.decoded.data ||
       extObj->content.decoded.type != &UA_TYPES[UA_TYPES_ENDPOINTTYPE])
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_Role role;
    UA_StatusCode res = UA_Server_getRoleById(server, *objectId, &role);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_EndpointType *newEps = (UA_EndpointType*)
        UA_realloc(role.endpoints,
                   (role.endpointsSize + 1) * sizeof(UA_EndpointType));
    if(!newEps) {
        UA_Role_clear(&role);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    role.endpoints = newEps;
    res = UA_EndpointType_copy((UA_EndpointType*)extObj->content.decoded.data,
                               &role.endpoints[role.endpointsSize]);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Role_clear(&role);
        return res;
    }
    role.endpointsSize++;

    res = UA_Server_updateRoleFromMethod(server, &role, sessionId, methodId,
                                         inputSize, input);
    UA_Role_clear(&role);
    return res;
}

static UA_StatusCode
removeEndpointMethodCallback(UA_Server *server,
                             const UA_NodeId *sessionId, void *sessionContext,
                             const UA_NodeId *methodId, void *methodContext,
                             const UA_NodeId *objectId, void *objectContext,
                             size_t inputSize, const UA_Variant *input,
                             size_t outputSize, UA_Variant *output) {
    UA_StatusCode access = checkRBACMethodAccess(server, sessionId);
    if(access != UA_STATUSCODE_GOOD)
        return access;
    if(inputSize != 1 || input[0].type != &UA_TYPES[UA_TYPES_EXTENSIONOBJECT])
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_ExtensionObject *extObj = (UA_ExtensionObject*)input[0].data;
    if(!extObj->content.decoded.data ||
       extObj->content.decoded.type != &UA_TYPES[UA_TYPES_ENDPOINTTYPE])
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_EndpointType *ep = (UA_EndpointType*)extObj->content.decoded.data;

    UA_Role role;
    UA_StatusCode res = UA_Server_getRoleById(server, *objectId, &role);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    size_t idx = SIZE_MAX;
    for(size_t i = 0; i < role.endpointsSize; i++) {
        if(UA_EndpointType_equal(&role.endpoints[i], ep)) {
            idx = i;
            break;
        }
    }
    if(idx == SIZE_MAX) {
        UA_Role_clear(&role);
        return UA_STATUSCODE_BADNOTFOUND;
    }

    UA_EndpointType_clear(&role.endpoints[idx]);
    if(idx < role.endpointsSize - 1)
        memmove(&role.endpoints[idx], &role.endpoints[idx + 1],
                (role.endpointsSize - idx - 1) * sizeof(UA_EndpointType));
    role.endpointsSize--;

    res = UA_Server_updateRoleFromMethod(server, &role, sessionId, methodId,
                                         inputSize, input);
    UA_Role_clear(&role);
    return res;
}

UA_Boolean
UA_Server_hasUserManagementProvider(const UA_AccessControl *ac) {
    return ac->getUsers && ac->getPasswordPolicy && ac->getUserConfiguration &&
           ac->addUser && ac->modifyUser && ac->removeUser && ac->changePassword;
}

static UA_Boolean
userMethodInputs(size_t inputSize, const UA_Variant *input,
                 size_t expectedSize, const UA_DataType **types) {
    if(inputSize != expectedSize)
        return false;
    for(size_t i = 0; i < expectedSize; i++) {
        if(input[i].type != types[i] || !UA_Variant_isScalar(&input[i]))
            return false;
    }
    return true;
}

static UA_StatusCode
validateUserConfiguration(UA_Server *server,
                          UA_UserConfigurationMask configuration) {
    if((configuration & UA_USERCONFIGURATIONMASK_NOCHANGEBYUSER) &&
       (configuration & UA_USERCONFIGURATIONMASK_MUSTCHANGEPASSWORD))
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    UA_Range length;
    UA_PasswordOptionsMask options = 0;
    UA_LocalizedText restrictions;
    UA_LocalizedText_init(&restrictions);
    UA_StatusCode res = server->config.accessControl.getPasswordPolicy(
        server, &server->config.accessControl, &length, &options,
        &restrictions);
    UA_LocalizedText_clear(&restrictions);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    if((configuration & UA_USERCONFIGURATIONMASK_NODELETE) &&
       !(options & UA_PASSWORDOPTIONSMASK_SUPPORTDISABLEDELETEFORUSER))
        return UA_STATUSCODE_BADNOTSUPPORTED;
    if((configuration & UA_USERCONFIGURATIONMASK_DISABLED) &&
       !(options & UA_PASSWORDOPTIONSMASK_SUPPORTDISABLEUSER))
        return UA_STATUSCODE_BADNOTSUPPORTED;
    if((configuration & UA_USERCONFIGURATIONMASK_NOCHANGEBYUSER) &&
       !(options & UA_PASSWORDOPTIONSMASK_SUPPORTNOCHANGEFORUSER))
        return UA_STATUSCODE_BADNOTSUPPORTED;
    if((configuration & UA_USERCONFIGURATIONMASK_MUSTCHANGEPASSWORD) &&
       !(options & UA_PASSWORDOPTIONSMASK_SUPPORTINITIALPASSWORDCHANGE))
        return UA_STATUSCODE_BADNOTSUPPORTED;
    return UA_STATUSCODE_GOOD;
}

static void
closeSessionsForUser(UA_Server *server, const UA_String *userName,
                     const UA_NodeId *exceptSessionId) {
    session_list_entry *entry, *next;
    LIST_FOREACH_SAFE(entry, &server->sessions, pointers, next) {
        UA_Session *session = &entry->session;
        if(exceptSessionId && UA_NodeId_equal(&session->sessionId,
                                              exceptSessionId))
            continue;
        if(session->hasIdentityContext &&
           UA_String_equal(&session->identityContext.userName, userName))
            UA_Session_remove(server, session, UA_SHUTDOWNREASON_CLOSE);
    }
}

static UA_StatusCode
addUserMethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                      void *sessionContext, const UA_NodeId *methodId,
                      void *methodContext, const UA_NodeId *objectId,
                      void *objectContext, size_t inputSize,
                      const UA_Variant *input, size_t outputSize,
                      UA_Variant *output) {
    UA_StatusCode res = checkRBACMethodAccess(server, sessionId);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    const UA_DataType *types[] = {&UA_TYPES[UA_TYPES_STRING],
        &UA_TYPES[UA_TYPES_STRING], &UA_TYPES[UA_TYPES_USERCONFIGURATIONMASK],
        &UA_TYPES[UA_TYPES_STRING]};
    if(!userMethodInputs(inputSize, input, 4, types))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_UserConfigurationMask configuration =
        *(UA_UserConfigurationMask*)input[2].data;
    res = validateUserConfiguration(server, configuration);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    return server->config.accessControl.addUser(
        server, &server->config.accessControl, (UA_String*)input[0].data,
        (UA_String*)input[1].data, configuration,
        (UA_String*)input[3].data);
}

static UA_StatusCode
modifyUserMethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                         void *sessionContext, const UA_NodeId *methodId,
                         void *methodContext, const UA_NodeId *objectId,
                         void *objectContext, size_t inputSize,
                         const UA_Variant *input, size_t outputSize,
                         UA_Variant *output) {
    UA_StatusCode res = checkRBACMethodAccess(server, sessionId);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    const UA_DataType *types[] = {&UA_TYPES[UA_TYPES_STRING],
        &UA_TYPES[UA_TYPES_BOOLEAN], &UA_TYPES[UA_TYPES_STRING],
        &UA_TYPES[UA_TYPES_BOOLEAN], &UA_TYPES[UA_TYPES_USERCONFIGURATIONMASK],
        &UA_TYPES[UA_TYPES_BOOLEAN], &UA_TYPES[UA_TYPES_STRING]};
    if(!userMethodInputs(inputSize, input, 7, types))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_Boolean modifyConfiguration = *(UA_Boolean*)input[3].data;
    UA_UserConfigurationMask configuration =
        *(UA_UserConfigurationMask*)input[4].data;
    if(modifyConfiguration) {
        res = validateUserConfiguration(server, configuration);
        if(res != UA_STATUSCODE_GOOD)
            return res;
        UA_Session *session = getSessionById(server, sessionId);
        if(session && (configuration & UA_USERCONFIGURATIONMASK_DISABLED) &&
           UA_String_equal(&session->identityContext.userName,
                           (UA_String*)input[0].data))
            return UA_STATUSCODE_BADINVALIDSELFREFERENCE;
    }
    res = server->config.accessControl.modifyUser(
        server, &server->config.accessControl, (UA_String*)input[0].data,
        *(UA_Boolean*)input[1].data, (UA_String*)input[2].data,
        modifyConfiguration, configuration, *(UA_Boolean*)input[5].data,
        (UA_String*)input[6].data);
    if(res == UA_STATUSCODE_GOOD && modifyConfiguration &&
       (configuration & UA_USERCONFIGURATIONMASK_DISABLED))
        closeSessionsForUser(server, (UA_String*)input[0].data, sessionId);
    return res;
}

static UA_StatusCode
removeUserMethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                         void *sessionContext, const UA_NodeId *methodId,
                         void *methodContext, const UA_NodeId *objectId,
                         void *objectContext, size_t inputSize,
                         const UA_Variant *input, size_t outputSize,
                         UA_Variant *output) {
    UA_StatusCode res = checkRBACMethodAccess(server, sessionId);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    const UA_DataType *types[] = {&UA_TYPES[UA_TYPES_STRING]};
    if(!userMethodInputs(inputSize, input, 1, types))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_Session *session = getSessionById(server, sessionId);
    if(session && UA_String_equal(&session->identityContext.userName,
                                  (UA_String*)input[0].data))
        return UA_STATUSCODE_BADINVALIDSELFREFERENCE;
    res = server->config.accessControl.removeUser(
        server, &server->config.accessControl, (UA_String*)input[0].data);
    if(res == UA_STATUSCODE_GOOD)
        closeSessionsForUser(server, (UA_String*)input[0].data, sessionId);
    return res;
}

static UA_StatusCode
changePasswordMethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                             void *sessionContext, const UA_NodeId *methodId,
                             void *methodContext, const UA_NodeId *objectId,
                             void *objectContext, size_t inputSize,
                             const UA_Variant *input, size_t outputSize,
                             UA_Variant *output) {
    UA_Session *session = getSessionById(server, sessionId);
    if(!session || !session->channel ||
       session->channel->securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        return UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT;
    if(!session->hasIdentityContext ||
       session->identityContext.userName.length == 0)
        return UA_STATUSCODE_BADINVALIDSTATE;
    const UA_DataType *types[] = {&UA_TYPES[UA_TYPES_STRING],
                                  &UA_TYPES[UA_TYPES_STRING]};
    if(!userMethodInputs(inputSize, input, 2, types))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    return server->config.accessControl.changePassword(
        server, &server->config.accessControl,
        &session->identityContext.userName, (UA_String*)input[0].data,
        (UA_String*)input[1].data);
}

static UA_StatusCode
readManagedUsers(UA_Server *server, const UA_NodeId *sessionId,
                 void *sessionContext, const UA_NodeId *nodeId,
                 void *nodeContext, UA_Boolean includeSourceTimeStamp,
                 const UA_NumericRange *range, UA_DataValue *value) {
    UA_UserManagementDataType *users = NULL;
    size_t usersSize = 0;
    UA_StatusCode res = server->config.accessControl.getUsers(
        server, &server->config.accessControl, &users, &usersSize);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    UA_Variant_setArray(&value->value, users, usersSize,
                        &UA_TYPES[UA_TYPES_USERMANAGEMENTDATATYPE]);
    value->value.storageType = UA_VARIANT_DATA;
    value->hasValue = true;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
readPasswordPolicy(UA_Server *server, const UA_NodeId *sessionId,
                   void *sessionContext, const UA_NodeId *nodeId,
                   void *nodeContext, UA_Boolean includeSourceTimeStamp,
                   const UA_NumericRange *range, UA_DataValue *value) {
    UA_Range length;
    UA_PasswordOptionsMask options = 0;
    UA_LocalizedText restrictions;
    UA_LocalizedText_init(&restrictions);
    UA_StatusCode res = server->config.accessControl.getPasswordPolicy(
        server, &server->config.accessControl, &length, &options,
        &restrictions);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    const UA_NodeId lengthId =
        UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT_PASSWORDLENGTH);
    const UA_NodeId optionsId =
        UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT_PASSWORDOPTIONS);
    if(UA_NodeId_equal(nodeId, &lengthId))
        res = UA_Variant_setScalarCopy(&value->value, &length,
                                       &UA_TYPES[UA_TYPES_RANGE]);
    else if(UA_NodeId_equal(nodeId, &optionsId))
        res = UA_Variant_setScalarCopy(&value->value, &options,
                                       &UA_TYPES[UA_TYPES_PASSWORDOPTIONSMASK]);
    else
        res = UA_Variant_setScalarCopy(&value->value, &restrictions,
                                       &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    UA_LocalizedText_clear(&restrictions);
    value->hasValue = (res == UA_STATUSCODE_GOOD);
    return res;
}

static UA_StatusCode
initUserManagement(UA_Server *server) {
    if(!UA_Server_hasUserManagementProvider(&server->config.accessControl))
        return UA_STATUSCODE_GOOD;
    /* The generated Namespace Zero may not carry the UserManagement Object.
     * Skip the wiring instead of failing the Server startup, as elsewhere in
     * the NS0 RBAC setup. */
    UA_QualifiedName umName;
    if(UA_Server_readBrowseName(server, UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT),
                                &umName) != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(server->config.logging, UA_LOGCATEGORY_SERVER,
                       "RBAC: A UserManagement provider is configured but the "
                       "UserManagement Object is not part of the generated "
                       "Namespace Zero - the provider stays unused");
        return UA_STATUSCODE_GOOD;
    }
    UA_QualifiedName_clear(&umName);
    UA_DataSource users = {readManagedUsers, NULL};
    UA_DataSource policy = {readPasswordPolicy, NULL};
    UA_StatusCode res = UA_Server_setVariableNode_dataSource(server,
        UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT_USERS), users);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_Server_setVariableNode_dataSource(server,
            UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT_PASSWORDLENGTH), policy);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_Server_setVariableNode_dataSource(server,
            UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT_PASSWORDOPTIONS), policy);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_Server_setVariableNode_dataSource(server,
            UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT_PASSWORDRESTRICTIONS),
            policy);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_Server_setMethodNode_callback(server,
        UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT_ADDUSER),
        addUserMethodCallback);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_Server_setMethodNode_callback(server,
            UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT_MODIFYUSER),
            modifyUserMethodCallback);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_Server_setMethodNode_callback(server,
            UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT_REMOVEUSER),
            removeUserMethodCallback);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_Server_setMethodNode_callback(server,
            UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT_CHANGEPASSWORD),
            changePasswordMethodCallback);
    return res;
}

static UA_StatusCode
addRoleManagementPermissions(UA_Server *server, const UA_NodeId *nodeId) {
    const UA_NodeId secAdmin =
        UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN);
    UA_StatusCode retval =
        UA_Server_addRolePermissions(server, *nodeId, secAdmin,
                                     UA_PERMISSIONTYPE_BROWSE |
                                     UA_PERMISSIONTYPE_READ |
                                     UA_PERMISSIONTYPE_CALL |
                                     UA_PERMISSIONTYPE_RECEIVEEVENTS |
                                     UA_PERMISSIONTYPE_READROLEPERMISSIONS,
                                     false, false);
    if(retval != UA_STATUSCODE_GOOD && retval != UA_STATUSCODE_BADNODEIDUNKNOWN)
        return retval;

    /* Role configuration is sensitive and may only be browsed/read/called via
     * an encrypted channel (Part 18 §4.4.1). */
    retval = UA_Server_setNodeAccessRestrictions(
        server, *nodeId,
        UA_ACCESSRESTRICTIONTYPE_ENCRYPTIONREQUIRED |
        UA_ACCESSRESTRICTIONTYPE_APPLYRESTRICTIONSTOBROWSE);
    if(retval == UA_STATUSCODE_BADNODEIDUNKNOWN)
        return UA_STATUSCODE_GOOD;
    return retval;
}

/* Protect every HasProperty child of a Role Object or management Method.
 * Exclude flags are the only Role Properties writable through Write. */
static UA_StatusCode
protectRolePropertyChildren(UA_Server *server, const UA_NodeId *parentId) {
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = *parentId;
    bd.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY);
    bd.includeSubtypes = false;
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.nodeClassMask = UA_NODECLASS_VARIABLE;
    bd.resultMask = UA_BROWSERESULTMASK_BROWSENAME;

    UA_BrowseResult br = UA_Server_browse(server, 0, &bd);
    if(br.statusCode != UA_STATUSCODE_GOOD) {
        UA_StatusCode res = br.statusCode;
        UA_BrowseResult_clear(&br);
        return res;
    }

    const UA_NodeId secAdmin =
        UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN);
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    const UA_String applicationsExclude = UA_STRING("ApplicationsExclude");
    const UA_String endpointsExclude = UA_STRING("EndpointsExclude");
    for(size_t i = 0; i < br.referencesSize; i++) {
        const UA_ReferenceDescription *ref = &br.references[i];
        UA_PermissionType permissions =
            UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ;
        if(UA_String_equal(&ref->browseName.name, &applicationsExclude) ||
           UA_String_equal(&ref->browseName.name, &endpointsExclude))
            permissions |= UA_PERMISSIONTYPE_WRITE;

        retval = UA_Server_addRolePermissions(server, ref->nodeId.nodeId,
                                              secAdmin, permissions,
                                              false, false);
        if(retval != UA_STATUSCODE_GOOD)
            break;
        retval = UA_Server_setNodeAccessRestrictions(
            server, ref->nodeId.nodeId,
            UA_ACCESSRESTRICTIONTYPE_ENCRYPTIONREQUIRED |
            UA_ACCESSRESTRICTIONTYPE_APPLYRESTRICTIONSTOBROWSE);
        if(retval != UA_STATUSCODE_GOOD)
            break;
    }
    UA_BrowseResult_clear(&br);
    return retval;
}

static UA_StatusCode
addOrBindRoleMethod(UA_Server *server, const UA_NodeId *roleId,
                    const char *name, UA_MethodCallback callback,
                    const char *inputName, size_t inputTypeIndex,
                    UA_Boolean applyPermissions) {
    UA_NodeId methodId = UA_NODEID_NULL;
    UA_StatusCode res = findMethodChild(server, *roleId, name, &methodId);
    if(res == UA_STATUSCODE_GOOD) {
        res = UA_Server_setMethodNode_callback(server, methodId, callback);
    } else if(res == UA_STATUSCODE_BADNOTFOUND) {
        UA_MethodAttributes attr = UA_MethodAttributes_default;
        attr.displayName = UA_LOCALIZEDTEXT("en-US", (char*)(uintptr_t)name);
        attr.executable = true;
        attr.userExecutable = true;

        UA_Argument inputArgument;
        UA_Argument_init(&inputArgument);
        inputArgument.name = UA_STRING((char*)(uintptr_t)inputName);
        inputArgument.dataType = UA_TYPES[inputTypeIndex].typeId;
        inputArgument.valueRank = UA_VALUERANK_SCALAR;

        res = UA_Server_addMethodNode(server, UA_NODEID_NULL, *roleId,
                                      UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                      UA_QUALIFIEDNAME(0, (char*)(uintptr_t)name),
                                      attr, callback, 1, &inputArgument,
                                      0, NULL, NULL, &methodId);
    }

    if(res == UA_STATUSCODE_GOOD && applyPermissions) {
        res = addRoleManagementPermissions(server, &methodId);
        if(res == UA_STATUSCODE_GOOD)
            res = protectRolePropertyChildren(server, &methodId);
    }
    UA_NodeId_clear(&methodId);
    return res;
}

static UA_StatusCode
ensureRoleTypeMethods(UA_Server *server, const UA_NodeId *roleId,
                      UA_Boolean applyPermissions) {
    if(applyPermissions) {
        UA_StatusCode res = addRoleManagementPermissions(server, roleId);
        if(res != UA_STATUSCODE_GOOD)
            return res;
        res = protectRolePropertyChildren(server, roleId);
        if(res != UA_STATUSCODE_GOOD)
            return res;
    }

    struct RoleMethodDef {
        const char *name;
        UA_MethodCallback callback;
        const char *inputName;
        size_t inputTypeIndex;
    } methods[] = {
        {"AddIdentity", addIdentityMethodCallback, "Rule",
         UA_TYPES_IDENTITYMAPPINGRULETYPE},
        {"RemoveIdentity", removeIdentityMethodCallback, "Rule",
         UA_TYPES_IDENTITYMAPPINGRULETYPE},
        {"AddApplication", addApplicationMethodCallback, "ApplicationUri",
         UA_TYPES_STRING},
        {"RemoveApplication", removeApplicationMethodCallback, "ApplicationUri",
         UA_TYPES_STRING},
        {"AddEndpoint", addEndpointMethodCallback, "Endpoint",
         UA_TYPES_ENDPOINTTYPE},
        {"RemoveEndpoint", removeEndpointMethodCallback, "Endpoint",
         UA_TYPES_ENDPOINTTYPE}
    };

    for(size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        UA_StatusCode res = addOrBindRoleMethod(server, roleId,
                                                methods[i].name,
                                                methods[i].callback,
                                                methods[i].inputName,
                                                methods[i].inputTypeIndex,
                                                applyPermissions);
        if(res != UA_STATUSCODE_GOOD)
            return res;
    }

    return UA_STATUSCODE_GOOD;
}

/* Restrict the RoleSet Object and the security-sensitive RoleSet/RoleType
 * Methods to the SecurityAdmin Role over an encrypted channel (OPC UA Part
 * 18). initNS0RBAC has ensured the RoleSet exists by the time this runs; the
 * probe below only keeps the function safe if it is ever called before that. */
UA_StatusCode
initRoleSetRolePermissions(UA_Server *server) {
    UA_NodeId roleSetId =
        UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERCAPABILITIES_ROLESET);
    UA_QualifiedName bn;
    if(UA_Server_readBrowseName(server, roleSetId, &bn) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_GOOD; /* no NS0 RBAC model -> nothing to protect */
    UA_QualifiedName_clear(&bn);

    const UA_NodeId secAdmin =
        UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN);
    /* Nodes whose CALL is restricted to SecurityAdmin. The RoleSet Object is
     * included because the Call service checks CALL on both the Object and the
     * Method node. */
    const UA_UInt32 callNodes[] = {
        UA_NS0ID_SERVER_SERVERCAPABILITIES_ROLESET,
        UA_NS0ID_SERVER_SERVERCAPABILITIES_ROLESET_ADDROLE,
        UA_NS0ID_SERVER_SERVERCAPABILITIES_ROLESET_REMOVEROLE,
        UA_NS0ID_ROLETYPE_ADDIDENTITY,
        UA_NS0ID_ROLETYPE_REMOVEIDENTITY,
        UA_NS0ID_ROLETYPE_ADDAPPLICATION,
        UA_NS0ID_ROLETYPE_REMOVEAPPLICATION,
        UA_NS0ID_ROLETYPE_ADDENDPOINT,
        UA_NS0ID_ROLETYPE_REMOVEENDPOINT
    };

    /* StatusCodes are not bit flags, so check each result individually.
     * A missing node (BadNodeIdUnknown) is tolerated: a reduced nodeset may
     * omit individual Methods. Any other failure aborts. */
    UA_StatusCode retval;

    /* Admin may additionally read the RolePermissions attribute of the RoleSet */
    retval = UA_Server_addRolePermissions(server, roleSetId, secAdmin,
                                          UA_PERMISSIONTYPE_READROLEPERMISSIONS,
                                          false, false);
    if(retval != UA_STATUSCODE_GOOD && retval != UA_STATUSCODE_BADNODEIDUNKNOWN)
        return retval;

#ifdef UA_NS0ID_ROLEMAPPINGRULECHANGEDAUDITEVENTTYPE
    /* Role changes use the affected Role Object as SourceNode. ReceiveEvents
     * is checked independently on that source and on the EventType. The Role
     * Objects are covered by addRoleManagementPermissions above; grant the
     * matching EventType permission here as well. */
    UA_NodeId roleAuditEventType = UA_NODEID_NUMERIC(
        0, UA_NS0ID_ROLEMAPPINGRULECHANGEDAUDITEVENTTYPE);
    retval = UA_Server_addRolePermissions(server, roleAuditEventType, secAdmin,
                                          UA_PERMISSIONTYPE_RECEIVEEVENTS,
                                          false, false);
    if(retval != UA_STATUSCODE_GOOD && retval != UA_STATUSCODE_BADNODEIDUNKNOWN)
        return retval;
#endif

    for(size_t i = 0; i < sizeof(callNodes) / sizeof(callNodes[0]); i++) {
        UA_NodeId nodeId = UA_NODEID_NUMERIC(0, callNodes[i]);

        /* SecurityAdmin: browse + call */
        retval = UA_Server_addRolePermissions(server, nodeId, secAdmin,
                                              UA_PERMISSIONTYPE_BROWSE |
                                              UA_PERMISSIONTYPE_READ |
                                              UA_PERMISSIONTYPE_CALL |
                                              UA_PERMISSIONTYPE_READROLEPERMISSIONS,
                                              false, false);
        if(retval != UA_STATUSCODE_GOOD && retval != UA_STATUSCODE_BADNODEIDUNKNOWN)
            return retval;

        retval = UA_Server_setNodeAccessRestrictions(
            server, nodeId,
            UA_ACCESSRESTRICTIONTYPE_ENCRYPTIONREQUIRED |
            UA_ACCESSRESTRICTIONTYPE_APPLYRESTRICTIONSTOBROWSE);
        if(retval != UA_STATUSCODE_GOOD && retval != UA_STATUSCODE_BADNODEIDUNKNOWN)
            return retval;

        retval = protectRolePropertyChildren(server, &nodeId);
        if(retval != UA_STATUSCODE_GOOD && retval != UA_STATUSCODE_BADNODEIDUNKNOWN)
            return retval;
    }

    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = roleSetId;
    bd.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT);
    bd.includeSubtypes = false;
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.nodeClassMask = UA_NODECLASS_OBJECT;
    bd.resultMask = UA_BROWSERESULTMASK_NONE;

    UA_BrowseResult br = UA_Server_browse(server, 0, &bd);
    retval = br.statusCode;
    if(retval == UA_STATUSCODE_GOOD) {
        for(size_t i = 0; i < br.referencesSize; i++) {
            retval = ensureRoleTypeMethods(server,
                                           &br.references[i].nodeId.nodeId,
                                           true);
            if(retval != UA_STATUSCODE_GOOD)
                break;
        }
    }
    UA_BrowseResult_clear(&br);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    if(UA_Server_hasUserManagementProvider(&server->config.accessControl)) {
        const UA_NodeId anonymous =
            UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_ANONYMOUS);
        const UA_UInt32 adminNodes[] = {
            UA_NS0ID_USERMANAGEMENT,
            UA_NS0ID_USERMANAGEMENT_USERS,
            UA_NS0ID_USERMANAGEMENT_ADDUSER,
            UA_NS0ID_USERMANAGEMENT_MODIFYUSER,
            UA_NS0ID_USERMANAGEMENT_REMOVEUSER
        };
        for(size_t i = 0; i < sizeof(adminNodes) / sizeof(adminNodes[0]); i++) {
            UA_NodeId nodeId = UA_NODEID_NUMERIC(0, adminNodes[i]);
            retval = UA_Server_addRolePermissions(
                server, nodeId, secAdmin,
                UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ |
                UA_PERMISSIONTYPE_CALL | UA_PERMISSIONTYPE_READROLEPERMISSIONS,
                false, false);
            if(retval != UA_STATUSCODE_GOOD)
                return retval;
            retval = UA_Server_setNodeAccessRestrictions(
                server, nodeId,
                UA_ACCESSRESTRICTIONTYPE_ENCRYPTIONREQUIRED |
                UA_ACCESSRESTRICTIONTYPE_APPLYRESTRICTIONSTOBROWSE);
            if(retval != UA_STATUSCODE_GOOD)
                return retval;
        }

        /* The Object and ChangePassword Method need CALL for the current
         * username Session even while MustChangePassword limits it to the
         * Anonymous Role. The callback still requires an encrypted channel
         * and a USERNAME token. */
        const UA_NodeId userManagement =
            UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT);
        const UA_NodeId changePassword =
            UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT_CHANGEPASSWORD);
        retval = UA_Server_addRolePermissions(server, userManagement, anonymous,
                                              UA_PERMISSIONTYPE_CALL,
                                              false, false);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
        retval = UA_Server_addRolePermissions(server, changePassword, anonymous,
                                              UA_PERMISSIONTYPE_CALL,
                                              false, false);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
        retval = UA_Server_setNodeAccessRestrictions(
            server, changePassword,
            UA_ACCESSRESTRICTIONTYPE_ENCRYPTIONREQUIRED |
            UA_ACCESSRESTRICTIONTYPE_APPLYRESTRICTIONSTOBROWSE);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
    }

    return UA_STATUSCODE_GOOD;
}

#define RBAC_INIT_TRY(EXPRESSION)                  \
    do {                                           \
        if(retval == UA_STATUSCODE_GOOD)           \
            retval = (EXPRESSION);                 \
    } while(0)

/* Back the Properties of an existing Role Object with the role registry and
 * bind its Methods. Optional Properties that the Object does not have are
 * skipped. Used for the well-known Role Objects of Namespace Zero and for a
 * Role Object that a custom nodeset brought along. */
static UA_StatusCode
bindRoleProperty(UA_Server *server, const UA_NodeId *roleId,
                 const char *browseName, UA_DataSource dataSource) {
    UA_NodeId propertyId;
    if(findPropertyChild(server, *roleId, browseName,
                         &propertyId) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_GOOD; /* The optional Property is not present */
    UA_StatusCode res =
        UA_Server_setVariableNode_dataSource(server, propertyId, dataSource);
    UA_NodeId_clear(&propertyId);
    return res;
}

UA_StatusCode
bindRoleRepresentation(UA_Server *server, const UA_NodeId *roleId,
                       UA_Boolean applyPermissions) {
    /* Reads of Identities return the currently configured mapping rules */
    UA_DataSource ds;
    ds.read = readRoleIdentities;
    ds.write = NULL;
    UA_StatusCode res = bindRoleProperty(server, roleId, "Identities", ds);

    if(res == UA_STATUSCODE_GOOD) {
        ds.read = readRoleApplicationsExclude;
        ds.write = writeRoleApplicationsExclude;
        res = bindRoleProperty(server, roleId, "ApplicationsExclude", ds);
    }

    if(res == UA_STATUSCODE_GOOD) {
        ds.read = readRoleEndpointsExclude;
        ds.write = writeRoleEndpointsExclude;
        res = bindRoleProperty(server, roleId, "EndpointsExclude", ds);
    }

    /* Reads of CustomConfiguration return the configured value (§4.4.1) */
    if(res == UA_STATUSCODE_GOOD) {
        ds.read = readRoleCustomConfiguration;
        ds.write = NULL;
        res = bindRoleProperty(server, roleId, "CustomConfiguration", ds);
    }

    if(res != UA_STATUSCODE_GOOD)
        return res;
    return ensureRoleTypeMethods(server, roleId, applyPermissions);
}

/* Classify the Node at roleId so that a Role is never mirrored onto a Node
 * that is not a Role Object. Returns BADNODEIDUNKNOWN when there is no such
 * Node, GOOD for an Object of RoleType (or a subtype) and BADNODEIDEXISTS for
 * anything else. The caller holds the server lock. */
UA_StatusCode
checkRoleRepresentation(UA_Server *server, const UA_NodeId *roleId) {
    UA_LOCK_ASSERT(&server->serviceMutex);
    const UA_Node *node = UA_NODESTORE_GET(server, roleId);
    if(!node)
        return UA_STATUSCODE_BADNODEIDUNKNOWN;

    UA_StatusCode res = UA_STATUSCODE_BADNODEIDEXISTS;
    if(node->head.nodeClass == UA_NODECLASS_OBJECT) {
        const UA_Node *type = getNodeType(server, &node->head,
                                          UA_NODEATTRIBUTESMASK_NODECLASS,
                                          UA_REFERENCETYPESET_ALL,
                                          UA_BROWSEDIRECTION_BOTH);
        if(type) {
            UA_NodeId roleTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ROLETYPE);
            if(isNodeInTree_singleRef(server, &type->head.nodeId, &roleTypeId,
                                      UA_REFERENCETYPEINDEX_HASSUBTYPE))
                res = UA_STATUSCODE_GOOD;
            UA_NODESTORE_RELEASE(server, type);
        }
    }

    UA_NODESTORE_RELEASE(server, node);
    return res;
}

UA_StatusCode
initNS0RBAC(UA_Server *server) {
    /* The RoleSetType and the well-known Role Nodes are part of the full
     * Namespace Zero, which CMake requires for UA_ENABLE_RBAC (see the
     * UA_ENABLE_RBAC checks in CMakeLists.txt). Everything below therefore
     * treats a missing Node as an error rather than degrading silently; the
     * Nodes the Server is allowed to create itself are created below. */
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    /* The NamespaceMetadata Properties are backed by syncNamespaceMetadata,
     * which needs the Roles registered by UA_Server_initRBAC */

    /* Ensure the RoleSet instance node exists */
    UA_NodeId roleSetId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERCAPABILITIES_ROLESET);
    UA_QualifiedName bn;
    if(UA_Server_readBrowseName(server, roleSetId, &bn) != UA_STATUSCODE_GOOD) {
        UA_ObjectAttributes oAttr = UA_ObjectAttributes_default;
        oAttr.displayName = UA_LOCALIZEDTEXT("", "RoleSet");
        RBAC_INIT_TRY(UA_Server_addObjectNode(
            server, roleSetId,
            UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERCAPABILITIES),
            UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
            UA_QUALIFIEDNAME(0, "RoleSet"),
            UA_NODEID_NUMERIC(0, UA_NS0ID_ROLESETTYPE),
            oAttr, NULL, NULL));
    } else {
        UA_QualifiedName_clear(&bn);
    }

    /* Ensure the well-known role instance nodes exist under the RoleSet */
    struct { UA_UInt32 id; const char *name; } roles[] = {
        {UA_NS0ID_WELLKNOWNROLE_ANONYMOUS,          "Anonymous"},
        {UA_NS0ID_WELLKNOWNROLE_AUTHENTICATEDUSER,  "AuthenticatedUser"},
        {UA_NS0ID_WELLKNOWNROLE_TRUSTEDAPPLICATION, "TrustedApplication"},
        {UA_NS0ID_WELLKNOWNROLE_OBSERVER,           "Observer"},
        {UA_NS0ID_WELLKNOWNROLE_OPERATOR,           "Operator"},
        {UA_NS0ID_WELLKNOWNROLE_ENGINEER,           "Engineer"},
        {UA_NS0ID_WELLKNOWNROLE_SUPERVISOR,         "Supervisor"},
        {UA_NS0ID_WELLKNOWNROLE_CONFIGUREADMIN,     "ConfigureAdmin"},
        {UA_NS0ID_WELLKNOWNROLE_SECURITYADMIN,      "SecurityAdmin"}
#ifdef UA_NS0ID_WELLKNOWNROLE_SECURITYKEYSERVERADMIN
        ,{UA_NS0ID_WELLKNOWNROLE_SECURITYKEYSERVERADMIN,  "SecurityKeyServerAdmin"}
        ,{UA_NS0ID_WELLKNOWNROLE_SECURITYKEYSERVERPUSH,   "SecurityKeyServerPush"}
        ,{UA_NS0ID_WELLKNOWNROLE_SECURITYKEYSERVERACCESS, "SecurityKeyServerAccess"}
#endif
    };
    for(size_t i = 0; i < sizeof(roles) / sizeof(roles[0]); i++) {
        UA_NodeId rId = UA_NODEID_NUMERIC(0, roles[i].id);
        if(UA_Server_readBrowseName(server, rId, &bn) != UA_STATUSCODE_GOOD) {
            UA_ObjectAttributes oAttr = UA_ObjectAttributes_default;
            oAttr.displayName = UA_LOCALIZEDTEXT("", (char*)(uintptr_t)roles[i].name);
            RBAC_INIT_TRY(UA_Server_addObjectNode(
                server, rId, roleSetId,
                UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                UA_QUALIFIEDNAME(0, (char*)(uintptr_t)roles[i].name),
                UA_NODEID_NUMERIC(0, UA_NS0ID_ROLETYPE),
                oAttr, NULL, NULL));
        } else {
            UA_QualifiedName_clear(&bn);
        }

        RBAC_INIT_TRY(bindRoleRepresentation(server, &rId, false));
    }

    /* The method callbacks must be attached to the RoleSet *instance* methods.
     * A Call resolves the object's own HasComponent method (the instance node),
     * not the type method, so a callback on the type node would never fire. */
    RBAC_INIT_TRY(UA_Server_setMethodNode_callback(
        server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERCAPABILITIES_ROLESET_ADDROLE),
        addRoleMethodCallback));
    RBAC_INIT_TRY(UA_Server_setMethodNode_callback(
        server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERCAPABILITIES_ROLESET_REMOVEROLE),
        removeRoleMethodCallback));

    RBAC_INIT_TRY(UA_Server_setMethodNode_callback(
        server, UA_NODEID_NUMERIC(0, UA_NS0ID_ROLETYPE_ADDIDENTITY),
        addIdentityMethodCallback));
    RBAC_INIT_TRY(UA_Server_setMethodNode_callback(
        server, UA_NODEID_NUMERIC(0, UA_NS0ID_ROLETYPE_REMOVEIDENTITY),
        removeIdentityMethodCallback));

    RBAC_INIT_TRY(UA_Server_setMethodNode_callback(
        server, UA_NODEID_NUMERIC(0, UA_NS0ID_ROLETYPE_ADDAPPLICATION),
        addApplicationMethodCallback));
    RBAC_INIT_TRY(UA_Server_setMethodNode_callback(
        server, UA_NODEID_NUMERIC(0, UA_NS0ID_ROLETYPE_REMOVEAPPLICATION),
        removeApplicationMethodCallback));

    RBAC_INIT_TRY(UA_Server_setMethodNode_callback(
        server, UA_NODEID_NUMERIC(0, UA_NS0ID_ROLETYPE_ADDENDPOINT),
        addEndpointMethodCallback));
    RBAC_INIT_TRY(UA_Server_setMethodNode_callback(
        server, UA_NODEID_NUMERIC(0, UA_NS0ID_ROLETYPE_REMOVEENDPOINT),
        removeEndpointMethodCallback));

    if(retval == UA_STATUSCODE_GOOD)
        retval = initUserManagement(server);

#undef RBAC_INIT_TRY
    return retval;
}

/*****************************/
/* NamespaceMetadata Objects */
/*****************************/

/* Every namespace is published by a NamespaceMetadata Object under
 * Server/Namespaces (Part 5 §6.3.13). Namespace Zero has the standard Object
 * i=15957. For the other namespaces an Object shipped by a nodeset (such as the
 * DI or GDS nodesets) is adopted; otherwise the Server creates one with an
 * automatically assigned NodeId in Namespace Zero.
 *
 * The permission Properties are backed by DataSources that read the live
 * namespace defaults. DefaultAccessRestrictions is always present.
 * DefaultRolePermissions and DefaultUserRolePermissions are present only if the
 * namespace has a RolePermission model (always in strict mode, in legacy mode
 * only with an explicit default). Otherwise the Server publishes no
 * information about how it manages Permissions (Part 3 §5.2.9). */

typedef struct {
    const char *name;
    UA_UInt32 ns0Id; /* NodeId of the Property of i=15957 */
    size_t typeIndex;
    UA_Boolean isArray;
    UA_StatusCode (*read)(UA_Server *server, const UA_NodeId *sessionId,
                          void *sessionContext, const UA_NodeId *nodeId,
                          void *nodeContext, UA_Boolean includeSourceTimeStamp,
                          const UA_NumericRange *range, UA_DataValue *value);
} NamespaceMetadataProperty;

static const NamespaceMetadataProperty defaultRolePermissionsProperty = {
    "DefaultRolePermissions",
    UA_NS0ID_OPCUANAMESPACEMETADATA_DEFAULTROLEPERMISSIONS,
    UA_TYPES_ROLEPERMISSIONTYPE, true, readNamespaceDefaultRolePermissions};
static const NamespaceMetadataProperty defaultUserRolePermissionsProperty = {
    "DefaultUserRolePermissions",
    UA_NS0ID_OPCUANAMESPACEMETADATA_DEFAULTUSERROLEPERMISSIONS,
    UA_TYPES_ROLEPERMISSIONTYPE, true, readNamespaceDefaultUserRolePermissions};
static const NamespaceMetadataProperty defaultAccessRestrictionsProperty = {
    "DefaultAccessRestrictions",
    UA_NS0ID_OPCUANAMESPACEMETADATA_DEFAULTACCESSRESTRICTIONS,
    UA_TYPES_ACCESSRESTRICTIONTYPE, false, readNamespaceDefaultAccessRestrictions};

/* Whether the Object is a NamespaceMetadata Object for the namespace URI. It
 * must be of NamespaceMetadataType (or a subtype) and carry the URI in its
 * NamespaceUri Property or as its BrowseName. */
static UA_Boolean
isNamespaceMetadataObjectFor(UA_Server *server, const UA_ReferenceDescription *rd,
                             const UA_String *uri) {
    const UA_NodeId nmType = UA_NS0ID(NAMESPACEMETADATATYPE);
    if(!isNodeInTree_singleRef(server, &rd->typeDefinition.nodeId, &nmType,
                               UA_REFERENCETYPEINDEX_HASSUBTYPE))
        return false;
    if(UA_String_equal(&rd->browseName.name, uri))
        return true;
    UA_Variant v;
    UA_Variant_init(&v);
    UA_Boolean match = false;
    if(readObjectProperty(server, rd->nodeId.nodeId,
                          UA_QUALIFIEDNAME(0, "NamespaceUri"),
                          &v) == UA_STATUSCODE_GOOD &&
       UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_STRING]))
        match = UA_String_equal((const UA_String*)v.data, uri);
    UA_Variant_clear(&v);
    return match;
}

/* Find a NamespaceMetadata Object for the namespace under Server/Namespaces
 * that is not yet assigned to another namespace */
static UA_StatusCode
findNamespaceMetadataObject(UA_Server *server, UA_UInt16 namespaceIndex,
                            UA_NodeId *objectId) {
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = UA_NS0ID(SERVER_NAMESPACES);
    bd.referenceTypeId = UA_NS0ID(HASCOMPONENT);
    bd.includeSubtypes = true;
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.nodeClassMask = UA_NODECLASS_OBJECT;
    bd.resultMask = UA_BROWSERESULTMASK_BROWSENAME |
        UA_BROWSERESULTMASK_TYPEDEFINITION;

    UA_BrowseResult br = UA_Server_browse(server, 0, &bd);
    UA_StatusCode res = br.statusCode;
    if(res != UA_STATUSCODE_GOOD) {
        UA_BrowseResult_clear(&br);
        return res;
    }

    res = UA_STATUSCODE_BADNOTFOUND;
    const UA_String *uri = &server->namespaces[namespaceIndex];
    for(size_t i = 0; i < br.referencesSize; i++) {
        const UA_ReferenceDescription *rd = &br.references[i];
        UA_Boolean assigned = false;
        for(size_t j = 0; j < server->namespaceMetadataSize; j++) {
            if(UA_NodeId_equal(&server->namespaceMetadata[j].objectId,
                               &rd->nodeId.nodeId)) {
                assigned = true;
                break;
            }
        }
        if(assigned || !isNamespaceMetadataObjectFor(server, rd, uri))
            continue;
        res = UA_NodeId_copy(&rd->nodeId.nodeId, objectId);
        break;
    }
    UA_BrowseResult_clear(&br);
    return res;
}

/* Create the NamespaceMetadata Object of a namespace. The mandatory Properties
 * are instantiated from the type and describe a namespace without static
 * NodeIds. */
static UA_StatusCode
addNamespaceMetadataObject(UA_Server *server, UA_UInt16 namespaceIndex,
                           UA_NodeId *objectId) {
    const UA_String *uri = &server->namespaces[namespaceIndex];
    UA_ObjectAttributes attr = UA_ObjectAttributes_default;
    attr.displayName.text = *uri;
    UA_QualifiedName browseName;
    browseName.namespaceIndex = namespaceIndex;
    browseName.name = *uri;
    UA_StatusCode res =
        UA_Server_addObjectNode(server, UA_NODEID_NUMERIC(0, 0),
                                UA_NS0ID(SERVER_NAMESPACES), UA_NS0ID(HASCOMPONENT),
                                browseName, UA_NS0ID(NAMESPACEMETADATATYPE),
                                attr, NULL, objectId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_String empty = UA_STRING_NULL;
    UA_DateTime publicationDate = 0;
    UA_Boolean isSubset = false;
    UA_Variant v;
    UA_Variant_setScalar(&v, (void*)(uintptr_t)uri, &UA_TYPES[UA_TYPES_STRING]);
    res |= writeObjectProperty(server, *objectId,
                               UA_QUALIFIEDNAME(0, "NamespaceUri"), v);
    UA_Variant_setScalar(&v, &empty, &UA_TYPES[UA_TYPES_STRING]);
    res |= writeObjectProperty(server, *objectId,
                               UA_QUALIFIEDNAME(0, "NamespaceVersion"), v);
    res |= writeObjectProperty(server, *objectId,
                               UA_QUALIFIEDNAME(0, "StaticStringNodeIdPattern"), v);
    UA_Variant_setScalar(&v, &publicationDate, &UA_TYPES[UA_TYPES_DATETIME]);
    res |= writeObjectProperty(server, *objectId,
                               UA_QUALIFIEDNAME(0, "NamespacePublicationDate"), v);
    UA_Variant_setScalar(&v, &isSubset, &UA_TYPES[UA_TYPES_BOOLEAN]);
    res |= writeObjectProperty(server, *objectId,
                               UA_QUALIFIEDNAME(0, "IsNamespaceSubset"), v);
    UA_Variant_setArray(&v, NULL, 0, &UA_TYPES[UA_TYPES_IDTYPE]);
    res |= writeObjectProperty(server, *objectId,
                               UA_QUALIFIEDNAME(0, "StaticNodeIdTypes"), v);
    UA_Variant_setArray(&v, NULL, 0, &UA_TYPES[UA_TYPES_STRING]);
    res |= writeObjectProperty(server, *objectId,
                               UA_QUALIFIEDNAME(0, "StaticNumericNodeIdRange"), v);
    if(res != UA_STATUSCODE_GOOD) {
        deleteNode(server, *objectId, true);
        UA_NodeId_clear(objectId);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    return UA_STATUSCODE_GOOD;
}

/* The NamespaceMetadata Object of the namespace: the remembered one if it
 * still exists, else an adopted or a new one */
static UA_StatusCode
getNamespaceMetadataObject(UA_Server *server, UA_UInt16 namespaceIndex,
                           UA_NodeId *objectId) {
    UA_NamespaceMetadata *nm = &server->namespaceMetadata[namespaceIndex];
    if(!UA_NodeId_isNull(&nm->objectId)) {
        const UA_Node *node = UA_NODESTORE_GET(server, &nm->objectId);
        if(node) {
            UA_NODESTORE_RELEASE(server, node);
            return UA_NodeId_copy(&nm->objectId, objectId);
        }
        UA_NodeId_clear(&nm->objectId); /* The Object was deleted */
    }

    UA_StatusCode res;
    if(namespaceIndex == 0) {
        *objectId = UA_NS0ID(OPCUANAMESPACEMETADATA);
        const UA_Node *node = UA_NODESTORE_GET(server, objectId);
        if(!node)
            return UA_STATUSCODE_BADNOTFOUND;
        UA_NODESTORE_RELEASE(server, node);
        res = UA_STATUSCODE_GOOD;
    } else {
        res = findNamespaceMetadataObject(server, namespaceIndex, objectId);
        if(res == UA_STATUSCODE_BADNOTFOUND)
            res = addNamespaceMetadataObject(server, namespaceIndex, objectId);
    }
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* Index again: the callbacks of addNode may have grown the array */
    res = UA_NodeId_copy(objectId, &server->namespaceMetadata[namespaceIndex].objectId);
    if(res != UA_STATUSCODE_GOOD)
        UA_NodeId_clear(objectId);
    return res;
}

/* Find the Property and back it with its DataSource. A missing Property is
 * added. The Properties of i=15957 keep their standard NodeIds. */
static UA_StatusCode
addNamespaceMetadataProperty(UA_Server *server, const UA_NodeId *objectId,
                             const NamespaceMetadataProperty *prop,
                             UA_NodeId *propertyId) {
    UA_StatusCode res = findPropertyChild(server, *objectId, prop->name, propertyId);
    if(res == UA_STATUSCODE_BADNOTFOUND) {
        const UA_DataType *type = &UA_TYPES[prop->typeIndex];
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        attr.displayName = UA_LOCALIZEDTEXT("", (char*)(uintptr_t)prop->name);
        attr.dataType = type->typeId;
        attr.accessLevel = UA_ACCESSLEVELMASK_READ;
        UA_UInt32 arrayDims = 0;
        UA_AccessRestrictionType none = UA_ACCESSRESTRICTIONTYPE_NONE;
        if(prop->isArray) {
            attr.valueRank = UA_VALUERANK_ONE_DIMENSION;
            attr.arrayDimensionsSize = 1;
            attr.arrayDimensions = &arrayDims;
            UA_Variant_setArray(&attr.value, NULL, 0, type);
        } else {
            attr.valueRank = UA_VALUERANK_SCALAR;
            UA_Variant_setScalar(&attr.value, &none, type);
        }
        const UA_NodeId ns0Object = UA_NS0ID(OPCUANAMESPACEMETADATA);
        UA_NodeId requestedId = UA_NODEID_NUMERIC(0, 0);
        if(UA_NodeId_equal(objectId, &ns0Object))
            requestedId.identifier.numeric = prop->ns0Id;
        res = UA_Server_addVariableNode(server, requestedId, *objectId,
                                        UA_NS0ID(HASPROPERTY),
                                        UA_QUALIFIEDNAME(0, (char*)(uintptr_t)prop->name),
                                        UA_NS0ID(PROPERTYTYPE), attr, NULL,
                                        propertyId);
    }
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_DataSource ds;
    ds.read = prop->read;
    ds.write = NULL;
    res = UA_Server_setVariableNode_dataSource(server, *propertyId, ds);
    if(res != UA_STATUSCODE_GOOD)
        UA_NodeId_clear(propertyId);
    return res;
}

static UA_StatusCode
removeNamespaceMetadataProperty(UA_Server *server, const UA_NodeId *objectId,
                                const NamespaceMetadataProperty *prop) {
    UA_NodeId propertyId;
    UA_StatusCode res = findPropertyChild(server, *objectId, prop->name, &propertyId);
    if(res == UA_STATUSCODE_BADNOTFOUND)
        return UA_STATUSCODE_GOOD;
    if(res != UA_STATUSCODE_GOOD)
        return res;
    res = deleteNode(server, propertyId, true);
    UA_NodeId_clear(&propertyId);
    return res;
}

/* Give the Node the RolePermissions unless it already has its own. The shared
 * entry of a Node can hold only AccessRestrictions; such a Node (and one with
 * an empty list, which is no override) has no RolePermissions of its own and
 * is protected. It keeps its AccessRestrictions. */
static UA_StatusCode
protectNamespaceMetadataNode(UA_Server *server, const UA_NodeId *nodeId,
                             size_t entriesSize, const UA_RolePermission *entries) {
    UA_LOCK_ASSERT(&server->serviceMutex);
    const UA_Node *node = UA_NODESTORE_GET(server, nodeId);
    if(!node)
        return UA_STATUSCODE_BADNODEIDUNKNOWN;
    const UA_RolePermissionEntry *rp =
        getRolePermissionsEntry(server, node->head.permissionIndex);
    UA_Boolean hasOwn = (rp && rp->rolePermissionsSize > 0);
    UA_NODESTORE_RELEASE(server, node);
    if(hasOwn)
        return UA_STATUSCODE_GOOD;
    return UA_Server_setNodeRolePermissions(server, *nodeId, entriesSize, entries,
                                            false, NULL);
}

/* An Object adopted from a nodeset has NodeIds in its own namespace. It must
 * stay readable under the template of that namespace, which lets Anonymous
 * Sessions only browse. */
static UA_StatusCode
protectAdoptedNamespaceMetadataObject(UA_Server *server, const UA_NodeId *objectId) {
    const UA_RolePermission readable[2] = {
        {UA_NS0ID(WELLKNOWNROLE_ANONYMOUS),
         UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ},
        {UA_NS0ID(WELLKNOWNROLE_SECURITYADMIN),
         UA_PERMISSIONTYPE_READROLEPERMISSIONS}};
    UA_StatusCode res = protectNamespaceMetadataNode(server, objectId, 2, readable);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = *objectId;
    bd.referenceTypeId = UA_NS0ID(HASPROPERTY);
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.nodeClassMask = UA_NODECLASS_VARIABLE;
    bd.resultMask = UA_BROWSERESULTMASK_BROWSENAME;
    UA_BrowseResult br = UA_Server_browse(server, 0, &bd);
    res = br.statusCode;
    const UA_String drp = UA_STRING((char*)(uintptr_t)defaultRolePermissionsProperty.name);
    for(size_t i = 0; i < br.referencesSize && res == UA_STATUSCODE_GOOD; i++) {
        if(UA_String_equal(&br.references[i].browseName.name, &drp))
            continue; /* Readable by administrators only */
        res = protectNamespaceMetadataNode(server, &br.references[i].nodeId.nodeId,
                                           2, readable);
    }
    UA_BrowseResult_clear(&br);
    return res;
}

/* The DefaultRolePermissions Property "shall only be readable by
 * administrators" (Part 3 §5.2.9) */
static UA_StatusCode
addDefaultRolePermissionsProperty(UA_Server *server, const UA_NodeId *objectId) {
    UA_NodeId propertyId;
    UA_StatusCode res =
        addNamespaceMetadataProperty(server, objectId, &defaultRolePermissionsProperty,
                                     &propertyId);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    const UA_RolePermission adminOnly[2] = {
        {UA_NS0ID(WELLKNOWNROLE_ANONYMOUS), UA_PERMISSIONTYPE_BROWSE},
        {UA_NS0ID(WELLKNOWNROLE_SECURITYADMIN),
         UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ |
         UA_PERMISSIONTYPE_READROLEPERMISSIONS}};
    res = protectNamespaceMetadataNode(server, &propertyId, 2, adminOnly);
    if(res != UA_STATUSCODE_GOOD) {
        /* Fail closed: do not publish the defaults unprotected */
        deleteNode(server, propertyId, true);
    }
    UA_NodeId_clear(&propertyId);
    return res;
}

UA_StatusCode
syncNamespaceMetadata(UA_Server *server, UA_UInt16 namespaceIndex) {
    UA_LOCK_ASSERT(&server->serviceMutex);
    if(namespaceIndex >= server->namespacesSize)
        return UA_STATUSCODE_BADINDEXRANGEINVALID;
    UA_StatusCode res = ensureNamespaceMetadataSize(server);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_NodeId objectId;
    res = getNamespaceMetadataObject(server, namespaceIndex, &objectId);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* DefaultAccessRestrictions is always published */
    UA_NodeId propertyId;
    res = addNamespaceMetadataProperty(server, &objectId,
                                       &defaultAccessRestrictionsProperty,
                                       &propertyId);
    if(res == UA_STATUSCODE_GOOD)
        UA_NodeId_clear(&propertyId);

    /* The RolePermission Properties follow the namespace model */
    size_t entriesSize = 0;
    const UA_RolePermission *entries = NULL;
    if(getNamespaceRolePermissionModel(server, namespaceIndex,
                                       &entriesSize, &entries)) {
        if(res == UA_STATUSCODE_GOOD)
            res = addDefaultRolePermissionsProperty(server, &objectId);
        if(res == UA_STATUSCODE_GOOD)
            res = addNamespaceMetadataProperty(server, &objectId,
                                               &defaultUserRolePermissionsProperty,
                                               &propertyId);
        if(res == UA_STATUSCODE_GOOD)
            UA_NodeId_clear(&propertyId);
    } else {
        UA_StatusCode res2 =
            removeNamespaceMetadataProperty(server, &objectId,
                                            &defaultRolePermissionsProperty);
        if(res2 == UA_STATUSCODE_GOOD)
            res2 = removeNamespaceMetadataProperty(server, &objectId,
                                                   &defaultUserRolePermissionsProperty);
        if(res == UA_STATUSCODE_GOOD)
            res = res2;
    }

    if(res == UA_STATUSCODE_GOOD && objectId.namespaceIndex != 0)
        res = protectAdoptedNamespaceMetadataObject(server, &objectId);

    UA_NodeId_clear(&objectId);
    return res;
}

static void
syncNamespaceMetadataLogged(UA_Server *server, UA_UInt16 namespaceIndex) {
    UA_StatusCode res = syncNamespaceMetadata(server, namespaceIndex);
    if(res != UA_STATUSCODE_GOOD)
        UA_LOG_WARNING(server->config.logging, UA_LOGCATEGORY_SERVER,
                       "RBAC: Could not publish the NamespaceMetadata Object "
                       "of namespace %u (%s)", (unsigned)namespaceIndex,
                       UA_StatusCode_name(res));
}

void
syncAllNamespaceMetadata(UA_Server *server) {
    UA_LOCK_ASSERT(&server->serviceMutex);
    for(size_t i = 0; i < server->namespacesSize; i++)
        syncNamespaceMetadataLogged(server, (UA_UInt16)i);
}

/* Publish the namespaces added since the last run. Executed as a delayed
 * callback, so a nodeset loaded right after addNamespace has added its own
 * NamespaceMetadata Object by now. */
static void
syncNewNamespaceMetadata(void *application, void *context) {
    UA_Server *server = (UA_Server*)application;
    lockServer(server);
    server->namespaceMetadataSyncPending = false;
    if(server->state == UA_LIFECYCLESTATE_STARTED) {
        for(size_t i = 1; i < server->namespacesSize; i++) {
            if(server->namespaceMetadata && i < server->namespaceMetadataSize &&
               !UA_NodeId_isNull(&server->namespaceMetadata[i].objectId))
                continue;
            syncNamespaceMetadataLogged(server, (UA_UInt16)i);
        }
    }
    unlockServer(server);
}

void
scheduleNamespaceMetadataSync(UA_Server *server) {
    UA_LOCK_ASSERT(&server->serviceMutex);
    if(server->state != UA_LIFECYCLESTATE_STARTED ||
       server->namespaceMetadataSyncPending)
        return;
    UA_EventLoop *el = server->config.eventLoop;
    server->namespaceMetadataSync.callback = syncNewNamespaceMetadata;
    server->namespaceMetadataSync.application = server;
    server->namespaceMetadataSync.context = NULL;
    server->namespaceMetadataSyncPending = true;
    el->addDelayedCallback(el, &server->namespaceMetadataSync);
}

void
cancelNamespaceMetadataSync(UA_Server *server) {
    if(!server->namespaceMetadataSyncPending)
        return;
    UA_EventLoop *el = server->config.eventLoop;
    if(el)
        el->removeDelayedCallback(el, &server->namespaceMetadataSync);
    server->namespaceMetadataSyncPending = false;
}

#endif /* UA_ENABLE_RBAC */
