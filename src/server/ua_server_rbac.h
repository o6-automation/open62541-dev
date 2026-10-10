/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2025-2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#ifndef UA_SERVER_RBAC_H_
#define UA_SERVER_RBAC_H_

#include <open62541/server.h>
#include <open62541/plugin/nodestore.h>

_UA_BEGIN_DECLS

#ifdef UA_ENABLE_RBAC

#include "ua_session.h"

/* Bounds the Role registry so repeated AddRole calls cannot allocate
 * unbounded memory (DoS mitigation) */
#define UA_RBAC_MAX_ROLES 1024

/* Set roles on a session. Validates all role IDs against the server registry.
 * Must be called with the server lock held. */
UA_StatusCode
UA_Session_setRoles(UA_Server *server, UA_Session *session,
                    const UA_NodeId *roleIds, size_t rolesSize);

/* Access guard for the RoleSet/RoleType Methods (Part 18): requires an
 * encrypted SecureChannel and the SecurityAdmin Role.
 * Must be called with the server lock held. */
UA_StatusCode
checkRBACMethodAccess(UA_Server *server, const UA_NodeId *sessionId);

/* The Roles granted to an identity context, always including Anonymous.
 * Must be called with the server lock held. */
UA_StatusCode
UA_Server_evaluateSessionRoles(UA_Server *server,
                               const UA_SessionIdentityContext *ctx,
                               size_t *outRolesSize, UA_NodeId **outRoleIds);

/* Re-evaluate the Roles of all Sessions after a RoleSet change.
 * Must be called with the server lock held. */
void
UA_Server_reevaluateSessionRoles(UA_Server *server);

/* Own value or the namespace default. Must be called with the server lock
 * held. */
UA_AccessRestrictionType
getNodeAccessRestrictions(UA_Server *server, const UA_Node *node);

/* forBrowse checks only with ApplyRestrictionsToBrowse.
 * Must be called with the server lock held. */
UA_StatusCode
checkNodeAccessRestrictions(UA_Server *server, const UA_Session *session,
                            const UA_Node *node, UA_Boolean forBrowse);

/* Decrement the refCount of a role permission entry at the given index.
 * Used during node deletion to keep refcounts consistent. */
void
UA_Server_decrementRolePermissionsRefCount(UA_Server *server,
                                           UA_PermissionIndex index);

/* Instance children inherit the AccessRestrictions of their
 * InstanceDeclaration, not its RolePermissions. Returns a retained entry with
 * only those AccessRestrictions. Must be called with the server lock held. */
UA_StatusCode
retainInstanceAccessRestrictions(UA_Server *server, UA_PermissionIndex declIndex,
                                 UA_PermissionIndex *outIndex);

/* Low-level permission index functions (internal, used by tests) */

/* Only the RolePermissions are taken from the entry, each node keeps its
 * AccessRestrictions. A recursive call visits all children and returns the
 * first error. */
UA_StatusCode
UA_Server_setNodePermissionIndex(UA_Server *server, const UA_NodeId nodeId,
                                 UA_PermissionIndex permissionIndex,
                                 UA_Boolean recursive);

UA_StatusCode
UA_Server_getNodePermissionIndex(UA_Server *server, const UA_NodeId nodeId,
                                 UA_PermissionIndex *permissionIndex);

UA_StatusCode
UA_Server_addRolePermissionConfig(UA_Server *server,
                                  size_t entriesSize,
                                  const UA_RolePermission *entries,
                                  UA_PermissionIndex *outIndex);

/* NULL if out of range or the entry has only AccessRestrictions */
const UA_RolePermissionSet *
UA_Server_getRolePermissionConfig(UA_Server *server,
                                  UA_PermissionIndex index);

/* Also updates the entries that combine the config with the AccessRestrictions
 * of a node. BADINVALIDSTATE while one of them is referenced, unless the config
 * is a protected preset. */
UA_StatusCode
UA_Server_updateRolePermissionConfig(UA_Server *server,
                                     UA_PermissionIndex index,
                                     size_t entriesSize,
                                     const UA_RolePermission *entries);

/* NS0 representation of a role under Server/ServerCapabilities/RoleSet
 * (defined in ua_server_ns0_rbac.c). Keeps the published Role Objects in sync
 * with the registry. */
UA_StatusCode
addRoleRepresentation(UA_Server *server, UA_Role *role);

UA_StatusCode
removeRoleRepresentation(UA_Server *server, const UA_NodeId *roleId);

/* Restrict the RoleSet Object and its security-sensitive Methods to the
 * SecurityAdmin Role (defined in ua_server_ns0_rbac.c) */
UA_StatusCode
initRoleSetRolePermissions(UA_Server *server);

/* Effective permission queries (internal, used by attribute service and tests) */
UA_StatusCode
UA_Server_getEffectivePermissions(UA_Server *server,
                                  const UA_NodeId *sessionId,
                                  const UA_NodeId *nodeId,
                                  UA_PermissionType *effectivePermissions);

/* Internal helper. Requires the server lock to be held.
 * Missing node -> UA_PERMISSIONTYPE_ALL (permissive sentinel). */
UA_StatusCode
getEffectivePermissions(UA_Server *server,
                        const UA_Session *session,
                        const UA_NodeId *nodeId,
                        UA_PermissionType *effectivePermissions);

UA_StatusCode
UA_Server_getUserRolePermissions(UA_Server *server,
                                 const UA_NodeId *sessionId,
                                 const UA_NodeId *nodeId,
                                 size_t *entriesSize,
                                 UA_RolePermissionType **entries);

#endif /* UA_ENABLE_RBAC */

_UA_END_DECLS

#endif /* UA_SERVER_RBAC_H_ */
