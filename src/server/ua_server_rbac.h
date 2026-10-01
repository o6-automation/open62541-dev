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

/* Whether the Session holds exactly the given set of Roles */
UA_Boolean
UA_Session_rolesEqual(const UA_Session *session,
                      const UA_NodeId *roleIds, size_t rolesSize);

/* Access guard for the RoleSet/RoleType Methods (Part 18): requires an
 * encrypted SecureChannel and the SecurityAdmin Role.
 * Must be called with the server lock held. */
UA_StatusCode
checkRBACMethodAccess(UA_Server *server, const UA_NodeId *sessionId);

/* Evaluate the identity mapping rules of all roles against the given session
 * identity context and return the matching role IDs in a newly allocated array.
 * The Anonymous well-known Role is always included (Part 18 §4.3).
 * Must be called with the server lock held. */
UA_StatusCode
UA_Server_evaluateSessionRoles(UA_Server *server,
                               const UA_SessionIdentityContext *ctx,
                               size_t *outRolesSize, UA_NodeId **outRoleIds);

/* Re-evaluate and reassign the Roles of all active Sessions from their stored
 * identity context. Called after the RoleSet changes (Part 18 §4.4.1).
 * Must be called with the server lock held. */
void
UA_Server_reevaluateSessionRoles(UA_Server *server);

/* Set the ApplicationsExclude (endpoints == false) or EndpointsExclude flag of
 * a Role. Used for a Write of the Role Property, which the Write service audits
 * with the AuditWriteUpdateEventType; no RoleMappingRuleChanged event is raised
 * (Part 18 §4.5). */
UA_StatusCode
updateRoleExcludeFlag(UA_Server *server, const UA_NodeId *roleId,
                      UA_Boolean endpoints, UA_Boolean exclude);

/* Whether the Method callback is one of the mapping Methods of the RoleType
 * (AddIdentity, RemoveIdentity, AddApplication, RemoveApplication, AddEndpoint
 * and RemoveEndpoint; defined in ua_server_ns0_rbac.c). A call that updated a
 * Role raises the RoleMappingRuleChangedAuditEventType instead of the generic
 * AuditUpdateMethodEventType (Part 18 §4.5). */
UA_Boolean
isRoleMappingMethod(UA_MethodCallback callback);

/* The NodeId (numeric in Namespace Zero) of the UserManagement Method that the
 * server binds the callback to (AddUser, ModifyUser, RemoveUser and
 * ChangePassword; defined in ua_server_ns0_rbac.c), or 0 for another callback.
 * Copies of the Methods share the callback. Used to redact their secret
 * arguments in audit events. */
UA_UInt32
getUserManagementMethodId(UA_MethodCallback callback);

/* Effective AccessRestrictions of a node (its own value or the namespace
 * default). Must be called with the server lock held. */
UA_AccessRestrictionType
getNodeAccessRestrictions(UA_Server *server, const UA_Node *node);

/* The node's own AccessRestrictions (stored in its shared role-permission
 * entry), UA_ACCESSRESTRICTIONTYPE_NONE if the node has none and the namespace
 * default applies. The value of the AccessRestrictions Attribute (Part 3
 * §5.2.11). Must be called with the server lock held. */
UA_AccessRestrictionType
getNodeOwnAccessRestrictions(UA_Server *server, const UA_Node *node);

/* Enforce a node's AccessRestrictions against the session (Part 3 §5.2.11).
 * forBrowse limits enforcement to the ApplyRestrictionsToBrowse bit.
 * Must be called with the server lock held. */
UA_StatusCode
checkNodeAccessRestrictions(UA_Server *server, const UA_Session *session,
                            const UA_Node *node, UA_Boolean forBrowse);

/* Decrement the refCount of a role permission entry at the given index.
 * Used during node deletion to keep refcounts consistent. */
void
UA_Server_decrementRolePermissionsRefCount(UA_Server *server,
                                           UA_PermissionIndex index);

/* The permission index that the copy of an instance declaration gets
 * (copyChildNode). The copy keeps the AccessRestrictions of the declaration.
 * It does not inherit the RolePermissions and uses the namespace default, but
 * a copied Method keeps the built-in protection of its declaration (see
 * protectNodeRolePermissions), so that copyMethodsOnInstances gives the
 * instance the same RolePermissions as the referenced declaration. Returns the
 * index of the shared entry with these parts and takes a reference on it
 * (release it with UA_Server_decrementRolePermissionsRefCount if the node is
 * not added). Without either part, outIndex is UA_PERMISSION_INDEX_INVALID.
 * Must be called with the server lock held. */
UA_StatusCode
retainCopiedNodePermissionIndex(UA_Server *server, UA_NodeClass nodeClass,
                                UA_PermissionIndex declIndex,
                                UA_PermissionIndex *outIndex);

/* Low-level permission index functions (internal, used by tests). A
 * configuration slot with an empty list is no override: Nodes referencing it
 * use the namespace default (Part 3 §5.2.9). */

/* Give the node (and with recursive its hierarchical children) the
 * RolePermissions of the entry at permissionIndex. Each node keeps its own
 * AccessRestrictions; a node with AccessRestrictions is pointed at the shared
 * entry that combines both. A node with an invalid (out-of-range) index is
 * repaired. In the recursive case a failing child does not stop the
 * traversal; the first error is returned. */
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

/* The RolePermissions of the entry at index. NULL if the index is out of
 * range or the entry has no RolePermissions (only AccessRestrictions; the
 * namespace default applies to its nodes). An empty set is no override
 * either: the namespace default applies to its nodes. */
const UA_RolePermissionSet *
UA_Server_getRolePermissionConfig(UA_Server *server,
                                  UA_PermissionIndex index);

/* Replace the RolePermissions of the configuration at index. The
 * configuration is shared by content: the entries that combine its current
 * RolePermissions with AccessRestrictions (nodes that use the configuration
 * and have AccessRestrictions of their own) are updated as well and keep their
 * AccessRestrictions. Returns BADINVALIDSTATE if the configuration or such an
 * entry is referenced by nodes, unless the configuration is a protected preset
 * (its nodes follow the update). */
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

/* Classify the Node at roleId: GOOD for an Object of RoleType or a subtype,
 * BADNODEIDUNKNOWN when no such Node exists, BADNODEIDEXISTS otherwise. */
UA_StatusCode
checkRoleRepresentation(UA_Server *server, const UA_NodeId *roleId);

/* The mandatory well-known Roles Anonymous, AuthenticatedUser and
 * TrustedApplication. Their mapping rules cannot be changed (Part 18 §4.3), so
 * their Role Objects have no mapping Methods (§4.4.1). */
UA_Boolean
isMandatoryWellKnownRole(const UA_NodeId *roleId);

/* Back the Properties of an existing Role Object with the role registry and
 * bind its Methods */
UA_StatusCode
bindRoleRepresentation(UA_Server *server, const UA_NodeId *roleId,
                       UA_Boolean applyPermissions);

/* Restrict the RoleSet and RoleType Methods and the Role Properties to the
 * SecurityAdmin Role; the RoleSet and the Role Objects stay browsable (defined
 * in ua_server_ns0_rbac.c) */
UA_StatusCode
initRoleSetRolePermissions(UA_Server *server);

/* Give a sensitive Node built-in RolePermissions that are enforced only while
 * its namespace has a RolePermission model (an explicit default or strict
 * mode). In legacy mode the Node stays unrestricted like every other Node
 * without RolePermissions, so allPermissionsForAnonymous still restores the
 * legacy behavior. RolePermissions already configured for the Node are kept;
 * a Node with only AccessRestrictions has none and is protected. The Node
 * keeps its AccessRestrictions (copy-on-write of its shared entry).
 * Adding or removing the permissions of a Role later keeps the protection
 * conditional; UA_Server_setNodeRolePermissions replaces it with an ordinary
 * override. Must be called with the server lock held. */
UA_StatusCode
protectNodeRolePermissions(UA_Server *server, const UA_NodeId *nodeId,
                           size_t entriesSize, const UA_RolePermission *entries);

/* Protect the Namespace Zero Nodes that the NS0 template would open to every
 * Session (defined in ua_server_ns0_rbac.c): the PubSub configuration and
 * Security Key Service Methods, the Condition Methods that change the state of
 * an Alarm, the AuditEventType hierarchy and the writable Properties of
 * RoleType, which ConfigureAdmin could otherwise write. Runs at the end of
 * UA_Server_initRBAC, before the PubSub information model binds its Method
 * callbacks to the same Nodes. */
UA_StatusCode
initNS0SensitiveRolePermissions(UA_Server *server);

/* Restrict a PubSub configuration Method to ConfigureAdmin (built-in
 * protection). Used for the Methods that the PubSub information model creates
 * at runtime. */
UA_StatusCode
protectPubSubConfigurationMethod(UA_Server *server, const UA_NodeId *methodId);

/* RolePermission resolution (Part 3 §4.9.3, §5.2.9). Single source of truth
 * for the effective permission checks and the RolePermission attributes and
 * Properties. All of them must be called with the server lock held. */

/* Whether the namespace has a RolePermission model: an explicit
 * DefaultRolePermissions, or in strict mode (allPermissionsForAnonymous ==
 * false) the template of the server configuration for Namespace Zero or for
 * all other namespaces. Without a model (legacy mode), Nodes without their own
 * RolePermissions are unrestricted and the Server publishes no RolePermission
 * information for them. entries points to the namespace default (borrowed,
 * may be empty to deny everything). */
UA_Boolean
getNamespaceRolePermissionModel(UA_Server *server, UA_UInt16 namespaceIndex,
                                size_t *entriesSize,
                                const UA_RolePermission **entries);

/* Resolve the RolePermissions that apply to a Node: its own override, else the
 * default of its namespace (borrowed). An empty list on the Node is no
 * override. isOverride reports whether the Node has its own RolePermissions,
 * nsHasModel whether its namespace has a model. Both may be NULL. A corrupt
 * permission index returns Bad_InternalError with an empty override. */
UA_StatusCode
resolveNodeRolePermissions(UA_Server *server, const UA_Node *node,
                           size_t *entriesSize, const UA_RolePermission **entries,
                           UA_Boolean *isOverride, UA_Boolean *nsHasModel);

/* Effective permissions of the Session on the Node: the logical OR over the
 * Session's Roles. UA_PERMISSIONTYPE_ALL for a Node without RolePermissions in
 * a namespace without a model. The Session may be NULL (no Roles). The local
 * admin Session is not special-cased here; callers exempt it. */
UA_PermissionType
getNodeEffectivePermissions(UA_Server *server, const UA_Session *session,
                            const UA_Node *node);

/* Allocate or grow the namespace metadata array to cover all namespaces. New
 * entries have no defaults. Must be called with the server lock held. */
UA_StatusCode
ensureNamespaceMetadataSize(UA_Server *server);

/* Copy the entries of a RolePermission list that belong to one of the
 * Session's Roles (UserRolePermissions semantics). A NULL Session has no
 * Roles. */
UA_StatusCode
filterRolePermissionsForSession(const UA_Session *session,
                                size_t entriesSize,
                                const UA_RolePermission *entries,
                                size_t *outSize, UA_RolePermissionType **out);

/* Effective permission queries (internal, used by attribute service and tests) */
UA_StatusCode
UA_Server_getEffectivePermissions(UA_Server *server,
                                  const UA_NodeId *sessionId,
                                  const UA_NodeId *nodeId,
                                  UA_PermissionType *effectivePermissions);

/* Whether the Session receives an Event: the ReceiveEvents bit must be set on
 * the EventType and on the SourceNode (Part 3 §8.55) and the AccessRestrictions
 * of both Nodes must be met at delivery time. Legacy mode yields all bits for
 * Nodes without RolePermissions. A SourceNode that is not in the AddressSpace
 * (a null or a remote NodeId) is evaluated with the defaults of its namespace
 * (Namespace Zero for the null NodeId): the namespace default RolePermissions
 * or template, all bits in legacy mode without a namespace default, and the
 * namespace default AccessRestrictions. An Event whose EventType is not in the
 * AddressSpace is not delivered. The caller exempts the local admin Session.
 * Must be called with the server lock held. */
UA_Boolean
mayReceiveEvent(UA_Server *server, const UA_Session *session,
                const UA_NodeId *eventType, const UA_NodeId *sourceNode);

UA_StatusCode
UA_Server_getEffectiveNamespacePermissions(UA_Server *server,
                                           const UA_NodeId *sessionId,
                                           UA_UInt16 namespaceIndex,
                                           UA_PermissionType *effectivePermissions);

UA_StatusCode
UA_Server_getUserRolePermissions(UA_Server *server,
                                 const UA_NodeId *sessionId,
                                 const UA_NodeId *nodeId,
                                 size_t *entriesSize,
                                 UA_RolePermissionType **entries);

/* True when every UserManagement callback is configured. The NS0 setup keeps
 * the UserManagement Object only in that case; initUserManagement binds it. */
UA_Boolean
UA_Server_hasUserManagementProvider(const UA_AccessControl *ac);

#endif /* UA_ENABLE_RBAC */

_UA_END_DECLS

#endif /* UA_SERVER_RBAC_H_ */
