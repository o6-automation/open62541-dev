.. _security-rbac:

Role-Based Access Control
=========================

:doc:`authentication` establishes *who* uses a Session.  Role-Based Access
Control (RBAC, OPC UA Part 18 and Part 3 §4.9) decides *what* it may do.  At
``ActivateSession`` the server grants the Session a set of *Roles*.  Nodes
carry *RolePermissions*, a list of Role/PermissionType pairs; the effective
permissions of a Session are the union over its Roles.

RBAC is experimental and off by default.  Enable it with
``-DUA_ENABLE_RBAC=ON`` (requires ``UA_ENABLE_METHODCALLS`` and
``UA_NAMESPACE_ZERO=FULL``).  The API is documented in :ref:`server-rbac`.

Roles and their assignment
--------------------------

The server registers the well-known Roles of Part 18: Anonymous,
AuthenticatedUser, TrustedApplication, Observer, Operator, Engineer,
Supervisor, ConfigureAdmin, SecurityAdmin and the three SecurityKeyServer
Roles.  They cannot be removed.  Custom Roles come from
``UA_ServerConfig::roles`` (JSON ``rbac.roles``, protected), from
``UA_Server_addRole`` and from the ``AddRole`` Method (removable).  Every Role
is a RoleType Object under ``Server/ServerCapabilities/RoleSet``.  All
Sessions may browse the RoleSet and the Role Objects; their Properties and
Methods are reserved to SecurityAdmin over an encrypted channel, also in
legacy mode.  Anonymous, AuthenticatedUser and TrustedApplication have no
mapping Methods.

Every Session gets Anonymous.  AuthenticatedUser is added for any
non-anonymous identity token, TrustedApplication for a validated client
certificate on a signed SecureChannel with a SecurityPolicy other than None.
These three mappings are fixed.  Any other Role is granted when one of its
identity mapping rules matches.  The rule types ``Anonymous``,
``AuthenticatedUser`` and ``TrustedApplication`` (empty criteria) match as
just described, the others when the criteria equals

- ``UserName`` -- the user name of the UserNameIdentityToken,
- ``Thumbprint`` -- the SHA-1 thumbprint of the user certificate (upper case),
- ``X509Subject`` -- the subject or issuer of the user certificate, as
  formatted by ``UA_CertificateUtils_getRoleSubjectCriteria``,
- ``Application`` -- the ApplicationUri in the validated client certificate,
- ``GroupId`` -- a group from the AccessControl callback ``getUserGroups``,
- ``Role`` -- a Role claim of an IssuedIdentityToken (``getUserTokenRoles``).

A matching rule grants the Role only if the Session passes the Role's
Application and Endpoint filters: with ``applicationsExclude`` /
``endpointsExclude`` set (the ``UA_Role_init`` default) the list excludes,
otherwise it includes and an empty list grants nothing.  Endpoints are
compared with the configured ServerUrl of the accepting listener.  A Role
without rules is never granted automatically.

``wellKnownRoleMappings`` in the config (or ``UA_Server_updateRole``) sets the
rules and filters of the other well-known Roles.  The Session attribute
``UA_QUALIFIEDNAME(0, "roles")`` (a NodeId array, set with
``UA_Server_setSessionAttribute``) pins the Roles of a Session, e.g. for Roles
with ``customConfiguration``; deleting it returns to the rules.  Changes of
the RoleSet re-evaluate all active Sessions immediately.

Permissions
-----------

The services and the default AccessControl plugin decide from the
PermissionType bits (``UA_PERMISSIONTYPE_*``) only, within the Node's
AccessLevel, WriteMask and Executable:

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Permission
     - Gates
   * - ``BROWSE``, ``READROLEPERMISSIONS``
     - Browse, TranslateBrowsePathsToNodeIds and reading attributes other than
       Value and RolePermissions; reading RolePermissions.
   * - ``READ``, ``WRITE``, ``READHISTORY``, ``INSERTHISTORY``,
       ``MODIFYHISTORY``, ``DELETEHISTORY``
     - CurrentRead; CurrentWrite, StatusWrite and TimestampWrite; HistoryRead;
       HistoryUpdate insert, replace/update, delete.
   * - ``WRITEATTRIBUTE``, ``WRITEHISTORIZING``
     - UserWriteMask for the other attributes and for Historizing.
   * - ``RECEIVEEVENTS``, ``CALL``
     - Events, checked on the EventType and on the SourceNode; Call, checked
       on the Object and on the Method.
   * - ``ADDREFERENCE``, ``REMOVEREFERENCE``, ``DELETENODE``, ``ADDNODE``
     - AddReferences / DeleteReferences on the source Node, DeleteNodes;
       AddNodes against the default of the new Node's namespace.

A Node uses its own RolePermissions (``UA_Server_setNodeRolePermissions``
replaces the list, ``UA_Server_addRolePermissions`` /
``UA_Server_removeRolePermissions`` change one Role's entry, all optionally
recursive; ``rolePermissionPresets`` preloads shared lists), else the explicit
namespace default (``UA_Server_setNamespaceDefaultRolePermissions``), else the
template of the configuration (``namespaceZeroDefaultRolePermissions`` for
Namespace Zero, ``namespaceDefaultRolePermissions`` for all others).
``UA_Server_removeNodeRolePermissions`` and
``UA_Server_removeNamespaceDefaultRolePermissions`` fall back a step.

A Node's list must name every Role that needs access.  An empty Node list is
no override; to deny all, set ``{Anonymous, 0}`` -- which is also what
removing a Role or a Node's last entry leaves.  An empty namespace default or
template denies everything.  The local admin Session of the C API bypasses all
checks.

Default rights
--------------

``allPermissionsForAnonymous`` is ``false`` by default, so every Node has a
default.  The default configurations (``UA_ServerConfig_setDefault()`` and
friends) fill the templates with
``UA_ServerConfig_setDefaultNamespacePermissions`` after the suggested
permissions of Part 3 Table 2.  Each roleId of a template must be a registered
Role, else startup fails with ``Bad_ConfigurationError``.  Every Session holds
Anonymous; the other rows list what a Role adds:

.. list-table::
   :header-rows: 1
   :widths: 24 34 42

   * - Role
     - Namespace Zero
     - Other namespaces
   * - Anonymous
     - Browse, Read, Call, ReceiveEvents
     - Browse
   * - AuthenticatedUser, TrustedApplication
     - --
     - Read
   * - Observer
     - ReadHistory
     - Read, ReadHistory, ReceiveEvents
   * - Operator / Supervisor
     - ReadHistory
     - as Observer, plus Call (Operator also Write)
   * - Engineer
     - ReadHistory
     - as Operator, plus WriteAttribute, WriteHistorizing
   * - ConfigureAdmin
     - Write, WriteAttribute, AddReference, RemoveReference
     - Read, Write, WriteAttribute, WriteHistorizing, Call, AddReference,
       RemoveReference, DeleteNode, AddNode
   * - SecurityAdmin
     - ReadRolePermissions
     - Read, ReadRolePermissions

Nobody adds or deletes Nodes in Namespace Zero; the SecurityKeyServer Roles
get nothing.  While Namespace Zero has a default, built-in RolePermissions
restrict the sensitive Nodes that its template would open (Anonymous keeps
Browse and Read; ``UA_Server_setNodeRolePermissions`` replaces them):

- PubSub configuration Methods -- Call for ConfigureAdmin only,
- Security Key Service Methods -- Call for the SecurityKeyServer Roles only,
- Condition Methods Enable, Disable, AddComment, Acknowledge, Confirm -- Call
  for Operator, Engineer and Supervisor only,
- AuditEventType and its subtypes -- ReceiveEvents for SecurityAdmin only,
- ``ApplicationsExclude`` / ``EndpointsExclude`` of RoleType -- not writable
  by ConfigureAdmin,
- SessionSecurityDiagnosticsArray -- other Sessions only for SecurityAdmin.

Only the three mandatory Roles have identity mappings, so no network client
holds SecurityAdmin, Operator, ... until one is configured.

**Migration:** ``allPermissionsForAnonymous = true`` (before
``UA_Server_newWithConfig``, or in the JSON ``rbac`` object) restores the old
behavior: Nodes without own list and explicit namespace default are
unrestricted; the templates and the built-in protections above are ignored.

AccessRestrictions and attributes
---------------------------------

AccessRestrictions (Part 3 §5.2.11) tie a Node to the channel security:
``UA_ACCESSRESTRICTIONTYPE_SIGNINGREQUIRED`` and ``ENCRYPTIONREQUIRED``
(else ``Bad_SecurityModeInsufficient``), ``SESSIONREQUIRED`` (else
``Bad_UserAccessDenied``).  All services and Event delivery enforce them,
Browse and TranslateBrowsePathsToNodeIds only with
``APPLYRESTRICTIONSTOBROWSE``.  Set them per Node
(``UA_Server_setNodeAccessRestrictions``) or per namespace
(``UA_Server_setNamespaceDefaultAccessRestrictions``);
``UA_Server_getNodeAccessRestrictions`` returns the effective value.

Clients can read, but not write (``Bad_NotWritable``), the RBAC attributes.
Reading RolePermissions needs ``READROLEPERMISSIONS``.

.. list-table::
   :header-rows: 1
   :widths: 25 23 32 20

   * - Node
     - RolePermissions
     - UserRolePermissions
     - AccessRestrictions
   * - With own list / value
     - the list
     - the list for the Session's Roles
     - the value
   * - Inheriting the default
     - ``[]``
     - the default for its Roles
     - ``0``
   * - Legacy mode, no default
     - ``Bad_AttributeIdInvalid``
     - ``Bad_AttributeIdInvalid``
     - ``0``

Every namespace has a NamespaceMetadata Object under ``Server/Namespaces``
whose ``DefaultRolePermissions`` (SecurityAdmin only),
``DefaultUserRolePermissions`` and ``DefaultAccessRestrictions`` show the live
defaults.

Configuration
-------------

Map the user ``alice`` to Engineer and let only Engineer write one Variable
(``examples/access_control/server_rbac.c`` is a complete server with a
UserManagement provider and an ``AccessPermissions`` folder of demo Nodes):

.. code-block:: c

   UA_Server *server = UA_Server_newWithConfig(&config);
   UA_IdentityMappingRuleType rule =
       {UA_IDENTITYCRITERIATYPE_USERNAME, UA_STRING_STATIC("alice")};
   UA_Role eng;
   UA_Role_init(&eng);
   eng.roleName = UA_QUALIFIEDNAME(0, "Engineer");
   eng.identityMappingRules = &rule;
   eng.identityMappingRulesSize = 1;
   UA_Server_updateRole(server, &eng); /* copies the rules */

   UA_PermissionType br = UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ;
   UA_RolePermission rp[2] = {
       {UA_NS0ID(WELLKNOWNROLE_AUTHENTICATEDUSER), br},
       {UA_NS0ID(WELLKNOWNROLE_ENGINEER), br | UA_PERMISSIONTYPE_WRITE}};
   UA_Server_setNodeRolePermissions(server, setpointId, 2, rp, false, NULL);

In a JSON configuration, the ``rbac`` object uses the field names of
``UA_ServerConfig``; the templates are set with
``namespaceZeroDefaultRolePermissions`` and ``namespaceDefaultRolePermissions``
as arrays of ``{"roleId": "i=15680", "permissions": 4193}`` entries.

UserManagement
--------------

The UserManagement Object of Part 18 §5 (under ``ServerConfiguration``) is
published when the seven callbacks ``getUsers``, ``getPasswordPolicy``,
``getUserConfiguration``, ``addUser``, ``modifyUser``, ``removeUser`` and
``changePassword`` of ``UA_AccessControl`` are set.  ``Users``, ``AddUser``,
``ModifyUser`` and ``RemoveUser`` require SecurityAdmin over an encrypted
channel; disabling or removing a user closes its Sessions.  ``ChangePassword``
changes the password of the Session's own UserName identity, encrypted.  A
disabled user is refused at ActivateSession like an unknown user.  A user with
``MustChangePassword`` gets ``Good_PasswordChangeRequired`` and only the
Anonymous Role, which suffices to call ``ChangePassword``.

Auditing
--------

With ``UA_ENABLE_AUDITING`` and ``UA_ServerConfig::auditingEnabled``, a
successful call of a Role's mapping Methods emits a
``RoleMappingRuleChangedAuditEventType`` Event with the Role as SourceNode;
AddRole, RemoveRole and writes of the ``*Exclude`` flags are audited as
ordinary calls and writes, C API changes not at all.  The ActivateSession
audit Event and the SessionDiagnostics (for the Session and SecurityAdmin)
report the Roles as ``CurrentRoleIds``.  Audit Events go to SecurityAdmin only
and never contain passwords, access tokens, private keys or PubSub keys.
