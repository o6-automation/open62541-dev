.. _security-rbac:

Role-Based Access Control
=========================

:doc:`authentication` establishes *who* uses a Session.  Role-Based Access
Control (RBAC, OPC UA Part 18 and Part 3 §4.9) decides *what* the Session may
do.  At ``ActivateSession`` the server grants the Session a set of *Roles*.
Nodes carry *RolePermissions*, a list of Role/PermissionType pairs.  The
effective permissions of a Session on a Node are the union of the permissions
of all its Roles.

RBAC is experimental and off by default.  Enable it with
``-DUA_ENABLE_RBAC=ON``; CMake requires ``UA_ENABLE_METHODCALLS`` and
``UA_NAMESPACE_ZERO=FULL``.  The API is documented in :ref:`server-rbac`.

Permissions
-----------

A Node's own RolePermissions apply first: ``UA_Server_setNodeRolePermissions``
replaces the list, ``UA_Server_addRolePermissions`` /
``UA_Server_removeRolePermissions`` change one Role's entry (all optionally
recursive), ``UA_Server_removeNodeRolePermissions`` drops the list, as does
removing its last entry.  ``rolePermissionPresets`` preloads lists that Nodes
share.  Without a list the namespace default of
``UA_Server_setNamespaceDefaultRolePermissions`` applies, without that
``allPermissionsForAnonymous``.  A list must name every Role that needs
access.  Clients cannot write the RolePermissions attribute.  The local admin
Session of the C API bypasses all checks.

The services and the default AccessControl plugin check the PermissionType
bits (``UA_PERMISSIONTYPE_*``) as follows.  The derived UserAccessLevel,
UserWriteMask and UserExecutable never exceed the Node's own attributes.

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Permission
     - Gates
   * - ``BROWSE``
     - Browse (also of the reference targets), TranslateBrowsePathsToNodeIds;
       reading attributes other than Value and RolePermissions.
   * - ``READROLEPERMISSIONS``, ``WRITEATTRIBUTE``,
       ``WRITEROLEPERMISSIONS``, ``WRITEHISTORIZING``
     - Reading RolePermissions; UserWriteMask: other attributes,
       RolePermissions, Historizing.
   * - ``READ``, ``WRITE``, ``READHISTORY``, ``INSERTHISTORY``,
       ``MODIFYHISTORY``, ``DELETEHISTORY``
     - UserAccessLevel CurrentRead, CurrentWrite, HistoryRead; HistoryUpdate
       insert, replace/update, delete.
   * - ``RECEIVEEVENTS``
     - Event delivery; needed on the EventType and on the SourceNode.
   * - ``CALL``
     - Call and UserExecutable; needed on the Object and on the Method.
   * - ``ADDREFERENCE``, ``REMOVEREFERENCE``, ``DELETENODE``
     - AddReferences / DeleteReferences on the source Node (AddNodes also on
       the parent), DeleteNodes on every deleted Node and child.
   * - ``ADDNODE``
     - AddNodes, checked on the parent Node.

MonitoredItems are sampled with the rights of the subscribing Session, also
when a write of another Session triggers the sample.  Samples of a detached
Subscription are denied.

Default rights
--------------

The default configurations (``UA_ServerConfig_setDefault()`` and friends) set
``allPermissionsForAnonymous = true`` for backwards compatibility: a Node with
neither own RolePermissions nor a namespace default grants *all* permissions
to every Session, whatever its Roles.  Explicit lists are enforced either
way.  No namespace has a default after startup.  To secure a server:

- set ``allPermissionsForAnonymous = false`` before creating the server,
- give every namespace, including Namespace Zero, a default,
- map users to Roles, including a SecurityAdmin for remote administration,
- require encryption with AccessRestrictions where needed.

Roles
-----

The server registers the well-known Roles of Part 18: Anonymous,
AuthenticatedUser, TrustedApplication, Observer, Operator, Engineer,
Supervisor, ConfigureAdmin, SecurityAdmin and the three SecurityKeyServer
Roles.  They cannot be removed and carry no permissions by themselves.
Custom Roles come from ``UA_ServerConfig::roles`` and ``UA_Server_addRole``.
Configured Roles are protected; Roles added at runtime can be removed with
``UA_Server_removeRole``, which also removes them from all RolePermissions.

Every Session gets Anonymous.  AuthenticatedUser is added for any
non-anonymous identity token, TrustedApplication for a validated client
certificate on a signed SecureChannel with a SecurityPolicy other than None.
These three mappings are fixed.  Any other Role is granted when one of its
identity mapping rules matches.  The rule types ``Anonymous``,
``AuthenticatedUser`` and ``TrustedApplication`` (empty criteria) match as
just described, the others when the criteria equals:

- ``UserName`` -- the user name of the UserNameIdentityToken,
- ``Thumbprint`` -- the SHA-1 thumbprint of the user certificate (40
  upper-case hex digits),
- ``X509Subject`` -- the subject or issuer of the user certificate (below),
- ``Application`` -- the ApplicationUri of the validated client certificate
  (its only SubjectAltName URI), never the one of CreateSession,
- ``GroupId`` / ``Role`` -- a group / a Role claim of an IssuedIdentityToken
  from the AccessControl callback ``getUserGroups`` / ``getUserTokenRoles``.

A Role without rules is never granted automatically.  A matching rule grants
the Role only if the Session also passes the Role's Application and Endpoint
filters.  With ``applicationsExclude`` / ``endpointsExclude`` set (the
``UA_Role_init`` default) the list excludes; with the flag cleared it
includes, and an empty include list grants nothing.  A non-empty Application
list requires a validated client certificate.  An Endpoint entry with an
EndpointUrl or TransportProfileUri fails closed for now: it never matches an
include list but always matches an exclude list.  ``UA_Server_addRole`` and
``UA_Server_updateRole`` reject malformed criteria with
``Bad_InvalidArgument`` and log the rule.

An ``X509Subject`` criteria lists ``NAME="value"`` pairs separated by ``/``
with the names of Part 18 Table 10 in table order (CN, O, OU, DC, L, S, C,
dnQualifier, serialNumber), e.g. ``CN="Jörg Müller"/O="Müller GmbH"/C="DE"``.
Values are non-empty UTF-8 without quotes and control characters, compared
byte-wise (write them in the normalization of the certificate, normally NFC).
``UA_CertificateUtils_getRoleSubjectCriteria`` derives the criteria of a
certificate; a name with a value that cannot be written this way matches no
rule.

Changes of the RoleSet re-evaluate all active Sessions immediately;
notifications sampled with the former Roles are dropped.  The Session
attribute ``UA_QUALIFIEDNAME(0, "roles")`` (a NodeId array, set with
``UA_Server_setSessionAttribute``) pins the Roles of a Session; only removed
Roles are dropped.  Deleting the attribute or a new ActivateSession returns
to the rules.
TransferSubscriptions requires the same user (``allowTransferSubscription``)
and the same Roles, SecureChannel SecurityMode, client application and
Endpoint as the Session the Subscription comes from.

AccessRestrictions
------------------

AccessRestrictions (Part 3 §5.2.11) tie a Node to the channel security:
``UA_ACCESSRESTRICTIONTYPE_SIGNINGREQUIRED`` and ``ENCRYPTIONREQUIRED``
(else ``Bad_SecurityModeInsufficient``), ``SESSIONREQUIRED`` (else
``Bad_UserAccessDenied``).  Read and MonitoredItem sampling, Write, Call
(Object and Method), HistoryRead, HistoryUpdate, the NodeManagement services
(the new Node, both ends of a reference, every deleted Node) and Event
delivery (EventType and SourceNode) enforce them, Browse and
TranslateBrowsePathsToNodeIds only with ``APPLYRESTRICTIONSTOBROWSE`` (Browse
then also hides restricted targets).  The local admin Session is exempt.

Set them with ``UA_Server_setNodeAccessRestrictions`` or, for all Nodes
without own value, ``UA_Server_setNamespaceDefaultAccessRestrictions``.  The
AccessRestrictions attribute reads the effective value and cannot be written
by clients.  The child Nodes of a new instance inherit the AccessRestrictions
of their InstanceDeclarations, but not their RolePermissions.

Auditing
--------

With ``UA_ENABLE_AUDITING`` and ``UA_ServerConfig::auditingEnabled``, Audit
Events never contain passwords, access tokens, private keys or PubSub
security keys.
