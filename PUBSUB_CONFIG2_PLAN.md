# Plan: Standard-compliant file-based PubSub configuration (PubSubConfiguration2DataType)

> **Implementation status (2026-07-02)** — see `PUBSUB_CONFIG2_HANDOVER.md` for
> the detailed working state.
>
> * **Milestone 1 (Phase A1/A3/A4) — DONE, verified**: converter module
>   `src/pubsub/ua_pubsub_config_map.c` (DataType→Config, borrowing views),
>   dual-type load (legacy + Config2 body), namespace remapping on load,
>   standalone SubscribedDataSets in the load path, initial-setup-mode fix in
>   `UA_PubSubManager_setState` (respect `config.enabled`). All existing
>   pubsub tests pass (`build-config2` with `UA_ENABLE_PUBSUB_FILE_CONFIG=ON`).
> * **Milestone 2 (Phase A2/A5/A6) — DONE, test-covered (2026-07-03)**:
>   reverse converters (Config→DataType), Config2 export with namespaces array
>   + enabled flags from live state, manager metadata
>   (configurationVersion/configurationProperties/defaultSecurityKeyServices),
>   new API `UA_Server_getPubSubConfig2`,
>   `UA_Server_writePubSubConfigurationToByteString` now emits Config2.
>   Covered by `tests/pubsub/check_pubsub_config2.c` (export/import round trip,
>   namespace remapping, mixed enabled flags, invalid body). Two bugs found by
>   the test and fixed: DSR `publisherId` was not mapped in
>   `UA_DataSetReaderConfig_fromDataType`; export emitted an empty DSW
>   `dataSetName` for API-built configs (now falls back to the connected PDS
>   name).
> * **M2 gap closure (§1.4) — DONE (2026-07-03)**: internal config structs
>   extended for the previously dropped Part 14 fields (storage-only, runtime
>   enforcement TODO): WG maxNetworkMessageSize/headerLayoutUri/localeIds/
>   securityKeyServices, RG messageSettings/maxNetworkMessageSize/
>   securityKeyServices, DSR keyFrameCount/headerLayoutUri/securityMode/
>   securityGroupId/securityKeyServices/dataSetReaderProperties, PDS
>   dataSetFolder/extensionFields, SSDS dataSetFolder. Converters wired both
>   directions, round-trip test extended. Still lossy: PDS metadata
>   description/dataSetClassId; SecurityGroups (SKS) export.
> * **Milestones 3-5 (Phases B, C, remaining tests §4.1/4.4-4.8) — not
>   started.**

Branch: `feat_pubsub_config2` — target: open62541 1.5 / master
Reference: OPC 10000-14 v1.05.06 (`OPC-10000-14-v1.05.06.md` in the repo root)
Relevant spec sections: 6.2.1 (PubSubState state machine), 6.2.12 (PubSubConfiguration
DataTypes), 9.1.3.7 (Modification of PubSub configuration: PubSubConfigurationType,
PubSubConfigurationRefMask/RefDataType/ValueDataType, ReserveIds, CloseAndUpdate).

---

## 1. Current implementation (as-is analysis)

### 1.1 File-based configuration (non standard-compliant)

Behind `UA_ENABLE_PUBSUB_FILE_CONFIG` (CMake, default **OFF**), implemented in
`src/pubsub/ua_pubsub_config.c`:

* `UA_Server_loadPubSubConfigFromByteString()` decodes an `ExtensionObject`
  containing a `UABinaryFileDataType` whose body must be the **legacy
  `PubSubConfigurationDataType`** (pre-1.05). `PubSubConfiguration2DataType` is
  rejected with `BadTypeMismatch`.
* Loading is **destructive full replace**: the PubSubManager must be/gets
  stopped, `UA_PubSubManager_clear()` deletes everything, then all components
  are re-created (Phase 1, always `enabled=false`), then the `enabled` flags
  from the file are written into the component configs (Phase 2) and the
  manager is started with `psm->pubSubInitialSetupMode = true` so the state
  machine drives enabled components to `Operational`.
* `UA_Server_writePubSubConfigurationToByteString()` exports the current
  runtime config as legacy `PubSubConfigurationDataType`.
* Information model surface (in `ua_pubsub_ns0.c`, `initPubSubNS0()`):
  two **vendor-defined** method nodes attached under `PublishSubscribe` with
  `HasOrderedComponent` — `"PubSub configuration"` (a.k.a.
  `LoadPubSubConfigurationFile`, single `ByteString` input) and
  `"Delete PubSub config"`. Neither exists in Part 14. This is the core
  non-compliance: the spec instead mandates the **`PubSubConfiguration` FileType
  object** with `Open/Close/Read/Write/GetPosition/SetPosition` plus
  `ReserveIds` and `CloseAndUpdate` (9.1.3.7.1).

### 1.2 What already exists and can be reused

* **Generated data types** (verified in all `build*/src_generated`): the
  `UA_TYPES` array already contains
  `UA_PubSubConfiguration2DataType` (387), `UA_PubSubConfigurationRefMask` (90),
  `UA_PubSubConfigurationRefDataType` (91), `UA_PubSubConfigurationValueDataType` (92),
  `UA_SecurityGroupDataType` (364), `UA_PubSubKeyPushTargetDataType` (365),
  `UA_StandaloneSubscribedDataSetDataType` (382), `UA_UABinaryFileDataType` (377),
  `UA_EndpointDescription` (152) — even with `UA_NAMESPACE_ZERO=REDUCED`.
  No type-generation work needed (adding them explicitly to
  `tools/schema/datatypes_pubsub.txt` is still recommended for robustness).
* **NodeIds**: all `UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_*` and
  `UA_NS0ID_PUBSUBCONFIGURATIONTYPE` (25482) defines are generated from
  `NodeIds.csv`. However, in `tools/schema/Opc.Ua.NodeSet2.PubSubMinimal.xml`
  the `PubSubConfiguration` object (i=25451) exists **with everything commented
  out except `ReserveIds` (i=25474)**: no FileType properties (Size, Writable,
  UserWritable, OpenCount i=25452..25455), no Open (25459), Close (25462),
  Read (25464), Write (25467), GetPosition (25469), SetPosition (25472),
  no CloseAndUpdate (25477/25478/25479), no HasTypeDefinition to
  PubSubConfigurationType (25482), and the ObjectType itself is missing.
* **ReserveIds** (9.1.3.7.5) is implemented: `UA_PubSubManager_reserveIds()`
  (`ua_pubsub_manager.c`) reserves WriterGroup-/DataSetWriterIds from
  `0x8000..0xFFFF` per transport profile, session-bound (freed when the session
  disappears, `UA_PubSubManager_freeIds`), checked against the running config.
  NS0 binding: `addReserveIdsAction`. Known gaps: `is_free` scan; hard-coded
  transport-profile whitelist; `DefaultPublisherId` output returns the
  ApplicationUri for MQTT profiles / `psm->defaultPublisherId` (UInt64)
  otherwise — must be checked against 6.2.7.1 defaults per profile.
* **FileType handling pattern**: `src/server/ua_server_ns0_gds.c` implements a
  complete FileType surface for the GDS TrustList (per-session
  `UA_FileContext` with file handle/open mode/position, `UA_FileInfo` with
  openCount, periodic `checkSessionActive` cleanup of orphaned handles).
  This is TrustList-specific but is the template for the PubSubConfiguration
  file object (or candidate for extraction into a shared FileType helper).
* **Component model / manager**: `UA_PubSubManager` holds connections,
  publishedDataSets, subscribedDataSets (standalone SDS supported via
  `UA_Server_addSubscribedDataSet`), reserveIds tree, SKS securityGroups.
  Per-component `UA_Server_get/update...Config()` APIs exist for connection,
  WriterGroup, DataSetWriter, ReaderGroup, DataSetReader — the building blocks
  for the *modify* element operation.

### 1.3 State machine (as-is) and element interactions

Spec model (6.2.1): `Disabled(0), Paused(1), Operational(2), Error(3),
PreOperational(4)`; children cascade from parents; root of the cascade is the
`PublishSubscribe` component.

open62541 implementation (documented in `ua_pubsub_internal.h` header table):

* Each active component (Connection, WriterGroup, DataSetWriter, ReaderGroup,
  DataSetReader) has `UA_PubSubComponentHead.state` and a
  `UA_<Comp>_setPubSubState(psm, comp, targetState)` function.
  Semantics: *enabled* = not `DISABLED`/`ERROR`; every enabled component
  "wants to become OPERATIONAL" on its own once external conditions allow.
* Cascade mechanics: after a parent state change, the parent iterates its
  children and re-invokes their state machine with the child's **current state
  as target** (`UA_PubSubConnection_setPubSubState` →
  `UA_ReaderGroup/WriterGroup_setPubSubState(child, child->head.state)`), which
  re-evaluates Paused vs. (Pre)Operational against the new parent state.
  `transientState` suppresses nested notifications; only the top-level change
  notifies the application (`stateChangeCallback`) and re-triggers children.
* `PAUSED` is entered when the component is enabled but the manager
  (`psm->sc.state != UA_LIFECYCLESTATE_STARTED`) or the parent is not
  operational.
* **`pubSubInitialSetupMode`** (manager flag): during config-file loading the
  manager start pushes each connection with `config.enabled` to `OPERATIONAL`,
  and inside the cascade children with `config.enabled==true` get target
  `OPERATIONAL` instead of their current state. This is how the two-phase file
  load activates the hierarchy bottom-up without races.
* Root `PublishSubscribe` state: represented by the PubSubManager
  server-component lifecycle (`STOPPED/STARTED/STOPPING`), surfaced in NS0 via
  `pubSubStateVariableDataSourceRead` (STARTED→OPERATIONAL else DISABLED) and
  the `PubSubStatusType` `Enable/Disable` methods
  (`enable/disablePubSubObjectAction` — strict "only from Disabled" / "not
  when already Disabled" checks).
* Hooks that any new config path must respect:
  `beforeStateChangeCallback`, `stateChangeCallback`,
  `componentLifecycleCallback` (server config), per-component
  `customStateMachine` (skips default socket/callback handling), and the SKS
  key storages attached to groups (`securityGroupId`/`securityPolicies`).

Implications for CloseAndUpdate: element operations mutate a **running**
hierarchy. Add/remove interacts with the parent cascade automatically
(children created disabled then enabled). Modify must either use the existing
`UA_Server_update*Config` functions (which internally handle
freeze/re-connect) or perform disable → replace config → restore state.

### 1.4 Known mapping gaps (DataType ⇄ internal config) to close

Loader (`updatePubSubConfig` path) currently drops:

| Element | Fields not mapped today |
|---|---|
| PubSubConnectionDataType | (none critical; address/transportSettings must be DECODED extension objects) |
| WriterGroupDataType | `maxNetworkMessageSize`, `headerLayoutUri`, `localeIds`, `securityGroupId`, `securityKeyServices` |
| DataSetWriterDataType | `transportSettings`, `enabled` handled only in Phase 2 |
| ReaderGroupDataType | `transportSettings`, `messageSettings`, `groupProperties`, `maxNetworkMessageSize`, `securityGroupId`, `securityKeyServices` |
| DataSetReaderDataType | `transportSettings`, `securityMode`, `securityGroupId`, `securityKeyServices`, `headerLayoutUri`, `keyFrameCount`(n/a) |
| PublishedDataSetDataType | `dataSetFolder`, full `dataSetMetaData` (only name/fields/configVersion partially), `extensionFields` |
| PubSubConfiguration(2) | `subscribedDataSets` (SSDS), `dataSetClasses`, `defaultSecurityKeyServices`, `securityGroups`, `pubSubKeyPushTargets`, `configurationVersion`, `configurationProperties` |

Exporter (`generatePubSubConfigurationDataType`) additionally never sets the
`enabled` flags, exports no SSDS/SecurityGroups/top-level fields, and loses the
same per-component fields as above. The export must also populate the
`UABinaryFileDataType.namespaces` array (spec: namespace indices in the body
must match the server NamespaceArray) — currently absent; the loader must
validate/remap namespace indices on import.

---

## 2. Target behavior (to-be, per Part 14 v1.05)

1. **`PublishSubscribe.PubSubConfiguration`** object of
   **`PubSubConfigurationType`** (FileType subtype):
   * File content = UA-Binary `ExtensionObject(UABinaryFileDataType)` with a
     **`PubSubConfiguration2DataType`** (or subtype) body.
   * `Open` restricted to modes Read (0x01), Read+Write (0x03),
     Write+EraseExisting (0x06). Parallel readers allowed; Write requires
     exclusive access. Read snapshot is generated at open.
   * Writes are buffered; plain `Close` **discards**; only **`CloseAndUpdate`**
     applies changes.
2. **`CloseAndUpdate`** (9.1.3.7.6): inputs `FileHandle`,
   `RequireCompleteUpdate`, `ConfigurationReferences[]`
   (PubSubConfigurationRefDataType). Outputs `ChangesApplied`,
   `ReferencesResults[]`, `ConfigurationValues[]`, `ConfigurationObjects[]`.
   * Ref mask: exactly one op bit of ElementAdd/ElementModify/ElementRemove
     (ElementMatch combinable with ElementAdd), exactly one reference bit
     (Writer/Reader/WriterGroup/ReaderGroup/Connection/PubDataset/SubDataset/
     SecurityGroup/PushTarget). Indices: `ElementIndex`, `ConnectionIndex`,
     `GroupIndex` address elements in the *file* config; unreferenced elements
     serve as name-only parents; unreferenced+unused elements are ignored.
   * Removes are processed first (allows remove+add with the same name).
   * Top-level fields: `Enabled` ignored; `DataSetClasses` ignored;
     `DefaultSecurityKeyServices` replaces existing if non-empty;
     `ConfigurationVersion` ignored on input, set to current time on success;
     `ConfigurationProperties` merged (null value ⇒ delete key).
   * Element result codes: Bad_BrowseNameDuplicated, Bad_NoMatch,
     Bad_NotFound (parent), Bad_InvalidArgument, Bad_ResourceUnavailable,
     Bad_InvalidState (Match on WG with active GroupHeader),
     Bad_UserAccessDenied.
   * Method result codes: Bad_TypeMismatch (wrong body), Bad_InvalidArgument
     (handle), Bad_InvalidState (not opened for write), Bad_UserAccessDenied,
     Bad_NothingToDo (empty refs).
3. **`ReserveIds`** as today, aligned with spec details (range 0x8000–0xFFFF,
   session lifetime, `Bad_ResourceUnavailable` when exhausted, correct
   `DefaultPublisherId` per transport profile).
4. Full read/write round trip of `PubSubConfiguration2DataType`, including
   `SubscribedDataSets` (SSDS), `SecurityGroups` (SKS builds),
   `ConfigurationVersion`, `ConfigurationProperties`,
   `DefaultSecurityKeyServices`; `PubSubKeyPushTargets` may be rejected
   per-element (not supported) in the first iteration.

---

## 3. Implementation plan

The work is split into five phases; each phase is independently mergeable and
testable.

### Phase A — Config2 core: complete DataType ⇄ internal mapping (C API level)

New/changed files: split `src/pubsub/ua_pubsub_config.c` into
* `ua_pubsub_config.c` — public entry points, decode/encode of the
  file container (`UABinaryFileDataType`), namespace handling;
* `ua_pubsub_config_map.c` (new) — bidirectional per-element mapping
  `*DataType ⇄ UA_*Config` as reusable functions (needed by both full load and
  the incremental engine, and by NS0 methods like `AddConnection` that today
  duplicate this mapping in `ua_pubsub_ns0.c`).

Steps:
1. **A1** Extract per-element converters with complete field coverage
   (close all gaps from §1.4), in both directions:
   `PubSubConnectionDataType⇄UA_PubSubConnectionConfig`,
   `WriterGroupDataType⇄UA_WriterGroupConfig`,
   `DataSetWriterDataType⇄UA_DataSetWriterConfig`,
   `ReaderGroupDataType⇄UA_ReaderGroupConfig`,
   `DataSetReaderDataType⇄UA_DataSetReaderConfig`,
   `PublishedDataSetDataType⇄UA_PublishedDataSetConfig(+fields)`,
   `StandaloneSubscribedDataSetDataType⇄UA_SubscribedDataSetConfig`,
   `SecurityGroupDataType⇄UA_SecurityGroupConfig` (under
   `UA_ENABLE_PUBSUB_SKS`).
2. **A2** Extend `UA_PubSubManager` with configuration-level metadata:
   `UA_UInt32 configurationVersion` (VersionTime, updated on every successful
   config change incl. CloseAndUpdate), `UA_KeyValueMap configurationProperties`,
   `UA_EndpointDescription *defaultSecurityKeyServices` (+size).
3. **A3** Accept **both** `PubSubConfigurationDataType` (legacy) and
   `PubSubConfiguration2DataType` as file body in
   `extractPubSubConfigFromExtensionObject`; dispatch on the decoded type
   (Config2 is a subtype — handle both `UA_TYPES` entries). Reject others with
   `BadTypeMismatch`.
4. **A4** Namespace handling: on load, build an index remap table from
   `UABinaryFileDataType.namespaces` → server NamespaceArray (add missing
   namespaces or fail with a clear error; decision below) and remap NodeIds in
   `PublishedVariableDataType.publishedVariable`,
   `FieldTargetDataType.targetNodeId`, DataSetMetaData
   structure/enum descriptions, KeyValuePair QualifiedNames. On save, emit the
   namespaces array (skipping ns0 per Table 88).
5. **A5** Export: `generatePubSubConfiguration2DataType()` producing a complete
   snapshot (all fields incl. `enabled` per component and top-level `enabled`
   = manager started, SSDS, SecurityGroups, ConfigurationVersion,
   ConfigurationProperties). Keep the legacy generator for the old API.
6. **A6** Public C API (all behind `UA_ENABLE_PUBSUB_FILE_CONFIG`):
   * keep `UA_Server_loadPubSubConfigFromByteString` (now accepting Config2,
     still full-replace semantics),
   * keep `UA_Server_writePubSubConfigurationToByteString` (now emitting
     Config2 — **breaking change**, document in CHANGES.md; legacy export
     available via option or dedicated function),
   * new `UA_Server_getPubSubConfig2(UA_Server*, UA_PubSubConfiguration2DataType*)`,
   * new `UA_Server_updatePubSubConfig2(UA_Server*,
     const UA_PubSubConfiguration2DataType *cfg,
     size_t refsSize, const UA_PubSubConfigurationRefDataType *refs,
     UA_Boolean requireCompleteUpdate, UA_PubSubConfigUpdateResult *result)` —
     the incremental engine exposed to C users (also what CloseAndUpdate calls).

### Phase B — Incremental update engine (CloseAndUpdate semantics)

New file: `src/pubsub/ua_pubsub_config_update.c`.

1. **B1 Reference resolution.** Validate each
   `PubSubConfigurationRefDataType`: exactly one reference bit; op bits per
   spec (Add|Match combinable, otherwise exclusive); resolve
   `ConnectionIndex`/`GroupIndex`/`ElementIndex` into the file config, and the
   *target* in the live model by name lookup (parents referenced by
   `ReferenceConnection=false` etc. resolve by name). Build an operation list;
   stable order: all Removes first (spec), then Match/Add/Modify in argument
   order.
2. **B2 Element operations**, implemented on top of Phase A converters and the
   existing component functions:
   * *Remove*: find by name → `UA_PubSubConnection_delete` /
     `UA_WriterGroup_remove` / ... (children cascade automatically).
     `Bad_NoMatch` when absent.
   * *Add*: duplicate name ⇒ `Bad_BrowseNameDuplicated`; parent must exist or
     have been added/matched earlier in the same call (`Bad_NotFound`);
     name/ID auto-assignment when null/0: name generated
     (`"Connection %N"`, ...), `WriterGroupId`/`DataSetWriterId` from the
     caller's session reservations if present else next free ID, PublisherId
     default per transport profile. Record assigned values for
     `ConfigurationValues` output. Component created disabled, then enabled iff
     `enabled` in the file element (reuses existing enable cascade; no
     `pubSubInitialSetupMode` — this is a live modification).
   * *Match*: only Connection/WriterGroup/ReaderGroup (`Bad_InvalidArgument`
     otherwise); compare exactly the field sets listed in Table 239 (for
     properties: only provided entries compared); WG match with active
     GroupHeader (NetworkMessageContentMask bit GroupHeader on a non-disabled
     WG) ⇒ `Bad_InvalidState`. Match+Add: use existing if match found, else
     add.
   * *Modify*: find by name (`Bad_NoMatch`); build new `UA_*Config` via
     converter; apply with the component's `UA_Server_update*Config`-internal
     equivalent. If the component is not Disabled: disable → update → restore
     previous enabled/target state (respecting `customStateMachine` and
     firing the regular state callbacks).
3. **B3 Transactionality.** `RequireCompleteUpdate=true`: two-pass approach —
   pass 1 validates every operation (name lookups, duplicate checks, converter
   validation, capability limits) against a *shadow view* (live model + queued
   ops, no mutation); only if all pass, pass 2 applies. Failures in pass 2
   (should be rare: resource exhaustion) abort and roll back by inverse ops;
   document that rollback of partially-applied phase-2 errors is best-effort.
   `RequireCompleteUpdate=false`: apply sequentially, collect per-ref status.
4. **B4 Outputs.** `ChangesApplied` (any op applied), `ReferencesResults[]`
   (1:1 with input refs), `ConfigurationValues[]` (assigned names/identifiers
   for Add/Match; `Identifier` = PublisherId/WriterGroupId/DataSetWriterId per
   element type), `ConfigurationObjects[]` (NodeIds when
   `UA_ENABLE_PUBSUB_INFORMATIONMODEL`; else empty).
5. **B5 Top-level fields** per 9.1.3.7.6: apply
   `DefaultSecurityKeyServices` (replace if non-empty),
   `ConfigurationProperties` merge/delete, bump `configurationVersion`
   ( `UA_PubSubConfigurationVersionTimeDifference`), ignore
   `Enabled`/`DataSetClasses`/input `ConfigurationVersion`.
6. **B6 State-machine integration rules** (make explicit + unit-tested):
   * ops never touch components not referenced (their state is untouched);
   * add under a running parent: child ends Paused/PreOperational/Operational
     according to the normal cascade;
   * modify preserves the pre-op enabled state;
   * remove of a running component disables it first (existing `_remove`
     behavior);
   * `componentLifecycleCallback` is invoked for every add/remove;
     a `Bad` return aborts that element op with its status.

### Phase C — Information model: FileType front-end

New file: `src/pubsub/ua_pubsub_ns0_config2.c`
(guarded by `UA_ENABLE_PUBSUB_INFORMATIONMODEL && UA_ENABLE_PUBSUB_FILE_CONFIG`).

1. **C1 Nodeset**: extend `tools/schema/Opc.Ua.NodeSet2.PubSubMinimal.xml`
   (source: `deps/ua-nodeset/Schema/Opc.Ua.NodeSet2.xml`):
   * `PubSubConfigurationType` ObjectType i=25482 incl. inherited FileType
     children and `ReserveIds`/`CloseAndUpdate` declarations;
   * un-comment/add the instance children of
     `PublishSubscribe.PubSubConfiguration` i=25451: properties
     Size/Writable/UserWritable/OpenCount (25452..25455), methods Open(25459),
     Close(25462), Read(25464), Write(25467), GetPosition(25469),
     SetPosition(25472), CloseAndUpdate(25477) + argument variables, and
     `HasTypeDefinition → i=25482`;
   * add the DataType nodes (PubSubConfiguration2DataType i=23602,
     PubSubConfigurationRefMask i=25517, PubSubConfigurationRefDataType
     i=25519, PubSubConfigurationValueDataType i=25520, SecurityGroupDataType,
     PubSubKeyPushTargetDataType, + encoding nodes) so clients can resolve the
     types.
   * Regenerate NS0 (`UA_NAMESPACE_ZERO` REDUCED/FULL both covered; FULL
     already contains everything).
2. **C2 File-session state**: per-manager open-file table
   (modeled on the GDS `UA_FileContext`/`UA_FileInfo` pattern):
   `{UA_UInt32 handle; UA_NodeId sessionId; UA_Byte openMode; size_t position;
   UA_ByteString buffer;}` + `openCount`, exclusive-writer flag,
   `lastModifiedTime`. Cleanup on session close (reuse/extend the GDS
   `checkSessionActive` approach — consider extracting a shared
   `ua_filetype_helper` if low-risk, else keep local).
   Open(Read) serializes the current config once (Phase A5 → encode) into the
   handle's buffer; Open(Write+Erase) starts an empty buffer; Open(Read+Write)
   snapshot + writable buffer per the spec's read-modify-write sequence.
3. **C3 Method callbacks** on the instance NodeIds: Open/Close/Read/Write/
   GetPosition/SetPosition semantics per Part 20 FileType (mode validation:
   only 0x01/0x03/0x06; `Bad_NotWritable`/`Bad_NotReadable` on wrong handle
   use; `Bad_InvalidState` if exclusive access violated), `CloseAndUpdate` →
   decode buffer (`Bad_TypeMismatch` on wrong body) → Phase B engine → outputs.
   Wire in `initPubSubNS0()` next to the existing `ReserveIds` binding.
4. **C4 Properties**: value callbacks for Size (current snapshot length /
   0 when closed), OpenCount, Writable/UserWritable (from access control +
   server config), LastModifiedTime (last successful CloseAndUpdate).
5. **C5 Access control**: gate Open-for-write, ReserveIds and CloseAndUpdate
   behind the access-control plugin (session user allowed to modify PubSub
   config ⇒ else `Bad_UserAccessDenied`). Minimal first version: executable-on
   -object via standard method permissions, documented hook for finer control.
6. **C6 Deprecation**: keep the two vendor method nodes for one release behind
   a new option `UA_ENABLE_PUBSUB_FILE_CONFIG_LEGACY_METHODS` (default ON in
   1.5, announce removal), so existing integrations keep working; document in
   CHANGES.md.

### Phase D — Build system & migration

* Add new sources to `CMakeLists.txt` pubsub block; consider defaulting
  `UA_ENABLE_PUBSUB_FILE_CONFIG` to ON when
  `UA_ENABLE_PUBSUB_INFORMATIONMODEL` is ON (decision below).
* Add the Config2 types explicitly to `tools/schema/datatypes_pubsub.txt`.
* CHANGES.md entry: export format now `PubSubConfiguration2DataType`;
  import accepts both.
* CI: enable `UA_ENABLE_PUBSUB_FILE_CONFIG=ON` in at least one Linux build +
  the valgrind job (tests are added below); ensure an SKS build variant also
  compiles the SecurityGroup mapping.

### Phase E — Examples & docs

* Rework `examples/pubsub/server_pubsub_file_configuration.c` to demo the
  FileType object usage + keep ByteString loading.
* New client example `examples/pubsub/client_pubsub_config2_update.c`:
  Open(Read) → decode → modify → SetPosition(0) → Write → CloseAndUpdate with
  ConfigurationReferences (spec 9.1.3.7.1 client sequence).
* Documentation section in `doc/` (pubsub tutorial) describing supported
  subset, deviations, and the state-machine interaction rules from B6.

### Suggested milestone order

A1→A3 (mapping + dual-type load) → A5/A6 (export + new C API) → B (engine,
C-API-testable without NS0) → C (FileType front-end) → D/E. Phases A and B
deliver value even before the information-model surface lands.

### Open decisions (to confirm before/during implementation)

1. Namespace mismatch on load: auto-add unknown namespaces to the server
   NamespaceArray (convenient) vs. hard error (strict). Proposal: remap known,
   auto-add unknown, WARN log.
2. `PubSubKeyPushTargets`: not supported by the manager → per-element
   `Bad_ResourceUnavailable` (proposal) vs. `Bad_NotImplemented` (non-spec).
3. Export of the legacy `PubSubConfigurationDataType`: keep an explicit API
   or drop silently? Proposal: keep `...ToByteString` emitting Config2 only,
   note in CHANGES.md.
4. Default for `UA_ENABLE_PUBSUB_FILE_CONFIG` (stay OFF vs. ON with
   information model). Proposal: ON when PubSub + information model are ON.
5. Rollback strategy for `RequireCompleteUpdate=true` (shadow-validate +
   best-effort rollback, as in B3) — acceptable?

---

## 4. Test plan

Framework: `check`-based suites in `tests/pubsub/`, registered in
`tests/CMakeLists.txt` under `UA_ENABLE_PUBSUB_FILE_CONFIG` (and
`UA_ENABLE_PUBSUB_INFORMATIONMODEL` for the NS0 parts). All tests run under
the existing valgrind targets automatically (`ua_add_test`).

### 4.0 Test fixtures — preconfigured configurations

Do **not** add more opaque `.bin` blobs. Instead:

* `tests/pubsub/pubsub_config2_fixtures.h/.c`: builders that construct
  `UA_PubSubConfiguration2DataType` values in code and encode them to the
  file ByteString (`UABinaryFileDataType` wrapper) via the Phase A encoder:
  * `fixtureMinimalPublisher()` — 1 UDP-UADP connection, 1 WG, 1 DSW, 1 PDS
    (2 fields);
  * `fixtureMinimalSubscriber()` — 1 connection, 1 RG, 1 DSR + TargetVariables;
  * `fixtureFull()` — everything: pub+sub, SSDS, all optional fields set
    (maxNetworkMessageSize, headerLayoutUri, localeIds, group/writer/connection
    properties, transportSettings on every level, ConfigurationProperties,
    DefaultSecurityKeyServices, mixed enabled flags), 2 namespaces used in
    published/target NodeIds;
  * `fixtureSecurityGroups()` — SKS-only fixture;
  * `fixtureLegacy()` — legacy `PubSubConfigurationDataType` body (backward
    compat).
* Keep the two existing `.bin` files as regression inputs for the legacy path.
* A deep-compare helper `comparePubSubModelToConfig2(psm, cfg)` that walks the
  live manager (connections→groups→writers/readers, PDS/SSDS) and asserts
  every field against the expected DataType — this is the workhorse of
  "load fixture → check resulting model".

### 4.1 `check_pubsub_config2_encoding.c` — container & round trip

* Encode fixtureFull → decode → `UA_order`-equality with original (all
  fields survive, namespaces array correct, ns0 skipped).
* Body-type dispatch: Config2 accepted, legacy accepted, other body types ⇒
  `Bad_TypeMismatch`; array body ⇒ error; truncated/garbage ByteStrings ⇒
  clean decode errors, no leaks (valgrind).

### 4.2 `check_pubsub_config2_load.c` — full load, model verification

For each fixture:
* load via `UA_Server_loadPubSubConfigFromByteString`;
* `comparePubSubModelToConfig2` (counts, names, every mapped field —
  explicitly including the fields from the §1.4 gap table);
* state checks: with all-enabled fixture on a running server, connection/WG/
  DSW reach `Operational` (readers `PreOperational` until first message);
  disabled elements stay `Disabled`; parent-disabled ⇒ children `Paused`;
* namespace remapping: fixture namespaces in different order than server
  NamespaceArray ⇒ target/published NodeIds remapped correctly;
* reload/replace: loading fixture B over fixture A fully replaces (old
  components gone, no leaked NS0 nodes);
* NS0 mirror (information model on): browse
  `PublishSubscribe` → connection object exists with correct
  `PublisherId`/`TransportProfileUri`, WG `PublishingInterval`, DSW
  `DataSetWriterId`, RG/DSR nodes, PDS under `PublishedDataSets`, SSDS under
  `SubscribedDataSets`, and `Status.State` values match the internal states;
* legacy fixture loads identically to before (regression with existing .bin).

### 4.3 `check_pubsub_config2_save.c` — export & config→model→config

* Build a server config via the C API (mirror of fixtureFull), export via
  `UA_Server_writePubSubConfigurationToByteString`, decode, compare to the
  expected Config2 (incl. `enabled` flags and top-level fields).
* Round trip: export server 1 → load into fresh server 2 →
  `comparePubSubModelToConfig2(server2, exported)`; export server 2 again and
  compare the two exported configs for equality (idempotence).
* `ConfigurationVersion` present and monotonic across a config change.

### 4.4 `check_pubsub_config2_filetype.c` — FileType surface (NS0)

Call methods via the internal call service (pattern from
`check_pubsub_informationmodel_methods.c`):
* type/instance sanity: `PubSubConfiguration` node has FileType children +
  ReserveIds + CloseAndUpdate, HasTypeDefinition = PubSubConfigurationType;
* Open(Read) → Size correct, chunked Read reassembles exactly the export from
  4.3; GetPosition/SetPosition; Close; OpenCount tracks handles;
* mode matrix: 0x01/0x03/0x06 ok; 0x02 (write w/o erase), 0x04, 0x08 masks ⇒
  `Bad_InvalidArgument`/`Bad_NotSupported`; second Open with write while a
  writer is active ⇒ rejected; parallel readers ok; read on write-only handle
  ⇒ `Bad_InvalidState`;
* Write + plain Close ⇒ configuration unchanged (deep compare);
* stale/invalid handle ⇒ `Bad_InvalidArgument`;
* handle cleanup on session close (close session with open handle, verify
  OpenCount drops and a new exclusive write open succeeds);
* CloseAndUpdate on a read-only handle ⇒ `Bad_InvalidState`; with garbage
  buffer ⇒ `Bad_TypeMismatch`; with empty refs ⇒ `Bad_NothingToDo`.

### 4.5 `check_pubsub_config2_incremental.c` — CloseAndUpdate element ops

Each test: preload a base fixture, apply one update file + refs (via the C API
`UA_Server_updatePubSubConfig2` for precision, plus at least one end-to-end
run through the NS0 method), then verify the **updated model** with the deep
compare against the expected post-state, and verify the outputs
(`ChangesApplied`, `ReferencesResults`, `ConfigurationValues`,
`ConfigurationObjects` NodeIds resolve to the right nodes):

* **Add**: connection; WG under existing connection (parent by name, parent
  fields ignored); DSW (PDS linked by `dataSetName`); RG; DSR; PDS; SSDS.
  Auto-assignment: null name ⇒ generated; 0 WriterGroupId/DataSetWriterId ⇒
  assigned from the session's ReserveIds reservation; null PublisherId ⇒
  transport default — all reported in `ConfigurationValues`.
  Duplicate name ⇒ `Bad_BrowseNameDuplicated`; missing parent ⇒
  `Bad_NotFound`.
* **Match**: exact-match connection/WG/RG succeeds (returns existing element's
  values); mismatch ⇒ `Bad_NoMatch`; Match on writer/reader/PDS ⇒
  `Bad_InvalidArgument`; Match+Add uses existing when present, adds when not;
  Match on WG with active GroupHeader ⇒ `Bad_InvalidState`;
  properties compared only for provided entries.
* **Modify**: WG publishingInterval + DSW contentMask + DSR
  messageReceiveTimeout; unknown name ⇒ `Bad_NoMatch`; state preserved
  (Operational before ⇒ Operational after, verified via stateChangeCallback
  trace Disabled→Operational or no-op depending on implementation choice B2).
* **Remove**: connection removes its groups/writers/readers (NS0 nodes gone
  too); remove+add same name in one call works (remove-first ordering);
  unknown name ⇒ `Bad_NoMatch`.
* **Mask validation**: multiple op bits, multiple reference bits, no
  reference bit, index out of range ⇒ `Bad_InvalidArgument` per element.
* **Atomicity**: `RequireCompleteUpdate=true` with one bad ref among good ones
  ⇒ `ChangesApplied=false`, model bit-identical (deep compare before/after);
  `=false` ⇒ good refs applied, bad refs reported individually.
* **Top-level semantics**: `Enabled` in file ignored (manager state
  unchanged); `ConfigurationProperties` insert/replace/delete-by-null;
  `DefaultSecurityKeyServices` replaced only when non-empty;
  `ConfigurationVersion` updated to ~now (tolerance window) only on success.
* **SKS build**: add/remove SecurityGroup element ops; key storage
  created/removed accordingly. PushTarget refs ⇒ documented unsupported code.

### 4.6 `check_pubsub_config2_state.c` — state machine interaction

* Load enabled fixture on a **stopped** server component ⇒ everything
  `Paused`; start server ⇒ cascade to `Operational` (pubSubInitialSetupMode
  path).
* Root Disable (`PublishSubscribe.Status.Disable`) then CloseAndUpdate-add an
  enabled WG ⇒ new WG `Paused`; root Enable ⇒ `Operational`.
* Modify of a running WG: verify publish callback keeps running afterwards
  (subscribe to the socket like `check_pubsub_publish.c` or use
  `UA_Server_getWriterGroupState`), and GroupVersion/sequence behavior sane.
* Remove of an Operational connection mid-publish: clean disable, no crash,
  no leaked sockets (valgrind), `UA_PubSubManager_setState` reaches STOPPED on
  shutdown.
* Callbacks: `componentLifecycleCallback` add/remove invocations for every
  element op (count + component types), veto (return Bad) blocks the op with
  that status in `ReferencesResults`; `beforeStateChangeCallback` /
  `stateChangeCallback` fire for state transitions triggered by the update;
  components with `customStateMachine` (pattern from
  `check_pubsub_custom_state_machine.c`) survive a config load and element
  ops without the default socket handling kicking in.
* DSR `PreOperational→Operational` on first received key frame still works
  for a reader created through the file path (loopback pub/sub like
  `check_pubsub_subscribe.c`).

### 4.7 ReserveIds (extend `check_pubsub_informationmodel_methods.c`)

* Reserve N WG-ids + M DSW-ids ⇒ all in 0x8000..0xFFFF, unique, not colliding
  with ids already used in the loaded fixture;
* reserved id honored by a subsequent CloseAndUpdate Add from the same
  session; a different session's CloseAndUpdate does not consume it;
* session close releases reservations;
* invalid transport profile ⇒ `Bad_InvalidArgument`; exhaustion ⇒
  `Bad_ResourceUnavailable` (constructible with a small artificial cap or
  documented as not-tested);
* `DefaultPublisherId` output type matches profile.

### 4.8 Regression & robustness

* Existing suites must stay green — especially `check_pubsub_configuration.c`
  (legacy .bin loading), `check_pubsub_informationmodel*.c`,
  `check_pubsub_custom_state_machine.c`, `check_pubsub_get_state.c`.
* Fuzzing: add the file-decode entry point to `tests/fuzz` corpus
  (ByteString → load on an ephemeral server) to harden the decoder against
  malformed files.
* Memory: every new test runs under the valgrind CI target; failure paths of
  each element op explicitly exercised at least once (they historically leak).

### Acceptance criteria

1. A third-party OPC UA client can read the full configuration through the
   `PubSubConfiguration` FileType object and apply an incremental update via
   `Write`+`CloseAndUpdate`, per Part 14 v1.05 §9.1.3.7.
2. `fixtureFull` load → export → load round trip is lossless
   (deep-compare equality).
3. All CloseAndUpdate element/method result codes from Tables in 9.1.3.7.6
   are produced in the situations the spec defines.
4. No regressions in the existing PubSub test suite; valgrind-clean.
