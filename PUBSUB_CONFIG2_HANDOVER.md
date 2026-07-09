# Handover: PubSubConfiguration2 implementation — working state

Companion to `PUBSUB_CONFIG2_PLAN.md` (read that first — it contains the full
as-is analysis, the target behavior per OPC 10000-14 v1.05.06, the phased
implementation plan and the complete test plan). This document captures the
concrete working state so an independent agent can continue without re-deriving
context.

Branch: `feat_pubsub_config2`. The OPC UA Part 14 spec as markdown is expected
at the repo root as `OPC-10000-14-v1.05.06.md` (NOT committed — copyrighted
OPC Foundation material; obtain/place it locally). Key spec locations in that
file: PubSubState state machine ≈ line 753, PubSubConfiguration2DataType
≈ line 2339, PubSubConfigurationType/RefMask/RefDataType/ReserveIds/
CloseAndUpdate ≈ lines 6289–6535.

## Build & test setup (working)

```sh
cmake -S . -B build-config2 -DCMAKE_BUILD_TYPE=Debug -DUA_ENABLE_PUBSUB=ON \
  -DUA_ENABLE_PUBSUB_INFORMATIONMODEL=ON -DUA_ENABLE_PUBSUB_FILE_CONFIG=ON \
  -DUA_ENABLE_JSON_ENCODING=ON -DUA_NAMESPACE_ZERO=REDUCED \
  -DUA_BUILD_UNIT_TESTS=ON -DUA_FORCE_WERROR=ON
cmake --build build-config2 -j $(nproc)
cd build-config2 && ctest -R pubsub --output-on-failure
```

Full `ctest -R pubsub` sweep (2026-07-03): 18/21 green including the new
`check_pubsub_config2`. The 3 failures are **pre-existing environment
failures** (verified identical on the committed tree without the working-tree
changes): `check_pubsub_subscribe_msgrcvtimeout` (loopback multicast timing,
WSL), `check_pubsub_connection_ethernet` (no raw ethernet interface),
`check_pubsub_informationmodel_methods` (env/timing: ReserveIds id-sequence
and state-reading asserts). Do not chase these on this machine.

Gating verified (2026-07-03): library builds with
`UA_ENABLE_PUBSUB_FILE_CONFIG=OFF` and with `UA_ENABLE_JSON_ENCODING=OFF`
(+`UA_ENABLE_SUBSCRIPTIONS_EVENTS=OFF`, which unconditionally requires JSON —
unrelated to pubsub). Note: this machine lacks `libcrypt`, so the full test
suite build fails at link for `check_server_password` — build tests with
`make -k` or per-target.

## What was changed (all committed on this branch)

### New: `src/pubsub/ua_pubsub_config_map.c` (+ decls in `ua_pubsub_internal.h`)

Bidirectional mapping between Part 14 DataTypes and internal `UA_*Config`:

* `_fromDataType` (Connection, WriterGroup, DataSetWriter, ReaderGroup,
  DataSetReader, PublishedDataSet, DataSetField, SubscribedDataSet/SSDS):
  **borrowing views** — no allocation, valid only while the source DataType
  lives; the `UA_*_create` functions deep-copy internally. Exception:
  PublisherId (allocates for String) ⇒ use `UA_PubSubConnectionConfig_clearView`
  / `UA_DataSetReaderConfig_clearView`, never the regular `_clear`.
  DSR mapping handles TargetVariables inline, StandaloneSubscribedDataSetRef
  (→ `linkedStandaloneSubscribedDataSetName`), rejects Mirror with
  `BADNOTIMPLEMENTED`. WriterGroup: JSON encoding detected from
  JsonWriterGroupMessageDataType; `maxEncapsulatedDataSetMessageCount = 255`
  (non-std default, matches old file loader).
* `_toDataType` (same set; PDS variant takes the **component**
  `UA_PublishedDataSet*` because export needs the internal metadata + field
  list): deep copies. `dst->enabled` is set by the **caller** from
  `UA_PubSubState_isEnabled(head.state)`.
* Fields with no internal storage yet are marked `TODO Part14` in the code:
  WG maxNetworkMessageSize/localeIds/headerLayoutUri/securityKeyServices;
  RG maxNetworkMessageSize/messageSettings/securityKeyServices;
  DSR keyFrameCount/headerLayoutUri/securityMode/securityGroupId/
  securityKeyServices/dataSetReaderProperties; PDS dataSetFolder/
  extensionFields. Closing these needs internal config struct extensions
  (plan §1.4, Phase A1/M2+).

### Rewritten: `src/pubsub/ua_pubsub_config.c`

* Load path (`UA_Server_loadPubSubConfigFromByteString`):
  * `extractPubSubConfig2FromExtensionObject` accepts
    `PubSubConfiguration2DataType` **and** legacy `PubSubConfigurationDataType`
    (legacy is upgraded into a Config2 *view*); wrong body ⇒
    `BADTYPEMISMATCH`.
  * `remapNamespaces`: file `namespaces[i]` ↔ body namespace index `i+1`
    (ns0 skipped, Part 14 Table 88); unknown URIs are **added** to the server
    via internal `addNamespace()`; identity map short-circuits; indices beyond
    the array are left unchanged. Remaps: published variables + metadata
    dataType NodeIds (only when the metadata has no own namespaces table),
    KeyValuePair keys, TargetVariables targetNodeIds, SSDS.
  * Creation via the converter module; SSDS created **before** connections
    (readers link by name via `connectDSR2Standalone` inside
    `UA_DataSetReader_create`); DSW finds PDS via
    `UA_PublishedDataSet_findByName`, empty `dataSetName` = heartbeat writer
    (NULL PDS, keyFrameCount must be 1 — enforced by writer.c).
  * Two-phase enable preserved: everything created with `enabled=false`, the
    flag is then written directly into the live component's config
    (`comp->config.enabled = <file value>`, no state machine call), finally
    `psm->pubSubInitialSetupMode = true` + manager start cascades the enable.
    Child creation errors now **abort** the load (old code silently skipped).
  * Top-level metadata stored in the manager; `configurationVersion` set to
    current time (file value ignored, per CloseAndUpdate semantics);
    SecurityGroups/PushTargets warn-ignored (SKS mapping = Phase B/M3+).
* Export path (M2, **compiles but untested**):
  `generatePubSubConfiguration2DataType` walks the manager (PDS, connections
  with groups/writers/readers, SSDS, top-level fields; `enabled` from live
  states, root enabled = manager STARTED). `encodePubSubConfiguration2` wraps
  in UABinaryFileDataType with `namespaces = server->namespaces[1..]`
  (borrowed, only encoded). `UA_Server_writePubSubConfigurationToByteString`
  now emits **Config2** (breaking change vs 1.4 — CHANGES.md entry still TODO).
  New public API `UA_Server_getPubSubConfig2` (deep copy out).

### Modified: `src/pubsub/ua_pubsub_internal.h`

* Converter declarations (section "Configuration DataType Mapping").
* `UA_SubscribedDataSet_create` exposed (was static `addSubscribedDataSet` in
  `ua_pubsub_dataset.c`; public `UA_Server_addSubscribedDataSet` now calls it).
* `UA_PubSubManager` gained: `UA_UInt32 configurationVersion`,
  `UA_KeyValueMap configurationProperties`,
  `UA_EndpointDescription *defaultSecurityKeyServices` (+size).
  Cleared in `UA_PubSubManager_clear` (ua_pubsub_manager.c).

### Modified: `src/pubsub/ua_pubsub_manager.c`

* `UA_PubSubManager_setState`: in `pubSubInitialSetupMode` connections are
  pushed to OPERATIONAL **only if `c->config.enabled`** (was: all connections —
  bug that enabled explicitly disabled connections on config load).
* Metadata cleanup in `UA_PubSubManager_clear`.

### Modified: `CMakeLists.txt`

* `ua_pubsub_config_map.c` added to the pubsub sources (always compiled with
  `UA_ENABLE_PUBSUB`, not gated on FILE_CONFIG — intended for later reuse by
  the NS0 Add* methods which currently duplicate lossy mappings in
  `ua_pubsub_ns0.c`, see plan Phase A1).

## Immediate next steps (in order)

1. ~~Full regression~~ DONE 2026-07-03 (see above).
2. ~~M2 test~~ DONE 2026-07-03: `tests/pubsub/check_pubsub_config2.c`
   (registered under `UA_ENABLE_PUBSUB_FILE_CONFIG`). Tests: getPubSubConfig2
   snapshot, export→load→export round trip A→B with deep compare
   (`compareConfig2`, excludes `configurationVersion` by design), mixed
   enabled flags (disabled connection stays disabled — covers the
   `pubSubInitialSetupMode` fix), namespace remapping (unknown ns auto-added
   at a different index, published-variable NodeId remapped), invalid body
   (garbage + wrong body type ⇒ `BADTYPEMISMATCH`, nothing created).
   Fixed on the way: DSR `publisherId` missing in
   `UA_DataSetReaderConfig_fromDataType` (empty Variant tolerated ⇒ Byte 0);
   DSW export `dataSetName` fallback to connected PDS name (API-built configs
   have it empty; empty means heartbeat on load).
   Note: top-level `enabled` in the export mirrors the PubSubManager
   lifecycle, which is STARTED right after `UA_Server_run_startup` — so
   exports from a running server always have `enabled=true` at the root.
3. ~~M2 gap closure~~ DONE 2026-07-03: internal config structs extended
   (public header `server_pubsub.h`) — WG maxNetworkMessageSize/
   headerLayoutUri/localeIds/securityKeyServices; RG messageSettings/
   maxNetworkMessageSize/securityKeyServices; DSR keyFrameCount/
   headerLayoutUri/securityMode/securityGroupId/securityKeyServices/
   dataSetReaderProperties; PDS dataSetFolder/extensionFields; SSDS
   dataSetFolder. All are **storage-only** (documented in the header):
   the runtime does not enforce maxNetworkMessageSize, publish extension
   fields, or evaluate reader security fields yet. `_copy`/`_clear` updated
   in ua_pubsub_writergroup.c/ua_pubsub_readergroup.c/ua_pubsub_reader.c/
   ua_pubsub_dataset.c; both converter directions wired; round-trip asserts
   extended in `check_pubsub_config2.c`. Remaining known mapping loss:
   PDS DataSetMetaData description/dataSetClassId (metadata is rebuilt from
   field configs — see `TODO Part14` in ua_pubsub_config_map.c);
   SecurityGroups export (SKS) still TODO in ua_pubsub_config.c.
4. ~~M3 (Phase B)~~ DONE 2026-07-06: `src/pubsub/ua_pubsub_config_update.c`
   with `UA_Server_updatePubSubConfig2` + `UA_PubSubConfigUpdateResult`
   (public API in server_pubsub.h under FILE_CONFIG). Facts for follow-up
   work:
   * Public `UA_Server_update*Config` functions were refactored into
     internal `UA_PubSubConnection_updateConfig` / `UA_WriterGroup_...` /
     `UA_ReaderGroup_...` / `UA_DataSetWriter_...` / `UA_DataSetReader_...`
     (psm + component pointer, lock held) — use these from NS0 callbacks.
   * Writer/reader add/remove/update require the parent group DISABLED —
     the engine wraps those ops with disable/restore of the group (children
     of a disabled parent are PAUSED, which still counts as "enabled", so
     the component itself is disabled for modify).
   * The converters (`_fromDataType`) now accept DECODED **and**
     DECODED_NODELETE ExtensionObjects and tolerate an empty PublisherId
     variant (default Byte 0) — needed for in-code update files.
   * `UA_ReserveId_isFree` is exposed internally for the id auto-assignment
     (range 0x8000+, per transport profile, respects session reservations).
   * Unsupported (documented in the file header): SecurityGroup/PushTarget
     refs (`Bad_ResourceUnavailable`), PDS/SSDS modify (`Bad_NotImplemented`),
     rollback of apply-phase failures with requireCompleteUpdate.
   * Tests: `tests/pubsub/check_pubsub_config2_incremental.c` — note the
     multicast validate-connect works on 4801 in this environment.
5. ~~M4 (Phase C)~~ DONE 2026-07-06. Facts for follow-up work:
   * Nodeset: instance nodes extracted from the official UA-Nodeset
     `latest` branch (raw.githubusercontent.com/OPCFoundation/UA-Nodeset/
     latest/Schema/Opc.Ua.NodeSet2.xml — the repo has no local copy;
     RolePermissions stripped, style matched). PubSubConfigurationType
     i=25482 is subtyped to BaseObjectType i=58 in the REDUCED nodeset
     (FileType i=11575 not present there) — documented deviation.
   * `ua_pubsub_ns0_config2.c` (gated INFORMATIONMODEL && FILE_CONFIG)
     implements the 7 method callbacks; the file-handle bookkeeping
     (`UA_PubSubFileContext`, remove/clear) lives in ua_pubsub_config.c so
     `UA_PubSubManager_clear` works without the information model.
   * Internal helpers: `UA_PubSubManager_encodeConfig2Blob` /
     `_decodeConfig2Blob` (decode gives a borrowing view + namespace remap;
     clear the ExtensionObject afterwards) / `_updateConfig2` (the engine,
     lock held).
   * Session cleanup: repeated callback (10s) closes handles of ended
     sessions; removed automatically when no handles remain.
   * Tests: `check_pubsub_config2_filetype.c` uses `UA_Server_call` — all
     handles belong to the admin session, so the session-cleanup path is
     not covered by it.
6. ~~M5 (partial: C4, C6, §4.6, Phase E)~~ DONE 2026-07-07. Facts:
   * LastModifiedTime (i=25458) is hand-authored in PubSubMinimal.xml — the
     official nodeset does NOT instantiate this optional FileType property,
     only the NodeIds.csv define exists. Updated on successful
     CloseAndUpdate, 0 before the first update.
    * `UA_ENABLE_PUBSUB_FILE_CONFIG_LEGACY_METHODS` and the two vendor
      method nodes + their callbacks in ua_pubsub_ns0.c have been removed
      (clean cut): only the standard PubSubConfiguration FileType object
      (Part 14 v1.05, 9.1.3.7) is supported now. The ByteString load/save
      C API (UA_Server_loadPubSubConfigFromByteString /
      UA_Server_writePubSubConfigurationToByteString) is retained.
   * Engine fix from §4.6 testing: `applyRemove` for connections disables
     first and maps the deferred-deletion BADINTERNALERROR (open channels,
     deleteFlag set, freed on later EL iterations) to GOOD. Note for tests:
     removed WGs/connections can linger in the component lists until the
     EventLoop unlinks them — compare by name/flag, not by count, and
     iterate before asserting.
   * componentLifecycleCallback caveat: a veto (bad return) on REMOVE also
     blocks the compensating removal inside a vetoed CREATE, orphaning the
     half-created component — application callbacks should only veto
     creations (documented in check_pubsub_config2_state.c).
   * The examples were verified end-to-end: server_pubsub_file_configuration
     (fixed argv[2]->argv[1] bug + ByteString leak) + new
     client_pubsub_config2_update read the config over the network, applied
     CloseAndUpdate (ChangesApplied=true) and saw the added connection.
   * Still open: §4.1 fuzz corpus, §4.7/4.8 additions, Phase D CI variants,
     C5 access control, SKS SecurityGroup element ops, PDS/SSDS modify.

## Facts that save you time

* All Config2-related C types are **already generated** even with
  `UA_NAMESPACE_ZERO=REDUCED`: `UA_TYPES_PUBSUBCONFIGURATION2DATATYPE`,
  `..._PUBSUBCONFIGURATIONREFMASK/REFDATATYPE/VALUEDATATYPE`,
  `..._SECURITYGROUPDATATYPE`, `..._PUBSUBKEYPUSHTARGETDATATYPE`,
  `..._STANDALONESUBSCRIBEDDATASETDATATYPE/REFDATATYPE`,
  `..._UABINARYFILEDATATYPE`, `..._ENDPOINTDESCRIPTION`. All
  `UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_*` defines exist; the NODES
  are what is missing (M4).
* ReserveIds is implemented and session-scoped
  (`UA_PubSubManager_reserveIds`, range 0x8000+, freed on session close);
  NS0-bound at `PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_RESERVEIDS`.
* State machine: components are "enabled" unless DISABLED/ERROR; parents
  re-trigger children with the child's current state as target;
  `transientState` suppresses nested notifications. Root PublishSubscribe
  state = PubSubManager lifecycle (STARTED→Operational shown in NS0).
  `UA_*Config.enabled` means "auto-enable at creation" — `UA_WriterGroup_create`
  etc. immediately call setPubSubState(OPERATIONAL) if set; that's why the
  file loader creates everything disabled and flips the flags afterwards.
* `UA_DataSetReaderConfig_copy` deep-copies TargetVariables and the SSDS link
  name; `UA_DataSetReader_create` does info-model representation, SSDS
  connect and config validation — do NOT call
  `DataSetReader_createTargetVariables` separately when the targets are
  already in the config.
* Legacy test fixtures `tests/pubsub/check_publisher_configuration.bin` /
  `check_subscriber_configuration.bin` contain legacy-body files; they load
  through the new path (backward-compat guard). ctest runs tests with the
  right CWD — running test binaries manually from `bin/tests` breaks their
  relative fixture paths.
* `deps/mdnsd` shows as locally modified (submodule pointer, pre-existing) —
  do not commit it as part of this work.
