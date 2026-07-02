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

Verified green (2026-07-02): `check_pubsub_configuration` (legacy .bin loading
through the NEW converter path), `check_pubsub_informationmodel`,
`check_pubsub_informationmodel_methods`, `check_pubsub_publish`,
`check_pubsub_subscribe`, `check_pubsub_custom_state_machine`,
`check_pubsub_get_state`, `check_pubsub_pds`. A full `ctest -R pubsub` sweep
was started but not finished — run it first.

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

1. **Full regression**: `ctest -R pubsub` in `build-config2`; also build a
   non-FILE_CONFIG and a MINIMAL-NS0 configuration to catch gating issues.
2. **M2 test**: new `tests/pubsub/check_pubsub_config2.c` (register in
   `tests/CMakeLists.txt` under `UA_ENABLE_PUBSUB_FILE_CONFIG`): build config
   via C API on server A → `UA_Server_writePubSubConfigurationToByteString` →
   load into server B → compare (counts/names/fields/enabled). Then the
   fixture-based suites from plan §4 (4.1–4.3). Watch out in the round-trip
   compare: `configurationVersion` differs by design.
3. **M2 gap closure**: extend the internal config structs for the `TODO
   Part14` fields (plan §1.4) incl. `_copy`/`_clear` updates in the component
   files, then wire them in both converter directions.
4. **M3 (Phase B)**: incremental engine `ua_pubsub_config_update.c` —
   `UA_Server_updatePubSubConfig2(server, cfg, refs, requireCompleteUpdate,
   &result)` implementing the CloseAndUpdate element ops (plan §3 Phase B has
   the full op semantics; removes first; per-ref status codes from Part 14
   9.1.3.7.6). Testable without NS0.
5. **M4 (Phase C)**: FileType front-end — un-comment/extend nodes in
   `tools/schema/Opc.Ua.NodeSet2.PubSubMinimal.xml` (PubSubConfigurationType
   i=25482, instance children i=25452..25479 of the PubSubConfiguration object
   i=25451 — currently everything except ReserveIds i=25474 is commented out),
   per-session file handles modeled on the GDS TrustList implementation in
   `src/server/ua_server_ns0_gds.c` (`UA_FileContext`/`UA_FileInfo`/
   `checkSessionActive`), method callbacks wired in `initPubSubNS0()`
   (`ua_pubsub_ns0.c` ≈ line 2348, next to the existing ReserveIds binding).

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
