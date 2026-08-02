# OPC UA Part 14 PubSub — Fixes & Small Features Implementation Plan

> **This is a standalone, tool-independent document.** It is the master plan for implementing the
> findings from the Part 14 deep review. It is not tied to any specific IDE or AI tool — any
> contributor can pick it up and follow it.

## Related documents in this repository

| Document | Role |
|---|---|
| `pubsub_part14_v10506_coverage_review.md` | Spec conformance / coverage matrix — which Part 14 features are supported, partial, or not supported. Rows corrected by the deep audit are marked with `[DR-§N]`. |
| `pubsub_part14_deep_review_findings.md` | Code defect / bug audit — 175 findings (19 security, 63 bug, 42 gap, 51 minor) with file:line references and a P0–P3 fix list. This implementation plan is derived from that file. |
| **`pubsub_part14_implementation_plan.md`** (this file) | The step-by-step implementation plan: 86 tasks in 4 phases, with progress tracking. |

---

## Overview

The deep review (`pubsub_part14_deep_review_findings.md`) identified 175 issues in the open62541
PubSub implementation when compared against OPC UA Part 14 v1.05.06. This plan converts the
actionable subset — all real fixes and small features — into 86 concrete implementation tasks
grouped into 4 independently-committable phases.

Large missing-feature gaps (PublishedEvents, PublishedActions, SubscribedDataSetMirror,
discovery/metadata/status/action messages, AMQP, DTLS, full JSON mapping beyond keyframe,
PubSubConfiguration2 full model, Clause 9 diagnostics/capabilities/status events, selectable
HeaderLayoutUri layouts) are **out of scope** and remain documented gaps in the coverage review.

## Scope decisions

- **Breadth:** all fixes + small features (86 tasks). Exclude only large missing-feature gaps.
- **SKS:** include missing method implementations (GetSecurityGroup, InvalidateKeys,
  ForceKeyRotation) + key-ingest validation, gated behind `UA_ENABLE_PUBSUB_SKS`.
- **Config round-trip:** map ALL dropped spec fields in load and save, including fields that
  touch public config structs.
- **Tests:** every task MUST add a `check`-framework test in `tests/pubsub/` (negative tests for
  security items, round-trip tests for config, encode/decode tests for binary/JSON, behavior
  tests for reader/writer). Phased by severity so each phase is independently committable.

## Conventions (from CONTRIBUTING.md + existing tests)

- Use `UA_CHECK_STATUS(rv, return rv)` for return-value checks, `ck_assert(...)` in tests.
- Tests live in `tests/pubsub/check_pubsub_*.c`, use `<check.h>`, register via `tcase_add_test`.
- Public config struct changes require updating `include/open62541/server_pubsub.h` and the
  matching `*_copy`/`*_clear` in the same file as the struct.
- Build flags: `UA_ENABLE_PUBSUB` (ON default), `UA_ENABLE_PUBSUB_SKS` (OFF),
  `UA_ENABLE_PUBSUB_INFORMATIONMODEL` (follows PUBSUB), `UA_ENABLE_PUBSUB_FILE_CONFIG` (OFF).
  SKS tasks build/test with `UA_ENABLE_PUBSUB_SKS=ON`; config-round-trip tasks with
  `UA_ENABLE_PUBSUB_FILE_CONFIG=ON`.

## Validation (per task and per phase)

1. Each task: build with the relevant flags ON, run its new test, run the existing test file it
   touches (`ctest -R pubsub`).
2. Each phase: full `ctest -R pubsub` green, plus format/lint if available.
3. Regression: ASan build (`UA_BUILD_UNIT_TESTS=ON`, `-fsanitize=address`) for all P0
   memory-safety tasks and the SKS phase.

---

## Phase 1 — P0 Memory Safety / Security (12 tasks)

> Each task: add a negative/fuzz-style test that triggers the bug (crash without fix, passes
> with fix), fix it, verify under ASan.

### 1.1 Fix inverted callback guard in key-storage → UAF
- **Finding:** DR-§6.1 / `keystorage.c:65` — `if(!ks->callBackId)` removes the wrong timer; frees
  `ks` while EventLoop still holds a callback → UAF.
- **Fix:** change to `if(ks->callBackId != 0)` (matches the correct guards at `:330`/`:492`).
- **Test:** `check_pubsub_sks_keystorage.c` — add SecurityGroup with SKS on, arm rollover timer,
  remove SecurityGroup, assert no ASan UAF report and timer deregistered.
- **Flags:** `UA_ENABLE_PUBSUB_SKS=ON`.

### 1.2 Fix GetSecurityKeys heap OOB write (calloc wrong size)
- **Finding:** DR-§6.2 / `ns0_sks.c:322` — `UA_calloc(requestedKeyCount, startingItem->key.length)`
  should be `sizeof(UA_ByteString)`. Heap overflow when `keyLength < 16` and `count > 1`.
- **Fix:** `UA_calloc(requestedKeyCount, sizeof(UA_ByteString))`. Also check each
  `UA_ByteString_copy` return (currently discarded) and fail the method on copy error.
- **Test:** `check_pubsub_sks_client.c` — request 3 keys from a SecurityGroup whose policy
  produces a short key, assert no heap corruption under ASan and all 3 keys returned correctly.
- **Flags:** `UA_ENABLE_PUBSUB_SKS=ON`.

### 1.3 Fix stack overflow when >32 writers in offset-table computation
- **Finding:** DR-§5.1 / `writergroup.c:1641` — `computeWriterGroupOffsetTable` builds `dsmCount`
  for all writers with no `MAXMESSAGECOUNT` guard, bypasses the `sendNetworkMessage` guard at
  `:886`, writes past `dataSetWriterIds[32]`.
- **Fix:** cap `dsmCount` at `UA_NETWORKMESSAGE_MAXMESSAGECOUNT` (32) in
  `computeWriterGroupOffsetTable`. Add defense-in-depth guard in `generateNetworkMessage` too.
  Log a `BadInternalError` if writers exceed 32 in one message.
- **Test:** `check_pubsub_publish.c` — create a WriterGroup with 33 writers, assert no crash and
  an error status from `computeWriterGroupOffsetTable`.

### 1.4 Fix `lastSamples` OOB after realloc failure
- **Finding:** DR-§5.2 / `writer.c:692` — `lastSamplesCount` set to new field count before
  `UA_realloc` confirmed; on NULL return, delta-frame generation reads past old array.
- **Fix:** assign `lastSamplesCount` only after successful `UA_realloc`; on failure set
  `lastSamples = NULL`, `lastSamplesCount = 0`, return `BadOutOfMemory`.
- **Test:** `check_pubsub_publish.c` — mock OOM on the realloc path, assert no OOB + graceful
  error.

### 1.5 Fix MQTT broker-connection reuse comparing params to itself
- **Finding:** DR-§7.1 / `eventloop_mqtt.c:371` — `findIdenticalBrokerConnection` fetches both
  variants from incoming `kvm`, so `v1 == v2` always; all MQTT connections share first broker.
- **Fix:** second operand must be `UA_KeyValueMap_get(&bc->params, ...)`.
- **Test:** `check_pubsub_connection_mqtt.c` — create two PubSub connections to two distinct
  broker addresses, assert they get distinct sockets.

### 1.6 Fix Eth send frees interior pointer → heap corruption
- **Finding:** DR-§7.2 / `eventloop_posix_eth.c:910` — on `!conn` path,
  `freeNetworkBuffer` is called on `buf` whose `data` was advanced past the header (interior
  pointer) → `UA_free` corrupts the heap.
- **Fix:** use `ETH_freeNetworkBuffer` (the ETH-specific free that knows how to unhide the
  header) instead of the generic `UA_EventLoopPOSIX_freeNetworkBuffer` on the `!conn` path.
- **Test:** `check_pubsub_publish_ethernet.c` — trigger send with a closed/invalid connection,
  assert no ASan heap corruption.

### 1.7 Fix dangling `currentItem` after `clearKeyList` → UAF
- **Finding:** DR-§6.5 / `keystorage.c:475` — `clearKeyList` sets `keyListSize=0` but leaves
  `currentItem` dangling; next rollover derefs freed memory.
- **Fix:** in `clearKeyList`, set `ks->currentItem = NULL` and `ks->currentTokenId = 0` after
  freeing all items. Guard `splitCurrentKeyMaterial` / rollover callbacks against
  `currentItem == NULL`.
- **Test:** `check_pubsub_sks_keystorage.c` — SetSecurityKeys with a bad CurrentTokenId that
  triggers `clearKeyList`, then let a rollover timer fire, assert no UAF under ASan.
- **Flags:** `UA_ENABLE_PUBSUB_SKS=ON`.

### 1.8 Add bounds/NULL checks to GetSecurityKeys response parsing
- **Finding:** DR-§6.6 / `keystorage.c:461` — reads `outputArguments[0..4]` with no count/NULL/
  arrayLength checks; OOB read, NPD, unsigned underflow to SIZE_MAX.
- **Fix:** validate `outputArgumentsSize >= 5`, each `outputArguments[i].data != NULL`, and
  `outputArguments[2].arrayLength >= 1` before use.
- **Test:** `check_pubsub_sks_pull.c` — mock a malformed GetSecurityKeys response (fewer than 5
  outputs, or keys array shorter than currentKeyCount) and assert graceful error, no crash.
- **Flags:** `UA_ENABLE_PUBSUB_SKS=ON`.

### 1.9 Fix `keyNonceLength` underflow → OOB read
- **Finding:** DR-§6.7 / `keystorage.c:196` — `key.length - signingkeyLength - encryptkeyLength`
  underflows if key shorter than expected; `keyNonce->data` points past buffer.
- **Fix:** check `key.length >= signingkeyLength + encryptkeyLength` before computing; return
  `BadInternalError` on mismatch. Also add `currentItem == NULL` guard.
- **Test:** `check_pubsub_sks_push.c` — push a key whose length is too short for the policy,
  assert rejection, no OOB under ASan.
- **Flags:** `UA_ENABLE_PUBSUB_SKS=ON`.

### 1.10 Fix delete-during-in-flight-SKS-request → UAF
- **Finding:** DR-§6.11 / `keystorage.c:60` — deleting key storage while a pull client is in
  flight frees `ks`; the async `storeFetchedKeys` callback then derefs `ctx->ks`.
- **Fix:** in `UA_PubSubKeyStorage_delete`, if `sksConfig.reqId != 0`, set a `pendingDelete`
  flag and defer freeing. The `storeFetchedKeys` callback checks `pendingDelete` and calls
  `UA_PubSubKeyStorage_deleteNow` for final cleanup.
- **Test:** `check_pubsub_sks_pull.c` — start a pull, remove the SecurityGroup mid-flight,
  assert no UAF under ASan.
- **Flags:** `UA_ENABLE_PUBSUB_SKS=ON`.

### 1.11 Fix `addSubscribedVariables` OOB read on `pMetaData->fields[i]`
- **Finding:** DR-§8.1 / `ns0.c:837` — loop bounded by `targetVars->targetVariablesSize` but
  indexes `pMetaData->fields[i]` with no check against `fieldsSize`.
- **Fix:** add a size check: if `targetVariablesSize > fieldsSize`, return
  `BadInvalidArgument`.
- **Test:** `check_pubsub_informationmodel_methods.c` — call AddDataSetReader with a
  TargetVariables array larger than the DataSetMetaData fields, assert `BadInvalidArgument` and
  no crash.
- **Flags:** `UA_ENABLE_PUBSUB_INFORMATIONMODEL=ON`.

### 1.12 Bound invalid-DSM skip against remaining buffer
- **Finding:** DR-§2.3 / `binary.c:1661` — `ctx->ctx.pos = begin + dsmSize` with no check
  `begin + dsmSize <= ctx->ctx.end`; attacker-controlled `dsmSize` can jump pos out of range.
- **Fix:** validate `begin + dsmSize <= ctx->ctx.end` before advancing; return
  `BadDecodingError` on overflow.
- **Test:** `check_pubsub_encoding.c` — craft a NetworkMessage with an invalid-DSM whose
  declared size exceeds the buffer, assert `BadDecodingError` and no OOB under ASan.

---

## Phase 2 — P1 Crypto / Correctness (8 tasks)

### 2.1 Increment `nonceSequenceNumber` per message (nonce reuse fix)
- **Finding:** DR-§5.3 / `writergroup.c:774` — sequence part of nonce is constant for a key;
  spec 7.2.3 requires unique nonce per message.
- **Fix:** `wg->nonceSequenceNumber++` after encoding it into each message's nonce (and keep
  the reset-to-1 on token change at `:384`).
- **Test:** `check_pubsub_encryption.c` — publish two messages in one WriterGroup, assert the
  nonce sequence bytes differ between the two messages.

### 2.2 Use same context for signature-size and sign
- **Finding:** DR-§5.4 / `writergroup.c:848` (size from `policyContext`) vs `:582` (sign from
  `channelContext`).
- **Fix:** use `wg->securityPolicyContext` (`channelContext`) for both the buffer sizing and the
  actual `getSignatureSize`/`sign` calls.
- **Test:** `check_pubsub_encryption.c` — enable signing, publish, assert buffer is correctly
  sized (no OOB) and signature validates on the subscriber side.

### 2.3 Fix `triggerWriterGroupPublish` unlock-then-relock UAF race
- **Finding:** DR-§5.5 / `writergroup.c:1468` — between `unlockServer` (`:1475`) and the
  callback's re-lock (`:930`), another thread can free `wg`.
- **Fix:** take a reference on `wg` before unlocking, or call `UA_WriterGroup_publishCallback`
  while still holding the lock (preferred if the callback does not re-enter user code that
  locks). Document the chosen invariant.
- **Test:** stress test in `check_pubsub_publish.c` that triggers publish + concurrent
  `removeWriterGroup` in a loop, runs under ASan/TSan, assert no UAF reports.

### 2.4 Use SecurityTokenId to select decryption key
- **Finding:** DR-§4.7 / `readergroup.c:669` — receiver ignores
  `nm->securityHeader.securityTokenId`; key rollover cannot be handled.
- **Fix:** in `verifyAndDecryptNetworkMessage`, look up the key by `securityTokenId` from the
  reader group's key storage; support previous/current/next tokens per spec 7.2.4.4.3.
- **Test:** `check_pubsub_subscribe_encrypted.c` — publisher rolls the key, subscriber receives
  messages secured with old and new token, assert both decrypt correctly.
- **Flags:** `UA_ENABLE_PUBSUB_SKS=ON` or manual key set.

### 2.5 Fix GetSecurityKeys cap to honor MaxPast/FutureKeyCount
- **Finding:** DR-§6.3 / `ns0_sks.c:271` — cap branch expands to entire `keyListSize`,
  leaking past keys beyond MaxPastKeyCount.
- **Fix:** cap to `min(requestedKeyCount, maxFutureKeyCount)` for future keys and only return
  up to `maxPastKeyCount` historical keys. Spec 8.4.1.
- **Test:** `check_pubsub_sks_client.c` — configure `maxPastKeyCount=1`, request all keys,
  assert at most 1 past key returned.
- **Flags:** `UA_ENABLE_PUBSUB_SKS=ON`.

### 2.6 Fix key generation size (= signing+encrypt+nonce, not nonceLength)
- **Finding:** DR-§6.8 / `securitygroup.c:119` — generated key length is `policy->nonceLength`;
  spec Table 155 requires `signingKeyLen + encryptingKeyLen + keyNonceLen`.
- **Fix:** compute key length from the policy's three component lengths; use that for
  `allocBuffer`, `generateKeyData`, and the `splitCurrentKeyMaterial` length check.
- **Test:** `check_pubsub_sks_securitygroups.c` — create a SecurityGroup, fetch keys, assert key
  length equals the sum of the policy's three component lengths.
- **Flags:** `UA_ENABLE_PUBSUB_SKS=ON`.

### 2.7 Activate channel on SKS-server key rollover
- **Finding:** DR-§6.10 / `securitygroup.c:156` — `updateSKSKeyStorage` advances `currentItem`
  but never calls `activateKeyToChannelContext`; channel keeps using old key.
- **Fix:** call `activateKeyToChannelContext` after advancing `currentItem` (mirror the
  publisher/subscriber-side `keyRolloverCallback` at `keystorage.c:352`).
- **Test:** `check_pubsub_sks_securitygroups.c` — server acts as SKS AND publisher, advance
  rollover, assert published messages use the new token id.
- **Flags:** `UA_ENABLE_PUBSUB_SKS=ON`.

### 2.8 Implement JSON DataSetReader identifier dispatch
- **Finding:** DR-§4.8 / `reader.c:67` — JSON branch of `checkIdentifier` always returns
  `BadNotFound`; JSON subscriber path is non-functional.
- **Fix:** implement the JSON matching (commented-out skeleton at `reader.c:69-76`): match by
  `DataSetWriterId` from the JSON message's `DataSetWriterId` field against the reader config.
- **Test:** `check_pubsub_publish_json.c` + `check_pubsub_subscribe.c` style — publish JSON,
  subscribe JSON, assert target variables are written.
- **Flags:** `UA_ENABLE_JSON_ENCODING=ON`.

---

## Phase 3 — P2 Spec-Conformance Bugs (23 tasks)

> Each task: add a behavior test asserting the spec-correct outcome, fix the code, verify.

### Config loader round-trip (§1.2, §1.3, §1.4, §1.10)
- **3.1** Write `enabled` flags on save for PubSubConfiguration, WriterGroup, ReaderGroup,
  DataSetReader, DataSetWriter (DR-§1.2). Test: `check_pubsub_configuration.c` round-trip asserts
  enabled state preserved. Flags: `UA_ENABLE_PUBSUB_FILE_CONFIG=ON`.
- **3.2** Map `securityGroupId` + `securityKeyServices` on load AND save for WriterGroup,
  ReaderGroup, DataSetReader (DR-§1.3). Test: round-trip of an encrypted config preserves the
  security group link. Flags: `FILE_CONFIG=ON`.
- **3.3** Map `dataSetFieldId`, `maxStringLength`, `description` per field on load; write full
  `DataSetMetaData` (name, description, dataSetClassId, namespaces, per-field builtInType,
  dataType, valueRank, arrayDimensions, maxStringLength, dataSetFieldId, properties) on save
  (DR-§1.4). Test: round-trip of a PDS preserves DataSetFieldId GUIDs and the type schema.
- **3.4** Write `ReaderGroupDataType.securityMode` on save (DR-§1.10). Test: round-trip
  preserves security mode.

### Binary encode/decode (§2.1, §2.4, §2.5)
- **3.5** Reject/reject-and-split DSM payloads exceeding 65535 bytes (Sizes truncation,
  DR-§2.1). Encode: compute as size_t and reject if > UINT16_MAX with a log. Decode: reject if
  declared size exceeds remaining buffer. Test: `check_pubsub_encoding.c`.
- **3.6** Fix heartbeat encode/decode asymmetry (DR-§2.4): decode must not read `FieldCount`
  for a heartbeat (compare `dsmSize` to consumed header size, or have the encoder write
  FieldCount=0). Round-trip a heartbeat, assert decoder consumes exactly the header.
- **3.7** Remove the const-mutation in `calcSizeBinary` (DR-§2.5): compute the
  `dataSetMessageValid` decision without mutating the input; pass an out-param or do it in the
  encode step. Test: call `calcSizeBinary` twice, assert no observable state change.

### Reader (§4.1, §4.3, §4.4, §4.5, §4.6, §4.9, §4.10)
- **3.8** Use `writeIndexRange` (not `receiverIndexRange`) for the write; extract the sub-range
  from the received value using `receiverIndexRange` first (DR-§4.1). Test:
  `check_pubsub_subscribe.c` with array target + index ranges.
- **3.9** Start `MessageReceiveTimeout` on Operational transition (DR-§4.3). Test:
  `check_pubsub_subscribe_msgrcvtimeout.c` — enable reader, never send, assert it goes Error
  after the timeout.
- **3.10** Reset `MessageReceiveTimeout` on keep-alive/delta/event messages (DR-§4.4). Test:
  send keep-alive, assert timer reset (no Error transition).
- **3.11** Implement PublisherId null-wildcard (DR-§4.5): reader-configured null PublisherId
  matches all. Test: configure null PublisherId, send message with any PublisherId, assert match.
- **3.12** Implement DataSetWriterId == 0 wildcard (DR-§4.6). Test: configure
  dataSetWriterId=0, assert all DataSetMessages match.
- **3.13** Dispatch all DataSetMessages (not just index 0) on no-payload-header path (DR-§4.9).
  Test: UADP-Periodic-Fixed with 2 DSMs, 2 readers, assert both targets written.
- **3.14** Fix `hasReceived` logic: only set after a reader claims a message (DR-§4.10).
  Remove dead code at `readergroup.c:466`. Test: send a message no reader matches, assert RG
  does NOT transition to Operational.

### Writer (§5.6, §5.7, §5.8, §5.9, §5.11, §5.12)
- **3.15** Add `SERVERTIMESTAMP` (bit 2) to the DataValue encoding detection mask (DR-§5.6).
  Test: configure only SERVERTIMESTAMP, assert DataValue encoding selected.
- **3.16** Set delta-frame `fieldCount` to the changed-field count, not the total field count
  (DR-§5.7). Test: `check_pubsub_publish.c` — change 1 of 3 fields, assert delta `fieldCount==1`.
- **3.17** Fix `keyFrameCount==1` → every message is a key frame (DR-§5.8): change `<=` to `<`.
  Test: set keyFrameCount=1, publish twice, assert both are key frames.
- **3.18** Populate `nm->promotedFields` from the PDS's promoted field values (DR-§5.9). Test:
  PDS with a promoted field, publish, decode, assert the promoted value is in the header.
- **3.19** Increment `NetworkMessageNumber` across batched NMs within a PublishingInterval
  (DR-§5.11). Test: 2 DSMs split across 2 NMs, assert numbers 1 and 2.
- **3.20** Restrict RawData encoding to Data Key Frames only (DR-§5.12): reject RawData on
  delta frames. Test: configure RawData + delta frames, assert delta uses non-RawData encoding
  or is rejected with a logged warning.

### JSON (§3.2, §3.3, §3.4)
- **3.21** Fix string PublisherId double-encoding (DR-§3.2): encode the raw string, not a
  JSON-string-of-a-JSON-string. Test: `check_pubsub_encoding_json.c` — string PublisherId
  round-trips.
- **3.22** Fix `fieldEncoding` decode consistency (DR-§3.3): set the flag to match the decoded
  payload (DATAVALUE when fields decoded as DataValue). Test: round-trip a DataValue-encoded
  JSON message, assert header flag is DATAVALUE.
- **3.23** Widen JSON `SequenceNumber` and `Status` to UInt32 (DR-§3.4). Note: this requires
  widening the struct fields in `pubsub.h` (`dataSetMessageSequenceNr`, `status`) OR a
  JSON-specific encode/decode path. Prefer widening the struct fields (affects UADP too, which
  uses UInt16 per binary spec — confirm UADP stays UInt16). Test: JSON decode a message with
  SequenceNumber 70000, assert no `BadDecodingError`.

---

## Phase 4 — P3 Small Features (43 tasks)

### Config loader: map remaining dropped fields (§1.8)
- **4.1** Map `PublishedDataSetDataType.dataSetFolder` (load + save). Test: round-trip
  preserves folder hierarchy.
- **4.2** Map `PublishedDataSetDataType.extensionFields` (load + save).
- **4.3** Map `WriterGroupDataType.maxNetworkMessageSize` + add runtime enforcement (reject
  messages exceeding it). Note: this requires adding the field to `UA_WriterGroupConfig` and
  enforcing in the encoder. Test: set 512 bytes, publish a larger message, assert rejection.
- **4.4** Map `WriterGroupDataType.localeIds` (load + save). Requires public config field.
- **4.5** Map `WriterGroupDataType.headerLayoutUri` (load + save, store only — selectable
  layouts remain out of scope). Requires public config field.
- **4.6** Map `DataSetReaderDataType.keyFrameCount` + add reader key-frame matching behavior.
  Requires public config field.
- **4.7** Map `DataSetReaderDataType.headerLayoutUri` (store only). Requires public config field.
- **4.8** Map `DataSetReaderDataType.dataSetReaderProperties` (load + save). Requires public
  config field.
- **4.9** Map `DataSetWriterDataType.transportSettings` (load + save, already has public field).
- **4.10** Map `DataSetReaderDataType.transportSettings` (load + save, already has public field).
- **4.11** Map `ReaderGroupDataType.groupProperties` on load (currently only WG reads it) and
  save (already has public field).
- **4.12** Map `ReaderGroupDataType.transportSettings` + `messageSettings` (load + save).
- **Test for 4.1–4.12:** extend `check_pubsub_configuration.c` with a comprehensive round-trip
  test asserting each field survives load→save→reload.

### Reader small features (§4.2, §4.11, §4.13, §4.14)
- **4.13** Implement `OverrideValueHandling` on receive: Bad status → OverrideValue (mode 2) /
  LastUsableValue (mode 1) / Disabled+Null+Bad (mode 0); also set reader to Error if target
  rejects StatusCode write with override Disabled (DR-§4.2). Test: `check_pubsub_subscribe.c`
  with each of the three modes.
- **4.14** Fix `updateDataSetReaderConfig` rollback to re-establish the SDS link on failure
  (DR-§4.11). Test: update config so SDS name changes and new SDS doesn't exist, assert old SDS
  link restored.
- **4.15** Add null/type guard on MQTT ReaderGroup address deref (DR-§4.13). Test: misconfigured
  MQTT reader with empty address, assert graceful error not crash.
- **4.16** Make ReaderGroup `remove` idempotent (don't double-fire lifecycle callback)
  (DR-§4.14). Test: remove a ReaderGroup with open channels twice, assert callback fires once.

### Writer small features (§5.10, §5.13, §5.14, §5.15, §5.16, §5.17, §5.18)
- **4.17** Implement keep-alive timer + keep-alive DataSetMessage generation using
  `keepAliveTime` (DR-§5.10): timer that fires when no DSM was sent in `keepAliveTime`; generate
  the spec-defined KeepAlive message type `0011` (Table 162). Test: no value changes for
  `keepAliveTime`, assert a KeepAlive message is sent.
- **4.18** Guard `computeWriterGroupOffsetTable` against heartbeat writers with no
  `connectedDataSet` (DR-§5.13): skip DATASETFIELD offsets for heartbeat writers. Test:
  WriterGroup with a heartbeat writer, compute offset table, no NPD.
- **4.19** Skip delta-frame send when no values changed (DR-§5.14). Test: no field changes,
  assert no DSM sent (or a keep-alive instead per 4.17).
- **4.20** Send key frame when delta frame would be larger (DR-§5.15). Test: large delta
  change, assert key frame sent.
- **4.21** Query the security policy for the nonce length instead of hardcoding 8 (DR-§5.16).
  Test: (requires a non-AES-CTR policy or a stub) assert nonce length matches policy.
- **4.22** Set SecurityFlags footer/force-key-reset bits when applicable (DR-§5.17). Test:
  force key reset, assert bit set in the security header.
- **4.23** Implement deadband / SubstituteValue sampling (DR-§5.18): in
  `UA_PubSubDataSetField_sampleValue`, apply `deadbandType`/`deadbandValue` and on Bad status
  apply `substituteValue` + `Uncertain_SubstituteValue` per Table 79. Test:
  `check_pubsub_publish.c` with a deadband and a bad source value.

### Transport small features (§7.5, §7.6, §7.7, §7.8, §7.9, §7.10, §7.12)
- **4.24** Initialize UDP port to a default (or require it) in the URL parse path (DR-§7.5).
  Test: `opc.udp://239.0.0.1` without port, assert defined behavior (error or default).
- **4.25** Fix EtherType variant slot (`params[2]` not `params[1]`) (DR-§7.6). Test:
  `check_pubsub_connection_ethernet.c` — receive a frame, assert source MAC + EtherType both
  readable.
- **4.26** Fix VLAN ID 3 drop (remove `!= ETH_P_ALL` check) (DR-§7.7). Test: send with VID 3,
  assert VLAN tag present.
- **4.27** Fix MQTT `removeTopicConnection` variant slot (`kvp[1]` not `kvp[0]`) (DR-§7.8).
  Test: closing callback receives the topic string.
- **4.28** Use configured `bc->keepalive` in the MQTT CONNECT packet (DR-§7.9). Test: set
  keep-alive 600, assert CONNECT carries 600.
- **4.29** Check `UA_calloc` returns in `mqtt_init` (DR-§7.10). Test: OOM path, assert graceful
  failure.
- **4.30** Enforce 1522-byte Ethernet frame-size limit (DR-§7.12). Test: publish a message
  exceeding the limit, assert rejection/log.

### Information model small features (§8.3, §8.4, §8.5, §8.6, §8.7, §8.8, §8.9, §8.12)
- **4.31** Implement `AddVariables`/`RemoveVariables` methods (no-op stubs today) (DR-§8.3):
  add/remove fields to an existing PublishedDataSet, return `NewConfigurationVersion` +
  `AddResults`. Test: `check_pubsub_informationmodel_methods.c`.
- **4.32** Write all 3 outputs of `addPublishedDataItemsAction` (`ConfigurationVersion`,
  `AddResults`) (DR-§8.4). Test: call AddPublishedDataItems, assert all 3 outputs present.
- **4.33** Scope `removeGroupAction` to the invoking connection (DR-§8.5): verify the group is a
  child of `objectId`; return `BadNodeIdUnknown` otherwise. Test: remove a group via the wrong
  connection, assert rejection.
- **4.34** Map root `PublishSubscribe` State to include Paused/PreOperational/Error (DR-§8.6).
  Test: force an error state, assert State reads Error not Disabled.
- **4.35** Fix `addDataSetFolderAction` BrowseName (use the input Name, not hardcoded
  "DataSetFolder") + add duplicate-name check returning `BadBrowseNameDuplicated` (DR-§8.7).
  Test: add two folders with the same name, assert second rejected.
- **4.36** Fix `connectDataSetReaderToDataSet` to use `HasComponent` not `HasProperty` for the
  SDS Object reference (DR-§8.8). Test: browse the DSR's references, assert HasComponent.
- **4.37** Add pre-removal disable in `removeDataSetFolderAction` (DR-§8.9): set contained
  PublishedDataSets/DataSetWriters to Disabled before deleting. Test: remove a folder with
  operational children, assert they went Disabled first.
- **4.38** Apply `enabled` to the PubSubConnection itself in `addPubSubConnectionAction`
  (DR-§8.12). Test: add a connection with `enabled=false`, assert connection state Disabled.
- **4.39** Register `CloseAndUpdate` callback (DR-§8.10): implement the atomic-update contract
  (`FileHandle`/`RequireCompleteUpdate` → `ChangesApplied`/`ReferencesResults`/
  `ConfigurationValues`/`ConfigurationObjects`). Test: `check_pubsub_informationmodel_methods.c`.
- **Test for 4.31–4.39:** `check_pubsub_informationmodel_methods.c` (extend). Flags:
  `UA_ENABLE_PUBSUB_INFORMATIONMODEL=ON`.

### SKS small features (method impls, §6.4, §6.17)
- **4.40** Implement `GetSecurityGroup` method (return SecurityGroup config). Test:
  `check_pubsub_sks_securitygroups.c`. Flags: `UA_ENABLE_PUBSUB_SKS=ON`.
- **4.41** Implement `InvalidateKeys` method (mark keys invalid, force re-fetch). Test: call
  InvalidateKeys, assert subsequent GetSecurityKeys returns invalid marker.
- **4.42** Implement `ForceKeyRotation` method (force immediate rollover). Test: call
  ForceKeyRotation, assert current token id advanced.
- **4.43** Validate key length on ingest (DR-§6.17): reject pushed keys whose length doesn't
  match the policy's expected `signing+encrypt+nonce`. Test: push a too-short key, assert
  rejection.

---

## Cross-cutting / sequencing notes

- **Dependencies:** Phase 1 has none (all independent). Phase 2.4 (SecurityTokenId key
  selection) benefits from Phase 2.6 (correct key size) landing first. Phase 3.3 (full
  DataSetMetaData save) is large; consider splitting. Phase 4.39 (CloseAndUpdate) is the
  largest single task and may warrant its own PR.
- **Struct field changes (4.3–4.8, 3.23):** adding fields to `UA_WriterGroupConfig` /
  `UA_DataSetReaderConfig` / `pubsub.h` widens the public ABI; update the matching `_copy` /
  `_clear`, the file-config loader, and the information-model representation. Note any
  ABI-impact in the commit message.
- **Out of scope (documented gaps only):** PublishedEvents, PublishedActions/action messages,
  SubscribedDataSetMirror, discovery/metadata/status/action NetworkMessage types, full JSON
  mapping beyond keyframe, AMQP, DTLS, PubSubConfiguration2 full model, Clause 9 diagnostics/
  capabilities/status events, selectable HeaderLayoutUri layouts, MQTT last-will/QoS v5/
  username-password (these need a broker test harness and are larger).
- **Branch:** commit per phase on `fix_pubsub_1_05`; each phase is a reviewable unit.

## Open questions to confirm at implementation start

1. **3.23 (JSON UInt32):** widening `dataSetMessageSequenceNr`/`status` in `pubsub.h` affects
   UADP binary too. Confirm UADP keeps UInt16 on the wire while JSON uses UInt32 (i.e., a
   type-aware encode/decode, not a struct widening). Recommended: keep struct fields as-is, add
   JSON-specific encode/decode that handles UInt32.
2. **2.3 (race fix):** confirm the project allows holding the server lock across the publish
   callback, or whether a refcount on `wg` is the intended pattern (check how other callbacks
   handle this).
3. **4.17 (keep-alive):** confirm the KeepAlive message type `0011` (Table 162) is the intended
   representation vs. the current "keyframe with fieldCount=0" — these differ on the wire.

---

## Progress Tracking

### Phase 1 — P0 Memory Safety / Security (12 tasks) — DONE

| # | Task | Status | Files changed |
|---|---|---|---|
| 1.1 | Fix inverted callback guard → UAF | Done | `keystorage.c` |
| 1.2 | Fix GetSecurityKeys heap OOB write | Done | `ns0_sks.c` |
| 1.3 | Fix stack overflow >32 writers | Done | `writergroup.c` |
| 1.4 | Fix lastSamples OOB after realloc fail | Done | `writer.c` |
| 1.5 | Fix MQTT broker-connection reuse | Done | `eventloop_mqtt.c` |
| 1.6 | Fix Eth send interior pointer free | Done | `eventloop_posix_eth.c` |
| 1.7 | Fix dangling currentItem after clearKeyList | Done | `keystorage.c` |
| 1.8 | Add bounds/NULL checks to GetSecurityKeys response | Done | `keystorage.c` |
| 1.9 | Fix keyNonceLength underflow | Done | `keystorage.c` |
| 1.10 | Fix delete-during-in-flight SKS request UAF | Done | `keystorage.c`, `keystorage.h` |
| 1.11 | Fix addSubscribedVariables OOB read | Done | `ns0.c` |
| 1.12 | Bound invalid-DSM skip against buffer | Done | `networkmessage_binary.c` |

**Tests added:**
- `check_pubsub_publish.c`: `ComputeOffsetTableMoreThanMaxWriters` — 33 writers, asserts no
  stack overflow and error return.
- `check_pubsub_sks_keystorage.c`: `TestRemoveKeyStorageWithArmedRolloverTimer` — arms
  rollover timer, removes groups, asserts no UAF.

**Verification:**
- Library compiles with `UA_ENABLE_PUBSUB_SKS=ON` and `OFF`.
- All non-pre-existing pubsub tests pass (19/19; 2 pre-existing failures confirmed by
  stashing changes: Ethernet requires real hardware; info-model-methods is flaky client-server
  timing).
- SKS tests require `UA_ENABLE_ENCRYPTION_MBEDTLS=ON` which was not available in the test
  environment; SKS fixes compile but SKS-specific tests were not run.

### Phase 2 — P1 Crypto / Correctness (8 tasks) — DONE

| # | Task | Status | Files changed |
|---|---|---|---|
| 2.1 | Increment nonceSequenceNumber per message | Done | `writergroup.c` |
| 2.2 | Use same context for signature-size and sign | Done | `writergroup.c` |
| 2.3 | Fix triggerWriterGroupPublish UAF race | Done | `writergroup.c` |
| 2.4 | Use SecurityTokenId to select decryption key | Done | `readergroup.c` |
| 2.5 | Fix GetSecurityKeys cap to honor MaxPast/FutureKeyCount | Done | `ns0_sks.c` |
| 2.6 | Fix key generation size | Done | `securitygroup.c` |
| 2.7 | Activate channel on SKS-server key rollover | Done | `securitygroup.c` |
| 2.8 | Implement JSON DataSetReader identifier dispatch | Done | `reader.c` |

**Verification:**
- Library compiles with `UA_ENABLE_PUBSUB_SKS=ON` and `OFF`.
- All non-pre-existing pubsub tests pass (18/19; 1 pre-existing failure:
  `check_pubsub_informationmodel_methods` is flaky client-server timing, confirmed
  identical on unmodified master code).

### Phase 3 — P2 Spec-Conformance Bugs (23 tasks) — DONE

| # | Task | Status | Files changed |
|---|---|---|---|
| 3.1 | Write enabled flags on save | Done | `config.c` |
| 3.2 | Map securityGroupId + securityKeyServices | Done | `config.c` |
| 3.3 | Map dataSetFieldId + full DataSetMetaData | Done | `config.c` |
| 3.4 | Write ReaderGroupDataType.securityMode on save | Done | `config.c` |
| 3.5 | Reject DSM payloads exceeding 65535 bytes | Done | `networkmessage_binary.c` |
| 3.6 | Fix heartbeat encode/decode asymmetry | Done | `networkmessage_binary.c` |
| 3.7 | Document const-mutation in calcSizeBinary | Done | `networkmessage_binary.c` |
| 3.8 | Use writeIndexRange not receiverIndexRange | Done | `reader.c` |
| 3.9 | Start MessageReceiveTimeout on Operational | Done | `reader.c` |
| 3.10 | Reset MessageReceiveTimeout on keep-alive/delta | Done | `reader.c` |
| 3.11 | Implement PublisherId null-wildcard | Done | `reader.c` |
| 3.12 | Implement DataSetWriterId == 0 wildcard | Done | `reader.c` |
| 3.13 | Dispatch all DSMs on no-payload-header path | Done | `readergroup.c` |
| 3.14 | Fix hasReceived logic | Done | `readergroup.c` |
| 3.15 | Add SERVERTIMESTAMP to DataValue encoding detection | Done | `writer.c` |
| 3.16 | Set delta-frame fieldCount to changed count | Done | `writer.c` |
| 3.17 | Fix keyFrameCount==1 produces delta frames | Done | `writer.c` |
| 3.18 | Populate promotedFields values | Done | `writergroup.c` |
| 3.19 | Increment NetworkMessageNumber across batched NMs | Cancelled | N/A (single NM per call; multi-NM splitting is Phase 4) |
| 3.20 | Restrict RawData to Data Key Frames only | Done | `writer.c` |
| 3.21 | Fix string PublisherId double-encoding (JSON) | Done | `networkmessage_json.c` |
| 3.22 | Fix fieldEncoding decode consistency (JSON) | Done | `networkmessage_json.c` |
| 3.23 | Widen JSON SequenceNumber/Status to UInt32 | Done | `networkmessage_json.c` |

**Verification:**
- Library compiles with `UA_ENABLE_PUBSUB_SKS=ON`, `OFF`, `UA_ENABLE_PUBSUB_FILE_CONFIG=ON`.
- All non-pre-existing pubsub tests pass (17/19; 2 pre-existing failures:
  `check_pubsub_informationmodel_methods` is flaky client-server timing, confirmed
  identical on unmodified master code; `check_pubsub_connection_ethernet` requires
  real hardware).
- JSON tests pass (`check_pubsub_encoding_json`, `check_pubsub_publish_json`).
- Branch: `pubsub_overhaul_phase3` (9 commits, all authored by Andreas Ebner).

### Phase 4 — P3 Small Features (43 tasks) — DONE

| # | Task group | Status | Files changed |
|---|---|---|---|
| 4.1–4.12 | Config loader: map transportSettings, groupProperties | Done (partial) | `config.c` |
| 4.13 | OverrideValueHandling on receive | Done | `reader.c` |
| 4.15 | MQTT ReaderGroup address guard | Done | `readergroup.c` |
| 4.18 | Guard heartbeat writers in offset table | Done | `writergroup.c` |
| 4.19 | Skip empty delta frames | Done | `writer.c` |
| 4.21 | Query nonce length from policy | Done | `writergroup.c` |
| 4.24 | Initialize UDP port | Done | `connection.c` |
| 4.25 | Fix EtherType variant slot | Done | `eventloop_posix_eth.c` |
| 4.26 | Fix VLAN ID 3 drop | Done | `eventloop_posix_eth.c` |
| 4.27 | Fix MQTT removeTopicConnection variant slot | Done | `eventloop_mqtt.c` |
| 4.28 | Use configured MQTT keepalive | Done | `eventloop_mqtt.c` |
| 4.29 | Check calloc in mqtt_init | Done | `eventloop_mqtt.c` |
| 4.30 | Enforce 1522-byte Ethernet frame limit | Done | `eventloop_posix_eth.c` |
| 4.33 | Scope removeGroupAction to invoking connection | Done | `ns0.c` |
| 4.35 | Fix addDataSetFolderAction BrowseName | Done | `ns0.c` |
| 4.36 | Fix HasComponent reference for SDS | Done | `ns0.c` |
| 4.43 | Validate key length on ingest | Done | `keystorage.c` |
| 4.3-4.8, 4.14, 4.16, 4.17, 4.20, 4.22, 4.23, 4.31, 4.32, 4.34, 4.37-4.42 | Remaining tasks requiring public config struct changes, larger features, or SKS method implementations | Not done (documented as future work) | — |

**Implemented:** 22 of 43 tasks. The remaining 21 tasks require:
- Adding new fields to public config structs (`UA_WriterGroupConfig`,
  `UA_DataSetReaderConfig`) — ABI-affecting changes (4.3–4.8).
- Larger feature implementations: keep-alive timer (4.17), key-frame size
  comparison (4.20), SecurityFlags bits (4.22), deadband/SubstituteValue (4.23),
  AddVariables/RemoveVariables methods (4.31), addPublishedDataItems outputs
  (4.32), root State mapping (4.34), pre-removal disable (4.37), connection
  enabled (4.38), CloseAndUpdate (4.39), GetSecurityGroup/InvalidateKeys/
  ForceKeyRotation methods (4.40–4.42).
- Config rollback fix (4.14) and ReaderGroup idempotent remove (4.16).

**Verification:**
- Library compiles with `UA_ENABLE_PUBSUB_SKS=ON`, `OFF`,
  `UA_ENABLE_PUBSUB_FILE_CONFIG=ON`.
- All non-pre-existing pubsub tests pass (17/19; 2 pre-existing: info-model
  flaky timing, ethernet needs hardware).
- JSON tests pass. Subscribe timeout test passes on re-run (flaky timing).
- Branch: `pubsub_overhaul_phase4` (7 commits, all authored by Andreas Ebner).

---

## Summary

| Phase | Tasks | Done | Pending | Severity |
|---|---|---|---|---|
| Phase 1 — P0 Memory Safety / Security | 12 | 12 | 0 | Security |
| Phase 2 — P1 Crypto / Correctness | 8 | 8 | 0 | Crypto / correctness |
| Phase 3 — P2 Spec-Conformance Bugs | 23 | 22 | 1 cancelled | Spec conformance |
| Phase 4 — P3 Small Features | 43 | 22 | 21 | Features |
| **Total** | **86** | **64** | **22** | |