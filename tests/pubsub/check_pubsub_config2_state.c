/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2025 Fraunhofer IOSB (Author: Andreas Ebner)
 */

/* State-machine interaction of the incremental configuration update engine
 * and the file-based configuration (plan section 4.6) */

#include <open62541/server_config_default.h>
#include <open62541/server_pubsub.h>
#include <open62541/types.h>

#include "test_helpers.h"
#include "testing_clock.h"
#include "pubsub_test_helpers.h"
#include "ua_pubsub_internal.h"
#include "ua_server_internal.h"

#include <check.h>
#include <stdlib.h>

#define PROFILE_UDP "http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp"

static UA_Server *server = NULL;
static UA_NodeId pubVarId, subVarId;

static void setup(void) {
    server = UA_Server_newForUnitTest();
    ck_assert(server != NULL);
    UA_Server_run_startup(server);
}

static void teardown(void) {
    UA_Server_run_shutdown(server);
    UA_Server_delete(server);
}

static UA_NodeId
addVariable(UA_UInt32 id, UA_UInt32 value) {
    UA_VariableAttributes vAttr = UA_VariableAttributes_default;
    UA_Variant_setScalar(&vAttr.value, &value, &UA_TYPES[UA_TYPES_UINT32]);
    vAttr.dataType = UA_TYPES[UA_TYPES_UINT32].typeId;
    vAttr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
    UA_NodeId varId;
    UA_StatusCode res =
        UA_Server_addVariableNode(server, UA_NODEID_NUMERIC(1, id),
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                  UA_QUALIFIEDNAME(1, "Var"),
                                  UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                                  vAttr, NULL, &varId);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    return varId;
}

/* Base config: connection "SConn" + WG "SWG" + DSW "SDSW" (PDS "SPDS") */
static UA_NodeId sConnId, sWgId, sDswId, sPdsId;

static void
buildBaseConfig(void) {
    pubVarId = addVariable(52001, 42);

    UA_PublishedDataSetConfig pdsConfig;
    memset(&pdsConfig, 0, sizeof(pdsConfig));
    pdsConfig.name = UA_STRING("SPDS");
    pdsConfig.publishedDataSetType = UA_PUBSUB_DATASET_PUBLISHEDITEMS;
    UA_AddPublishedDataSetResult pdsRes =
        UA_Server_addPublishedDataSet(server, &pdsConfig, &sPdsId);
    ck_assert_int_eq(pdsRes.addResult, UA_STATUSCODE_GOOD);

    UA_DataSetFieldConfig fieldConfig;
    memset(&fieldConfig, 0, sizeof(fieldConfig));
    fieldConfig.dataSetFieldType = UA_PUBSUB_DATASETFIELD_VARIABLE;
    fieldConfig.field.variable.fieldNameAlias = UA_STRING("Field1");
    fieldConfig.field.variable.publishParameters.publishedVariable = pubVarId;
    fieldConfig.field.variable.publishParameters.attributeId = UA_ATTRIBUTEID_VALUE;
    UA_DataSetFieldResult fieldRes =
        UA_Server_addDataSetField(server, sPdsId, &fieldConfig, NULL);
    ck_assert_int_eq(fieldRes.result, UA_STATUSCODE_GOOD);

    UA_PubSubConnectionConfig connectionConfig;
    memset(&connectionConfig, 0, sizeof(connectionConfig));
    connectionConfig.name = UA_STRING("SConn");
    UA_NetworkAddressUrlDataType networkAddressUrl =
        UA_PUBSUB_TEST_NETWORKADDRESSURL(UA_PUBSUB_TEST_UDP_MULTICAST_URL_4801);
    UA_Variant_setScalar(&connectionConfig.address, &networkAddressUrl,
                         &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE]);
    connectionConfig.transportProfileUri = UA_STRING(PROFILE_UDP);
    connectionConfig.publisherId.idType = UA_PUBLISHERIDTYPE_UINT16;
    connectionConfig.publisherId.id.uint16 = 2234;
    UA_StatusCode res =
        UA_Server_addPubSubConnection(server, &connectionConfig, &sConnId);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);

    UA_WriterGroupConfig wgConfig;
    memset(&wgConfig, 0, sizeof(wgConfig));
    wgConfig.name = UA_STRING("SWG");
    wgConfig.writerGroupId = 100;
    wgConfig.publishingInterval = 50.0;
    wgConfig.keepAliveTime = 5000.0;
    res = UA_Server_addWriterGroup(server, sConnId, &wgConfig, &sWgId);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);

    UA_DataSetWriterConfig dswConfig;
    memset(&dswConfig, 0, sizeof(dswConfig));
    dswConfig.name = UA_STRING("SDSW");
    dswConfig.dataSetWriterId = 200;
    res = UA_Server_addDataSetWriter(server, sWgId, sPdsId, &dswConfig, &sDswId);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
}

/* Update file with a single WriterGroup under the named connection */
static UA_PubSubConnectionDataType fileConn;
static UA_WriterGroupDataType fileWg;

static void
buildAddWgFile(UA_PubSubConfiguration2DataType *cfg, const char *connName,
               const char *wgName, UA_Boolean enabled) {
    UA_PubSubConfiguration2DataType_init(cfg);
    UA_PubSubConnectionDataType_init(&fileConn);
    fileConn.name = UA_STRING((char*)(uintptr_t)connName);
    UA_WriterGroupDataType_init(&fileWg);
    fileWg.name = UA_STRING((char*)(uintptr_t)wgName);
    fileWg.writerGroupId = 150;
    fileWg.publishingInterval = 50.0;
    fileWg.keepAliveTime = 5000.0;
    fileWg.enabled = enabled;
    fileConn.writerGroups = &fileWg;
    fileConn.writerGroupsSize = 1;
    cfg->connections = &fileConn;
    cfg->connectionsSize = 1;
}

static UA_PubSubConfigurationRefDataType
makeRef(UA_UInt32 mask) {
    UA_PubSubConfigurationRefDataType ref;
    UA_PubSubConfigurationRefDataType_init(&ref);
    ref.configurationMask = mask;
    return ref;
}

/* A component added under a disabled parent stays Paused and cascades to
 * Operational when the parent is enabled */
START_TEST(AddUnderDisabledParent) {
    buildBaseConfig();
    UA_PubSubManager *psm = getPSM(server);

    UA_PubSubConfiguration2DataType cfg;
    buildAddWgFile(&cfg, "SConn", "PausedWG", true);
    UA_PubSubConfigurationRefDataType ref =
        makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP);

    UA_PubSubConfigUpdateResult result;
    UA_StatusCode res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref,
                                                      false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_GOOD);
    UA_NodeId newWgId = result.configurationObjects[0];

    /* The connection is disabled -- the enabled WG waits in Paused */
    UA_WriterGroup *wg = UA_WriterGroup_find(psm, newWgId);
    ck_assert(wg != NULL);
    ck_assert_int_eq((int)wg->head.state, (int)UA_PUBSUBSTATE_PAUSED);

    /* Enabling the connection cascades the WG to Operational */
    res = UA_Server_enablePubSubConnection(server, sConnId);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq((int)wg->head.state, (int)UA_PUBSUBSTATE_OPERATIONAL);

    UA_PubSubConfigUpdateResult_clear(&result);
} END_TEST

/* A modify of a running WriterGroup restores the state and the publish
 * callback keeps running (the sequence number continues to increase) */
START_TEST(ModifyRunningKeepsPublishing) {
    buildBaseConfig();
    UA_PubSubManager *psm = getPSM(server);
    UA_StatusCode res = UA_Server_enableAllPubSubComponents(server);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);

    /* Let the group publish */
    UA_WriterGroup *wg = UA_WriterGroup_find(psm, sWgId);
    ck_assert(wg != NULL);
    for(size_t i = 0; i < 20 && wg->sequenceNumber < 3; i++) {
        UA_fakeSleep(50);
        UA_Server_run_iterate(server, false);
    }
    UA_UInt16 seqBefore = wg->sequenceNumber;
    ck_assert_uint_ge(seqBefore, 3);

    /* Modify the publishing interval through the engine */
    UA_PubSubConfiguration2DataType cfg;
    buildAddWgFile(&cfg, "SConn", "SWG", true);
    fileWg.writerGroupId = 100;
    fileWg.publishingInterval = 25.0;
    UA_PubSubConfigurationRefDataType ref =
        makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMODIFY |
                UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP);
    UA_PubSubConfigUpdateResult result;
    res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_GOOD);
    UA_PubSubConfigUpdateResult_clear(&result);

    ck_assert(wg->config.publishingInterval == 25.0);
    ck_assert_int_eq((int)wg->head.state, (int)UA_PUBSUBSTATE_OPERATIONAL);

    /* Publishing continues after the modification */
    for(size_t i = 0; i < 20 && wg->sequenceNumber < seqBefore + 3; i++) {
        UA_fakeSleep(50);
        UA_Server_run_iterate(server, false);
    }
    ck_assert_uint_ge(wg->sequenceNumber, seqBefore + 3);
} END_TEST

/* Removing an Operational connection mid-publish shuts it down cleanly */
START_TEST(RemoveOperationalConnection) {
    buildBaseConfig();
    UA_PubSubManager *psm = getPSM(server);
    UA_StatusCode res = UA_Server_enableAllPubSubComponents(server);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);

    for(size_t i = 0; i < 5; i++) {
        UA_fakeSleep(50);
        UA_Server_run_iterate(server, false);
    }

    UA_PubSubConfiguration2DataType cfg;
    UA_PubSubConfiguration2DataType_init(&cfg);
    UA_PubSubConnectionDataType conn;
    UA_PubSubConnectionDataType_init(&conn);
    conn.name = UA_STRING("SConn");
    cfg.connections = &conn;
    cfg.connectionsSize = 1;
    UA_PubSubConfigurationRefDataType ref =
        makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTREMOVE |
                UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION);

    UA_PubSubConfigUpdateResult result;
    res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_GOOD);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* The connection and its children are gone. The removal can be deferred
     * until the sockets are closed -- iterate to let that happen. */
    for(size_t i = 0; i < 100 && psm->connectionsSize > 0; i++) {
        UA_fakeSleep(50);
        UA_Server_run_iterate(server, false);
    }
    ck_assert_uint_eq(psm->connectionsSize, 0);
} END_TEST

/* The componentLifecycleCallback is invoked for engine add/remove and a bad
 * return vetoes the element operation */
static size_t lifecycleAddCount;
static size_t lifecycleRemoveCount;
static UA_StatusCode lifecycleReturn;

static UA_StatusCode
countingLifecycleCallback(UA_Server *s, const UA_NodeId id,
                          const UA_PubSubComponentType componentType,
                          UA_Boolean remove) {
    /* Only creations are vetoed. A veto of the removal would also block the
     * cleanup of a vetoed creation. */
    if(remove) {
        lifecycleRemoveCount++;
        return UA_STATUSCODE_GOOD;
    }
    lifecycleAddCount++;
    return lifecycleReturn;
}

START_TEST(LifecycleCallbackAndVeto) {
    buildBaseConfig();
    UA_PubSubManager *psm = getPSM(server);

    lifecycleAddCount = 0;
    lifecycleRemoveCount = 0;
    lifecycleReturn = UA_STATUSCODE_GOOD;
    UA_Server_getConfig(server)->pubSubConfig.componentLifecycleCallback =
        countingLifecycleCallback;

    /* Add a WriterGroup */
    UA_PubSubConfiguration2DataType cfg;
    buildAddWgFile(&cfg, "SConn", "CallbackWG", false);
    UA_PubSubConfigurationRefDataType ref =
        makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP);
    UA_PubSubConfigUpdateResult result;
    UA_StatusCode res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref,
                                                      false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(lifecycleAddCount, 1);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* Remove it again */
    ref = makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTREMOVE |
                  UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP);
    res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_GOOD);
    ck_assert_uint_ge(lifecycleRemoveCount, 1);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* A bad return code vetoes the add */
    UA_PubSubConnection *c = UA_PubSubConnection_find(psm, sConnId);
    lifecycleReturn = UA_STATUSCODE_BADUSERACCESSDENIED;
    ref = makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                  UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP);
    res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0],
                     UA_STATUSCODE_BADUSERACCESSDENIED);
    ck_assert(!result.changesApplied);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* No WriterGroup with the vetoed name exists (removed groups can linger
     * until the EventLoop unlinks them -- compare by name, not by count) */
    for(size_t i = 0; i < 5; i++) {
        UA_fakeSleep(50);
        UA_Server_run_iterate(server, false);
    }
    UA_String vetoedName = UA_STRING("CallbackWG");
    UA_WriterGroup *iterWg;
    LIST_FOREACH(iterWg, &c->writerGroups, listEntry) {
        ck_assert(!UA_String_equal(&iterWg->config.name, &vetoedName));
    }

    UA_Server_getConfig(server)->pubSubConfig.componentLifecycleCallback = NULL;
} END_TEST

/* State-change callbacks fire for the transitions triggered by a modify of
 * a running component (disable -> update -> restore) */
static size_t beforeStateChangeCount;
static size_t stateChangeCount;

static void
countingBeforeStateChange(UA_Server *s, const UA_NodeId id,
                          UA_PubSubState *targetState) {
    beforeStateChangeCount++;
}

static void
countingStateChange(UA_Server *s, const UA_NodeId id,
                    UA_PubSubState state, UA_StatusCode status) {
    stateChangeCount++;
}

START_TEST(StateCallbacksOnModify) {
    buildBaseConfig();
    UA_StatusCode res = UA_Server_enableAllPubSubComponents(server);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);

    UA_ServerConfig *sc = UA_Server_getConfig(server);
    sc->pubSubConfig.beforeStateChangeCallback = countingBeforeStateChange;
    sc->pubSubConfig.stateChangeCallback = countingStateChange;
    beforeStateChangeCount = 0;
    stateChangeCount = 0;

    UA_PubSubConfiguration2DataType cfg;
    buildAddWgFile(&cfg, "SConn", "SWG", true);
    fileWg.writerGroupId = 100;
    fileWg.publishingInterval = 30.0;
    UA_PubSubConfigurationRefDataType ref =
        makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMODIFY |
                UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP);
    UA_PubSubConfigUpdateResult result;
    res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_GOOD);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* At least the disable and the restore-to-operational transitions */
    ck_assert_uint_ge(beforeStateChangeCount, 2);
    ck_assert_uint_ge(stateChangeCount, 2);

    sc->pubSubConfig.beforeStateChangeCallback = NULL;
    sc->pubSubConfig.stateChangeCallback = NULL;
} END_TEST

/* A connection with a custom state machine survives element operations
 * without the default socket handling kicking in */
static UA_StatusCode
connectionStateMachine(UA_Server *s, const UA_NodeId componentId,
                       void *componentContext, UA_PubSubState *state,
                       UA_PubSubState targetState) {
    /* No sockets are opened. Move directly to the target state. */
    if(targetState == UA_PUBSUBSTATE_OPERATIONAL ||
       targetState == UA_PUBSUBSTATE_PREOPERATIONAL)
        *state = UA_PUBSUBSTATE_OPERATIONAL;
    else
        *state = targetState;
    return UA_STATUSCODE_GOOD;
}

START_TEST(CustomStateMachineSurvivesOps) {
    buildBaseConfig();
    UA_PubSubManager *psm = getPSM(server);

    /* Attach the custom state machine and enable the connection */
    UA_PubSubConnectionConfig cc;
    UA_StatusCode res = UA_Server_getPubSubConnectionConfig(server, sConnId, &cc);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    cc.customStateMachine = connectionStateMachine;
    res = UA_Server_updatePubSubConnectionConfig(server, sConnId, &cc);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    UA_PubSubConnectionConfig_clear(&cc);

    res = UA_Server_enablePubSubConnection(server, sConnId);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    UA_PubSubConnection *c = UA_PubSubConnection_find(psm, sConnId);
    ck_assert_int_eq((int)c->head.state, (int)UA_PUBSUBSTATE_OPERATIONAL);

    /* Add a ReaderGroup under the custom-state-machine connection */
    UA_PubSubConfiguration2DataType cfg;
    UA_PubSubConfiguration2DataType_init(&cfg);
    UA_PubSubConnectionDataType conn;
    UA_PubSubConnectionDataType_init(&conn);
    conn.name = UA_STRING("SConn");
    UA_ReaderGroupDataType rg;
    UA_ReaderGroupDataType_init(&rg);
    rg.name = UA_STRING("CustomRG");
    conn.readerGroups = &rg;
    conn.readerGroupsSize = 1;
    cfg.connections = &conn;
    cfg.connectionsSize = 1;
    UA_PubSubConfigurationRefDataType ref =
        makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADERGROUP);
    UA_PubSubConfigUpdateResult result;
    res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_GOOD);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* The connection state is still managed by the custom machine */
    ck_assert_int_eq((int)c->head.state, (int)UA_PUBSUBSTATE_OPERATIONAL);
    ck_assert_uint_eq(c->readerGroupsSize, 1);
} END_TEST

/* A subscriber created through the file path receives the published data
 * (loopback publisher/subscriber on the same server) */
START_TEST(FileLoadedReaderReceives) {
    pubVarId = addVariable(52001, 42);
    subVarId = addVariable(52002, 0);

    /* Build the enabled publisher+subscriber configuration in code */
    UA_PubSubConfiguration2DataType cfg;
    UA_PubSubConfiguration2DataType_init(&cfg);
    cfg.enabled = true;

    /* PublishedDataSet with one field */
    UA_PublishedDataSetDataType pds;
    UA_PublishedDataSetDataType_init(&pds);
    pds.name = UA_STRING("LoopPDS");
    UA_FieldMetaData fmd;
    UA_FieldMetaData_init(&fmd);
    fmd.name = UA_STRING("Field1");
    fmd.dataType = UA_TYPES[UA_TYPES_UINT32].typeId;
    fmd.builtInType = UA_NS0ID_UINT32;
    fmd.valueRank = -1;
    pds.dataSetMetaData.name = UA_STRING("LoopPDS");
    pds.dataSetMetaData.fields = &fmd;
    pds.dataSetMetaData.fieldsSize = 1;
    UA_PublishedDataItemsDataType pdi;
    UA_PublishedDataItemsDataType_init(&pdi);
    UA_PublishedVariableDataType pv;
    UA_PublishedVariableDataType_init(&pv);
    pv.publishedVariable = pubVarId;
    pv.attributeId = UA_ATTRIBUTEID_VALUE;
    pdi.publishedData = &pv;
    pdi.publishedDataSize = 1;
    pds.dataSetSource.encoding = UA_EXTENSIONOBJECT_DECODED_NODELETE;
    pds.dataSetSource.content.decoded.type =
        &UA_TYPES[UA_TYPES_PUBLISHEDDATAITEMSDATATYPE];
    pds.dataSetSource.content.decoded.data = &pdi;
    cfg.publishedDataSets = &pds;
    cfg.publishedDataSetsSize = 1;

    /* Connection with WriterGroup/DataSetWriter and ReaderGroup/
     * DataSetReader, everything enabled */
    UA_PubSubConnectionDataType conn;
    UA_PubSubConnectionDataType_init(&conn);
    conn.name = UA_STRING("LoopConn");
    conn.enabled = true;
    conn.transportProfileUri = UA_STRING(PROFILE_UDP);
    UA_NetworkAddressUrlDataType addr;
    UA_PubSubTest_initNetworkAddressUrl(&addr,
        UA_PubSubTest_getUdpMulticastUrl4801());
    conn.address.encoding = UA_EXTENSIONOBJECT_DECODED_NODELETE;
    conn.address.content.decoded.type =
        &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE];
    conn.address.content.decoded.data = &addr;
    UA_UInt16 publisherId = 2234;
    UA_Variant_setScalar(&conn.publisherId, &publisherId,
                         &UA_TYPES[UA_TYPES_UINT16]);

    UA_WriterGroupDataType wg;
    UA_WriterGroupDataType_init(&wg);
    wg.name = UA_STRING("LoopWG");
    wg.enabled = true;
    wg.writerGroupId = 100;
    wg.publishingInterval = 50.0;
    wg.keepAliveTime = 5000.0;
    UA_DataSetWriterDataType dsw;
    UA_DataSetWriterDataType_init(&dsw);
    dsw.name = UA_STRING("LoopDSW");
    dsw.enabled = true;
    dsw.dataSetWriterId = 200;
    dsw.dataSetName = UA_STRING("LoopPDS");
    wg.dataSetWriters = &dsw;
    wg.dataSetWritersSize = 1;
    conn.writerGroups = &wg;
    conn.writerGroupsSize = 1;

    UA_ReaderGroupDataType rg;
    UA_ReaderGroupDataType_init(&rg);
    rg.name = UA_STRING("LoopRG");
    rg.enabled = true;
    UA_DataSetReaderDataType dsr;
    UA_DataSetReaderDataType_init(&dsr);
    dsr.name = UA_STRING("LoopDSR");
    dsr.enabled = true;
    dsr.writerGroupId = 100;
    dsr.dataSetWriterId = 200;
    UA_Variant_setScalar(&dsr.publisherId, &publisherId,
                         &UA_TYPES[UA_TYPES_UINT16]);
    dsr.dataSetMetaData.fields = &fmd;
    dsr.dataSetMetaData.fieldsSize = 1;
    UA_TargetVariablesDataType targets;
    UA_TargetVariablesDataType_init(&targets);
    UA_FieldTargetDataType target;
    UA_FieldTargetDataType_init(&target);
    target.attributeId = UA_ATTRIBUTEID_VALUE;
    target.targetNodeId = subVarId;
    targets.targetVariables = &target;
    targets.targetVariablesSize = 1;
    dsr.subscribedDataSet.encoding = UA_EXTENSIONOBJECT_DECODED_NODELETE;
    dsr.subscribedDataSet.content.decoded.type =
        &UA_TYPES[UA_TYPES_TARGETVARIABLESDATATYPE];
    dsr.subscribedDataSet.content.decoded.data = &targets;
    rg.dataSetReaders = &dsr;
    rg.dataSetReadersSize = 1;
    conn.readerGroups = &rg;
    conn.readerGroupsSize = 1;

    cfg.connections = &conn;
    cfg.connectionsSize = 1;

    /* Encode as a configuration file blob */
    UA_UABinaryFileDataType binFile;
    UA_UABinaryFileDataType_init(&binFile);
    UA_Variant_setScalar(&binFile.body, &cfg,
                         &UA_TYPES[UA_TYPES_PUBSUBCONFIGURATION2DATATYPE]);
    UA_ExtensionObject eo;
    UA_ExtensionObject_init(&eo);
    eo.encoding = UA_EXTENSIONOBJECT_DECODED_NODELETE;
    eo.content.decoded.type = &UA_TYPES[UA_TYPES_UABINARYFILEDATATYPE];
    eo.content.decoded.data = &binFile;
    UA_ByteString blob = UA_BYTESTRING_NULL;
    UA_StatusCode res =
        UA_encodeBinary(&eo, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT], &blob, NULL);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);

    /* Load and run until the subscriber received the published value */
    res = UA_Server_loadPubSubConfigFromByteString(server, blob);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    UA_ByteString_clear(&blob);

    UA_Boolean received = false;
    for(size_t i = 0; i < 100 && !received; i++) {
        UA_fakeSleep(50);
        UA_Server_run_iterate(server, false);

        UA_ReadValueId rvi;
        UA_ReadValueId_init(&rvi);
        rvi.nodeId = subVarId;
        rvi.attributeId = UA_ATTRIBUTEID_VALUE;
        UA_DataValue dv = UA_Server_read(server, &rvi,
                                         UA_TIMESTAMPSTORETURN_NEITHER);
        if(dv.hasValue && dv.value.type == &UA_TYPES[UA_TYPES_UINT32] &&
           *(UA_UInt32*)dv.value.data == 42)
            received = true;
        UA_DataValue_clear(&dv);
    }
    ck_assert(received);

    /* The reader reached Operational */
    UA_PubSubManager *psm = getPSM(server);
    UA_PubSubConnection *c = TAILQ_FIRST(&psm->connections);
    UA_ReaderGroup *liveRg = LIST_FIRST(&c->readerGroups);
    UA_DataSetReader *liveDsr = LIST_FIRST(&liveRg->readers);
    ck_assert_int_eq((int)liveDsr->head.state, (int)UA_PUBSUBSTATE_OPERATIONAL);
} END_TEST

int main(void) {
    TCase *tc_state = tcase_create("Config2 state machine interaction");
    tcase_add_checked_fixture(tc_state, setup, teardown);
    tcase_add_test(tc_state, AddUnderDisabledParent);
    tcase_add_test(tc_state, ModifyRunningKeepsPublishing);
    tcase_add_test(tc_state, RemoveOperationalConnection);
    tcase_add_test(tc_state, LifecycleCallbackAndVeto);
    tcase_add_test(tc_state, StateCallbacksOnModify);
    tcase_add_test(tc_state, CustomStateMachineSurvivesOps);
    tcase_add_test(tc_state, FileLoadedReaderReceives);

    Suite *s = suite_create("PubSub Configuration2 state machine");
    suite_add_tcase(s, tc_state);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
