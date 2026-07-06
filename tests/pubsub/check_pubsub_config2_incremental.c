/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2025 Fraunhofer IOSB (Author: Andreas Ebner)
 */

#include <open62541/server_config_default.h>
#include <open62541/server_pubsub.h>
#include <open62541/types.h>

#include "test_helpers.h"
#include "pubsub_test_helpers.h"
#include "ua_pubsub_internal.h"
#include "ua_server_internal.h"

#include <check.h>
#include <stdlib.h>

#define PROFILE_UDP "http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp"

static UA_Server *server = NULL;

static void setup(void) {
    server = UA_Server_newForUnitTest();
    ck_assert(server != NULL);
    UA_Server_run_startup(server);
}

static void teardown(void) {
    UA_Server_run_shutdown(server);
    UA_Server_delete(server);
}

/* Add a variable for published fields */
static UA_NodeId
addVariable(UA_UInt32 id) {
    UA_VariableAttributes vAttr = UA_VariableAttributes_default;
    UA_UInt32 initVal = 42;
    UA_Variant_setScalar(&vAttr.value, &initVal, &UA_TYPES[UA_TYPES_UINT32]);
    vAttr.dataType = UA_TYPES[UA_TYPES_UINT32].typeId;
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

/* Create a base configuration via the C API: connection "BaseConn" with
 * WriterGroup "BaseWG" + DataSetWriter "BaseDSW" (PDS "BasePDS") and
 * ReaderGroup "BaseRG" */
static UA_NodeId baseConnId, baseWgId, baseRgId, basePdsId;

static void
buildBaseConfig(void) {
    UA_NodeId varId = addVariable(51001);

    UA_PublishedDataSetConfig pdsConfig;
    memset(&pdsConfig, 0, sizeof(pdsConfig));
    pdsConfig.name = UA_STRING("BasePDS");
    pdsConfig.publishedDataSetType = UA_PUBSUB_DATASET_PUBLISHEDITEMS;
    UA_AddPublishedDataSetResult pdsRes =
        UA_Server_addPublishedDataSet(server, &pdsConfig, &basePdsId);
    ck_assert_int_eq(pdsRes.addResult, UA_STATUSCODE_GOOD);

    UA_DataSetFieldConfig fieldConfig;
    memset(&fieldConfig, 0, sizeof(fieldConfig));
    fieldConfig.dataSetFieldType = UA_PUBSUB_DATASETFIELD_VARIABLE;
    fieldConfig.field.variable.fieldNameAlias = UA_STRING("Field1");
    fieldConfig.field.variable.publishParameters.publishedVariable = varId;
    fieldConfig.field.variable.publishParameters.attributeId = UA_ATTRIBUTEID_VALUE;
    UA_DataSetFieldResult fieldRes =
        UA_Server_addDataSetField(server, basePdsId, &fieldConfig, NULL);
    ck_assert_int_eq(fieldRes.result, UA_STATUSCODE_GOOD);

    UA_PubSubConnectionConfig connectionConfig;
    memset(&connectionConfig, 0, sizeof(connectionConfig));
    connectionConfig.name = UA_STRING("BaseConn");
    UA_NetworkAddressUrlDataType networkAddressUrl =
        UA_PUBSUB_TEST_NETWORKADDRESSURL(UA_PUBSUB_TEST_UDP_MULTICAST_URL_4801);
    UA_Variant_setScalar(&connectionConfig.address, &networkAddressUrl,
                         &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE]);
    connectionConfig.transportProfileUri = UA_STRING(PROFILE_UDP);
    connectionConfig.publisherId.idType = UA_PUBLISHERIDTYPE_UINT16;
    connectionConfig.publisherId.id.uint16 = 2234;
    UA_StatusCode res =
        UA_Server_addPubSubConnection(server, &connectionConfig, &baseConnId);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);

    UA_WriterGroupConfig wgConfig;
    memset(&wgConfig, 0, sizeof(wgConfig));
    wgConfig.name = UA_STRING("BaseWG");
    wgConfig.writerGroupId = 100;
    wgConfig.publishingInterval = 100.0;
    wgConfig.keepAliveTime = 5000.0;
    res = UA_Server_addWriterGroup(server, baseConnId, &wgConfig, &baseWgId);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);

    UA_DataSetWriterConfig dswConfig;
    memset(&dswConfig, 0, sizeof(dswConfig));
    dswConfig.name = UA_STRING("BaseDSW");
    dswConfig.dataSetWriterId = 200;
    UA_NodeId dswId;
    res = UA_Server_addDataSetWriter(server, baseWgId, basePdsId, &dswConfig, &dswId);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);

    UA_ReaderGroupConfig rgConfig;
    memset(&rgConfig, 0, sizeof(rgConfig));
    rgConfig.name = UA_STRING("BaseRG");
    res = UA_Server_addReaderGroup(server, baseConnId, &rgConfig, &baseRgId);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
}

/* Helpers to build the update file elements in place. The structures
 * reference stack memory and must not be cleared. */
static UA_NetworkAddressUrlDataType fileAddr;
static UA_UInt16 filePublisherId;

static void
fileConnectionInit(UA_PubSubConnectionDataType *c, const char *name,
                   UA_UInt16 publisherId) {
    UA_PubSubConnectionDataType_init(c);
    c->name = UA_STRING((char*)(uintptr_t)name);
    c->transportProfileUri = UA_STRING(PROFILE_UDP);
    UA_PubSubTest_initNetworkAddressUrl(&fileAddr,
        UA_PubSubTest_getUdpMulticastUrl4801());
    c->address.encoding = UA_EXTENSIONOBJECT_DECODED_NODELETE;
    c->address.content.decoded.type = &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE];
    c->address.content.decoded.data = &fileAddr;
    if(publisherId != 0) {
        filePublisherId = publisherId;
        UA_Variant_setScalar(&c->publisherId, &filePublisherId,
                             &UA_TYPES[UA_TYPES_UINT16]);
    }
}

static void
fileWriterGroupInit(UA_WriterGroupDataType *wg, const char *name,
                    UA_UInt16 wgId) {
    UA_WriterGroupDataType_init(wg);
    wg->name = UA_STRING((char*)(uintptr_t)name);
    wg->writerGroupId = wgId;
    wg->publishingInterval = 150.0;
    wg->keepAliveTime = 5000.0;
}

static UA_PubSubConfigurationRefDataType
makeRef(UA_UInt32 mask, UA_UInt16 elementIndex, UA_UInt16 connectionIndex,
        UA_UInt16 groupIndex) {
    UA_PubSubConfigurationRefDataType ref;
    UA_PubSubConfigurationRefDataType_init(&ref);
    ref.configurationMask = mask;
    ref.elementIndex = elementIndex;
    ref.connectionIndex = connectionIndex;
    ref.groupIndex = groupIndex;
    return ref;
}

/* Add a connection, then a WriterGroup/DataSetWriter/PDS under it in a
 * second call (parent referenced by name) */
START_TEST(AddElements) {
    buildBaseConfig();
    UA_PubSubManager *psm = getPSM(server);
    ck_assert_uint_eq(psm->connectionsSize, 1);

    /* Add a second connection */
    UA_PubSubConfiguration2DataType cfg;
    UA_PubSubConfiguration2DataType_init(&cfg);
    UA_PubSubConnectionDataType conn;
    fileConnectionInit(&conn, "IncConn", 2334);
    cfg.connections = &conn;
    cfg.connectionsSize = 1;

    UA_PubSubConfigurationRefDataType ref =
        makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION, 0, 0, 0);

    UA_PubSubConfigUpdateResult result;
    UA_StatusCode res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref,
                                                      false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert(result.changesApplied);
    ck_assert_uint_eq(result.referencesResultsSize, 1);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_GOOD);
    ck_assert(!UA_NodeId_isNull(&result.configurationObjects[0]));
    ck_assert_uint_eq(psm->connectionsSize, 2);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* Add PDS + WriterGroup + DataSetWriter + ReaderGroup + DataSetReader
     * under the new connection in one call. The connection element only
     * provides the parent name. */
    UA_PubSubConfiguration2DataType cfg2;
    UA_PubSubConfiguration2DataType_init(&cfg2);

    UA_NodeId varId = addVariable(51002);
    UA_PublishedDataSetDataType pds;
    UA_PublishedDataSetDataType_init(&pds);
    pds.name = UA_STRING("IncPDS");
    UA_FieldMetaData fmd;
    UA_FieldMetaData_init(&fmd);
    fmd.name = UA_STRING("Field1");
    fmd.dataType = UA_TYPES[UA_TYPES_UINT32].typeId;
    fmd.builtInType = UA_NS0ID_UINT32;
    fmd.valueRank = -1;
    pds.dataSetMetaData.name = UA_STRING("IncPDS");
    pds.dataSetMetaData.fields = &fmd;
    pds.dataSetMetaData.fieldsSize = 1;
    UA_PublishedDataItemsDataType pdi;
    UA_PublishedDataItemsDataType_init(&pdi);
    UA_PublishedVariableDataType pv;
    UA_PublishedVariableDataType_init(&pv);
    pv.publishedVariable = varId;
    pv.attributeId = UA_ATTRIBUTEID_VALUE;
    pdi.publishedData = &pv;
    pdi.publishedDataSize = 1;
    pds.dataSetSource.encoding = UA_EXTENSIONOBJECT_DECODED_NODELETE;
    pds.dataSetSource.content.decoded.type =
        &UA_TYPES[UA_TYPES_PUBLISHEDDATAITEMSDATATYPE];
    pds.dataSetSource.content.decoded.data = &pdi;
    cfg2.publishedDataSets = &pds;
    cfg2.publishedDataSetsSize = 1;

    UA_PubSubConnectionDataType parentConn;
    UA_PubSubConnectionDataType_init(&parentConn);
    parentConn.name = UA_STRING("IncConn");

    UA_WriterGroupDataType wg;
    fileWriterGroupInit(&wg, "IncWG", 101);
    UA_DataSetWriterDataType dsw;
    UA_DataSetWriterDataType_init(&dsw);
    dsw.name = UA_STRING("IncDSW");
    dsw.dataSetWriterId = 201;
    dsw.dataSetName = UA_STRING("IncPDS");
    wg.dataSetWriters = &dsw;
    wg.dataSetWritersSize = 1;
    parentConn.writerGroups = &wg;
    parentConn.writerGroupsSize = 1;

    UA_ReaderGroupDataType rg;
    UA_ReaderGroupDataType_init(&rg);
    rg.name = UA_STRING("IncRG");
    UA_DataSetReaderDataType dsr;
    UA_DataSetReaderDataType_init(&dsr);
    dsr.name = UA_STRING("IncDSR");
    dsr.writerGroupId = 101;
    dsr.dataSetWriterId = 201;
    UA_Variant_setScalar(&dsr.publisherId, &filePublisherId,
                         &UA_TYPES[UA_TYPES_UINT16]);
    dsr.dataSetMetaData.fields = &fmd;
    dsr.dataSetMetaData.fieldsSize = 1;
    UA_TargetVariablesDataType targets;
    UA_TargetVariablesDataType_init(&targets);
    UA_FieldTargetDataType target;
    UA_FieldTargetDataType_init(&target);
    target.attributeId = UA_ATTRIBUTEID_VALUE;
    target.targetNodeId = varId;
    targets.targetVariables = &target;
    targets.targetVariablesSize = 1;
    dsr.subscribedDataSet.encoding = UA_EXTENSIONOBJECT_DECODED_NODELETE;
    dsr.subscribedDataSet.content.decoded.type =
        &UA_TYPES[UA_TYPES_TARGETVARIABLESDATATYPE];
    dsr.subscribedDataSet.content.decoded.data = &targets;
    rg.dataSetReaders = &dsr;
    rg.dataSetReadersSize = 1;
    parentConn.readerGroups = &rg;
    parentConn.readerGroupsSize = 1;

    cfg2.connections = &parentConn;
    cfg2.connectionsSize = 1;

    UA_PubSubConfigurationRefDataType refs[5];
    refs[0] = makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                      UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEPUBDATASET, 0, 0, 0);
    refs[1] = makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                      UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP, 0, 0, 0);
    refs[2] = makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                      UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITER, 0, 0, 0);
    refs[3] = makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                      UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADERGROUP, 0, 0, 0);
    refs[4] = makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                      UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEREADER, 0, 0, 0);

    res = UA_Server_updatePubSubConfig2(server, &cfg2, 5, refs, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    for(size_t i = 0; i < 5; i++)
        ck_assert_int_eq(result.referencesResults[i], UA_STATUSCODE_GOOD);
    ck_assert(result.changesApplied);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* Verify the model */
    UA_PubSubConnection *c = NULL, *iter;
    UA_String connName = UA_STRING("IncConn");
    TAILQ_FOREACH(iter, &psm->connections, listEntry) {
        if(UA_String_equal(&iter->config.name, &connName))
            c = iter;
    }
    ck_assert(c != NULL);
    ck_assert_uint_eq(c->writerGroupsSize, 1);
    ck_assert_uint_eq(c->readerGroupsSize, 1);
    UA_WriterGroup *liveWg = LIST_FIRST(&c->writerGroups);
    ck_assert_uint_eq(liveWg->writersCount, 1);
    UA_ReaderGroup *liveRg = LIST_FIRST(&c->readerGroups);
    ck_assert_uint_eq(liveRg->readersCount, 1);
    ck_assert_uint_eq(psm->publishedDataSetsSize, 2);
} END_TEST

/* Auto-assignment of names and identifiers */
START_TEST(AutoAssign) {
    buildBaseConfig();
    UA_PubSubManager *psm = getPSM(server);

    /* Connection with empty name and null PublisherId */
    UA_PubSubConfiguration2DataType cfg;
    UA_PubSubConfiguration2DataType_init(&cfg);
    UA_PubSubConnectionDataType conn;
    fileConnectionInit(&conn, "", 0);
    cfg.connections = &conn;
    cfg.connectionsSize = 1;

    UA_PubSubConfigurationRefDataType ref =
        makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION, 0, 0, 0);

    UA_PubSubConfigUpdateResult result;
    UA_StatusCode res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref,
                                                      false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(result.configurationValuesSize, 1);
    ck_assert(result.configurationValues[0].name.length > 0);
    ck_assert(!UA_Variant_isEmpty(&result.configurationValues[0].identifier));
    UA_String assignedConnName = result.configurationValues[0].name;
    ck_assert_uint_eq(psm->connectionsSize, 2);

    /* WriterGroup with empty name and id 0 under the new connection */
    UA_PubSubConfiguration2DataType cfg2;
    UA_PubSubConfiguration2DataType_init(&cfg2);
    UA_PubSubConnectionDataType parentConn;
    UA_PubSubConnectionDataType_init(&parentConn);
    parentConn.name = assignedConnName;
    UA_WriterGroupDataType wg;
    fileWriterGroupInit(&wg, "", 0);
    parentConn.writerGroups = &wg;
    parentConn.writerGroupsSize = 1;
    cfg2.connections = &parentConn;
    cfg2.connectionsSize = 1;

    UA_PubSubConfigurationRefDataType ref2 =
        makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP, 0, 0, 0);

    UA_PubSubConfigUpdateResult result2;
    res = UA_Server_updatePubSubConfig2(server, &cfg2, 1, &ref2, false, &result2);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result2.referencesResults[0], UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(result2.configurationValuesSize, 1);
    UA_Variant *ident = &result2.configurationValues[0].identifier;
    ck_assert(UA_Variant_hasScalarType(ident, &UA_TYPES[UA_TYPES_UINT16]));
    ck_assert_uint_ge(*(UA_UInt16*)ident->data, 0x8000);

    UA_PubSubConfigUpdateResult_clear(&result);
    UA_PubSubConfigUpdateResult_clear(&result2);
} END_TEST

/* Error codes: duplicate names, missing parents, unknown elements */
START_TEST(ErrorCodes) {
    buildBaseConfig();

    /* Duplicate connection name */
    UA_PubSubConfiguration2DataType cfg;
    UA_PubSubConfiguration2DataType_init(&cfg);
    UA_PubSubConnectionDataType conn;
    fileConnectionInit(&conn, "BaseConn", 9999);
    cfg.connections = &conn;
    cfg.connectionsSize = 1;

    UA_PubSubConfigurationRefDataType ref =
        makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION, 0, 0, 0);
    UA_PubSubConfigUpdateResult result;
    UA_StatusCode res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref,
                                                      false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0],
                     UA_STATUSCODE_BADBROWSENAMEDUPLICATED);
    ck_assert(!result.changesApplied);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* WriterGroup under a missing connection */
    UA_PubSubConfiguration2DataType cfg2;
    UA_PubSubConfiguration2DataType_init(&cfg2);
    UA_PubSubConnectionDataType parentConn;
    UA_PubSubConnectionDataType_init(&parentConn);
    parentConn.name = UA_STRING("MissingConn");
    UA_WriterGroupDataType wg;
    fileWriterGroupInit(&wg, "NewWG", 111);
    parentConn.writerGroups = &wg;
    parentConn.writerGroupsSize = 1;
    cfg2.connections = &parentConn;
    cfg2.connectionsSize = 1;

    UA_PubSubConfigurationRefDataType ref2 =
        makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP, 0, 0, 0);
    res = UA_Server_updatePubSubConfig2(server, &cfg2, 1, &ref2, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_BADNOTFOUND);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* Remove of an unknown connection */
    UA_PubSubConfiguration2DataType cfg3;
    UA_PubSubConfiguration2DataType_init(&cfg3);
    UA_PubSubConnectionDataType conn3;
    UA_PubSubConnectionDataType_init(&conn3);
    conn3.name = UA_STRING("MissingConn");
    cfg3.connections = &conn3;
    cfg3.connectionsSize = 1;
    UA_PubSubConfigurationRefDataType ref3 =
        makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTREMOVE |
                UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION, 0, 0, 0);
    res = UA_Server_updatePubSubConfig2(server, &cfg3, 1, &ref3, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_BADNOMATCH);
    UA_PubSubConfigUpdateResult_clear(&result);
} END_TEST

/* Mask and index validation */
START_TEST(MaskValidation) {
    buildBaseConfig();

    UA_PubSubConfiguration2DataType cfg;
    UA_PubSubConfiguration2DataType_init(&cfg);
    UA_PubSubConnectionDataType conn;
    fileConnectionInit(&conn, "X", 1);
    cfg.connections = &conn;
    cfg.connectionsSize = 1;

    UA_PubSubConfigUpdateResult result;

    /* Empty references */
    UA_StatusCode res = UA_Server_updatePubSubConfig2(server, &cfg, 0, NULL,
                                                      false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_BADNOTHINGTODO);

    /* Add and Modify combined */
    UA_PubSubConfigurationRefDataType ref =
        makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMODIFY |
                UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION, 0, 0, 0);
    res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_BADINVALIDARGUMENT);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* No reference bit */
    ref = makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD, 0, 0, 0);
    res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_BADINVALIDARGUMENT);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* Two reference bits */
    ref = makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                  UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION |
                  UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEPUBDATASET, 0, 0, 0);
    res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_BADINVALIDARGUMENT);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* Index out of range */
    ref = makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                  UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION, 0, 5, 0);
    res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_BADINVALIDARGUMENT);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* Match on a writer reference */
    ref = makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMATCH |
                  UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITER, 0, 0, 0);
    res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_BADINVALIDARGUMENT);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* SecurityGroup reference is not supported */
    ref = makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                  UA_PUBSUBCONFIGURATIONREFMASK_REFERENCESECURITYGROUP, 0, 0, 0);
    res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0],
                     UA_STATUSCODE_BADRESOURCEUNAVAILABLE);
    UA_PubSubConfigUpdateResult_clear(&result);
} END_TEST

/* Remove and re-add with the same name in one call (removes first) */
START_TEST(RemoveAndReAdd) {
    buildBaseConfig();
    UA_PubSubManager *psm = getPSM(server);
    ck_assert_uint_eq(psm->connectionsSize, 1);

    UA_PubSubConfiguration2DataType cfg;
    UA_PubSubConfiguration2DataType_init(&cfg);
    UA_PubSubConnectionDataType conns[2];
    /* [0] the new element to add, [1] the remove reference (name only) */
    fileConnectionInit(&conns[0], "BaseConn", 7777);
    UA_PubSubConnectionDataType_init(&conns[1]);
    conns[1].name = UA_STRING("BaseConn");
    cfg.connections = conns;
    cfg.connectionsSize = 2;

    UA_PubSubConfigurationRefDataType refs[2];
    /* The add is passed first -- the engine must process the remove first */
    refs[0] = makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                      UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION, 0, 0, 0);
    refs[1] = makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTREMOVE |
                      UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION, 0, 1, 0);

    UA_PubSubConfigUpdateResult result;
    UA_StatusCode res = UA_Server_updatePubSubConfig2(server, &cfg, 2, refs,
                                                      false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[1], UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(psm->connectionsSize, 1);

    /* The children of the removed connection are gone, the new connection
     * has the new PublisherId */
    UA_PubSubConnection *c = TAILQ_FIRST(&psm->connections);
    ck_assert_uint_eq(c->writerGroupsSize, 0);
    ck_assert_uint_eq(c->readerGroupsSize, 0);
    ck_assert_uint_eq(c->config.publisherId.id.uint16, 7777);
    UA_PubSubConfigUpdateResult_clear(&result);
} END_TEST

/* Modify a WriterGroup and check that the state is preserved */
START_TEST(ModifyElements) {
    buildBaseConfig();
    UA_PubSubManager *psm = getPSM(server);

    UA_PubSubConfiguration2DataType cfg;
    UA_PubSubConfiguration2DataType_init(&cfg);
    UA_PubSubConnectionDataType parentConn;
    UA_PubSubConnectionDataType_init(&parentConn);
    parentConn.name = UA_STRING("BaseConn");
    UA_WriterGroupDataType wg;
    fileWriterGroupInit(&wg, "BaseWG", 100);
    wg.publishingInterval = 250.0;
    parentConn.writerGroups = &wg;
    parentConn.writerGroupsSize = 1;
    cfg.connections = &parentConn;
    cfg.connectionsSize = 1;

    UA_PubSubConfigurationRefDataType ref =
        makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMODIFY |
                UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP, 0, 0, 0);

    UA_PubSubConfigUpdateResult result;
    UA_StatusCode res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref,
                                                      false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_GOOD);
    UA_PubSubConfigUpdateResult_clear(&result);

    UA_WriterGroup *liveWg = UA_WriterGroup_find(psm, baseWgId);
    ck_assert(liveWg != NULL);
    ck_assert(liveWg->config.publishingInterval == 250.0);
    /* The base config is disabled -- the state stays disabled */
    ck_assert_int_eq((int)liveWg->head.state, (int)UA_PUBSUBSTATE_DISABLED);

    /* Modify with an unknown name */
    wg.name = UA_STRING("MissingWG");
    res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_BADNOMATCH);
    UA_PubSubConfigUpdateResult_clear(&result);
} END_TEST

/* Modify a running WriterGroup: the operational state is restored */
START_TEST(ModifyRunning) {
    buildBaseConfig();
    UA_PubSubManager *psm = getPSM(server);
    UA_StatusCode res = UA_Server_enableAllPubSubComponents(server);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);

    UA_WriterGroup *liveWg = UA_WriterGroup_find(psm, baseWgId);
    ck_assert(UA_PubSubState_isEnabled(liveWg->head.state));

    UA_PubSubConfiguration2DataType cfg;
    UA_PubSubConfiguration2DataType_init(&cfg);
    UA_PubSubConnectionDataType parentConn;
    UA_PubSubConnectionDataType_init(&parentConn);
    parentConn.name = UA_STRING("BaseConn");
    UA_WriterGroupDataType wg;
    fileWriterGroupInit(&wg, "BaseWG", 100);
    wg.publishingInterval = 300.0;
    parentConn.writerGroups = &wg;
    parentConn.writerGroupsSize = 1;
    cfg.connections = &parentConn;
    cfg.connectionsSize = 1;

    UA_PubSubConfigurationRefDataType ref =
        makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMODIFY |
                UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP, 0, 0, 0);

    UA_PubSubConfigUpdateResult result;
    res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_GOOD);
    UA_PubSubConfigUpdateResult_clear(&result);

    ck_assert(liveWg->config.publishingInterval == 300.0);
    ck_assert(UA_PubSubState_isEnabled(liveWg->head.state));
} END_TEST

/* Match operations on connections */
START_TEST(MatchElements) {
    buildBaseConfig();

    /* Matching connection: same profile and address as BaseConn */
    UA_PubSubConfiguration2DataType cfg;
    UA_PubSubConfiguration2DataType_init(&cfg);
    UA_PubSubConnectionDataType conn;
    UA_PubSubConnectionDataType_init(&conn);
    conn.transportProfileUri = UA_STRING(PROFILE_UDP);
    UA_NetworkAddressUrlDataType addr;
    UA_PubSubTest_initNetworkAddressUrl(&addr,
        UA_PubSubTest_getUdpMulticastUrl4801());
    conn.address.encoding = UA_EXTENSIONOBJECT_DECODED_NODELETE;
    conn.address.content.decoded.type =
        &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE];
    conn.address.content.decoded.data = &addr;
    cfg.connections = &conn;
    cfg.connectionsSize = 1;

    UA_PubSubConfigurationRefDataType ref =
        makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMATCH |
                UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION, 0, 0, 0);

    UA_PubSubConfigUpdateResult result;
    UA_StatusCode res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref,
                                                      false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(result.configurationValuesSize, 1);
    UA_String baseName = UA_STRING("BaseConn");
    ck_assert(UA_String_equal(&result.configurationValues[0].name, &baseName));
    /* A pure match does not change the configuration */
    ck_assert(!result.changesApplied);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* Mismatching address */
    UA_PubSubTest_initNetworkAddressUrl(&addr, (char*)(uintptr_t)"opc.udp://224.0.0.99:9999/");
    res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_BADNOMATCH);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* Match|Add: no match -> the connection is added */
    conn.name = UA_STRING("MatchAddConn");
    UA_UInt16 pubId = 4567;
    UA_Variant_setScalar(&conn.publisherId, &pubId, &UA_TYPES[UA_TYPES_UINT16]);
    ref = makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                  UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTMATCH |
                  UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION, 0, 0, 0);
    res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_GOOD);
    ck_assert(result.changesApplied);
    UA_PubSubManager *psm = getPSM(server);
    ck_assert_uint_eq(psm->connectionsSize, 2);
    UA_PubSubConfigUpdateResult_clear(&result);
} END_TEST

/* RequireCompleteUpdate: a single invalid reference prevents all changes */
START_TEST(Atomicity) {
    buildBaseConfig();
    UA_PubSubManager *psm = getPSM(server);
    UA_PubSubConnection *baseConn = UA_PubSubConnection_find(psm, baseConnId);
    ck_assert_uint_eq(baseConn->writerGroupsSize, 1);

    UA_PubSubConfiguration2DataType cfg;
    UA_PubSubConfiguration2DataType_init(&cfg);
    UA_PubSubConnectionDataType conns[2];
    UA_PubSubConnectionDataType_init(&conns[0]);
    conns[0].name = UA_STRING("BaseConn");
    UA_WriterGroupDataType wg;
    fileWriterGroupInit(&wg, "AtomicWG", 150);
    conns[0].writerGroups = &wg;
    conns[0].writerGroupsSize = 1;
    UA_PubSubConnectionDataType_init(&conns[1]);
    conns[1].name = UA_STRING("MissingConn");
    UA_WriterGroupDataType wg2;
    fileWriterGroupInit(&wg2, "AtomicWG2", 151);
    conns[1].writerGroups = &wg2;
    conns[1].writerGroupsSize = 1;
    cfg.connections = conns;
    cfg.connectionsSize = 2;

    UA_PubSubConfigurationRefDataType refs[2];
    refs[0] = makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                      UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP, 0, 0, 0);
    refs[1] = makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                      UA_PUBSUBCONFIGURATIONREFMASK_REFERENCEWRITERGROUP, 0, 1, 0);

    /* Complete update required: nothing is applied */
    UA_PubSubConfigUpdateResult result;
    UA_StatusCode res = UA_Server_updatePubSubConfig2(server, &cfg, 2, refs,
                                                      true, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert(!result.changesApplied);
    ck_assert_int_eq(result.referencesResults[1], UA_STATUSCODE_BADNOTFOUND);
    ck_assert_uint_eq(baseConn->writerGroupsSize, 1);
    UA_PubSubConfigUpdateResult_clear(&result);

    /* Partial update allowed: the valid reference is applied */
    res = UA_Server_updatePubSubConfig2(server, &cfg, 2, refs, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert(result.changesApplied);
    ck_assert_int_eq(result.referencesResults[0], UA_STATUSCODE_GOOD);
    ck_assert_int_eq(result.referencesResults[1], UA_STATUSCODE_BADNOTFOUND);
    ck_assert_uint_eq(baseConn->writerGroupsSize, 2);
    UA_PubSubConfigUpdateResult_clear(&result);
} END_TEST

/* Top-level fields: ConfigurationProperties merge and version bump */
START_TEST(TopLevelFields) {
    buildBaseConfig();
    UA_PubSubManager *psm = getPSM(server);
    UA_UInt32 versionBefore = psm->configurationVersion;

    /* Insert a property along with an add operation */
    UA_PubSubConfiguration2DataType cfg;
    UA_PubSubConfiguration2DataType_init(&cfg);
    UA_PubSubConnectionDataType conn;
    fileConnectionInit(&conn, "PropConn", 3434);
    cfg.connections = &conn;
    cfg.connectionsSize = 1;
    UA_KeyValuePair prop;
    prop.key = UA_QUALIFIEDNAME(0, "Vendor");
    UA_UInt32 vendorValue = 99;
    UA_Variant_setScalar(&prop.value, &vendorValue, &UA_TYPES[UA_TYPES_UINT32]);
    cfg.configurationProperties = &prop;
    cfg.configurationPropertiesSize = 1;

    UA_PubSubConfigurationRefDataType ref =
        makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
                UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION, 0, 0, 0);

    UA_PubSubConfigUpdateResult result;
    UA_StatusCode res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref,
                                                      false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert(result.changesApplied);
    UA_PubSubConfigUpdateResult_clear(&result);

    const UA_Variant *v = UA_KeyValueMap_get(&psm->configurationProperties,
                                             UA_QUALIFIEDNAME(0, "Vendor"));
    ck_assert(v != NULL);
    ck_assert_uint_eq(*(UA_UInt32*)v->data, 99);
    ck_assert(psm->configurationVersion != versionBefore);

    /* Delete the property with a null value. The referenced remove op keeps
     * the update valid. */
    UA_Variant_init(&prop.value);
    conn.name = UA_STRING("PropConn");
    ref = makeRef(UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTREMOVE |
                  UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION, 0, 0, 0);
    res = UA_Server_updatePubSubConfig2(server, &cfg, 1, &ref, false, &result);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    ck_assert(result.changesApplied);
    UA_PubSubConfigUpdateResult_clear(&result);

    v = UA_KeyValueMap_get(&psm->configurationProperties,
                           UA_QUALIFIEDNAME(0, "Vendor"));
    ck_assert(v == NULL);
} END_TEST

int main(void) {
    TCase *tc_incremental = tcase_create("CloseAndUpdate element operations");
    tcase_add_checked_fixture(tc_incremental, setup, teardown);
    tcase_add_test(tc_incremental, AddElements);
    tcase_add_test(tc_incremental, AutoAssign);
    tcase_add_test(tc_incremental, ErrorCodes);
    tcase_add_test(tc_incremental, MaskValidation);
    tcase_add_test(tc_incremental, RemoveAndReAdd);
    tcase_add_test(tc_incremental, ModifyElements);
    tcase_add_test(tc_incremental, ModifyRunning);
    tcase_add_test(tc_incremental, MatchElements);
    tcase_add_test(tc_incremental, Atomicity);
    tcase_add_test(tc_incremental, TopLevelFields);

    Suite *s = suite_create("PubSub Configuration2 incremental update");
    suite_add_tcase(s, tc_incremental);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
