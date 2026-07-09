/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */

/* Server with file-based PubSub configuration (OPC UA Part 14 v1.05, 9.1.3.7)
 *
 * The configuration file is a UA Binary encoded ExtensionObject with a
 * UABinaryFileDataType that contains a PubSubConfiguration2DataType (or the
 * legacy PubSubConfigurationDataType) as body.
 *
 * The server exposes the standard PubSubConfiguration FileType object below
 * PublishSubscribe (requires the PubSub information model). OPC UA clients
 * can read the running configuration with Open(Read)/Read/Close and apply
 * incremental updates with Open(Write+EraseExisting)/Write/CloseAndUpdate --
 * see the matching client example client_pubsub_config2_update.c.
 *
 * Usage: ./server_pubsub_file_configuration [configfile.bin]
 *
 * When a configuration file is given, it is loaded at startup (full replace)
 * and the running configuration is written back to the file on shutdown.
 * Without a file a small demo publisher is created via the C API. */

#include <open62541/plugin/log_stdout.h>
#include <open62541/server.h>
#include <open62541/server_pubsub.h>
#include <open62541/server_config_default.h>

#include "common.h"

static void
addPubSubVariables(UA_Server *server) {
    UA_NodeId parentReferenceNodeId = UA_NS0ID(ORGANIZES);
    UA_NodeId pubSubVariableObjectId = UA_NODEID_STRING(1, "PubSubObject");

    UA_ObjectAttributes oAttr = UA_ObjectAttributes_default;
    oAttr.displayName = UA_LOCALIZEDTEXT("en-US", "PubSubVariables");
    UA_Server_addObjectNode(server, pubSubVariableObjectId, UA_NS0ID(OBJECTSFOLDER),
                            parentReferenceNodeId, UA_QUALIFIEDNAME(1, "PubSubVariables"),
                            UA_NS0ID(BASEOBJECTTYPE),
                            oAttr, NULL, NULL);

    UA_VariableAttributes attr = UA_VariableAttributes_default;
    UA_Boolean myBool = UA_TRUE;
    UA_Variant_setScalar(&attr.value, &myBool, &UA_TYPES[UA_TYPES_BOOLEAN]);
    attr.description = UA_LOCALIZEDTEXT("en-US","BoolToggle");
    attr.displayName = UA_LOCALIZEDTEXT("en-US","BoolToggle");
    attr.dataType = UA_TYPES[UA_TYPES_BOOLEAN].typeId;
    attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
    UA_Server_addVariableNode(server, UA_NODEID_STRING(1, "BoolToggle"),
                              pubSubVariableObjectId,
                              parentReferenceNodeId, UA_QUALIFIEDNAME(1, "BoolToggle"),
                              UA_NS0ID(BASEDATAVARIABLETYPE), attr, NULL, NULL);

    attr = UA_VariableAttributes_default;
    UA_Int32 myInteger = 0;
    UA_Variant_setScalar(&attr.value, &myInteger, &UA_TYPES[UA_TYPES_INT32]);
    attr.description = UA_LOCALIZEDTEXT("en-US","Int32");
    attr.displayName = UA_LOCALIZEDTEXT("en-US","Int32");
    attr.dataType = UA_TYPES[UA_TYPES_INT32].typeId;
    attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
    UA_Server_addVariableNode(server, UA_NODEID_STRING(1, "Int32"),
                              pubSubVariableObjectId,
                              parentReferenceNodeId, UA_QUALIFIEDNAME(1, "Int32"),
                              UA_NS0ID(BASEDATAVARIABLETYPE), attr, NULL, NULL);

    attr = UA_VariableAttributes_default;
    UA_Int32 myIntegerFast = 24;
    UA_Variant_setScalar(&attr.value, &myIntegerFast, &UA_TYPES[UA_TYPES_INT32]);
    attr.description = UA_LOCALIZEDTEXT("en-US","Int32Fast");
    attr.displayName = UA_LOCALIZEDTEXT("en-US","Int32Fast");
    attr.dataType = UA_TYPES[UA_TYPES_INT32].typeId;
    attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
    UA_Server_addVariableNode(server, UA_NODEID_STRING(1, "Int32Fast"),
                              pubSubVariableObjectId,
                              parentReferenceNodeId, UA_QUALIFIEDNAME(1, "Int32Fast"),
                              UA_NS0ID(BASEDATAVARIABLETYPE), attr, NULL, NULL);

    attr = UA_VariableAttributes_default;
    UA_DateTime myDate = UA_DateTime_now() + UA_DateTime_localTimeUtcOffset();
    UA_Variant_setScalar(&attr.value, &myDate, &UA_TYPES[UA_TYPES_DATETIME]);
    attr.description = UA_LOCALIZEDTEXT("en-US","DateTime");
    attr.displayName = UA_LOCALIZEDTEXT("en-US","DateTime");
    attr.dataType = UA_TYPES[UA_TYPES_DATETIME].typeId;
    attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
    UA_Server_addVariableNode(server, UA_NODEID_STRING(1, "DateTime"),
                              pubSubVariableObjectId,
                              parentReferenceNodeId, UA_QUALIFIEDNAME(1, "DateTime"),
                              UA_NS0ID(BASEDATAVARIABLETYPE), attr, NULL, NULL);
}

/* Create a small demo publisher via the C API. This is the configuration
 * that clients see when they read the PubSubConfiguration file object. */
static void
addDemoPublisher(UA_Server *server) {
    UA_PubSubConnectionConfig connectionConfig;
    memset(&connectionConfig, 0, sizeof(connectionConfig));
    connectionConfig.name = UA_STRING("Demo Connection");
    UA_NetworkAddressUrlDataType networkAddressUrl =
        {UA_STRING_NULL, UA_STRING("opc.udp://224.0.0.22:4840/")};
    UA_Variant_setScalar(&connectionConfig.address, &networkAddressUrl,
                         &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE]);
    connectionConfig.transportProfileUri =
        UA_STRING("http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp");
    connectionConfig.publisherId.idType = UA_PUBLISHERIDTYPE_UINT16;
    connectionConfig.publisherId.id.uint16 = 2234;
    UA_NodeId connectionId;
    UA_Server_addPubSubConnection(server, &connectionConfig, &connectionId);

    UA_PublishedDataSetConfig pdsConfig;
    memset(&pdsConfig, 0, sizeof(pdsConfig));
    pdsConfig.name = UA_STRING("Demo PDS");
    pdsConfig.publishedDataSetType = UA_PUBSUB_DATASET_PUBLISHEDITEMS;
    UA_NodeId pdsId;
    UA_Server_addPublishedDataSet(server, &pdsConfig, &pdsId);

    UA_DataSetFieldConfig fieldConfig;
    memset(&fieldConfig, 0, sizeof(fieldConfig));
    fieldConfig.dataSetFieldType = UA_PUBSUB_DATASETFIELD_VARIABLE;
    fieldConfig.field.variable.fieldNameAlias = UA_STRING("Int32");
    fieldConfig.field.variable.publishParameters.publishedVariable =
        UA_NODEID_STRING(1, "Int32");
    fieldConfig.field.variable.publishParameters.attributeId = UA_ATTRIBUTEID_VALUE;
    UA_Server_addDataSetField(server, pdsId, &fieldConfig, NULL);

    UA_WriterGroupConfig wgConfig;
    memset(&wgConfig, 0, sizeof(wgConfig));
    wgConfig.name = UA_STRING("Demo WriterGroup");
    wgConfig.writerGroupId = 100;
    wgConfig.publishingInterval = 100.0;
    wgConfig.keepAliveTime = 10000.0;
    UA_NodeId wgId;
    UA_Server_addWriterGroup(server, connectionId, &wgConfig, &wgId);

    UA_DataSetWriterConfig dswConfig;
    memset(&dswConfig, 0, sizeof(dswConfig));
    dswConfig.name = UA_STRING("Demo DataSetWriter");
    dswConfig.dataSetWriterId = 200;
    UA_Server_addDataSetWriter(server, wgId, pdsId, &dswConfig, NULL);
}

static void usage_info(void) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                "USAGE: ./server_pubsub_file_configuration [name of UA_Binary_Config_File]");
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                "Without a file a demo publisher is created via the C API. "
                "Clients can read/update the configuration through the "
                "PubSubConfiguration file object below PublishSubscribe.");
}

int main(int argc, char** argv) {
    UA_Boolean loadPubSubFromFile = UA_FALSE;

    /* 1. Check arguments and set name of PubSub configuration file */
    switch(argc) {
        case 2:
            loadPubSubFromFile = UA_TRUE;
            break;
        default:
            usage_info();
    }

    /* 2. Initialize the server */
    UA_Server *server = UA_Server_new();

    /* 3. Add the variable nodes used by the demo configurations */
    addPubSubVariables(server);

    /* 4. Load the configuration from the file (full replace) or create the
     * demo publisher via the C API */
    if(loadPubSubFromFile) {
        UA_ByteString configuration = loadFile(argv[1]);
        UA_StatusCode res =
            UA_Server_loadPubSubConfigFromByteString(server, configuration);
        UA_ByteString_clear(&configuration);
        if(res != UA_STATUSCODE_GOOD)
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                         "Loading the PubSub configuration failed with %s",
                         UA_StatusCode_name(res));
    } else {
        addDemoPublisher(server);
    }

    /* 5. Start the server. Besides the ByteString load/save used here, the
     * configuration is accessible to clients through the standard
     * PubSubConfiguration FileType object (Open/Read/Write/CloseAndUpdate,
     * Part 14 v1.05 9.1.3.7). */
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION, "Starting server...");

    UA_StatusCode statusCode = UA_STATUSCODE_GOOD;
    statusCode |= UA_Server_enableAllPubSubComponents(server);
    statusCode |= UA_Server_runUntilInterrupt(server);
    if(statusCode != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                     "Server stopped. Status code: 0x%x\n", statusCode);
        UA_Server_delete(server);
        return -1;
    }

    if(loadPubSubFromFile) {
        /* 6. Save the current configuration back to the file. The export is
         * a PubSubConfiguration2DataType body. */
        UA_ByteString buffer = UA_BYTESTRING_NULL;
        statusCode = UA_Server_writePubSubConfigurationToByteString(server, &buffer);
        if(statusCode == UA_STATUSCODE_GOOD)
            statusCode = writeFile(argv[1], buffer);

        if(statusCode != UA_STATUSCODE_GOOD)
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_APPLICATION,
                         "Saving PubSub configuration to file failed. "
                         "StatusCode: 0x%x\n", statusCode);

        UA_ByteString_clear(&buffer);
    }

    UA_Server_delete(server);

    return 0;
}
