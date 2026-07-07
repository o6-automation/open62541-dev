/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */

/* Client for the PubSubConfiguration FileType object (OPC UA Part 14,
 * 9.1.3.7). The client demonstrates the standard sequences against a server
 * with UA_ENABLE_PUBSUB_FILE_CONFIG and the PubSub information model (for
 * example examples/pubsub/server_pubsub_file_configuration):
 *
 * 1. Read the configuration:
 *    Open(Read) -> Read (chunked) -> Close -> decode the
 *    PubSubConfiguration2DataType and print a summary.
 *
 * 2. Apply an incremental update:
 *    Open(Write+EraseExisting) -> Write the update file -> CloseAndUpdate
 *    with a ConfigurationReferences entry that adds a PubSubConnection.
 *
 * Usage: ./client_pubsub_config2_update [opc.tcp://server:port] */

#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/log_stdout.h>

#include <stdlib.h>

#define FILE_OBJECT UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION)

static UA_StatusCode
openFile(UA_Client *client, UA_Byte mode, UA_UInt32 *fileHandle) {
    UA_Variant input;
    UA_Variant_setScalar(&input, &mode, &UA_TYPES[UA_TYPES_BYTE]);
    size_t outputSize = 0;
    UA_Variant *output = NULL;
    UA_StatusCode res = UA_Client_call(client, FILE_OBJECT,
        UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_OPEN),
        1, &input, &outputSize, &output);
    if(res == UA_STATUSCODE_GOOD && outputSize == 1)
        *fileHandle = *(UA_UInt32*)output[0].data;
    UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    return res;
}

static UA_StatusCode
closeFile(UA_Client *client, UA_UInt32 fileHandle) {
    UA_Variant input;
    UA_Variant_setScalar(&input, &fileHandle, &UA_TYPES[UA_TYPES_UINT32]);
    size_t outputSize = 0;
    UA_Variant *output = NULL;
    UA_StatusCode res = UA_Client_call(client, FILE_OBJECT,
        UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_CLOSE),
        1, &input, &outputSize, &output);
    UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    return res;
}

/* Read the complete file in chunks */
static UA_StatusCode
readFile(UA_Client *client, UA_UInt32 fileHandle, UA_ByteString *content) {
    UA_ByteString_init(content);
    UA_Int32 chunkSize = 2048;
    while(true) {
        UA_Variant input[2];
        UA_Variant_setScalar(&input[0], &fileHandle, &UA_TYPES[UA_TYPES_UINT32]);
        UA_Variant_setScalar(&input[1], &chunkSize, &UA_TYPES[UA_TYPES_INT32]);
        size_t outputSize = 0;
        UA_Variant *output = NULL;
        UA_StatusCode res = UA_Client_call(client, FILE_OBJECT,
            UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_READ),
            2, input, &outputSize, &output);
        if(res != UA_STATUSCODE_GOOD)
            return res;
        UA_ByteString *chunk = (UA_ByteString*)output[0].data;
        if(chunk->length == 0) {
            UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
            break; /* Complete */
        }
        UA_Byte *merged = (UA_Byte*)
            UA_realloc(content->data, content->length + chunk->length);
        if(!merged) {
            UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        memcpy(merged + content->length, chunk->data, chunk->length);
        content->data = merged;
        content->length += chunk->length;
        UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
writeFile(UA_Client *client, UA_UInt32 fileHandle, const UA_ByteString data) {
    UA_Variant input[2];
    UA_Variant_setScalar(&input[0], &fileHandle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&input[1], (void*)(uintptr_t)&data,
                         &UA_TYPES[UA_TYPES_BYTESTRING]);
    size_t outputSize = 0;
    UA_Variant *output = NULL;
    UA_StatusCode res = UA_Client_call(client, FILE_OBJECT,
        UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_WRITE),
        2, input, &outputSize, &output);
    UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    return res;
}

/* 1. Read and print the current configuration */
static UA_StatusCode
readConfiguration(UA_Client *client) {
    UA_UInt32 fileHandle = 0;
    UA_StatusCode res = openFile(client, UA_OPENFILEMODE_READ, &fileHandle);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_ByteString content = UA_BYTESTRING_NULL;
    res = readFile(client, fileHandle, &content);
    closeFile(client, fileHandle);
    if(res != UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(&content);
        return res;
    }

    /* The file content is an ExtensionObject with a UABinaryFileDataType.
     * The body holds the PubSubConfiguration2DataType. */
    UA_ExtensionObject eo;
    res = UA_decodeBinary(&content, &eo, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT], NULL);
    UA_ByteString_clear(&content);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    if(eo.encoding != UA_EXTENSIONOBJECT_DECODED ||
       eo.content.decoded.type != &UA_TYPES[UA_TYPES_UABINARYFILEDATATYPE]) {
        UA_ExtensionObject_clear(&eo);
        return UA_STATUSCODE_BADTYPEMISMATCH;
    }
    UA_UABinaryFileDataType *binFile =
        (UA_UABinaryFileDataType*)eo.content.decoded.data;
    if(!UA_Variant_hasScalarType(&binFile->body,
           &UA_TYPES[UA_TYPES_PUBSUBCONFIGURATION2DATATYPE])) {
        UA_ExtensionObject_clear(&eo);
        return UA_STATUSCODE_BADTYPEMISMATCH;
    }
    UA_PubSubConfiguration2DataType *cfg =
        (UA_PubSubConfiguration2DataType*)binFile->body.data;

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "Current PubSub configuration: %u connections, "
                "%u PublishedDataSets, ConfigurationVersion %u",
                (UA_UInt32)cfg->connectionsSize,
                (UA_UInt32)cfg->publishedDataSetsSize,
                cfg->configurationVersion);
    for(size_t i = 0; i < cfg->connectionsSize; i++) {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "  Connection \"%.*s\": %u WriterGroups, %u ReaderGroups",
                    (int)cfg->connections[i].name.length,
                    cfg->connections[i].name.data,
                    (UA_UInt32)cfg->connections[i].writerGroupsSize,
                    (UA_UInt32)cfg->connections[i].readerGroupsSize);
    }

    UA_ExtensionObject_clear(&eo);
    return UA_STATUSCODE_GOOD;
}

/* 2. Add a PubSubConnection through CloseAndUpdate */
static UA_StatusCode
updateConfiguration(UA_Client *client) {
    UA_UInt32 fileHandle = 0;
    UA_StatusCode res = openFile(client,
        UA_OPENFILEMODE_WRITE | UA_OPENFILEMODE_ERASEEXISTING, &fileHandle);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* Build the update file: one connection element */
    UA_PubSubConfiguration2DataType cfg;
    UA_PubSubConfiguration2DataType_init(&cfg);
    UA_PubSubConnectionDataType conn;
    UA_PubSubConnectionDataType_init(&conn);
    conn.name = UA_STRING("Client Added Connection");
    conn.transportProfileUri =
        UA_STRING("http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp");
    UA_NetworkAddressUrlDataType addr =
        {UA_STRING_NULL, UA_STRING("opc.udp://224.0.0.23:4841/")};
    conn.address.encoding = UA_EXTENSIONOBJECT_DECODED_NODELETE;
    conn.address.content.decoded.type =
        &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE];
    conn.address.content.decoded.data = &addr;
    UA_UInt16 publisherId = 4711;
    UA_Variant_setScalar(&conn.publisherId, &publisherId,
                         &UA_TYPES[UA_TYPES_UINT16]);
    cfg.connections = &conn;
    cfg.connectionsSize = 1;

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
    res = UA_encodeBinary(&eo, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT], &blob, NULL);
    if(res != UA_STATUSCODE_GOOD) {
        closeFile(client, fileHandle);
        return res;
    }

    res = writeFile(client, fileHandle, blob);
    UA_ByteString_clear(&blob);
    if(res != UA_STATUSCODE_GOOD) {
        closeFile(client, fileHandle);
        return res;
    }

    /* CloseAndUpdate: add the connection element (index 0 in the file) */
    UA_PubSubConfigurationRefDataType ref;
    UA_PubSubConfigurationRefDataType_init(&ref);
    ref.configurationMask = UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
        UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION;

    UA_Variant input[3];
    UA_Variant_setScalar(&input[0], &fileHandle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Boolean requireCompleteUpdate = true;
    UA_Variant_setScalar(&input[1], &requireCompleteUpdate,
                         &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_Variant_setArray(&input[2], &ref, 1,
                        &UA_TYPES[UA_TYPES_PUBSUBCONFIGURATIONREFDATATYPE]);

    size_t outputSize = 0;
    UA_Variant *output = NULL;
    res = UA_Client_call(client, FILE_OBJECT,
        UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_CLOSEANDUPDATE),
        3, input, &outputSize, &output);
    if(res != UA_STATUSCODE_GOOD) {
        closeFile(client, fileHandle);
        return res;
    }

    UA_Boolean changesApplied = *(UA_Boolean*)output[0].data;
    UA_StatusCode *refResults = (UA_StatusCode*)output[1].data;
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "CloseAndUpdate: ChangesApplied=%s, first reference result %s",
                changesApplied ? "true" : "false",
                UA_StatusCode_name(refResults[0]));

    UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    return UA_STATUSCODE_GOOD;
}

int main(int argc, char *argv[]) {
    const char *url = "opc.tcp://localhost:4840";
    if(argc > 1)
        url = argv[1];

    UA_Client *client = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));
    UA_StatusCode res = UA_Client_connect(client, url);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Could not connect to %s: %s", url, UA_StatusCode_name(res));
        UA_Client_delete(client);
        return EXIT_FAILURE;
    }

    res = readConfiguration(client);
    if(res != UA_STATUSCODE_GOOD)
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Reading the configuration failed: %s",
                     UA_StatusCode_name(res));

    res = updateConfiguration(client);
    if(res != UA_STATUSCODE_GOOD)
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Updating the configuration failed: %s",
                     UA_StatusCode_name(res));

    /* Read again to show the added connection */
    res = readConfiguration(client);
    if(res != UA_STATUSCODE_GOOD)
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Reading the configuration failed: %s",
                     UA_StatusCode_name(res));

    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return (res == UA_STATUSCODE_GOOD) ? EXIT_SUCCESS : EXIT_FAILURE;
}
