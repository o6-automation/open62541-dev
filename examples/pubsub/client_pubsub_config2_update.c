/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */

/* Client for the PubSubConfiguration file object (OPC UA Part 14 v1.05,
 * 9.1.3.7) of a server with the PubSub information model and the
 * file-transfer driver, for example
 * examples/pubsub/server_pubsub_file_configuration:
 *
 * 1. Open(Read) -> Read (chunked) -> Close, print a summary of the
 *    PubSubConfiguration2DataType in the file.
 * 2. Open(Write+EraseExisting) -> Write an update file -> CloseAndUpdate with
 *    a reference that adds the PubSubConnection of the file.
 *
 * Usage: ./client_pubsub_config2_update [opc.tcp://server:port] */

#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/log_stdout.h>

#include <stdlib.h>

#define FILE_METHOD(NAME) \
    UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_##NAME)

/* Call a Method of the PubSubConfiguration object. Without output the output
 * arguments are discarded. */
static UA_StatusCode
callFileMethod(UA_Client *client, const UA_NodeId methodId, size_t inputSize,
               UA_Variant *input, size_t *outputSize, UA_Variant **output) {
    size_t discardSize = 0;
    UA_Variant *discard = NULL;
    UA_StatusCode res = UA_Client_call(client,
        UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION),
        methodId, inputSize, input,
        (output) ? outputSize : &discardSize, (output) ? output : &discard);
    UA_Array_delete(discard, discardSize, &UA_TYPES[UA_TYPES_VARIANT]);
    return res;
}

static UA_StatusCode
openFile(UA_Client *client, UA_Byte mode, UA_UInt32 *fileHandle) {
    UA_Variant input;
    UA_Variant_setScalar(&input, &mode, &UA_TYPES[UA_TYPES_BYTE]);
    size_t outputSize = 0;
    UA_Variant *output = NULL;
    UA_StatusCode res = callFileMethod(client, FILE_METHOD(OPEN), 1, &input,
                                       &outputSize, &output);
    if(res == UA_STATUSCODE_GOOD)
        *fileHandle = *(UA_UInt32*)output[0].data;
    UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    return res;
}

static void
closeFile(UA_Client *client, UA_UInt32 fileHandle) {
    UA_Variant input;
    UA_Variant_setScalar(&input, &fileHandle, &UA_TYPES[UA_TYPES_UINT32]);
    callFileMethod(client, FILE_METHOD(CLOSE), 1, &input, NULL, NULL);
}

/* The file content is a UA Binary encoded ExtensionObject with a
 * UABinaryFileDataType whose body is the PubSubConfiguration2DataType */
static UA_StatusCode
encodeFile(UA_PubSubConfiguration2DataType *cfg, UA_ByteString *file) {
    UA_UABinaryFileDataType binFile;
    UA_UABinaryFileDataType_init(&binFile);
    UA_Variant_setScalar(&binFile.body, cfg,
                         &UA_TYPES[UA_TYPES_PUBSUBCONFIGURATION2DATATYPE]);
    UA_ExtensionObject eo;
    UA_ExtensionObject_setValueNoDelete(&eo, &binFile,
                                        &UA_TYPES[UA_TYPES_UABINARYFILEDATATYPE]);
    UA_ByteString_init(file);
    return UA_encodeBinary(&eo, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT], file, NULL);
}

/* 1. Read the file in chunks and print a summary */
static UA_StatusCode
readConfiguration(UA_Client *client) {
    UA_UInt32 fileHandle = 0;
    UA_StatusCode res = openFile(client, UA_OPENFILEMODE_READ, &fileHandle);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    UA_ByteString content = UA_BYTESTRING_NULL;
    UA_Int32 chunkSize = 2048;
    while(res == UA_STATUSCODE_GOOD) {
        UA_Variant input[2];
        UA_Variant_setScalar(&input[0], &fileHandle, &UA_TYPES[UA_TYPES_UINT32]);
        UA_Variant_setScalar(&input[1], &chunkSize, &UA_TYPES[UA_TYPES_INT32]);
        size_t outputSize = 0;
        UA_Variant *output = NULL;
        res = callFileMethod(client, FILE_METHOD(READ), 2, input,
                             &outputSize, &output);
        if(res != UA_STATUSCODE_GOOD)
            break;
        UA_ByteString *chunk = (UA_ByteString*)output[0].data;
        if(chunk->length == 0) {
            UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
            break; /* End of the file */
        }
        UA_Byte *merged = (UA_Byte*)
            UA_realloc(content.data, content.length + chunk->length);
        if(merged) {
            memcpy(merged + content.length, chunk->data, chunk->length);
            content.data = merged;
            content.length += chunk->length;
        } else {
            res = UA_STATUSCODE_BADOUTOFMEMORY;
        }
        UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    }
    closeFile(client, fileHandle);

    UA_ExtensionObject eo;
    UA_ExtensionObject_init(&eo);
    if(res == UA_STATUSCODE_GOOD)
        res = UA_decodeBinary(&content, &eo, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT], NULL);
    UA_ByteString_clear(&content);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    UA_UABinaryFileDataType *binFile =
        (UA_UABinaryFileDataType*)eo.content.decoded.data;
    if(!UA_ExtensionObject_hasDecodedType(&eo, &UA_TYPES[UA_TYPES_UABINARYFILEDATATYPE]) ||
       !UA_Variant_hasScalarType(&binFile->body,
                                 &UA_TYPES[UA_TYPES_PUBSUBCONFIGURATION2DATATYPE])) {
        UA_ExtensionObject_clear(&eo);
        return UA_STATUSCODE_BADTYPEMISMATCH;
    }
    UA_PubSubConfiguration2DataType *cfg =
        (UA_PubSubConfiguration2DataType*)binFile->body.data;
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "PubSub configuration: %u connections, %u PublishedDataSets",
                (unsigned)cfg->connectionsSize, (unsigned)cfg->publishedDataSetsSize);
    for(size_t i = 0; i < cfg->connectionsSize; i++)
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "  Connection \"%S\": %u WriterGroups, %u ReaderGroups",
                    cfg->connections[i].name,
                    (unsigned)cfg->connections[i].writerGroupsSize,
                    (unsigned)cfg->connections[i].readerGroupsSize);
    UA_ExtensionObject_clear(&eo);
    return UA_STATUSCODE_GOOD;
}

/* 2. Add a PubSubConnection with CloseAndUpdate */
static UA_StatusCode
updateConfiguration(UA_Client *client) {
    UA_PubSubConfiguration2DataType cfg;
    UA_PubSubConfiguration2DataType_init(&cfg);
    UA_PubSubConnectionDataType conn;
    UA_PubSubConnectionDataType_init(&conn);
    conn.name = UA_STRING("Client Added Connection");
    conn.transportProfileUri =
        UA_STRING("http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp");
    UA_NetworkAddressUrlDataType addr =
        {UA_STRING_NULL, UA_STRING("opc.udp://224.0.0.23:4841/")};
    UA_ExtensionObject_setValueNoDelete(&conn.address, &addr,
        &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE]);
    UA_UInt16 publisherId = 4711;
    UA_Variant_setScalar(&conn.publisherId, &publisherId, &UA_TYPES[UA_TYPES_UINT16]);
    cfg.connections = &conn;
    cfg.connectionsSize = 1;
    UA_ByteString file;
    UA_StatusCode res = encodeFile(&cfg, &file);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    UA_UInt32 fileHandle = 0;
    res = openFile(client, UA_OPENFILEMODE_WRITE | UA_OPENFILEMODE_ERASEEXISTING,
                   &fileHandle);
    if(res != UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(&file);
        return res;
    }
    UA_Variant input[3];
    UA_Variant_setScalar(&input[0], &fileHandle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&input[1], &file, &UA_TYPES[UA_TYPES_BYTESTRING]);
    res = callFileMethod(client, FILE_METHOD(WRITE), 2, input, NULL, NULL);
    UA_ByteString_clear(&file);

    /* Add the connection element (index 0 of the file) and close the file */
    UA_PubSubConfigurationRefDataType ref;
    UA_PubSubConfigurationRefDataType_init(&ref);
    ref.configurationMask = UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
        UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION;
    UA_Boolean requireCompleteUpdate = true;
    UA_Variant_setScalar(&input[1], &requireCompleteUpdate,
                         &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_Variant_setArray(&input[2], &ref, 1,
                        &UA_TYPES[UA_TYPES_PUBSUBCONFIGURATIONREFDATATYPE]);
    size_t outputSize = 0;
    UA_Variant *output = NULL;
    if(res == UA_STATUSCODE_GOOD)
        res = callFileMethod(client, FILE_METHOD(CLOSEANDUPDATE), 3, input,
                             &outputSize, &output);
    if(res != UA_STATUSCODE_GOOD) {
        closeFile(client, fileHandle);
        return res;
    }
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "CloseAndUpdate: ChangesApplied %s, reference result %s",
                *(UA_Boolean*)output[0].data ? "true" : "false",
                UA_StatusCode_name(((UA_StatusCode*)output[1].data)[0]));
    UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    return UA_STATUSCODE_GOOD;
}

int main(int argc, char *argv[]) {
    const char *url = (argc > 1) ? argv[1] : "opc.tcp://localhost:4840";
    UA_Client *client = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));
    UA_StatusCode res = UA_Client_connect(client, url);
    if(res == UA_STATUSCODE_GOOD)
        res = readConfiguration(client);
    if(res == UA_STATUSCODE_GOOD)
        res = updateConfiguration(client);
    if(res == UA_STATUSCODE_GOOD)
        res = readConfiguration(client); /* Shows the added connection */
    if(res != UA_STATUSCODE_GOOD)
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "The PubSubConfiguration file sequence failed: %s",
                     UA_StatusCode_name(res));
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return (res == UA_STATUSCODE_GOOD) ? EXIT_SUCCESS : EXIT_FAILURE;
}
