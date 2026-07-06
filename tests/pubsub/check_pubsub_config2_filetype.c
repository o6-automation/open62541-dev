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

/* Add a connection via the C API so that the file has content */
static void
addBaseConnection(void) {
    UA_PubSubConnectionConfig connectionConfig;
    memset(&connectionConfig, 0, sizeof(connectionConfig));
    connectionConfig.name = UA_STRING("FileBaseConn");
    UA_NetworkAddressUrlDataType networkAddressUrl =
        UA_PUBSUB_TEST_NETWORKADDRESSURL(UA_PUBSUB_TEST_UDP_MULTICAST_URL_4801);
    UA_Variant_setScalar(&connectionConfig.address, &networkAddressUrl,
                         &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE]);
    connectionConfig.transportProfileUri = UA_STRING(PROFILE_UDP);
    connectionConfig.publisherId.idType = UA_PUBLISHERIDTYPE_UINT16;
    connectionConfig.publisherId.id.uint16 = 2234;
    UA_StatusCode res =
        UA_Server_addPubSubConnection(server, &connectionConfig, NULL);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
}

/* Call a method on the PubSubConfiguration object */
static UA_CallMethodResult
callFileMethod(UA_UInt32 methodId, size_t inputSize, const UA_Variant *input) {
    UA_CallMethodRequest request;
    UA_CallMethodRequest_init(&request);
    request.objectId =
        UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION);
    request.methodId = UA_NODEID_NUMERIC(0, methodId);
    request.inputArgumentsSize = inputSize;
    request.inputArguments = (UA_Variant*)(uintptr_t)input;
    return UA_Server_call(server, &request);
}

static UA_UInt32
openFile(UA_Byte mode, UA_StatusCode expected) {
    UA_Variant input;
    UA_Variant_setScalar(&input, &mode, &UA_TYPES[UA_TYPES_BYTE]);
    UA_CallMethodResult result = callFileMethod(
        UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_OPEN, 1, &input);
    ck_assert_int_eq(result.statusCode, expected);
    UA_UInt32 handle = 0;
    if(expected == UA_STATUSCODE_GOOD) {
        ck_assert_uint_eq(result.outputArgumentsSize, 1);
        handle = *(UA_UInt32*)result.outputArguments[0].data;
    }
    UA_CallMethodResult_clear(&result);
    return handle;
}

static void
closeFile(UA_UInt32 handle, UA_StatusCode expected) {
    UA_Variant input;
    UA_Variant_setScalar(&input, &handle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_CallMethodResult result = callFileMethod(
        UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_CLOSE, 1, &input);
    ck_assert_int_eq(result.statusCode, expected);
    UA_CallMethodResult_clear(&result);
}

static UA_ByteString
readFile(UA_UInt32 handle, UA_Int32 length, UA_StatusCode expected) {
    UA_Variant input[2];
    UA_Variant_setScalar(&input[0], &handle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&input[1], &length, &UA_TYPES[UA_TYPES_INT32]);
    UA_CallMethodResult result = callFileMethod(
        UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_READ, 2, input);
    ck_assert_int_eq(result.statusCode, expected);
    UA_ByteString data = UA_BYTESTRING_NULL;
    if(expected == UA_STATUSCODE_GOOD) {
        ck_assert_uint_eq(result.outputArgumentsSize, 1);
        UA_ByteString_copy((UA_ByteString*)result.outputArguments[0].data, &data);
    }
    UA_CallMethodResult_clear(&result);
    return data;
}

static void
writeFile(UA_UInt32 handle, UA_ByteString data, UA_StatusCode expected) {
    UA_Variant input[2];
    UA_Variant_setScalar(&input[0], &handle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&input[1], &data, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_CallMethodResult result = callFileMethod(
        UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_WRITE, 2, input);
    ck_assert_int_eq(result.statusCode, expected);
    UA_CallMethodResult_clear(&result);
}

static void
setPosition(UA_UInt32 handle, UA_UInt64 position) {
    UA_Variant input[2];
    UA_Variant_setScalar(&input[0], &handle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&input[1], &position, &UA_TYPES[UA_TYPES_UINT64]);
    UA_CallMethodResult result = callFileMethod(
        UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_SETPOSITION, 2, input);
    ck_assert_int_eq(result.statusCode, UA_STATUSCODE_GOOD);
    UA_CallMethodResult_clear(&result);
}

static UA_UInt64
getPosition(UA_UInt32 handle) {
    UA_Variant input;
    UA_Variant_setScalar(&input, &handle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_CallMethodResult result = callFileMethod(
        UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_GETPOSITION, 1, &input);
    ck_assert_int_eq(result.statusCode, UA_STATUSCODE_GOOD);
    UA_UInt64 position = *(UA_UInt64*)result.outputArguments[0].data;
    UA_CallMethodResult_clear(&result);
    return position;
}

static UA_UInt16
readOpenCount(void) {
    UA_ReadValueId rvi;
    UA_ReadValueId_init(&rvi);
    rvi.nodeId = UA_NODEID_NUMERIC(0,
        UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_OPENCOUNT);
    rvi.attributeId = UA_ATTRIBUTEID_VALUE;
    UA_DataValue dv = UA_Server_read(server, &rvi, UA_TIMESTAMPSTORETURN_NEITHER);
    ck_assert(dv.hasValue);
    UA_UInt16 count = *(UA_UInt16*)dv.value.data;
    UA_DataValue_clear(&dv);
    return count;
}

/* Encode an update file with one connection element */
static UA_ByteString
buildUpdateFileBlob(const char *connName, UA_UInt16 publisherId) {
    UA_PubSubConfiguration2DataType cfg;
    UA_PubSubConfiguration2DataType_init(&cfg);
    UA_PubSubConnectionDataType conn;
    UA_PubSubConnectionDataType_init(&conn);
    conn.name = UA_STRING((char*)(uintptr_t)connName);
    conn.transportProfileUri = UA_STRING(PROFILE_UDP);
    UA_NetworkAddressUrlDataType addr;
    UA_PubSubTest_initNetworkAddressUrl(&addr,
        UA_PubSubTest_getUdpMulticastUrl4801());
    conn.address.encoding = UA_EXTENSIONOBJECT_DECODED_NODELETE;
    conn.address.content.decoded.type =
        &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE];
    conn.address.content.decoded.data = &addr;
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

    UA_ByteString buf = UA_BYTESTRING_NULL;
    UA_StatusCode res =
        UA_encodeBinary(&eo, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT], &buf, NULL);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);
    return buf;
}

/* The read of the file returns the exported configuration, chunked reads
 * reassemble it */
START_TEST(OpenReadCloseRoundTrip) {
    addBaseConnection();

    UA_ByteString expected = UA_BYTESTRING_NULL;
    UA_StatusCode res =
        UA_Server_writePubSubConfigurationToByteString(server, &expected);
    ck_assert_int_eq(res, UA_STATUSCODE_GOOD);

    UA_UInt32 handle = openFile(UA_OPENFILEMODE_READ, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(readOpenCount(), 1);
    ck_assert_uint_eq(getPosition(handle), 0);

    /* Read everything in one chunk */
    UA_ByteString data = readFile(handle, (UA_Int32)expected.length + 100,
                                  UA_STATUSCODE_GOOD);
    ck_assert(UA_ByteString_equal(&data, &expected));

    /* Reassemble in two chunks */
    setPosition(handle, 0);
    UA_ByteString chunk1 = readFile(handle, (UA_Int32)expected.length / 2,
                                    UA_STATUSCODE_GOOD);
    UA_ByteString chunk2 = readFile(handle, (UA_Int32)expected.length,
                                    UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(chunk1.length + chunk2.length, expected.length);
    ck_assert(memcmp(chunk1.data, expected.data, chunk1.length) == 0);
    ck_assert(memcmp(chunk2.data, expected.data + chunk1.length,
                     chunk2.length) == 0);

    closeFile(handle, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(readOpenCount(), 0);

    /* Reads on a closed handle fail */
    UA_ByteString none = readFile(handle, 10, UA_STATUSCODE_BADINVALIDARGUMENT);
    ck_assert_uint_eq(none.length, 0);

    UA_ByteString_clear(&data);
    UA_ByteString_clear(&chunk1);
    UA_ByteString_clear(&chunk2);
    UA_ByteString_clear(&expected);
} END_TEST

/* Mode validation and exclusive-writer semantics */
START_TEST(ModeMatrix) {
    /* Unsupported modes */
    openFile(0x00, UA_STATUSCODE_BADINVALIDARGUMENT);
    openFile(UA_OPENFILEMODE_WRITE, UA_STATUSCODE_BADINVALIDARGUMENT);
    openFile(UA_OPENFILEMODE_ERASEEXISTING, UA_STATUSCODE_BADINVALIDARGUMENT);
    openFile(0x08, UA_STATUSCODE_BADINVALIDARGUMENT);

    /* Parallel readers are allowed */
    UA_UInt32 r1 = openFile(UA_OPENFILEMODE_READ, UA_STATUSCODE_GOOD);
    UA_UInt32 r2 = openFile(UA_OPENFILEMODE_READ, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(readOpenCount(), 2);

    /* A writer needs exclusive access */
    openFile(UA_OPENFILEMODE_WRITE | UA_OPENFILEMODE_ERASEEXISTING,
             UA_STATUSCODE_BADNOTWRITABLE);

    /* Writing on a read-only handle fails */
    UA_ByteString data = UA_BYTESTRING("data");
    writeFile(r1, data, UA_STATUSCODE_BADINVALIDSTATE);

    closeFile(r1, UA_STATUSCODE_GOOD);
    closeFile(r2, UA_STATUSCODE_GOOD);

    /* With a writer active no reader can open */
    UA_UInt32 w = openFile(UA_OPENFILEMODE_WRITE | UA_OPENFILEMODE_ERASEEXISTING,
                           UA_STATUSCODE_GOOD);
    openFile(UA_OPENFILEMODE_READ, UA_STATUSCODE_BADNOTREADABLE);
    openFile(UA_OPENFILEMODE_WRITE | UA_OPENFILEMODE_ERASEEXISTING,
             UA_STATUSCODE_BADNOTWRITABLE);

    /* Reading on a write-only handle fails */
    readFile(w, 10, UA_STATUSCODE_BADINVALIDSTATE);

    closeFile(w, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(readOpenCount(), 0);

    /* Stale handle */
    closeFile(w, UA_STATUSCODE_BADINVALIDARGUMENT);
} END_TEST

/* Write followed by a plain Close leaves the configuration unchanged */
START_TEST(WriteCloseDiscards) {
    addBaseConnection();
    UA_PubSubManager *psm = getPSM(server);
    ck_assert_uint_eq(psm->connectionsSize, 1);

    UA_UInt32 w = openFile(UA_OPENFILEMODE_WRITE | UA_OPENFILEMODE_ERASEEXISTING,
                           UA_STATUSCODE_GOOD);
    UA_ByteString blob = buildUpdateFileBlob("DiscardedConn", 4444);
    writeFile(w, blob, UA_STATUSCODE_GOOD);
    closeFile(w, UA_STATUSCODE_GOOD);

    ck_assert_uint_eq(psm->connectionsSize, 1);
    UA_ByteString_clear(&blob);
} END_TEST

/* Full client sequence: Open(write) -> Write -> CloseAndUpdate */
START_TEST(CloseAndUpdateFlow) {
    addBaseConnection();
    UA_PubSubManager *psm = getPSM(server);

    UA_UInt32 w = openFile(UA_OPENFILEMODE_WRITE | UA_OPENFILEMODE_ERASEEXISTING,
                           UA_STATUSCODE_GOOD);
    UA_ByteString blob = buildUpdateFileBlob("FileAddedConn", 5555);
    writeFile(w, blob, UA_STATUSCODE_GOOD);

    UA_PubSubConfigurationRefDataType ref;
    UA_PubSubConfigurationRefDataType_init(&ref);
    ref.configurationMask = UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
        UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION;

    UA_Variant input[3];
    UA_Variant_setScalar(&input[0], &w, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Boolean requireComplete = false;
    UA_Variant_setScalar(&input[1], &requireComplete, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_Variant_setArray(&input[2], &ref, 1,
                        &UA_TYPES[UA_TYPES_PUBSUBCONFIGURATIONREFDATATYPE]);

    UA_CallMethodResult result = callFileMethod(
        UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_CLOSEANDUPDATE, 3, input);
    ck_assert_int_eq(result.statusCode, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(result.outputArgumentsSize, 4);

    /* ChangesApplied */
    ck_assert(UA_Variant_hasScalarType(&result.outputArguments[0],
                                       &UA_TYPES[UA_TYPES_BOOLEAN]));
    ck_assert(*(UA_Boolean*)result.outputArguments[0].data);
    /* ReferencesResults */
    ck_assert(UA_Variant_hasArrayType(&result.outputArguments[1],
                                      &UA_TYPES[UA_TYPES_STATUSCODE]));
    ck_assert_uint_eq(result.outputArguments[1].arrayLength, 1);
    ck_assert_int_eq(((UA_StatusCode*)result.outputArguments[1].data)[0],
                     UA_STATUSCODE_GOOD);
    /* ConfigurationObjects */
    ck_assert(UA_Variant_hasArrayType(&result.outputArguments[3],
                                      &UA_TYPES[UA_TYPES_NODEID]));
    ck_assert_uint_eq(result.outputArguments[3].arrayLength, 1);
    UA_NodeId newConnId = ((UA_NodeId*)result.outputArguments[3].data)[0];
    ck_assert(!UA_NodeId_isNull(&newConnId));
    UA_CallMethodResult_clear(&result);

    /* The connection was added, the handle is closed */
    ck_assert_uint_eq(psm->connectionsSize, 2);
    ck_assert_uint_eq(readOpenCount(), 0);
    UA_String connName = UA_STRING("FileAddedConn");
    UA_Boolean found = false;
    UA_PubSubConnection *c;
    TAILQ_FOREACH(c, &psm->connections, listEntry) {
        if(UA_String_equal(&c->config.name, &connName))
            found = true;
    }
    ck_assert(found);

    UA_ByteString_clear(&blob);
} END_TEST

/* Error paths of CloseAndUpdate */
START_TEST(CloseAndUpdateErrors) {
    addBaseConnection();

    UA_PubSubConfigurationRefDataType ref;
    UA_PubSubConfigurationRefDataType_init(&ref);
    ref.configurationMask = UA_PUBSUBCONFIGURATIONREFMASK_ELEMENTADD |
        UA_PUBSUBCONFIGURATIONREFMASK_REFERENCECONNECTION;

    /* On a read-only handle */
    UA_UInt32 r = openFile(UA_OPENFILEMODE_READ, UA_STATUSCODE_GOOD);
    UA_Variant input[3];
    UA_Variant_setScalar(&input[0], &r, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Boolean requireComplete = false;
    UA_Variant_setScalar(&input[1], &requireComplete, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_Variant_setArray(&input[2], &ref, 1,
                        &UA_TYPES[UA_TYPES_PUBSUBCONFIGURATIONREFDATATYPE]);
    UA_CallMethodResult result = callFileMethod(
        UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_CLOSEANDUPDATE, 3, input);
    ck_assert_int_eq(result.statusCode, UA_STATUSCODE_BADINVALIDSTATE);
    UA_CallMethodResult_clear(&result);
    closeFile(r, UA_STATUSCODE_GOOD);

    /* With a garbage buffer */
    UA_UInt32 w = openFile(UA_OPENFILEMODE_WRITE | UA_OPENFILEMODE_ERASEEXISTING,
                           UA_STATUSCODE_GOOD);
    UA_ByteString garbage = UA_BYTESTRING("this is not a configuration");
    writeFile(w, garbage, UA_STATUSCODE_GOOD);
    UA_Variant_setScalar(&input[0], &w, &UA_TYPES[UA_TYPES_UINT32]);
    result = callFileMethod(
        UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_CLOSEANDUPDATE, 3, input);
    ck_assert_int_eq(result.statusCode, UA_STATUSCODE_BADTYPEMISMATCH);
    UA_CallMethodResult_clear(&result);

    /* Empty references */
    UA_Variant_setArray(&input[2], NULL, 0,
                        &UA_TYPES[UA_TYPES_PUBSUBCONFIGURATIONREFDATATYPE]);
    result = callFileMethod(
        UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_CLOSEANDUPDATE, 3, input);
    ck_assert_int_eq(result.statusCode, UA_STATUSCODE_BADNOTHINGTODO);
    UA_CallMethodResult_clear(&result);

    /* The handle survived the failed updates -- close it */
    closeFile(w, UA_STATUSCODE_GOOD);

    /* Invalid handle */
    UA_UInt32 invalidHandle = 12345;
    UA_Variant_setScalar(&input[0], &invalidHandle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setArray(&input[2], &ref, 1,
                        &UA_TYPES[UA_TYPES_PUBSUBCONFIGURATIONREFDATATYPE]);
    result = callFileMethod(
        UA_NS0ID_PUBLISHSUBSCRIBE_PUBSUBCONFIGURATION_CLOSEANDUPDATE, 3, input);
    ck_assert_int_eq(result.statusCode, UA_STATUSCODE_BADINVALIDARGUMENT);
    UA_CallMethodResult_clear(&result);
} END_TEST

int main(void) {
    TCase *tc_filetype = tcase_create("PubSubConfiguration FileType");
    tcase_add_checked_fixture(tc_filetype, setup, teardown);
    tcase_add_test(tc_filetype, OpenReadCloseRoundTrip);
    tcase_add_test(tc_filetype, ModeMatrix);
    tcase_add_test(tc_filetype, WriteCloseDiscards);
    tcase_add_test(tc_filetype, CloseAndUpdateFlow);
    tcase_add_test(tc_filetype, CloseAndUpdateErrors);

    Suite *s = suite_create("PubSub Configuration2 FileType surface");
    suite_add_tcase(s, tc_filetype);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
