/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Julius Pfrommer)
 */

#include <open62541/server.h>

#include <check.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* API-level smoke test related to GHSA-38g6-5hfj-2fj7: a malformed field
 * name inside a nested JSON5 config object (an unpaired UTF-16 surrogate
 * escape) must not crash the process when loaded through the public
 * config-loading API.
 *
 * This is NOT a reliable regression test for the underlying OOB read on
 * this branch: BuildInfo_parseJson() only ever runs strcmp() against the
 * unterminated buffer here (the "Unknown field name." log message on
 * 1.4/1.5 is a static string, not "%s"-formatted with the field content),
 * and strcmp() against a short literal like "productUri" almost always
 * diverges within the first byte or two -- so it does not reliably walk
 * past the end of the allocation. Verified empirically: running this same
 * test against the pre-fix cj5_get_str() does NOT reproduce a crash here.
 * tests/check_cj5.c's getStr*IsTerminated tests are the actual, deterministic
 * regression guard, because they call strlen()/strcmp() on the buffer
 * directly and always exercise the failure. Keep this test for API-level
 * robustness coverage (e.g. against a future reintroduction of "%s"
 * logging, as already happened on the unreleased master branch), not as
 * the primary defense for this bug class.
 *
 * Note on the assertions below: an unrecognized field name is logged as an
 * error and otherwise silently skipped -- it does *not* fail parsing or
 * refuse to start the server. That is the parser's existing (separate,
 * pre-existing) behavior for any unknown field, not something this
 * regression test is meant to change; these tests only guard against a
 * crash/OOB-read regression in cj5_get_str(), not against permissive
 * unknown-field handling. */
START_TEST(LoadFromFile_MalformedNestedFieldName_NoCrash) {
    const char *json = "{\"buildInfo\":{\"\\uD800\":0}}";
    UA_ByteString jsonConfig = UA_STRING((char*)(uintptr_t)json);
    jsonConfig.length = strlen(json);

    UA_ServerConfig config;

    /* The malformed field is skipped (logged, not rejected); parsing still
     * reports success. What matters here is that this returns at all,
     * without an OOB read/crash. */
    UA_StatusCode retval = UA_ServerConfig_loadFromFile(&config, jsonConfig);
    ck_assert_int_eq(retval, UA_STATUSCODE_GOOD);

    UA_ServerConfig_clear(&config);
} END_TEST

START_TEST(NewFromFile_MalformedNestedFieldName_NoCrash) {
    const char *json = "{\"buildInfo\":{\"\\uD800\":0}}";
    UA_ByteString jsonConfig = UA_STRING((char*)(uintptr_t)json);
    jsonConfig.length = strlen(json);

    UA_Server *server = UA_Server_newFromFile(jsonConfig);
    ck_assert(server != NULL); /* malformed field is skipped, server still starts */
    UA_Server_delete(server);
} END_TEST

START_TEST(LoadFromFile_ValidBuildInfo_StillWorks) {
    const char *json = "{\"buildInfo\":{\"productUri\":\"urn:test\"}}";
    UA_ByteString jsonConfig = UA_STRING((char*)(uintptr_t)json);
    jsonConfig.length = strlen(json);

    UA_ServerConfig config;
    UA_StatusCode retval = UA_ServerConfig_loadFromFile(&config, jsonConfig);
    ck_assert_int_eq(retval, UA_STATUSCODE_GOOD);

    UA_String expected = UA_STRING((char*)(uintptr_t)"urn:test");
    ck_assert(UA_String_equal(&config.buildInfo.productUri, &expected));

    UA_ServerConfig_clear(&config);
} END_TEST

#ifdef UA_ENABLE_LWS
START_TEST(LoadFromFile_HttpListenAddress) {
    const char *json =
        "{\"httpEnabled\":true,\"httpAllowUnencrypted\":true,"
        "\"http\":{\"listenAddress\":\"\","
        "\"maxMsgSize\":4096,\"maxDecompressedMsgSize\":8192,"
        "\"timeout\":15}}";
    UA_ByteString jsonConfig = UA_STRING((char *)(uintptr_t)json);
    jsonConfig.length = strlen(json);

    UA_ServerConfig config;
    UA_StatusCode retval = UA_ServerConfig_loadFromFile(&config, jsonConfig);
    ck_assert_int_eq(retval, UA_STATUSCODE_GOOD);
    ck_assert(config.httpEnabled);
    ck_assert(config.httpAllowUnencrypted);
    ck_assert_ptr_nonnull(config.httpListenAddress.data);
    ck_assert_uint_eq(config.httpListenAddress.length, 0);
    ck_assert_uint_eq(config.httpMaxMsgSize, 4096);
    ck_assert_uint_eq(config.httpMaxDecompressedMsgSize, 8192);
    ck_assert_uint_eq(config.httpTimeout, 15);

    UA_ServerConfig_clear(&config);
} END_TEST
#endif

static const struct {
    const char *json;
    UA_StatusCode status;
} invalidConfigurations[] = {
    {"", UA_STATUSCODE_BADDECODINGERROR},
    {"{}", UA_STATUSCODE_BADDECODINGERROR},
    {"[]", UA_STATUSCODE_BADDECODINGERROR},
    {"null", UA_STATUSCODE_BADDECODINGERROR},
    {"{tcpEnabled:", UA_STATUSCODE_BADDECODINGERROR},
    {"{shutdownDelay:true}", UA_STATUSCODE_BADDECODINGERROR},
    {"{maxSecureChannels:65536}", UA_STATUSCODE_BADDECODINGERROR},
    {"{maxNodesPerRead:-1}", UA_STATUSCODE_BADDECODINGERROR},
    {"{maxAsyncOperationQueueSize:'18446744073709551616'}",
     UA_STATUSCODE_BADDECODINGERROR},
    {"{verifyRequestTimestamp:-1}", UA_STATUSCODE_BADDECODINGERROR},
    {"{tcpEnabled:1}", UA_STATUSCODE_BADTYPEMISMATCH},
    {"{serverUrls:['opc.tcp://example.invalid:4840',7]}",
     UA_STATUSCODE_BADDECODINGERROR},
    {"{buildInfo:{buildDate:'not-a-date'}}", UA_STATUSCODE_BADDECODINGERROR},
    {"{applicationDescription:{applicationType:'Unknown'}}", UA_STATUSCODE_BAD},
    {"{applicationDescription:{applicationType:-1}}", UA_STATUSCODE_BADDECODINGERROR},
    {"{applicationDescription:{applicationName:{locale:7}}}",
     UA_STATUSCODE_BADDECODINGERROR},
    {"{tcp:{tcpBufSize:-1}}", UA_STATUSCODE_BADDECODINGERROR},
    {"{http:{timeout:65536}}", UA_STATUSCODE_BADDECODINGERROR},
    {"{drivers:{driver:'x'}}", UA_STATUSCODE_BADDECODINGERROR},
    {"{drivers:['x']}", UA_STATUSCODE_BADDECODINGERROR},
    {"{drivers:[{port:1}]}", UA_STATUSCODE_BADDECODINGERROR},
    {"{drivers:[{driver:7}]}", UA_STATUSCODE_BADDECODINGERROR},
    {"{drivers:[{driver:'x',a:null}]}", UA_STATUSCODE_BADDECODINGERROR},
    {"{drivers:[{driver:'x',a:[null]}]}", UA_STATUSCODE_BADDECODINGERROR},
    {"{drivers:[{driver:'x',a:{b:{c:null}}}]}", UA_STATUSCODE_BADDECODINGERROR},
    {"{drivers:[{driver:'x',name:7}]}", UA_STATUSCODE_BADDECODINGERROR},
    {"{drivers:[{driver:'x',a:{file:'/nonexistent/driver.pem'}}]}",
     UA_STATUSCODE_BADNOTFOUND},
#ifdef UA_ENABLE_SUBSCRIPTIONS
    {"{subscriptions:{publishingIntervalLimits:{min:false}}}",
     UA_STATUSCODE_BADDECODINGERROR},
    {"{subscriptions:{lifeTimeCountLimits:{max:-1}}}",
     UA_STATUSCODE_BADDECODINGERROR},
    {"{subscriptions:{enableRetransmissionQueue:1}}", UA_STATUSCODE_BADTYPEMISMATCH},
#endif
#ifdef UA_ENABLE_PUBSUB
    {"{pubsub:{enableDeltaFrames:1}}", UA_STATUSCODE_BADTYPEMISMATCH},
#endif
#ifdef UA_ENABLE_HISTORIZING
    {"{historizing:{accessHistoryDataCapability:1}}", UA_STATUSCODE_BADTYPEMISMATCH},
#endif
};

START_TEST(LoadFromFile_InvalidConfigurationClearsResources) {
    UA_ByteString json = UA_STRING((char*)(uintptr_t)invalidConfigurations[_i].json);
    UA_ServerConfig config;
    UA_StatusCode res = UA_ServerConfig_loadFromFile(&config, json);
    ck_assert_uint_eq(res, invalidConfigurations[_i].status);

    /* The loader owns cleanup on failure, including partially parsed fields. */
    ck_assert_ptr_null(config.eventLoop);
    ck_assert_ptr_null(config.logging);
    ck_assert_ptr_null(config.serverUrls);
    ck_assert_uint_eq(config.serverUrlsSize, 0);
    ck_assert_ptr_null(config.buildInfo.productUri.data);
    ck_assert_ptr_null(config.applicationDescription.applicationName.locale.data);
    ck_assert_ptr_null(config.securityPolicies);
    ck_assert_uint_eq(config.securityPoliciesSize, 0);
    ck_assert_ptr_null(config.drivers);
    ck_assert_uint_eq(config.driversSize, 0);
} END_TEST

START_TEST(LoadFromFile_Drivers) {
    /* A file whose content becomes a ByteString parameter */
    const char *path = "check_server_config_json_driver.pem";
    FILE *f = fopen(path, "wb");
    ck_assert_ptr_nonnull(f);
    ck_assert_uint_eq(fwrite("PEM", 1, 3, f), 3);
    ck_assert_int_eq(fclose(f), 0);

    UA_ByteString json = UA_STRING(
        "{drivers:[{driver:'probe',port:4840,ratio:0.5,negative:-3,"
        "enabled:true,names:['a','b'],key:{file:'check_server_config_json_driver.pem'}},"
        "{driver:'other',name:'nested',calls:{get:{method:'GET',ports:[1,2]}}}]}");
    UA_ServerConfig config;
    UA_StatusCode res = UA_ServerConfig_loadFromFile(&config, json);
    remove(path);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(config.driversSize, 2);

    UA_String probe = UA_STRING("probe");
    UA_String other = UA_STRING("other");
    ck_assert(UA_String_equal(&config.drivers[0].driver, &probe));
    ck_assert(UA_String_equal(&config.drivers[1].driver, &other));
    UA_String nested = UA_STRING("nested");
    ck_assert(UA_String_equal(&config.drivers[1].name, &nested));
    ck_assert_uint_eq(config.drivers[0].name.length, 0);

    /* Objects become KeyValuePair arrays, mixed arrays Variant arrays */
    const UA_Variant *calls = UA_KeyValueMap_get(&config.drivers[1].params,
                                                 UA_QUALIFIEDNAME(0, "calls"));
    ck_assert(UA_Variant_hasArrayType(calls, &UA_TYPES[UA_TYPES_KEYVALUEPAIR]));
    ck_assert_uint_eq(calls->arrayLength, 1);
    const UA_KeyValuePair *get = (const UA_KeyValuePair *)calls->data;
    UA_KeyValueMap getMap = {get->value.arrayLength, (UA_KeyValuePair *)get->value.data};
    ck_assert(UA_Variant_hasArrayType(&get->value, &UA_TYPES[UA_TYPES_KEYVALUEPAIR]));
    ck_assert_ptr_nonnull(UA_KeyValueMap_getScalar(&getMap, UA_QUALIFIEDNAME(0, "method"),
                                                   &UA_TYPES[UA_TYPES_STRING]));
    const UA_Variant *ports = UA_KeyValueMap_get(&getMap, UA_QUALIFIEDNAME(0, "ports"));
    ck_assert(UA_Variant_hasArrayType(ports, &UA_TYPES[UA_TYPES_VARIANT]));
    ck_assert_uint_eq(ports->arrayLength, 2);

    const UA_KeyValueMap *params = &config.drivers[0].params;
    ck_assert_uint_eq(params->mapSize, 6);
    const UA_Int64 *port = (const UA_Int64*)UA_KeyValueMap_getScalar(
        params, UA_QUALIFIEDNAME(0, "port"), &UA_TYPES[UA_TYPES_INT64]);
    ck_assert_ptr_nonnull(port);
    ck_assert_int_eq(*port, 4840);
    const UA_Int64 *negative = (const UA_Int64*)UA_KeyValueMap_getScalar(
        params, UA_QUALIFIEDNAME(0, "negative"), &UA_TYPES[UA_TYPES_INT64]);
    ck_assert_ptr_nonnull(negative);
    ck_assert_int_eq(*negative, -3);
    const UA_Double *ratio = (const UA_Double*)UA_KeyValueMap_getScalar(
        params, UA_QUALIFIEDNAME(0, "ratio"), &UA_TYPES[UA_TYPES_DOUBLE]);
    ck_assert_ptr_nonnull(ratio);
    ck_assert(*ratio == 0.5);
    const UA_Boolean *enabled = (const UA_Boolean*)UA_KeyValueMap_getScalar(
        params, UA_QUALIFIEDNAME(0, "enabled"), &UA_TYPES[UA_TYPES_BOOLEAN]);
    ck_assert_ptr_nonnull(enabled);
    ck_assert(*enabled);
    const UA_Variant *names = UA_KeyValueMap_get(params, UA_QUALIFIEDNAME(0, "names"));
    ck_assert(UA_Variant_hasArrayType(names, &UA_TYPES[UA_TYPES_STRING]));
    ck_assert_uint_eq(names->arrayLength, 2);
    const UA_ByteString *key = (const UA_ByteString*)UA_KeyValueMap_getScalar(
        params, UA_QUALIFIEDNAME(0, "key"), &UA_TYPES[UA_TYPES_BYTESTRING]);
    ck_assert_ptr_nonnull(key);
    UA_ByteString pem = UA_BYTESTRING("PEM");
    ck_assert(UA_ByteString_equal(key, &pem));
    UA_ServerConfig_clear(&config);
} END_TEST

START_TEST(NewFromFile_InvalidConfiguration) {
    UA_ByteString json = UA_STRING("{tcpEnabled:1}");
    ck_assert_ptr_null(UA_Server_newFromFile(json));
} END_TEST

START_TEST(LoadFromFile_ApplicationTypeNamesAndNumbers) {
    static const struct {
        const char *json;
        UA_ApplicationType expected;
    } cases[] = {
        {"{applicationDescription:{applicationType:'Server'}}",
         UA_APPLICATIONTYPE_SERVER},
        {"{applicationDescription:{applicationType:'Client'}}",
         UA_APPLICATIONTYPE_CLIENT},
        {"{applicationDescription:{applicationType:'ClientAndServer'}}",
         UA_APPLICATIONTYPE_CLIENTANDSERVER},
        {"{applicationDescription:{applicationType:'DiscoveryServer'}}",
         UA_APPLICATIONTYPE_DISCOVERYSERVER},
        {"{applicationDescription:{applicationType:2}}",
         UA_APPLICATIONTYPE_CLIENTANDSERVER},
        {"{applicationDescription:{applicationType:3}}",
         UA_APPLICATIONTYPE_DISCOVERYSERVER}
    };
    UA_ByteString json = UA_STRING((char*)(uintptr_t)cases[_i].json);
    UA_ServerConfig config;
    UA_StatusCode res = UA_ServerConfig_loadFromFile(&config, json);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(config.applicationDescription.applicationType, cases[_i].expected);
    UA_ServerConfig_clear(&config);
} END_TEST

START_TEST(LoadFromFile_HttpConfiguration) {
    UA_ByteString json = UA_STRING(
        "{httpEnabled:true,httpAllowUnencrypted:false,"
        "http:{listenAddress:'127.0.0.1',maxMsgSize:4096,"
        "maxDecompressedMsgSize:8192,timeout:30}}");
    UA_ServerConfig config;
    UA_StatusCode res = UA_ServerConfig_loadFromFile(&config, json);
    ck_assert_uint_eq(res, UA_STATUSCODE_GOOD);
    ck_assert(config.httpEnabled);
    ck_assert(!config.httpAllowUnencrypted);
    ck_assert_uint_eq(config.httpMaxMsgSize, 4096);
    ck_assert_uint_eq(config.httpMaxDecompressedMsgSize, 8192);
    ck_assert_uint_eq(config.httpTimeout, 30);
    UA_String address = UA_STRING("127.0.0.1");
    ck_assert(UA_String_equal(&config.httpListenAddress, &address));
    UA_ServerConfig_clear(&config);
} END_TEST

static Suite *testSuite_ServerConfigJson(void) {
    Suite *s = suite_create("Server config from JSON5 file");

    TCase *tc = tcase_create("Malformed input regressions");
    tcase_add_test(tc, LoadFromFile_MalformedNestedFieldName_NoCrash);
    tcase_add_test(tc, NewFromFile_MalformedNestedFieldName_NoCrash);
    tcase_add_test(tc, LoadFromFile_ValidBuildInfo_StillWorks);
#ifdef UA_ENABLE_LWS
    tcase_add_test(tc, LoadFromFile_HttpListenAddress);
#endif
    suite_add_tcase(s, tc);

    TCase *tc_validation = tcase_create("Configuration validation");
    tcase_add_loop_test(tc_validation, LoadFromFile_InvalidConfigurationClearsResources,
                       0, sizeof(invalidConfigurations) / sizeof(invalidConfigurations[0]));
    tcase_add_test(tc_validation, NewFromFile_InvalidConfiguration);
    tcase_add_loop_test(tc_validation, LoadFromFile_ApplicationTypeNamesAndNumbers, 0, 6);
    tcase_add_test(tc_validation, LoadFromFile_HttpConfiguration);
    tcase_add_test(tc_validation, LoadFromFile_Drivers);
    suite_add_tcase(s, tc_validation);

    return s;
}

int main(void) {
    Suite *s = testSuite_ServerConfigJson();
    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
