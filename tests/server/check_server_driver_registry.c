/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

#include <open62541/server.h>

#include "test_helpers.h"

#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A third-party driver that is only known through its registration */

static size_t probesCreated;
static UA_Server *probeServer;

static UA_StatusCode
probeStart(UA_Driver *drv) {
    drv->state = UA_LIFECYCLESTATE_STARTED;
    return UA_STATUSCODE_GOOD;
}

/* The names of the stopped drivers in the order of stopping */
static UA_String stopped[16];
static size_t stoppedSize;

static void
probeStop(UA_Driver *drv) {
    if(stoppedSize < 16)
        stopped[stoppedSize++] = drv->name;
    drv->state = UA_LIFECYCLESTATE_STOPPED;
}

/* Echo the input as the result */
static UA_StatusCode
probeCall(UA_Driver *drv, const UA_String call, const UA_KeyValueMap *input,
          UA_DriverCallCallback callback, void *context) {
    UA_String echo = UA_STRING("echo");
    UA_String name = UA_STRING("name");
    if(UA_String_equal(&call, &name)) {
        UA_KeyValuePair result;
        result.key = UA_QUALIFIEDNAME(0, "name");
        UA_Variant_setScalar(&result.value, &drv->name, &UA_TYPES[UA_TYPES_STRING]);
        UA_KeyValueMap map = {1, &result};
        callback(context, UA_STATUSCODE_GOOD, &map);
        return UA_STATUSCODE_GOOD;
    }
    if(!UA_String_equal(&call, &echo))
        return UA_STATUSCODE_BADNOTFOUND;
    callback(context, UA_STATUSCODE_GOOD, input);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
probeFree(UA_Driver *drv) {
    UA_KeyValueMap_clear(&drv->params);
    UA_free(drv);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
probeCreate(UA_Server *server, const UA_KeyValueMap params,
            UA_Driver **outDriver) {
    /* The factory can reject parameters with a StatusCode */
    if(UA_KeyValueMap_contains(&params, UA_QUALIFIEDNAME(0, "fail")))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_Driver *drv = (UA_Driver *)UA_calloc(1, sizeof(UA_Driver));
    if(!drv)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    drv->name = UA_STRING("probe");
    drv->start = probeStart;
    drv->stop = probeStop;
    drv->call = probeCall;
    drv->free = probeFree;
    UA_StatusCode res = UA_KeyValueMap_copy(&params, &drv->params);
    if(res != UA_STATUSCODE_GOOD) {
        UA_free(drv);
        return res;
    }
    probeServer = server;
    probesCreated++;
    *outDriver = drv;
    return UA_STATUSCODE_GOOD;
}

static const UA_DriverParameter probeParameters[] = {
    {"port", UA_TYPES_UINT16, false, true},
    {"ratio", UA_TYPES_DOUBLE, false, false},
    {"key", UA_TYPES_BYTESTRING, false, false},
    {"names", UA_TYPES_STRING, true, false},
    {"enabled", UA_TYPES_BOOLEAN, false, false}
};

static const UA_DriverRegistration probeRegistration = {
    "probe", probeParameters,
    sizeof(probeParameters) / sizeof(probeParameters[0]), probeCreate
};

static UA_Server *server;

static void setup(void) {
    probesCreated = 0;
    stoppedSize = 0;
    probeServer = NULL;
    server = UA_Server_newForUnitTest();
    ck_assert_ptr_nonnull(server);
}

static void teardown(void) {
    UA_Server_delete(server);
}

static UA_Driver *
findProbe(UA_Server *s) {
    for(UA_Driver *drv = UA_Server_getDrivers(s); drv; drv = drv->next) {
        if(drv->start == probeStart)
            return drv;
    }
    return NULL;
}

static size_t
countProbes(UA_Server *s) {
    size_t count = 0;
    for(UA_Driver *drv = UA_Server_getDrivers(s); drv; drv = drv->next) {
        if(drv->start == probeStart)
            count++;
    }
    return count;
}

/* Add a probe with a single parameter */
static void
addProbe(UA_ServerConfig *config, const char *key, const void *value,
         const UA_DataType *type) {
    UA_KeyValueMap params = UA_KEYVALUEMAP_NULL;
    if(key) {
        UA_QualifiedName name = UA_QUALIFIEDNAME(0, (char *)(uintptr_t)key);
        ck_assert_uint_eq(UA_KeyValueMap_setScalar(&params, name, value, type),
                          UA_STATUSCODE_GOOD);
    }
    ck_assert_uint_eq(UA_ServerConfig_addDriver(config, "probe", NULL, params),
                      UA_STATUSCODE_GOOD);
    UA_KeyValueMap_clear(&params);
}

START_TEST(CreatedAtStartupWithConvertedTypes) {
    UA_ServerConfig *config = UA_Server_getConfig(server);
    ck_assert_uint_eq(UA_ServerConfig_registerDriver(config, &probeRegistration),
                      UA_STATUSCODE_GOOD);

    /* Parameters as the JSON configuration produces them */
    UA_KeyValueMap params = UA_KEYVALUEMAP_NULL;
    UA_Int64 port = 4841;
    UA_Int64 ratio = 2;
    UA_String key = UA_STRING("secret");
    UA_String names[2] = {UA_STRING("a"), UA_STRING("b")};
    UA_Boolean enabled = true;
    UA_Variant v;
    UA_KeyValueMap_setScalar(&params, UA_QUALIFIEDNAME(0, "port"), &port,
                             &UA_TYPES[UA_TYPES_INT64]);
    UA_KeyValueMap_setScalar(&params, UA_QUALIFIEDNAME(0, "ratio"), &ratio,
                             &UA_TYPES[UA_TYPES_INT64]);
    UA_KeyValueMap_setScalar(&params, UA_QUALIFIEDNAME(0, "key"), &key,
                             &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setArray(&v, names, 2, &UA_TYPES[UA_TYPES_STRING]);
    UA_KeyValueMap_set(&params, UA_QUALIFIEDNAME(0, "names"), &v);
    UA_KeyValueMap_setScalar(&params, UA_QUALIFIEDNAME(0, "enabled"), &enabled,
                             &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_KeyValueMap_setScalar(&params, UA_QUALIFIEDNAME(0, "extra"), &enabled,
                             &UA_TYPES[UA_TYPES_BOOLEAN]);
    ck_assert_uint_eq(UA_ServerConfig_addDriver(config, "probe", NULL, params),
                      UA_STATUSCODE_GOOD);
    UA_KeyValueMap_clear(&params);

    /* Not created before the startup */
    ck_assert_ptr_null(findProbe(server));
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);

    UA_Driver *drv = findProbe(server);
    ck_assert_ptr_nonnull(drv);
    ck_assert_ptr_eq(probeServer, server);
    ck_assert_int_eq(drv->state, UA_LIFECYCLESTATE_STARTED);
    const UA_UInt16 *p = (const UA_UInt16 *)UA_KeyValueMap_getScalar(
        &drv->params, UA_QUALIFIEDNAME(0, "port"), &UA_TYPES[UA_TYPES_UINT16]);
    ck_assert_ptr_nonnull(p);
    ck_assert_uint_eq(*p, 4841);
    const UA_Double *r = (const UA_Double *)UA_KeyValueMap_getScalar(
        &drv->params, UA_QUALIFIEDNAME(0, "ratio"), &UA_TYPES[UA_TYPES_DOUBLE]);
    ck_assert_ptr_nonnull(r);
    ck_assert(*r == 2.0);
    const UA_ByteString *k = (const UA_ByteString *)UA_KeyValueMap_getScalar(
        &drv->params, UA_QUALIFIEDNAME(0, "key"), &UA_TYPES[UA_TYPES_BYTESTRING]);
    ck_assert_ptr_nonnull(k);
    ck_assert(UA_String_equal(k, &key));
    const UA_Variant *n =
        UA_KeyValueMap_get(&drv->params, UA_QUALIFIEDNAME(0, "names"));
    ck_assert(UA_Variant_hasArrayType(n, &UA_TYPES[UA_TYPES_STRING]));
    ck_assert_uint_eq(n->arrayLength, 2);
    /* Parameters outside of the schema are passed on */
    ck_assert(UA_KeyValueMap_contains(&drv->params, UA_QUALIFIEDNAME(0, "extra")));

    ck_assert_uint_eq(UA_Server_run_shutdown(server), UA_STATUSCODE_GOOD);
    ck_assert_int_eq(drv->state, UA_LIFECYCLESTATE_STOPPED);
} END_TEST

#ifdef UA_ENABLE_JSON_ENCODING
START_TEST(RegisteredAfterNewFromFile) {
    UA_ByteString json = UA_STRING(
        "{tcpEnabled:false,"
        "drivers:[{driver:'probe',port:4841,ratio:0.5,names:['a']}]}");
    UA_Server *s = UA_Server_newFromFile(json);
    ck_assert_ptr_nonnull(s);
    ck_assert_uint_eq(UA_ServerConfig_registerDriver(UA_Server_getConfig(s),
                                                     &probeRegistration),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_run_startup(s), UA_STATUSCODE_GOOD);
    UA_Driver *drv = findProbe(s);
    ck_assert_ptr_nonnull(drv);
    const UA_Double *r = (const UA_Double *)UA_KeyValueMap_getScalar(
        &drv->params, UA_QUALIFIEDNAME(0, "ratio"), &UA_TYPES[UA_TYPES_DOUBLE]);
    ck_assert_ptr_nonnull(r);
    ck_assert(*r == 0.5);
    ck_assert_uint_eq(UA_Server_run_shutdown(s), UA_STATUSCODE_GOOD);
    UA_Server_delete(s);
} END_TEST
#endif

START_TEST(NotCreatedTwiceOnRestart) {
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_registerDriver(config, &probeRegistration);
    UA_UInt16 port = 4841;
    addProbe(config, "port", &port, &UA_TYPES[UA_TYPES_UINT16]);

    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_run_shutdown(server), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(probesCreated, 1);
    ck_assert_uint_eq(countProbes(server), 1);

    /* An entry that is added later is created during the next startup */
    ck_assert_uint_eq(UA_Server_run_shutdown(server), UA_STATUSCODE_GOOD);
    UA_KeyValueMap params = UA_KEYVALUEMAP_NULL;
    UA_KeyValueMap_setScalar(&params, UA_QUALIFIEDNAME(0, "port"), &port,
                             &UA_TYPES[UA_TYPES_UINT16]);
    UA_ServerConfig_addDriver(config, "probe", "later", params);
    UA_KeyValueMap_clear(&params);
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(probesCreated, 2);
    ck_assert_uint_eq(countProbes(server), 2);
    ck_assert_uint_eq(UA_Server_run_shutdown(server), UA_STATUSCODE_GOOD);
} END_TEST

START_TEST(UnknownDriverFailsStartup) {
    UA_ServerConfig *config = UA_Server_getConfig(server);
    ck_assert_uint_eq(UA_ServerConfig_addDriver(config, "missing", NULL, UA_KEYVALUEMAP_NULL),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_BADNOTFOUND);
} END_TEST

/* Invalid values of the required UInt16 port parameter */
START_TEST(InvalidParameterFailsStartup) {
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_registerDriver(config, &probeRegistration);
    UA_Int64 tooLarge = 70000;
    UA_Int64 negative = -1;
    UA_Double tooLargeReal = 1e10;
    UA_String text = UA_STRING("4840");
    switch(_i) {
    case 0: addProbe(config, NULL, NULL, NULL); break; /* missing */
    case 1: addProbe(config, "port", &tooLarge, &UA_TYPES[UA_TYPES_INT64]); break;
    case 2: addProbe(config, "port", &negative, &UA_TYPES[UA_TYPES_INT64]); break;
    case 3: addProbe(config, "port", &tooLargeReal, &UA_TYPES[UA_TYPES_DOUBLE]); break;
    default: addProbe(config, "port", &text, &UA_TYPES[UA_TYPES_STRING]); break;
    }
    ck_assert_uint_eq(UA_Server_run_startup(server),
                      UA_STATUSCODE_BADCONFIGURATIONERROR);
    ck_assert_uint_eq(probesCreated, 0);
} END_TEST

START_TEST(FactoryErrorFailsStartup) {
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_registerDriver(config, &probeRegistration);
    UA_KeyValueMap params = UA_KEYVALUEMAP_NULL;
    UA_UInt16 port = 4841;
    UA_Boolean yes = true;
    UA_KeyValueMap_setScalar(&params, UA_QUALIFIEDNAME(0, "port"), &port,
                             &UA_TYPES[UA_TYPES_UINT16]);
    UA_KeyValueMap_setScalar(&params, UA_QUALIFIEDNAME(0, "fail"), &yes,
                             &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_ServerConfig_addDriver(config, "probe", NULL, params);
    UA_KeyValueMap_clear(&params);
    ck_assert_uint_eq(UA_Server_run_startup(server),
                      UA_STATUSCODE_BADINVALIDARGUMENT);
    ck_assert_ptr_null(findProbe(server));
} END_TEST

static UA_Int64 echoedValue;

static void
echoResult(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    ck_assert_uint_eq(status, UA_STATUSCODE_GOOD);
    *(size_t *)context += 1;
    const UA_Int64 *v = (const UA_Int64 *)UA_KeyValueMap_getScalar(
        result, UA_QUALIFIEDNAME(0, "value"), &UA_TYPES[UA_TYPES_INT64]);
    ck_assert_ptr_nonnull(v);
    echoedValue = *v;
}

START_TEST(InstanceNamesAndCalls) {
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_registerDriver(config, &probeRegistration);
    UA_KeyValueMap params = UA_KEYVALUEMAP_NULL;
    UA_UInt16 port = 4841;
    UA_KeyValueMap_setScalar(&params, UA_QUALIFIEDNAME(0, "port"), &port,
                             &UA_TYPES[UA_TYPES_UINT16]);
    UA_ServerConfig_addDriver(config, "probe", "first", params);
    UA_ServerConfig_addDriver(config, "probe", "second", params);
    UA_KeyValueMap_clear(&params);
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(countProbes(server), 2);

    /* Call a driver by its instance name */
    UA_KeyValueMap input = UA_KEYVALUEMAP_NULL;
    UA_Int64 value = 42;
    UA_KeyValueMap_setScalar(&input, UA_QUALIFIEDNAME(0, "value"), &value,
                             &UA_TYPES[UA_TYPES_INT64]);
    size_t results = 0;
    ck_assert_uint_eq(UA_Server_callDriver(server, "second", "echo", &input,
                                           echoResult, &results),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(results, 1);
    ck_assert_int_eq(echoedValue, 42);

    ck_assert_uint_eq(UA_Server_callDriver(server, "third", "echo", &input,
                                           echoResult, &results),
                      UA_STATUSCODE_BADNOTFOUND);
    ck_assert_uint_eq(UA_Server_callDriver(server, "first", "unknown", &input,
                                           echoResult, &results),
                      UA_STATUSCODE_BADNOTFOUND);
    /* The binary transport offers no calls */
    ck_assert_uint_eq(UA_Server_callDriver(server, "binary", "echo", &input,
                                           echoResult, &results),
                      UA_STATUSCODE_BADNOTSUPPORTED);
    ck_assert_uint_eq(results, 1);
    UA_KeyValueMap_clear(&input);
    ck_assert_uint_eq(UA_Server_run_shutdown(server), UA_STATUSCODE_GOOD);
} END_TEST

START_TEST(DuplicateInstanceName) {
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_registerDriver(config, &probeRegistration);
    UA_KeyValueMap params = UA_KEYVALUEMAP_NULL;
    UA_UInt16 port = 4841;
    UA_KeyValueMap_setScalar(&params, UA_QUALIFIEDNAME(0, "port"), &port,
                             &UA_TYPES[UA_TYPES_UINT16]);
    UA_ServerConfig_addDriver(config, "probe", "same", params);
    UA_ServerConfig_addDriver(config, "probe", "same", params);
    UA_KeyValueMap_clear(&params);
    ck_assert_uint_eq(UA_Server_run_startup(server), UA_STATUSCODE_BADALREADYEXISTS);
} END_TEST

START_TEST(DuplicateRegistration) {
    UA_ServerConfig *config = UA_Server_getConfig(server);
    size_t defaultRegistrations = config->driverRegistrationsSize;
    ck_assert_uint_eq(UA_ServerConfig_registerDriver(config, &probeRegistration),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(UA_ServerConfig_registerDriver(config, &probeRegistration),
                      UA_STATUSCODE_BADALREADYEXISTS);
    ck_assert_uint_eq(config->driverRegistrationsSize, defaultRegistrations + 1);
} END_TEST

#ifdef UA_ENABLE_JSON_ENCODING

static UA_Server *
newNested(const char *json) {
    UA_Server *s = UA_Server_newFromFile(UA_STRING((char *)(uintptr_t)json));
    ck_assert_ptr_nonnull(s);
    UA_ServerConfig_registerDriver(UA_Server_getConfig(s), &probeRegistration);
    return s;
}

static UA_Driver *
driverByName(UA_Server *s, const char *name) {
    UA_String n = UA_STRING((char *)(uintptr_t)name);
    for(UA_Driver *drv = UA_Server_getDrivers(s); drv; drv = drv->next) {
        if(UA_String_equal(&drv->name, &n))
            return drv;
    }
    return NULL;
}

static char resolvedName[64];

static void
onName(void *context, UA_StatusCode status, const UA_KeyValueMap *result) {
    (void)context;
    ck_assert_uint_eq(status, UA_STATUSCODE_GOOD);
    const UA_String *n = (const UA_String *)UA_KeyValueMap_getScalar(
        result, UA_QUALIFIEDNAME(0, "name"), &UA_TYPES[UA_TYPES_STRING]);
    snprintf(resolvedName, sizeof(resolvedName), "%.*s", (int)n->length, (char *)n->data);
}

/* The full name of the driver that a call from the scope reaches */
static const char *
resolve(UA_Server *s, const UA_Driver *scope, const char *name) {
    strcpy(resolvedName, "(none)");
    UA_Server_callDriverFrom(s, scope, name, "name", NULL, onName, NULL);
    return resolvedName;
}

static size_t
stoppedAt(const char *name) {
    UA_String n = UA_STRING((char *)(uintptr_t)name);
    for(size_t i = 0; i < stoppedSize; i++) {
        if(UA_String_equal(&stopped[i], &n))
            return i;
    }
    return SIZE_MAX;
}

START_TEST(NestedNamesAndScopes) {
    UA_Server *s = newNested(
        "{tcpEnabled:false,drivers:["
        " {driver:'probe',name:'a',port:1,drivers:["
        "   {driver:'probe',port:2,drivers:[{driver:'probe',name:'leaf',port:3}]},"
        "   {driver:'probe',name:'b',port:4}]},"
        " {driver:'probe',name:'top',port:5}]}");
    ck_assert_uint_eq(UA_Server_run_startup(s), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(probesCreated, 5);

    /* Full names. The keys of the nesting are not parameters. */
    const char *names[] = {"a", "a/probe", "a/probe/leaf", "a/b", "top"};
    for(size_t i = 0; i < 5; i++) {
        UA_Driver *drv = driverByName(s, names[i]);
        ck_assert_msg(drv != NULL, "%s not found", names[i]);
        ck_assert_uint_eq(drv->params.mapSize, 1); /* Only the port */
        ck_assert(UA_KeyValueMap_contains(&drv->params, UA_QUALIFIEDNAME(0, "port")));
    }

    /* References are resolved from the inside out */
    UA_Driver *a = driverByName(s, "a");
    UA_Driver *mid = driverByName(s, "a/probe");
    UA_Driver *leaf = driverByName(s, "a/probe/leaf");
    ck_assert_str_eq(resolve(s, leaf, "b"), "a/b");
    ck_assert_str_eq(resolve(s, mid, "top"), "top");
    ck_assert_str_eq(resolve(s, a, "probe/leaf"), "a/probe/leaf");
    ck_assert_str_eq(resolve(s, leaf, "a"), "a");
    ck_assert_str_eq(resolve(s, a, "leaf"), "(none)"); /* Not visible */
    ck_assert_str_eq(resolve(s, NULL, "b"), "(none)");
    ck_assert_str_eq(resolve(s, NULL, "a/b"), "a/b");

    /* An empty name is the only nested driver */
    ck_assert_str_eq(resolve(s, mid, ""), "a/probe/leaf");
    ck_assert_str_eq(resolve(s, a, ""), "(none)");    /* Two nested */
    ck_assert_str_eq(resolve(s, leaf, ""), "(none)"); /* None nested */

    /* The lookup without a call resolves the same way */
    ck_assert_ptr_eq(UA_Server_getDriver(s, leaf, "b"), driverByName(s, "a/b"));
    ck_assert_ptr_eq(UA_Server_getDriver(s, a, "probe/leaf"), leaf);
    ck_assert_ptr_eq(UA_Server_getDriver(s, mid, ""), leaf);
    ck_assert_ptr_eq(UA_Server_getDriver(s, NULL, "a/probe"), mid);
    ck_assert_ptr_null(UA_Server_getDriver(s, a, "leaf"));
    ck_assert_ptr_null(UA_Server_getDriver(s, a, ""));

    /* Calls are resolved the same way */
    UA_KeyValueMap input = UA_KEYVALUEMAP_NULL;
    UA_Int64 value = 9;
    UA_KeyValueMap_setScalar(&input, UA_QUALIFIEDNAME(0, "value"), &value,
                             &UA_TYPES[UA_TYPES_INT64]);
    echoedValue = 0;
    size_t results = 0;
    ck_assert_uint_eq(UA_Server_callDriverFrom(s, leaf, "b", "echo", &input,
                                               echoResult, &results), UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(results, 1);
    ck_assert_int_eq(echoedValue, 9);
    ck_assert_uint_eq(UA_Server_callDriver(s, "b", "echo", &input, echoResult, &results),
                      UA_STATUSCODE_BADNOTFOUND);
    UA_KeyValueMap_clear(&input);

    /* A driver is stopped before the drivers nested in it */
    ck_assert_uint_eq(UA_Server_run_shutdown(s), UA_STATUSCODE_GOOD);
    ck_assert_uint_lt(stoppedAt("a"), stoppedAt("a/probe"));
    ck_assert_uint_lt(stoppedAt("a/probe"), stoppedAt("a/probe/leaf"));
    ck_assert_uint_lt(stoppedAt("a"), stoppedAt("a/b"));
    UA_Server_delete(s);
} END_TEST

static const char *nestedErrors[] = {
    /* drivers is not an array */
    "{tcpEnabled:false,drivers:[{driver:'probe',port:1,drivers:{driver:'probe',port:2}}]}",
    /* A nested entry without driver */
    "{tcpEnabled:false,drivers:[{driver:'probe',port:1,drivers:[{port:2}]}]}",
    /* A slash in a name */
    "{tcpEnabled:false,drivers:[{driver:'probe',name:'x/y',port:1}]}",
    /* A nested driver with an invalid parameter */
    "{tcpEnabled:false,drivers:[{driver:'probe',port:1,drivers:[{driver:'probe'}]}]}",
    /* Two nested drivers with the same name */
    "{tcpEnabled:false,drivers:[{driver:'probe',port:1,"
    " drivers:[{driver:'probe',port:2},{driver:'probe',port:3}]}]}"
};

START_TEST(NestedErrorsFailStartup) {
    UA_Server *s = newNested(nestedErrors[_i]);
    ck_assert_uint_ne(UA_Server_run_startup(s), UA_STATUSCODE_GOOD);
    UA_Server_run_shutdown(s);
    UA_Server_delete(s);
} END_TEST

#endif /* UA_ENABLE_JSON_ENCODING */

static Suite *testSuite_DriverRegistry(void) {
    Suite *s = suite_create("Drivers from the configuration");
    TCase *tc = tcase_create("Registry");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, CreatedAtStartupWithConvertedTypes);
#ifdef UA_ENABLE_JSON_ENCODING
    tcase_add_test(tc, RegisteredAfterNewFromFile);
#endif
    tcase_add_test(tc, NotCreatedTwiceOnRestart);
    tcase_add_test(tc, UnknownDriverFailsStartup);
    tcase_add_loop_test(tc, InvalidParameterFailsStartup, 0, 5);
    tcase_add_test(tc, FactoryErrorFailsStartup);
    tcase_add_test(tc, InstanceNamesAndCalls);
    tcase_add_test(tc, DuplicateInstanceName);
    tcase_add_test(tc, DuplicateRegistration);
#ifdef UA_ENABLE_JSON_ENCODING
    tcase_add_test(tc, NestedNamesAndScopes);
    tcase_add_loop_test(tc, NestedErrorsFailStartup, 0,
                        sizeof(nestedErrors) / sizeof(nestedErrors[0]));
#endif
    suite_add_tcase(s, tc);
    return s;
}

int main(void) {
    Suite *s = testSuite_DriverRegistry();
    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
