/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <open62541/server.h>

#include "../common.h"
#include "test_helpers.h"

#include <check.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
# include <windows.h>
# define TEST_PATH_MAX MAX_PATH
#else
# include <limits.h>
# define TEST_PATH_MAX PATH_MAX
#endif

/* Test: pkiFolder in JSON config actually configures the filestore
 * certificate group, rather than leaving the AcceptAll default in place.
 *
 * Regression test for #8057 */
START_TEST(server_from_json_with_pkifolder) {
    UA_StatusCode retval;

    /* Build a JSON config with pkiFolder pointing to a real temp dir */
    char pkiDir[TEST_PATH_MAX];
    ck_assert(UA_UnitTest_createTempDir("ua_pki_test", pkiDir, sizeof(pkiDir)));

    char pkiFolder[TEST_PATH_MAX];
    int pkiFolderLen = snprintf(pkiFolder, sizeof(pkiFolder), "%s/pki", pkiDir);
    ck_assert_int_gt(pkiFolderLen, 0);
    ck_assert_int_lt((size_t)pkiFolderLen, sizeof(pkiFolder));

    char *json = NULL;
    const size_t bufsize = 2048;
    json = (char *)UA_malloc(bufsize);
    ck_assert_ptr_ne(json, NULL);
    int n = snprintf(json, bufsize,
        "{\n"
        "  \"serverUrls\": [\"opc.tcp://localhost:4840\"],\n"
        "  \"pkiFolder\": \"%s\"\n"
        "}\n",
        pkiFolder);
    ck_assert_int_gt(n, 0);
    ck_assert_int_lt((size_t)n, bufsize);

    UA_ByteString jsonBytes;
    jsonBytes.length = strlen(json);
    jsonBytes.data = (UA_Byte *)UA_malloc(jsonBytes.length);
    ck_assert_ptr_ne(jsonBytes.data, NULL);
    memcpy(jsonBytes.data, json, jsonBytes.length);
    UA_free(json);

    UA_ServerConfig probeConfig;
    retval = UA_ServerConfig_loadFromFile(&probeConfig, jsonBytes);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
    ck_assert_ptr_ne(probeConfig.secureChannelPKI.context, NULL);
    ck_assert_ptr_ne(probeConfig.sessionPKI.context, NULL);
    UA_ServerConfig_clear(&probeConfig);

    /* Create server from config */
    UA_Server *server = UA_Server_newFromFile(jsonBytes);
    UA_ByteString_clear(&jsonBytes);

    ck_assert_ptr_ne(server, NULL);

    UA_ServerConfig *config = UA_Server_getConfig(server);

    /* The bug: secureChannelPKI and sessionPKI should have a filestore context
     * (non-NULL) because pkiFolder was set. With AcceptAll, context remains NULL. */
    ck_assert_ptr_ne(config->secureChannelPKI.context, NULL);
    ck_assert_ptr_ne(config->sessionPKI.context, NULL);

    /* Simple verification: the PKI store should be a filestore, not AcceptAll */
    UA_TrustListDataType trustList;
    memset(&trustList, 0, sizeof(UA_TrustListDataType));
    retval = config->secureChannelPKI.getTrustList(&config->secureChannelPKI, &trustList);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
    /* The trust list from a fresh filestore should be empty (not an error) */

    UA_Server_delete(server);

    /* Clean up temp dir */
    UA_UnitTest_removeDir(pkiDir);
}
END_TEST

static Suite *testSuite_pki_from_json(void) {
    Suite *s = suite_create("Load server from json config with pkiFolder");
    TCase *tc_new = tcase_create("pki_regression");
    tcase_add_test(tc_new, server_from_json_with_pkifolder);
    suite_add_tcase(s, tc_new);
    return s;
}

int main(void) {
    int      number_failed = 0;
    Suite   *s;
    SRunner *sr;

    /* Only run if encryption is compiled in */
#if defined(UA_ENABLE_ENCRYPTION)
    s  = testSuite_pki_from_json();
    sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    number_failed += srunner_ntests_failed(sr);
    srunner_free(sr);
#else
    (void)number_failed;
#endif

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
