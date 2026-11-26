/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

/* The Transform stage of the REST driver: pure functions, no server. JSON
 * (RFC 8259), paths (RFC 9535), conversion into OPC UA types (Part 6). */

#include "../../drivers/rest/rest_internal.h"

#include <check.h>
#include <stdlib.h>
#include <string.h>

static UA_Variant tree;

static void
decode(const char *json) {
    UA_ByteString doc = UA_BYTESTRING((char *)(uintptr_t)json);
    ck_assert_uint_eq(restJsonDecode(&doc, &tree), UA_STATUSCODE_GOOD);
}

static void
teardown(void) {
    UA_Variant_clear(&tree);
}

static const UA_Variant *
find(const char *path) {
    static UA_Variant element;
    UA_String p = UA_STRING((char *)(uintptr_t)path);
    const UA_Variant *v = restPathFind(&tree, &p, &element);
    return (v && p.length == 0) ? v : NULL;
}

static UA_Boolean
isString(const UA_Variant *v, const char *text) {
    UA_String t = UA_STRING((char *)(uintptr_t)text);
    return v && UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_STRING]) &&
        UA_String_equal((const UA_String *)v->data, &t);
}

/************/
/* RFC 8259 */
/************/

START_TEST(JsonValues) {
    decode("{\"int\":42,\"big\":12345678901234567890,\"frac\":1.5,\"text\":\"\\u00e4\","
           "\"null\":null,\"empty\":[],\"obj\":{},\"yes\":true,\"nums\":[1,2.5]}");
    const UA_Variant *v = find("int");
    ck_assert(UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_INT64]));
    v = find("big"); /* Out of the range of Int64 */
    ck_assert(UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_DOUBLE]));
    ck_assert(UA_Variant_hasScalarType(find("frac"), &UA_TYPES[UA_TYPES_DOUBLE]));
    ck_assert(isString(find("text"), "\xc3\xa4"));
    ck_assert(UA_Variant_isEmpty(find("null")));
    ck_assert(UA_Variant_hasArrayType(find("empty"), &UA_TYPES[UA_TYPES_VARIANT]));
    ck_assert(UA_Variant_hasArrayType(find("obj"), &UA_TYPES[UA_TYPES_KEYVALUEPAIR]));
    ck_assert(UA_Variant_hasScalarType(find("yes"), &UA_TYPES[UA_TYPES_BOOLEAN]));
    ck_assert(UA_Variant_hasArrayType(find("nums"), &UA_TYPES[UA_TYPES_DOUBLE]));
} END_TEST

START_TEST(DuplicateKeysLastWins) {
    decode("{\"a\":1,\"a\":2}");
    ck_assert_int_eq(*(UA_Int64 *)find("a")->data, 2);
} END_TEST

/* Deep nesting is rejected instead of overflowing the stack */
START_TEST(TooDeep) {
    size_t depth = 100000;
    UA_ByteString doc;
    UA_ByteString_allocBuffer(&doc, depth * 2);
    memset(doc.data, '[', depth);
    memset(&doc.data[depth], ']', depth);
    ck_assert_uint_eq(restJsonDecode(&doc, &tree), UA_STATUSCODE_BADDECODINGERROR);
    UA_ByteString_clear(&doc);
    decode("[[[[[[[[[[1]]]]]]]]]]"); /* Moderate nesting is fine */
} END_TEST

START_TEST(NotJson) {
    UA_ByteString doc = UA_BYTESTRING("<html>");
    ck_assert_uint_eq(restJsonDecode(&doc, &tree), UA_STATUSCODE_BADDECODINGERROR);
} END_TEST

/************/
/* RFC 9535 */
/************/

START_TEST(Paths) {
    decode("{\"Name\":\"x\",\"a.b\":\"dot\",\"items\":[{\"id\":7},{\"id\":8}],"
           "\"headers\":{\"Content-Type\":\"json\"}}");
    ck_assert(isString(find("$.Name"), "x"));
    ck_assert_ptr_null(find("$.name")); /* Keys are case-sensitive */
    ck_assert(isString(find("$['a.b']"), "dot"));
    ck_assert_int_eq(*(UA_Int64 *)find("$.items[1].id")->data, 8);
    ck_assert_int_eq(*(UA_Int64 *)find("items.1.id")->data, 8); /* Dotted form */
    ck_assert_ptr_null(find("$.items[2]"));
    ck_assert_ptr_null(find("$.missing"));
    ck_assert(isString(find("headers.content-type"), "json")); /* RFC 9110 */

    UA_Variant all;
    ck_assert_uint_eq(restPathCollect(&tree, UA_STRING("$.items[*].id"), &all),
                      UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(all.arrayLength, 2);
    UA_Variant_clear(&all);
    ck_assert(restPathMatches(UA_STRING("$.items[*].id"), UA_STRING("items.0.id")));
    ck_assert(!restPathMatches(UA_STRING("$.Items[*].id"), UA_STRING("items.0.id")));
} END_TEST

/**********/
/* Part 6 */
/**********/

static UA_StatusCode
convert(const char *path, UA_UInt16 typeIndex, UA_Variant *out) {
    return restSelect(&tree, UA_STRING((char *)(uintptr_t)path), &UA_TYPES[typeIndex], out);
}

START_TEST(Conversion) {
    decode("{\"time\":\"2026-11-19T08:00:00Z\",\"bytes\":\"aGk=\",\"count\":\"6\","
           "\"big\":300,\"frac\":7.5,\"int\":81,\"speed\":12.5,\"temps\":[84,81]}");
    UA_Variant v;
    ck_assert_uint_eq(convert("time", UA_TYPES_DATETIME, &v), UA_STATUSCODE_GOOD);
    UA_DateTimeStruct dts = UA_DateTime_toStruct(*(UA_DateTime *)v.data);
    ck_assert_uint_eq(dts.year, 2026);
    ck_assert_uint_eq(dts.hour, 8);
    UA_Variant_clear(&v);

    ck_assert_uint_eq(convert("bytes", UA_TYPES_BYTESTRING, &v), UA_STATUSCODE_GOOD);
    UA_Variant_clear(&v); /* Text is taken over as it is */

    ck_assert_uint_eq(convert("count", UA_TYPES_INT32, &v), UA_STATUSCODE_GOOD);
    ck_assert_int_eq(*(UA_Int32 *)v.data, 6);
    UA_Variant_clear(&v);

    ck_assert_uint_eq(convert("big", UA_TYPES_BYTE, &v), UA_STATUSCODE_BADOUTOFRANGE);
    ck_assert_uint_eq(convert("frac", UA_TYPES_INT32, &v), UA_STATUSCODE_BADTYPEMISMATCH);

    ck_assert_uint_eq(convert("int", UA_TYPES_DOUBLE, &v), UA_STATUSCODE_GOOD);
    ck_assert(*(UA_Double *)v.data == 81.0);
    UA_Variant_clear(&v);

    ck_assert_uint_eq(convert("speed", UA_TYPES_STRING, &v), UA_STATUSCODE_GOOD);
    ck_assert(isString(&v, "12.5"));
    UA_Variant_clear(&v);

    ck_assert_uint_eq(convert("$.temps[*]", UA_TYPES_INT16, &v), UA_STATUSCODE_GOOD);
    ck_assert(UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_INT16]));
    ck_assert_int_eq(((UA_Int16 *)v.data)[1], 81);
    UA_Variant_clear(&v);

    ck_assert_uint_eq(convert("missing", UA_TYPES_INT32, &v), UA_STATUSCODE_BADNOTFOUND);
} END_TEST

START_TEST(Scale) {
    UA_Int64 raw = 53;
    UA_Variant in, out;
    UA_Variant_setScalar(&in, &raw, &UA_TYPES[UA_TYPES_INT64]);
    ck_assert_uint_eq(restScale(&in, 0.1, &out), UA_STATUSCODE_GOOD);
    ck_assert(*(UA_Double *)out.data == 5.3); /* Not 5.300000000000001 */
    UA_Variant_clear(&out);
} END_TEST

static Suite *testSuite_RestTransform(void) {
    TCase *tc = tcase_create("Transform");
    tcase_add_checked_fixture(tc, NULL, teardown);
    tcase_add_test(tc, JsonValues);
    tcase_add_test(tc, DuplicateKeysLastWins);
    tcase_add_test(tc, TooDeep);
    tcase_add_test(tc, NotJson);
    tcase_add_test(tc, Paths);
    tcase_add_test(tc, Conversion);
    tcase_add_test(tc, Scale);
    Suite *s = suite_create("Transform of the REST driver");
    suite_add_tcase(s, tc);
    return s;
}

int main(void) {
    SRunner *sr = srunner_create(testSuite_RestTransform());
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
