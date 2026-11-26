/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

/* The Transform stage of the REST driver on input of a web API: JSON into a
 * value tree, paths, conversion into OPC UA types and scale.
 *
 * Input: <JSON> [ '\n' <path> ] <4 bytes memory limit>. Without a path, a few
 * fixed paths are used. */

#include "custom_memory_manager.h"

#include "../../drivers/rest/rest_internal.h"

#include <cstdint>
#include <cstddef>
#include <cstring>

static UA_String
str(const char *s) {
    return UA_STRING((char *)(uintptr_t)s);
}

static void
usePath(const UA_Variant *tree, const UA_String path) {
    UA_Variant element;
    UA_String rest = path;
    const UA_Variant *v = restPathFind(tree, &rest, &element);
    if(v) {
        UA_Variant scaled;
        if(restScale(v, 0.1, &scaled) == UA_STATUSCODE_GOOD)
            UA_Variant_clear(&scaled);
    }

    UA_Variant all;
    if(restPathCollect(tree, path, &all) == UA_STATUSCODE_GOOD)
        UA_Variant_clear(&all);

    UA_String text = UA_STRING_NULL;
    restPathText(tree, path, &text);
    UA_String_clear(&text);

    static const UA_UInt16 types[] = {UA_TYPES_INT32, UA_TYPES_BYTE, UA_TYPES_DOUBLE,
                                      UA_TYPES_BOOLEAN, UA_TYPES_STRING,
                                      UA_TYPES_DATETIME, UA_TYPES_GUID};
    for(size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        UA_Variant out;
        if(restSelect(tree, path, &UA_TYPES[types[i]], &out) == UA_STATUSCODE_GOOD)
            UA_Variant_clear(&out);
    }
    restPathMatches(str("$.a[*].b"), path);
    restPathHasWildcard(path);
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* The last four bytes set the memory limit */
    if(!UA_memoryManager_setLimitFromLast4Bytes(data, size))
        return 0;
    size -= 4;

    const uint8_t *newline = (const uint8_t *)memchr(data, '\n', size);
    size_t jsonSize = newline ? (size_t)(newline - data) : size;
    UA_ByteString doc = {jsonSize, (UA_Byte *)(uintptr_t)data};

    UA_Variant tree;
    if(restJsonDecode(&doc, &tree) != UA_STATUSCODE_GOOD)
        return 0;

    if(newline) {
        UA_String path = {size - jsonSize - 1, (UA_Byte *)(uintptr_t)(newline + 1)};
        usePath(&tree, path);
    } else {
        usePath(&tree, str("$"));
        usePath(&tree, str("$.a"));
        usePath(&tree, str("$[0]"));
        usePath(&tree, str("$.*[*]"));
        usePath(&tree, str("headers.content-type"));
    }
    UA_Variant_clear(&tree);
    return 0;
}
