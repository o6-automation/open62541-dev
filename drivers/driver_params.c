/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

#include <open62541/config.h>

#if defined(UA_ENABLE_DRIVER_HTTP) || defined(UA_ENABLE_DRIVER_REST)

#include "driver_params.h"

UA_KeyValueMap
driverParamsMap(const UA_Variant *v) {
    UA_KeyValueMap map = {0, NULL};
    if(v && UA_Variant_hasArrayType(v, &UA_TYPES[UA_TYPES_KEYVALUEPAIR])) {
        map.mapSize = v->arrayLength;
        map.map = (UA_KeyValuePair *)v->data;
    }
    return map;
}

const UA_String *
driverParamsString(const UA_KeyValueMap *map, const char *key) {
    return (const UA_String *)UA_KeyValueMap_getScalar(
        map, UA_QUALIFIEDNAME(0, (char *)(uintptr_t)key), &UA_TYPES[UA_TYPES_STRING]);
}

UA_Boolean
driverParamsBoolean(const UA_KeyValueMap *map, const char *key) {
    const UA_Boolean *b = (const UA_Boolean *)UA_KeyValueMap_getScalar(
        map, UA_QUALIFIEDNAME(0, (char *)(uintptr_t)key), &UA_TYPES[UA_TYPES_BOOLEAN]);
    return b && *b;
}

const UA_ByteString *
driverParamsText(const UA_KeyValueMap *map, const char *key) {
    const UA_Variant *v =
        UA_KeyValueMap_get(map, UA_QUALIFIEDNAME(0, (char *)(uintptr_t)key));
    if(!v || !UA_Variant_isScalar(v) ||
       (v->type != &UA_TYPES[UA_TYPES_STRING] &&
        v->type != &UA_TYPES[UA_TYPES_BYTESTRING]))
        return NULL;
    return (const UA_ByteString *)v->data;
}

UA_UInt16
driverErrorStatus(const UA_KeyValueMap *result) {
    const UA_UInt16 *status = (const UA_UInt16 *)UA_KeyValueMap_getScalar(
        result, UA_QUALIFIEDNAME(0, "status"), &UA_TYPES[UA_TYPES_UINT16]);
    return (status && *status >= 400) ? *status : 0;
}

char *
driverCString(const UA_String *s) {
    size_t length = s ? s->length : 0;
    char *c = (char *)UA_malloc(length + 1);
    if(!c)
        return NULL;
    if(length > 0)
        memcpy(c, s->data, length);
    c[length] = '\0';
    return c;
}

UA_Boolean
driverNumber(const UA_Variant *v, UA_Double *out) {
    if(!v || !UA_Variant_isScalar(v) || !UA_DataType_isNumeric(v->type))
        return false;
    if(v->type == &UA_TYPES[UA_TYPES_DOUBLE]) {
        *out = *(const UA_Double *)v->data;
        return true;
    }
    if(v->type == &UA_TYPES[UA_TYPES_INT64]) {
        *out = (UA_Double)*(const UA_Int64 *)v->data;
        return true;
    }
    UA_Variant d;
    UA_castNumerical(v, &UA_TYPES[UA_TYPES_DOUBLE], &d);
    if(UA_Variant_isEmpty(&d))
        return false;
    *out = *(UA_Double *)d.data;
    UA_Variant_clear(&d);
    return true;
}

UA_StatusCode
driverParamsInterval(const UA_KeyValueMap *map, UA_Double *interval) {
    const UA_Variant *v = UA_KeyValueMap_get(map, UA_QUALIFIEDNAME(0, "interval"));
    if(!v)
        return UA_STATUSCODE_GOOD;
    UA_Double d;
    if(!driverNumber(v, &d) || d <= 0.0)
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    *interval = d;
    return UA_STATUSCODE_GOOD;
}

#endif /* UA_ENABLE_DRIVER_HTTP || UA_ENABLE_DRIVER_REST */
