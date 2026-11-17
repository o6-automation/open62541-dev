/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

#include <open62541/config.h>

#ifdef UA_ENABLE_DRIVER_REST

#include "driver_params.h"
#include "cj5.h"

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

UA_String
driverPathSegment(UA_String *path) {
    UA_String segment = *path;
    for(size_t i = 0; i < path->length; i++) {
        if(path->data[i] == '.') {
            segment.length = i;
            path->data += i + 1;
            path->length -= i + 1;
            return segment;
        }
    }
    path->length = 0;
    return segment;
}

static UA_StatusCode
appendValue(const UA_Variant *v, UA_String *out) {
    if(!v || !UA_Variant_isScalar(v))
        return UA_STATUSCODE_BADNOTFOUND;
    if(v->type == &UA_TYPES[UA_TYPES_STRING] ||
       v->type == &UA_TYPES[UA_TYPES_BYTESTRING])
        return UA_String_append(out, *(const UA_String *)v->data);
    UA_ByteString json = UA_BYTESTRING_NULL;
    UA_StatusCode res = UA_encodeJson(v->data, v->type, &json, NULL);
    UA_String text = json;
    if(text.length >= 2 && text.data[0] == '"') { /* Int64 is a JSON string */
        text.data++;
        text.length -= 2;
    }
    if(res == UA_STATUSCODE_GOOD)
        res = UA_String_append(out, text);
    UA_ByteString_clear(&json);
    return res;
}

static UA_StatusCode
appendJsonField(const UA_ByteString *doc, UA_String path, UA_String *out) {
    cj5_token small[64];
    cj5_token *tokens = small;
    cj5_result r = cj5_parse((const char *)doc->data, (unsigned int)doc->length,
                             small, 64, NULL);
    if(r.error == CJ5_ERROR_OVERFLOW) {
        unsigned int count = r.num_tokens;
        tokens = (cj5_token *)UA_malloc(sizeof(cj5_token) * count);
        if(!tokens)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        r = cj5_parse((const char *)doc->data, (unsigned int)doc->length,
                      tokens, count, NULL);
    }
    UA_StatusCode res = (r.error == CJ5_ERROR_NONE) ?
        UA_STATUSCODE_GOOD : UA_STATUSCODE_BADDECODINGERROR;

    unsigned int idx = 0;
    while(res == UA_STATUSCODE_GOOD && path.length > 0) {
        UA_String segment = driverPathSegment(&path);
        const cj5_token *tok = &r.tokens[idx];
        unsigned int child = idx + 1;
        res = UA_STATUSCODE_BADNOTFOUND;
        if(tok->type == CJ5_TOKEN_OBJECT) {
            for(unsigned int i = 0; i < tok->size / 2; i++) {
                const cj5_token *key = &r.tokens[child];
                UA_String keyName = {key->end + 1 - key->start,
                                     (UA_Byte *)(uintptr_t)&r.json5[key->start]};
                child++;
                if(UA_String_equal(&keyName, &segment)) {
                    idx = child;
                    res = UA_STATUSCODE_GOOD;
                    break;
                }
                cj5_skip(&r, &child);
            }
        } else if(tok->type == CJ5_TOKEN_ARRAY) {
            UA_UInt32 index = 0;
            if(segment.length > 0 &&
               UA_readNumber(segment.data, segment.length, &index) == segment.length &&
               index < tok->size) {
                for(UA_UInt32 i = 0; i < index; i++)
                    cj5_skip(&r, &child);
                idx = child;
                res = UA_STATUSCODE_GOOD;
            }
        }
    }

    if(res == UA_STATUSCODE_GOOD) {
        const cj5_token *tok = &r.tokens[idx];
        if(tok->type == CJ5_TOKEN_STRING) {
            char *buf = (char *)UA_malloc(tok->size + 1);
            unsigned int len = 0;
            if(!buf || cj5_get_str(&r, idx, buf, &len) != CJ5_ERROR_NONE)
                res = UA_STATUSCODE_BADDECODINGERROR;
            else
                res = UA_String_append(out, UA_STRING(buf));
            UA_free(buf);
        } else {
            UA_String raw = {tok->end + 1 - tok->start,
                             (UA_Byte *)(uintptr_t)&r.json5[tok->start]};
            res = UA_String_append(out, raw);
        }
    }
    if(tokens != small)
        UA_free(tokens);
    return res;
}

UA_StatusCode
driverPathAppend(const UA_Variant *v, UA_String path, UA_String *out) {
    UA_Variant element;
    while(v && path.length > 0) {
        if(UA_Variant_isScalar(v) && (v->type == &UA_TYPES[UA_TYPES_STRING] ||
                                      v->type == &UA_TYPES[UA_TYPES_BYTESTRING]))
            return appendJsonField((const UA_ByteString *)v->data, path, out);
        UA_String segment = driverPathSegment(&path);
        if(UA_Variant_hasArrayType(v, &UA_TYPES[UA_TYPES_KEYVALUEPAIR])) {
            const UA_KeyValuePair *pairs = (const UA_KeyValuePair *)v->data;
            const UA_Variant *next = NULL;
            for(size_t i = 0; i < v->arrayLength && !next; i++) {
                if(UA_String_equal_ignorecase(&pairs[i].key.name, &segment))
                    next = &pairs[i].value;
            }
            v = next;
        } else if(!UA_Variant_isScalar(v) && v->type) {
            UA_UInt32 index = 0;
            if(segment.length == 0 ||
               UA_readNumber(segment.data, segment.length, &index) != segment.length ||
               index >= v->arrayLength)
                return UA_STATUSCODE_BADNOTFOUND;
            void *data = (UA_Byte *)v->data + (index * v->type->memSize);
            if(v->type == &UA_TYPES[UA_TYPES_VARIANT]) {
                v = (const UA_Variant *)data;
            } else {
                UA_Variant_setScalar(&element, data, v->type);
                v = &element;
            }
        } else {
            return UA_STATUSCODE_BADNOTFOUND;
        }
    }
    return appendValue(v, out);
}
#endif /* UA_ENABLE_DRIVER_REST */
