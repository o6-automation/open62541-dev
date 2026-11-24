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

UA_String
driverPathSegment(UA_String *path, UA_Boolean *wildcard) {
    UA_String rest = *path;
    UA_Boolean quoted = false;
    if(rest.length > 0 && rest.data[0] == '.') {
        rest.data++;
        rest.length--;
    }
    UA_String segment = rest;
    size_t end = 0;
    if(rest.length > 0 && rest.data[0] == '[') {
        while(end < rest.length && rest.data[end] != ']')
            end++;
        segment.data = &rest.data[1];
        segment.length = (end > 0) ? end - 1 : 0;
        if(segment.length >= 2 && (segment.data[0] == '\'' || segment.data[0] == '"') &&
           segment.data[segment.length - 1] == segment.data[0]) {
            segment.data++;
            segment.length -= 2;
            quoted = true;
        }
        if(end < rest.length)
            end++; /* The closing bracket */
    } else {
        while(end < rest.length && rest.data[end] != '.' && rest.data[end] != '[')
            end++;
        segment.length = end;
    }
    path->data = rest.data + end;
    path->length = rest.length - end;
    if(wildcard) /* ['*'] is a key */
        *wildcard = !quoted && segment.length == 1 && segment.data[0] == '*';
    return segment;
}

/* "$" is the root in JSONPath, e.g. "$.items[0]". Not "$ref". */
static void
skipJsonPathRoot(UA_String *path) {
    if(path->length > 0 && path->data[0] == '$' &&
       (path->length == 1 || path->data[1] == '.' || path->data[1] == '[')) {
        path->data++;
        path->length--;
    }
}

/* Is the segment an index below size? */
static UA_Boolean
parseIndex(const UA_String *segment, size_t size, UA_UInt32 *index) {
    return segment->length > 0 &&
        UA_readNumber(segment->data, segment->length, index) == segment->length &&
        *index < size;
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

/* Small documents are tokenized into the buffer on the stack */
typedef struct {
    cj5_token small[64];
    cj5_token *tokens;
    cj5_result r;
} JsonTokens;

static UA_StatusCode
jsonTokenize(const UA_ByteString *doc, JsonTokens *jt) {
    jt->tokens = jt->small;
    jt->r = cj5_parse((const char *)doc->data, (unsigned int)doc->length,
                      jt->small, 64, NULL);
    if(jt->r.error == CJ5_ERROR_OVERFLOW) {
        unsigned int count = jt->r.num_tokens;
        jt->tokens = (cj5_token *)UA_malloc(sizeof(cj5_token) * count);
        if(!jt->tokens)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        jt->r = cj5_parse((const char *)doc->data, (unsigned int)doc->length,
                          jt->tokens, count, NULL);
    }
    return (jt->r.error == CJ5_ERROR_NONE) ?
        UA_STATUSCODE_GOOD : UA_STATUSCODE_BADDECODINGERROR;
}

static void
jsonTokensClear(JsonTokens *jt) {
    if(jt->tokens != jt->small)
        UA_free(jt->tokens);
}

static UA_StatusCode
appendJsonField(const UA_ByteString *doc, UA_String path, UA_String *out) {
    JsonTokens jt;
    UA_StatusCode res = jsonTokenize(doc, &jt);
    if(res == UA_STATUSCODE_BADOUTOFMEMORY)
        return res;
    const cj5_result r = jt.r;

    unsigned int idx = 0;
    while(res == UA_STATUSCODE_GOOD && path.length > 0) {
        UA_Boolean wildcard;
        UA_String segment = driverPathSegment(&path, &wildcard);
        const cj5_token *tok = &r.tokens[idx];
        unsigned int child = idx + 1;
        res = UA_STATUSCODE_BADNOTFOUND;
        if(wildcard)
            break;
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
            if(parseIndex(&segment, tok->size, &index)) {
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
    jsonTokensClear(&jt);
    return res;
}

/**************************/
/* JSON into a value tree */
/**************************/

static UA_StatusCode
tokenString(const cj5_result *r, unsigned int idx, UA_String *out) {
    char *buf = (char *)UA_malloc(r->tokens[idx].size + 1);
    unsigned int len = 0;
    if(!buf)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    if(cj5_get_str(r, idx, buf, &len) != CJ5_ERROR_NONE) {
        UA_free(buf);
        return UA_STATUSCODE_BADDECODINGERROR;
    }
    out->data = (UA_Byte *)buf;
    out->length = len;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
numberToVariant(const cj5_result *r, unsigned int idx, UA_Variant *out) {
    const cj5_token *tok = &r->tokens[idx];
    UA_Boolean integer = true;
    for(unsigned int i = tok->start; i <= tok->end && integer; i++)
        integer = (r->json5[i] == '-' || r->json5[i] == '+' ||
                   (r->json5[i] >= '0' && r->json5[i] <= '9'));
    int64_t i64;
    if(integer && cj5_get_int(r, idx, &i64) == CJ5_ERROR_NONE) {
        UA_Int64 v = i64;
        return UA_Variant_setScalarCopy(out, &v, &UA_TYPES[UA_TYPES_INT64]);
    }
    double d;
    if(cj5_get_float(r, idx, &d) != CJ5_ERROR_NONE)
        return UA_STATUSCODE_BADDECODINGERROR;
    UA_Double v = d;
    return UA_Variant_setScalarCopy(out, &v, &UA_TYPES[UA_TYPES_DOUBLE]);
}

static UA_Boolean
isJsonNumber(const UA_DataType *type) {
    return type == &UA_TYPES[UA_TYPES_INT64] || type == &UA_TYPES[UA_TYPES_DOUBLE];
}

/* The common scalar type of the items, Double for a mix of numbers. NULL if
 * there is none. */
static const UA_DataType *
commonScalarType(const UA_Variant *items, size_t size) {
    const UA_DataType *type = NULL;
    for(size_t i = 0; i < size; i++) {
        const UA_DataType *t = items[i].type;
        if(!t || !UA_Variant_isScalar(&items[i]) ||
           t == &UA_TYPES[UA_TYPES_KEYVALUEPAIR])
            return NULL;
        if(!type || t == type)
            type = t;
        else if(isJsonNumber(t) && isJsonNumber(type))
            type = &UA_TYPES[UA_TYPES_DOUBLE];
        else
            return NULL;
    }
    return type;
}

/* Move the scalars into an array of their type */
static UA_StatusCode
toTypedArray(UA_Variant *items, size_t size, const UA_DataType *type,
             UA_Variant *out) {
    void *array = UA_Array_new(size, type);
    if(!array)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    for(size_t i = 0; i < size; i++) {
        void *slot = (UA_Byte *)array + i * type->memSize;
        if(items[i].type == type)
            memcpy(slot, items[i].data, type->memSize);
        else
            *(UA_Double *)slot = (UA_Double)*(UA_Int64 *)items[i].data;
        UA_free(items[i].data);
        UA_Variant_init(&items[i]);
    }
    UA_Variant_setArray(out, array, size, type);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
jsonToVariant(const cj5_result *r, unsigned int *idx, UA_Variant *out);

static UA_StatusCode
arrayToVariant(const cj5_result *r, unsigned int *idx, UA_Variant *out) {
    size_t size = r->tokens[(*idx)++].size;
    UA_Variant *items = (UA_Variant *)UA_Array_new(size, &UA_TYPES[UA_TYPES_VARIANT]);
    if(!items)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < size && res == UA_STATUSCODE_GOOD; i++)
        res = jsonToVariant(r, idx, &items[i]);
    const UA_DataType *type = (res == UA_STATUSCODE_GOOD && size > 0) ?
        commonScalarType(items, size) : NULL;
    if(res == UA_STATUSCODE_GOOD && !type) {
        UA_Variant_setArray(out, items, size, &UA_TYPES[UA_TYPES_VARIANT]);
        return UA_STATUSCODE_GOOD;
    }
    if(res == UA_STATUSCODE_GOOD)
        res = toTypedArray(items, size, type, out);
    UA_Array_delete(items, size, &UA_TYPES[UA_TYPES_VARIANT]);
    return res;
}

static UA_StatusCode
objectToVariant(const cj5_result *r, unsigned int *idx, UA_Variant *out) {
    size_t size = r->tokens[(*idx)++].size / 2;
    UA_KeyValuePair *pairs = (UA_KeyValuePair *)
        UA_Array_new(size, &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
    if(!pairs)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < size && res == UA_STATUSCODE_GOOD; i++) {
        res = tokenString(r, (*idx)++, &pairs[i].key.name);
        if(res == UA_STATUSCODE_GOOD)
            res = jsonToVariant(r, idx, &pairs[i].value);
    }
    if(res != UA_STATUSCODE_GOOD) {
        UA_Array_delete(pairs, size, &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
        return res;
    }
    UA_Variant_setArray(out, pairs, size, &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
jsonToVariant(const cj5_result *r, unsigned int *idx, UA_Variant *out) {
    switch(r->tokens[*idx].type) {
    case CJ5_TOKEN_OBJECT:
        return objectToVariant(r, idx, out);
    case CJ5_TOKEN_ARRAY:
        return arrayToVariant(r, idx, out);
    case CJ5_TOKEN_NUMBER:
        return numberToVariant(r, (*idx)++, out);
    case CJ5_TOKEN_BOOL: {
        bool b = false;
        cj5_get_bool(r, (*idx)++, &b);
        UA_Boolean v = b;
        return UA_Variant_setScalarCopy(out, &v, &UA_TYPES[UA_TYPES_BOOLEAN]);
    }
    case CJ5_TOKEN_STRING: {
        UA_String *s = UA_String_new();
        if(!s)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        UA_StatusCode res = tokenString(r, (*idx)++, s);
        if(res != UA_STATUSCODE_GOOD) {
            UA_free(s);
            return res;
        }
        UA_Variant_setScalar(out, s, &UA_TYPES[UA_TYPES_STRING]);
        return UA_STATUSCODE_GOOD;
    }
    default: /* null */
        (*idx)++;
        UA_Variant_init(out);
        return UA_STATUSCODE_GOOD;
    }
}

UA_StatusCode
driverJsonParse(const UA_ByteString *doc, UA_Variant *out) {
    UA_Variant_init(out);
    JsonTokens jt;
    UA_StatusCode res = jsonTokenize(doc, &jt);
    if(res == UA_STATUSCODE_BADOUTOFMEMORY)
        return res;
    unsigned int idx = 0;
    if(res == UA_STATUSCODE_GOOD)
        res = jsonToVariant(&jt.r, &idx, out);
    jsonTokensClear(&jt);
    return res;
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
    return false; /* Other number types need a numeric cast */
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

static UA_Boolean
isText(const UA_Variant *v) {
    return UA_Variant_isScalar(v) && (v->type == &UA_TYPES[UA_TYPES_STRING] ||
                                      v->type == &UA_TYPES[UA_TYPES_BYTESTRING]);
}

/* A scalar of a typed array is placed in element */
static const UA_Variant *
arrayElement(const UA_Variant *v, size_t index, UA_Variant *element) {
    void *data = (UA_Byte *)v->data + (index * v->type->memSize);
    if(v->type == &UA_TYPES[UA_TYPES_VARIANT])
        return (const UA_Variant *)data;
    UA_Variant_setScalar(element, data, v->type);
    return element;
}

const UA_Variant *
driverPathFind(const UA_Variant *v, UA_String *path, UA_Variant *element) {
    skipJsonPathRoot(path);
    while(v && path->length > 0) {
        if(isText(v))
            return v;
        UA_Boolean wildcard;
        UA_String segment = driverPathSegment(path, &wildcard);
        if(wildcard)
            return NULL; /* Only single values */
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
            if(!parseIndex(&segment, v->arrayLength, &index))
                return NULL;
            v = arrayElement(v, index, element);
        } else {
            return NULL;
        }
    }
    return v;
}

UA_Boolean
driverPathHasWildcard(UA_String path) {
    skipJsonPathRoot(&path);
    while(path.length > 0) {
        UA_Boolean wildcard;
        driverPathSegment(&path, &wildcard);
        if(wildcard)
            return true;
    }
    return false;
}

static UA_StatusCode
collect(const UA_Variant *v, UA_String path, UA_Variant **items, size_t *size);

/* JSON text, e.g. an HTTP body, is parsed to continue the path in it */
static UA_StatusCode
collectInText(const UA_Variant *v, UA_String path, UA_Variant **items, size_t *size) {
    UA_Variant tree;
    if(driverJsonParse((const UA_ByteString *)v->data, &tree) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_GOOD; /* No matches */
    UA_StatusCode res = collect(&tree, path, items, size);
    UA_Variant_clear(&tree);
    return res;
}

static UA_StatusCode
collect(const UA_Variant *v, UA_String path, UA_Variant **items, size_t *size) {
    if(!v)
        return UA_STATUSCODE_GOOD;
    if(path.length == 0)
        return UA_Array_appendCopy((void **)items, size, v, &UA_TYPES[UA_TYPES_VARIANT]);
    if(isText(v))
        return collectInText(v, path, items, size);

    UA_Boolean wildcard;
    UA_String segment = driverPathSegment(&path, &wildcard);
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(UA_Variant_hasArrayType(v, &UA_TYPES[UA_TYPES_KEYVALUEPAIR])) {
        const UA_KeyValuePair *pairs = (const UA_KeyValuePair *)v->data;
        for(size_t i = 0; i < v->arrayLength && res == UA_STATUSCODE_GOOD; i++) {
            if(wildcard || UA_String_equal_ignorecase(&pairs[i].key.name, &segment))
                res = collect(&pairs[i].value, path, items, size);
        }
    } else if(!UA_Variant_isScalar(v) && v->type) {
        UA_Variant element;
        UA_UInt32 index = 0;
        if(wildcard) {
            for(size_t i = 0; i < v->arrayLength && res == UA_STATUSCODE_GOOD; i++)
                res = collect(arrayElement(v, i, &element), path, items, size);
        } else if(parseIndex(&segment, v->arrayLength, &index)) {
            res = collect(arrayElement(v, index, &element), path, items, size);
        }
    }
    return res;
}

UA_StatusCode
driverPathCollect(const UA_Variant *v, UA_String path, UA_Variant *out) {
    UA_Variant *items = NULL;
    size_t size = 0;
    skipJsonPathRoot(&path);
    UA_StatusCode res = collect(v, path, &items, &size);
    if(res == UA_STATUSCODE_GOOD && !items) {
        items = (UA_Variant *)UA_Array_new(0, &UA_TYPES[UA_TYPES_VARIANT]);
        if(!items)
            res = UA_STATUSCODE_BADOUTOFMEMORY;
    }
    if(res != UA_STATUSCODE_GOOD) {
        UA_Array_delete(items, size, &UA_TYPES[UA_TYPES_VARIANT]);
        return res;
    }
    UA_Variant_setArray(out, items, size, &UA_TYPES[UA_TYPES_VARIANT]);
    return UA_STATUSCODE_GOOD;
}

UA_Boolean
driverPathMatches(UA_String pattern, UA_String path) {
    skipJsonPathRoot(&pattern);
    while(pattern.length > 0 && path.length > 0) {
        UA_Boolean wildcard;
        UA_String expected = driverPathSegment(&pattern, &wildcard);
        UA_String actual = driverPathSegment(&path, NULL);
        if(!wildcard && !UA_String_equal_ignorecase(&expected, &actual))
            return false;
    }
    return pattern.length == 0 && path.length == 0;
}

UA_StatusCode
driverPathAppend(const UA_Variant *v, UA_String path, UA_String *out) {
    UA_Variant element;
    v = driverPathFind(v, &path, &element);
    if(v && path.length > 0) /* Stopped at JSON text */
        return appendJsonField((const UA_ByteString *)v->data, path, out);
    return appendValue(v, out);
}
#endif /* UA_ENABLE_DRIVER_REST */
