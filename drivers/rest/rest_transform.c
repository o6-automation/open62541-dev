/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

/* Transform: pure functions on the value tree, without a server.
 *
 * - JSON (RFC 8259) is decoded once into the value tree.
 * - Paths are JSONPath (RFC 9535, a subset). Keys are case-sensitive, except
 *   below "headers": HTTP header names are not (RFC 9110).
 * - Values are converted to OPC UA types like the OPC UA JSON encoding
 *   (Part 6, 5.4). */

#include "rest_internal.h"
#include "cj5.h"

#include <stdlib.h>

#ifdef UA_ENABLE_DRIVER_REST

/***********************************/
/* JSON into a value tree (RFC 8259) */
/***********************************/

/* Deeper documents are rejected, the value tree is built recursively */
#define REST_JSON_MAX_DEPTH 100

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

/* Integers in the range of Int64 stay exact, other numbers are Double
 * (RFC 8259, section 6) */
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
    if(!integer && cj5_get_float(r, idx, &d) != CJ5_ERROR_NONE)
        return UA_STATUSCODE_BADDECODINGERROR;
    if(integer) { /* Beyond Int64, cj5 has no float for it */
        char buf[64];
        size_t len = (size_t)(tok->end + 1 - tok->start);
        if(len >= sizeof(buf))
            return UA_STATUSCODE_BADDECODINGERROR;
        memcpy(buf, &r->json5[tok->start], len);
        buf[len] = '\0';
        char *end = NULL;
        d = strtod(buf, &end);
        if(end != &buf[len])
            return UA_STATUSCODE_BADDECODINGERROR;
    }
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
jsonToVariant(const cj5_result *r, unsigned int *idx, size_t depth, UA_Variant *out);

static UA_StatusCode
arrayToVariant(const cj5_result *r, unsigned int *idx, size_t depth, UA_Variant *out) {
    size_t size = r->tokens[(*idx)++].size;
    UA_Variant *items = (UA_Variant *)UA_Array_new(size, &UA_TYPES[UA_TYPES_VARIANT]);
    if(!items)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < size && res == UA_STATUSCODE_GOOD; i++)
        res = jsonToVariant(r, idx, depth, &items[i]);
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
objectToVariant(const cj5_result *r, unsigned int *idx, size_t depth, UA_Variant *out) {
    size_t size = r->tokens[(*idx)++].size / 2;
    UA_KeyValuePair *pairs = (UA_KeyValuePair *)
        UA_Array_new(size, &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
    if(!pairs)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < size && res == UA_STATUSCODE_GOOD; i++) {
        res = tokenString(r, (*idx)++, &pairs[i].key.name);
        if(res == UA_STATUSCODE_GOOD)
            res = jsonToVariant(r, idx, depth, &pairs[i].value);
    }
    if(res != UA_STATUSCODE_GOOD) {
        UA_Array_delete(pairs, size, &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
        return res;
    }
    UA_Variant_setArray(out, pairs, size, &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
jsonToVariant(const cj5_result *r, unsigned int *idx, size_t depth, UA_Variant *out) {
    switch(r->tokens[*idx].type) {
    case CJ5_TOKEN_OBJECT:
        if(depth == REST_JSON_MAX_DEPTH)
            return UA_STATUSCODE_BADDECODINGERROR;
        return objectToVariant(r, idx, depth + 1, out);
    case CJ5_TOKEN_ARRAY:
        if(depth == REST_JSON_MAX_DEPTH)
            return UA_STATUSCODE_BADDECODINGERROR;
        return arrayToVariant(r, idx, depth + 1, out);
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
restJsonDecode(const UA_ByteString *doc, UA_Variant *out) {
    UA_Variant_init(out);
    JsonTokens jt;
    UA_StatusCode res = jsonTokenize(doc, &jt);
    if(res == UA_STATUSCODE_BADOUTOFMEMORY)
        return res;
    unsigned int idx = 0;
    if(res == UA_STATUSCODE_GOOD)
        res = jsonToVariant(&jt.r, &idx, 0, out);
    jsonTokensClear(&jt);
    return res;
}

/***************************/
/* Paths (RFC 9535 subset) */
/***************************/

UA_String
restPathSegment(UA_String *path, UA_Boolean *wildcard) {
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
skipRoot(UA_String *path) {
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

/* A scalar of a typed array is placed in element */
static const UA_Variant *
arrayElement(const UA_Variant *v, size_t index, UA_Variant *element) {
    void *data = (UA_Byte *)v->data + (index * v->type->memSize);
    if(v->type == &UA_TYPES[UA_TYPES_VARIANT])
        return (const UA_Variant *)data;
    UA_Variant_setScalar(element, data, v->type);
    return element;
}

static const UA_String headersKey = UA_STRING_STATIC("headers");

/* Keys are case-sensitive, HTTP header names are not */
static UA_Boolean
keyMatches(const UA_String *key, const UA_String *segment, UA_Boolean inHeaders) {
    return inHeaders ? UA_String_equal_ignorecase(key, segment) :
        UA_String_equal(key, segment);
}

const UA_Variant *
restPathFind(const UA_Variant *v, UA_String *path, UA_Variant *element) {
    skipRoot(path);
    UA_Boolean inHeaders = false;
    while(v && path->length > 0) {
        UA_Boolean wildcard;
        UA_String segment = restPathSegment(path, &wildcard);
        if(wildcard)
            return NULL; /* Only single values */
        if(UA_Variant_hasArrayType(v, &UA_TYPES[UA_TYPES_KEYVALUEPAIR])) {
            const UA_KeyValuePair *pairs = (const UA_KeyValuePair *)v->data;
            const UA_Variant *next = NULL; /* The last one of duplicate keys */
            for(size_t i = 0; i < v->arrayLength; i++) {
                if(keyMatches(&pairs[i].key.name, &segment, inHeaders))
                    next = &pairs[i].value;
            }
            inHeaders = UA_String_equal(&segment, &headersKey);
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
restPathHasWildcard(UA_String path) {
    skipRoot(&path);
    while(path.length > 0) {
        UA_Boolean wildcard;
        restPathSegment(&path, &wildcard);
        if(wildcard)
            return true;
    }
    return false;
}

static UA_StatusCode
collect(const UA_Variant *v, UA_String path, UA_Boolean inHeaders,
        UA_Variant **items, size_t *size) {
    if(!v)
        return UA_STATUSCODE_GOOD;
    if(path.length == 0)
        return UA_Array_appendCopy((void **)items, size, v, &UA_TYPES[UA_TYPES_VARIANT]);

    UA_Boolean wildcard;
    UA_String segment = restPathSegment(&path, &wildcard);
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(UA_Variant_hasArrayType(v, &UA_TYPES[UA_TYPES_KEYVALUEPAIR])) {
        const UA_KeyValuePair *pairs = (const UA_KeyValuePair *)v->data;
        UA_Boolean childInHeaders = !wildcard && UA_String_equal(&segment, &headersKey);
        for(size_t i = 0; i < v->arrayLength && res == UA_STATUSCODE_GOOD; i++) {
            if(wildcard || keyMatches(&pairs[i].key.name, &segment, inHeaders))
                res = collect(&pairs[i].value, path, childInHeaders, items, size);
        }
    } else if(!UA_Variant_isScalar(v) && v->type) {
        UA_Variant element;
        UA_UInt32 index = 0;
        if(wildcard) {
            for(size_t i = 0; i < v->arrayLength && res == UA_STATUSCODE_GOOD; i++)
                res = collect(arrayElement(v, i, &element), path, false, items, size);
        } else if(parseIndex(&segment, v->arrayLength, &index)) {
            res = collect(arrayElement(v, index, &element), path, false, items, size);
        }
    }
    return res;
}

UA_StatusCode
restPathCollect(const UA_Variant *v, UA_String path, UA_Variant *out) {
    UA_Variant *items = NULL;
    size_t size = 0;
    skipRoot(&path);
    UA_StatusCode res = collect(v, path, false, &items, &size);
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
restPathMatches(UA_String pattern, UA_String path) {
    skipRoot(&pattern);
    while(pattern.length > 0 && path.length > 0) {
        UA_Boolean wildcard;
        UA_String expected = restPathSegment(&pattern, &wildcard);
        UA_String actual = restPathSegment(&path, NULL);
        if(!wildcard && !UA_String_equal(&expected, &actual))
            return false;
    }
    return pattern.length == 0 && path.length == 0;
}

/* Strings without quotes, other values as JSON */
UA_StatusCode
restValueText(const UA_Variant *v, UA_String *out) {
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

UA_StatusCode
restPathText(const UA_Variant *v, UA_String path, UA_String *out) {
    UA_Variant element;
    v = restPathFind(v, &path, &element);
    return (v && path.length == 0) ? restValueText(v, out) : UA_STATUSCODE_BADNOTFOUND;
}

/******************************************/
/* Values into OPC UA types (Part 6, 5.4) */
/******************************************/

static UA_Boolean
isText(const UA_Variant *v) {
    return v->type == &UA_TYPES[UA_TYPES_STRING] ||
        v->type == &UA_TYPES[UA_TYPES_BYTESTRING];
}

static UA_Boolean
isInteger(const UA_DataType *type) {
    return UA_DataType_isNumeric(type) && type != &UA_TYPES[UA_TYPES_FLOAT] &&
        type != &UA_TYPES[UA_TYPES_DOUBLE];
}

/* The text as the JSON encoding of the type: first as it is (a number, a
 * boolean), then as a JSON string (DateTime, Guid, ByteString in base64, a
 * number in a string) */
static UA_StatusCode
decodeText(const UA_String *text, const UA_DataType *type, UA_Variant *out) {
    void *data = UA_new(type);
    if(!data)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode res = UA_decodeJson(text, data, type, NULL);
    if(res != UA_STATUSCODE_GOOD) {
        UA_clear(data, type);
        UA_String quoted = UA_STRING_NULL;
        res = UA_String_format(&quoted, "\"%S\"", *text);
        if(res == UA_STATUSCODE_GOOD)
            res = UA_decodeJson(&quoted, data, type, NULL);
        UA_String_clear(&quoted);
    }
    if(res != UA_STATUSCODE_GOOD) {
        UA_delete(data, type);
        return UA_STATUSCODE_BADDECODINGERROR;
    }
    UA_Variant_setScalar(out, data, type);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
restConvert(const UA_Variant *v, const UA_DataType *type, UA_Variant *out) {
    UA_Variant_init(out);
    if(!v || UA_Variant_isEmpty(v))
        return UA_STATUSCODE_BADNOTFOUND;
    if(!UA_Variant_isScalar(v))
        return UA_STATUSCODE_BADTYPEMISMATCH;
    if(v->type == type)
        return UA_Variant_copy(v, out);

    /* Numbers: exact, with a range check */
    if(UA_DataType_isNumeric(v->type) && UA_DataType_isNumeric(type)) {
        UA_Double d;
        if(isInteger(type) && !isInteger(v->type) && driverNumber(v, &d) &&
           d != (UA_Double)(UA_Int64)d)
            return UA_STATUSCODE_BADTYPEMISMATCH;
        UA_castNumerical(v, type, out);
        return UA_Variant_isEmpty(out) ? UA_STATUSCODE_BADOUTOFRANGE : UA_STATUSCODE_GOOD;
    }

    /* Text: taken over for String and ByteString, else decoded */
    UA_String text = UA_STRING_NULL;
    UA_StatusCode res = restValueText(v, &text);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    if(type == &UA_TYPES[UA_TYPES_STRING] || type == &UA_TYPES[UA_TYPES_BYTESTRING]) {
        UA_String *s = UA_String_new();
        if(!s) {
            UA_String_clear(&text);
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        *s = text;
        UA_Variant_setScalar(out, s, type);
        return UA_STATUSCODE_GOOD;
    }
    res = isText(v) || v->type == &UA_TYPES[UA_TYPES_BOOLEAN] ?
        decodeText(&text, type, out) : UA_STATUSCODE_BADTYPEMISMATCH;
    UA_String_clear(&text);
    return res;
}

/* All matches of a path with wildcards as an array of the type */
static UA_StatusCode
selectArray(const UA_Variant *root, UA_String path, const UA_DataType *type,
            UA_Variant *out) {
    UA_Variant matches;
    UA_StatusCode res = restPathCollect(root, path, &matches);
    if(res != UA_STATUSCODE_GOOD)
        return res;
    size_t size = matches.arrayLength;
    void *array = UA_Array_new(size, type);
    if(!array) {
        UA_Variant_clear(&matches);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    for(size_t i = 0; i < size && res == UA_STATUSCODE_GOOD; i++) {
        UA_Variant one;
        res = restConvert(&((UA_Variant *)matches.data)[i], type, &one);
        if(res != UA_STATUSCODE_GOOD)
            break;
        memcpy((UA_Byte *)array + i * type->memSize, one.data, type->memSize);
        UA_free(one.data); /* The content moved into the array */
    }
    UA_Variant_clear(&matches);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Array_delete(array, size, type);
        return res;
    }
    UA_Variant_setArray(out, array, size, type);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
restSelect(const UA_Variant *root, UA_String path, const UA_DataType *type,
           UA_Variant *out) {
    UA_Variant_init(out);
    if(restPathHasWildcard(path))
        return selectArray(root, path, type, out);
    UA_Variant element;
    const UA_Variant *v = restPathFind(root, &path, &element);
    if(!v || path.length > 0)
        return UA_STATUSCODE_BADNOTFOUND;
    return restConvert(v, type, out);
}

/*******************/
/* Scale and units */
/*******************/

/* Dividing by 10 gives 5.3 where multiplying by 0.1 gives 5.300000000000001 */
static UA_Double
applyScale(UA_Double value, UA_Double factor) {
    UA_Double inverse = 1.0 / factor;
    if(inverse == (UA_Double)(UA_Int64)inverse)
        return value / inverse;
    return value * factor;
}

UA_StatusCode
restScale(const UA_Variant *v, UA_Double factor, UA_Variant *out) {
    UA_Double d;
    if(driverNumber(v, &d)) {
        d = applyScale(d, factor);
        return UA_Variant_setScalarCopy(out, &d, &UA_TYPES[UA_TYPES_DOUBLE]);
    }
    if(UA_Variant_isScalar(v) || !v->type || !(v->type == &UA_TYPES[UA_TYPES_VARIANT] ||
                                               UA_DataType_isNumeric(v->type)))
        return UA_Variant_copy(v, out);

    /* Variant arrays stay Variant arrays, e.g. with nulls in between */
    const UA_DataType *type = (v->type == &UA_TYPES[UA_TYPES_VARIANT]) ?
        v->type : &UA_TYPES[UA_TYPES_DOUBLE];
    void *array = UA_Array_new(v->arrayLength, type);
    if(!array)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < v->arrayLength && res == UA_STATUSCODE_GOOD; i++) {
        if(type == &UA_TYPES[UA_TYPES_VARIANT]) {
            res = restScale(&((const UA_Variant *)v->data)[i], factor,
                            &((UA_Variant *)array)[i]);
            continue;
        }
        UA_Variant element;
        UA_Variant_setScalar(&element, (UA_Byte *)v->data + i * v->type->memSize,
                             v->type);
        driverNumber(&element, &((UA_Double *)array)[i]);
        ((UA_Double *)array)[i] = applyScale(((UA_Double *)array)[i], factor);
    }
    if(res != UA_STATUSCODE_GOOD) {
        UA_Array_delete(array, v->arrayLength, type);
        return res;
    }
    UA_Variant_setArray(out, array, v->arrayLength, type);
    return UA_STATUSCODE_GOOD;
}

const UA_Variant *
restOption(const UA_KeyValueMap *options, UA_String name, UA_String path) {
    for(size_t i = 0; i < options->mapSize; i++) {
        const UA_String *key = &options->map[i].key.name;
        UA_Boolean pattern = key->length > 0 && key->data[0] == '$';
        if(pattern ? restPathMatches(*key, path) : UA_String_equal(key, &name))
            return &options->map[i].value;
    }
    return NULL;
}

#endif /* UA_ENABLE_DRIVER_REST */
