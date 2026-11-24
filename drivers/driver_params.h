/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Gesa Schönbohm)
 */

#ifndef UA_DRIVER_PARAMS_H_
#define UA_DRIVER_PARAMS_H_

#include <open62541/types.h>

#include "../src/util/ua_util_internal.h"

_UA_BEGIN_DECLS

UA_KeyValueMap
driverParamsMap(const UA_Variant *v);

const UA_String *
driverParamsString(const UA_KeyValueMap *map, const char *key);

/* False if missing */
UA_Boolean
driverParamsBoolean(const UA_KeyValueMap *map, const char *key);

/* A String or ByteString, e.g. a body */
const UA_ByteString *
driverParamsText(const UA_KeyValueMap *map, const char *key);

/* The "status" of a result if it is 400 or higher (as HTTP reports errors),
 * else 0 */
UA_UInt16
driverErrorStatus(const UA_KeyValueMap *result);

/* Zero-terminated copy. NULL is copied as an empty string. */
char *
driverCString(const UA_String *s);

/* The next key or index of a path and the rest of the path. Paths use dots
 * (items.0.id) or the JSONPath notation (items[0]['id']). A wildcard ([*] or
 * .*) sets the flag, which can be NULL. */
UA_String
driverPathSegment(UA_String *path, UA_Boolean *wildcard);

/* Follows the path through objects (KeyValuePair arrays) and arrays. A leading
 * "$" (the JSONPath root) is the value itself. Stops at JSON text (a String or
 * ByteString) with the rest of the path left in path. A scalar from a typed
 * array is placed in element. NULL if not found. */
const UA_Variant *
driverPathFind(const UA_Variant *v, UA_String *path, UA_Variant *element);

UA_StatusCode
driverPathAppend(const UA_Variant *v, UA_String path, UA_String *out);

UA_Boolean
driverPathHasWildcard(UA_String path);

/* Copies of all values at a path with wildcards, as a Variant array in the
 * order of the data. Paths into JSON text parse the text. */
UA_StatusCode
driverPathCollect(const UA_Variant *v, UA_String path, UA_Variant *out);

/* Does a JSONPath pattern (e.g. $.days[*].x) match a dotted path (days.0.x)? */
UA_Boolean
driverPathMatches(UA_String pattern, UA_String path);

/* JSON as a value tree, mapped as documented for the polling of the REST driver */
UA_StatusCode
driverJsonParse(const UA_ByteString *doc, UA_Variant *out);

/* Any numeric scalar as a Double. False for other values. */
UA_Boolean
driverNumber(const UA_Variant *v, UA_Double *out);

/* The positive "interval" of the map in milliseconds. Unchanged if missing. */
UA_StatusCode
driverParamsInterval(const UA_KeyValueMap *map, UA_Double *interval);

_UA_END_DECLS

#endif /* UA_DRIVER_PARAMS_H_ */
