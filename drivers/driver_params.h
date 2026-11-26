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

/* Any numeric scalar as a Double. False for other values. */
UA_Boolean
driverNumber(const UA_Variant *v, UA_Double *out);

/* The positive "interval" of the map in milliseconds. Unchanged if missing. */
UA_StatusCode
driverParamsInterval(const UA_KeyValueMap *map, UA_Double *interval);

_UA_END_DECLS

#endif /* UA_DRIVER_PARAMS_H_ */
