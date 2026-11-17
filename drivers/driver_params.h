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

/* Zero-terminated copy. NULL is copied as an empty string. */
char *
driverCString(const UA_String *s);

UA_String
driverPathSegment(UA_String *path);

UA_StatusCode
driverPathAppend(const UA_Variant *v, UA_String path, UA_String *out);

_UA_END_DECLS

#endif /* UA_DRIVER_PARAMS_H_ */
