/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) o6 Automation GmbH (Author: Andreas Ebner)
 */

#include <open62541/types.h>

#if defined(__EMSCRIPTEN__)

#include <emscripten/emscripten.h>
#include <emscripten/html5.h>

/**
 * Clock implementation for Emscripten / browser environment.
 *
 * UA_DateTime_now()          — wall-clock via emscripten_date_now()
 * UA_DateTime_nowMonotonic() — high-res via emscripten_get_now()
 *
 * emscripten_date_now()  returns ms since Unix epoch (Date.now())
 * emscripten_get_now()   returns ms from performance.now() (monotonic)
 */

UA_DateTime UA_DateTime_now(void) {
    /* emscripten_date_now() returns milliseconds since Unix epoch as double */
    double ms = emscripten_date_now();
    return (UA_DateTime)((ms * UA_DATETIME_MSEC) + UA_DATETIME_UNIX_EPOCH);
}

UA_Int64 UA_DateTime_localTimeUtcOffset(void) {
    /* Use JS to get timezone offset.
     * new Date().getTimezoneOffset() returns minutes *west* of UTC,
     * so we negate it for a proper UTC offset. */
    int offsetMinutes = EM_ASM_INT({
        return -(new Date().getTimezoneOffset());
    });
    return (UA_Int64)offsetMinutes * 60 * UA_DATETIME_SEC;
}

UA_DateTime UA_DateTime_nowMonotonic(void) {
    /* emscripten_get_now() returns performance.now() in ms as double.
     * Add the Unix epoch offset so callers see a "normal" date range. */
    double ms = emscripten_get_now();
    return (UA_DateTime)((ms * UA_DATETIME_MSEC) + UA_DATETIME_UNIX_EPOCH);
}

#endif /* __EMSCRIPTEN__ */
