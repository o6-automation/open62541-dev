/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2025 (c) open62541 contributors
 */

#include <open62541/config.h>

#ifdef UA_ENABLE_DISCOVERY_SEMAPHORE

#include <zephyr/fs/fs.h>

int UA_fileExists(const char *path) {
    struct fs_dirent entry;
    int rc = fs_stat(path, &entry);
    return rc == 0;
}

#endif /* UA_ENABLE_DISCOVERY_SEMAPHORE */
